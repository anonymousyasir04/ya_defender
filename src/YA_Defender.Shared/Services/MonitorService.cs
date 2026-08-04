using System.Diagnostics;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using YA_Defender.Shared.Database;
using YA_Defender.Shared.Models;

namespace YA_Defender.Shared.Services;

public class MonitorService : IDisposable
{
    public event Action<ProcessEvent>? ProcessCreated;
    public event Action<FileEvent>? FileChanged;
    public event Action<NetworkEvent>? ConnectionDetected;

    private readonly DatabaseHelper _db;
    private readonly List<ManagementEventWatcher> _watchers = new();
    private readonly List<FileSystemWatcher> _fileWatchers = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly HashSet<string> _seenConnections = new();
    private readonly Dictionary<string, Queue<DateTime>> _beaconCounters = new();
    private readonly object _lock = new();
    private bool _enabled;

    public MonitorService(DatabaseHelper db)
    {
        _db = db;
    }

    public void Start()
    {
        if (_enabled) return;
        _enabled = true;

        try
        {
            var processWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            processWatcher.EventArrived += OnProcessStarted;
            processWatcher.Start();
            _watchers.Add(processWatcher);
        }
        catch { }

        var watchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
        };
        foreach (var dir in watchDirs.Where(Directory.Exists))
        {
            try
            {
                var fw = new FileSystemWatcher(dir)
                {
                    IncludeSubdirectories = true,
                    InternalBufferSize = 32 * 1024
                };
                fw.Created += OnFileCreated;
                fw.Error += (_, _) => { };
                fw.EnableRaisingEvents = true;
                _fileWatchers.Add(fw);
            }
            catch { }
        }

        _ = NetworkPollLoopAsync(_cts.Token);
    }

    public void Stop()
    {
        _enabled = false;
        foreach (var w in _watchers)
        {
            try { w.Stop(); } catch { }
            w.Dispose();
        }
        _watchers.Clear();
        foreach (var f in _fileWatchers) f.Dispose();
        _fileWatchers.Clear();
        _cts.Cancel();
    }

    private async void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var evt = e.NewEvent;
            string name = evt.Properties["ProcessName"]?.Value?.ToString() ?? "";
            if (string.IsNullOrEmpty(name)) return;
            uint pid = Convert.ToUInt32(evt.Properties["ProcessID"]?.Value ?? 0);
            uint parentPid = Convert.ToUInt32(evt.Properties["ParentProcessID"]?.Value ?? 0);
            string commandLine = await TryGetCommandLineAsync((int)pid);

            bool suspicious = name.ToLowerInvariant().Contains("powershell") ||
                              name.ToLowerInvariant().Contains("cmd") ||
                              name.ToLowerInvariant().Contains("wscript") ||
                              name.ToLowerInvariant().Contains("cscript") ||
                              name.ToLowerInvariant().Contains("mshta") ||
                              name.ToLowerInvariant().Contains("rundll32");

            var proc = new ProcessEvent
            {
                ProcessName = name,
                Pid = (int)pid,
                ParentPid = (int)parentPid,
                CommandLine = commandLine,
                User = Environment.UserName,
                Timestamp = DateTime.Now,
                IsSuspicious = suspicious,
                RiskScore = suspicious ? 30 : 0,
                ThreatType = suspicious ? "Watch" : ""
            };
            await _db.LogProcessEvent(proc);
            ProcessCreated?.Invoke(proc);
        }
        catch { }
    }

    private void OnFileCreated(object sender, FileSystemEventArgs e)
    {
        try
        {
            var fi = new FileInfo(e.FullPath);
            if (!fi.Exists) return;
            var evt = new FileEvent
            {
                FilePath = e.FullPath,
                Action = "Created",
                Size = fi.Length,
                Entropy = 0,
                ProcessPid = 0,
                Timestamp = DateTime.Now
            };
            _ = LogFileAsync(evt);
            FileChanged?.Invoke(evt);
        }
        catch { }
    }

    private async Task LogFileAsync(FileEvent evt) => await _db.LogFileEvent(evt);

    private async Task NetworkPollLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var table = GetTcpTable();
                foreach (var row in table)
                {
                    if ((MibTcpState)row.State != MibTcpState.Established && (MibTcpState)row.State != MibTcpState.SynSent) continue;
                    var remoteIp = ToIp(row.RemoteAddr);
                    if (remoteIp == null || remoteIp.Equals(IPAddress.Any) || remoteIp.Equals(IPAddress.Loopback)) continue;
                    int remotePort = IPAddress.NetworkToHostOrder(row.RemotePort);

                    string key = $"{row.OwningPid}|{remoteIp}|{remotePort}";
                    bool isNew;
                    lock (_lock)
                    {
                        isNew = _seenConnections.Add(key);
                        if (_seenConnections.Count > 20_000) _seenConnections.Clear();

                        if (!_beaconCounters.TryGetValue(remoteIp.ToString(), out var times))
                        {
                            times = new Queue<DateTime>();
                            _beaconCounters[remoteIp.ToString()] = times;
                        }
                        var now = DateTime.Now;
                        while (times.Count > 0 && (now - times.Peek()).TotalSeconds > 60) times.Dequeue();
                        times.Enqueue(now);
                    }
                    if (!isNew) continue;

                    string processName = row.OwningPid > 0 ? GetProcessName(row.OwningPid) : "unknown";
                    int beaconCount;
                    lock (_lock) beaconCount = _beaconCounters.TryGetValue(remoteIp.ToString(), out var t) ? t.Count : 0;

                    var evt = new NetworkEvent
                    {
                        DestinationIp = remoteIp.ToString(),
                        DestinationPort = remotePort,
                        Protocol = "TCP",
                        ProcessPid = row.OwningPid,
                        ProcessName = processName,
                        Timestamp = DateTime.Now,
                        IsSuspicious = beaconCount > 15 || remotePort is 4444 or 5555 or 31337 or 6667,
                        RiskScore = beaconCount > 15 ? 60 : remotePort is 4444 or 5555 or 31337 or 6667 ? 50 : 0,
                        ThreatType = beaconCount > 15 ? "C2 Beacon" : remotePort is 4444 or 5555 or 31337 or 6667 ? "Suspicious" : ""
                    };
                    await _db.LogNetworkEvent(evt);
                    ConnectionDetected?.Invoke(evt);
                }
            }
            catch { }
            await Task.Delay(TimeSpan.FromSeconds(3), ct);
        }
    }

    private static IPAddress? ToIp(uint networkOrder)
    {
        try
        {
            return new IPAddress(BitConverter.GetBytes(networkOrder));
        }
        catch { return null; }
    }    private static string GetProcessName(int pid)
    {
        try { return Process.GetProcessById(pid).ProcessName; }
        catch { return "unknown"; }
    }

    private static async Task<string> TryGetCommandLineAsync(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            var obj = searcher.Get().Cast<ManagementObject>().FirstOrDefault();
            return obj?.Properties["CommandLine"]?.Value?.ToString() ?? "";
        }
        catch { return ""; }
    }

    #region TCP table

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcprowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public int LocalPort;
        public uint RemoteAddr;
        public int RemotePort;
        public int OwningPid;
    }

    private static MibTcprowOwnerPid[] GetTcpTable()
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, TcpTableClass.OwnerPidAll, 0);
        if (size <= 0) return Array.Empty<MibTcprowOwnerPid>();

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, 2, TcpTableClass.OwnerPidAll, 0) != 0)
                return Array.Empty<MibTcprowOwnerPid>();

            int rowCount = Marshal.ReadInt32(buffer);
            int rowSize = Marshal.SizeOf<MibTcprowOwnerPid>();
            var rows = new MibTcprowOwnerPid[rowCount];
            for (int i = 0; i < rowCount; i++)
            {
                var ptr = buffer + IntPtr.Size + i * rowSize;
                rows[i] = Marshal.PtrToStructure<MibTcprowOwnerPid>(ptr);
            }
            return rows;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private enum MibTcpState
    {
        Closed = 1, Listen = 2, SynSent = 3, SynReceived = 4, Established = 5,
        FinWait1 = 6, FinWait2 = 7, CloseWait = 8, Closing = 9, LastAck = 10, TimeWait = 11, DeleteTcb = 12
    }

    private enum TcpTableClass
    {
        Basic = 0, OwnerPidListen = 1, OwnerPidConnections = 2, OwnerPidAll = 3
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, TcpTableClass tableClass, uint reserved);

    #endregion

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
    }
}
