using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using YA_Defender.Shared.Utils;

namespace YA_Defender.WPF.Services;

public class RansomwareAlert
{
    public string Message { get; set; } = "";
    public List<string> SuspendedProcesses { get; set; } = new();
    public int ModificationsDetected { get; set; }
    public DateTime DetectedAt { get; set; } = DateTime.Now;
}

public class RansomwareShieldService : IDisposable
{
    public event Action<RansomwareAlert>? ShieldTriggered;

    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly Queue<(DateTime Time, string Path)> _recentMods = new();
    private readonly object _lock = new();
    private readonly List<string> _suspendedProcesses = new();
    private readonly HashSet<string> _knownPaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _alertLock = new(1, 1);
    private bool _triggered;
    private bool _enabled;

    private const int EncryptionThreshold = 25;
    private const int WindowSeconds = 60;
    private const double HighEntropy = 7.4;

    private static readonly HashSet<string> SensitiveExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".jpg", ".jpeg", ".png", ".bmp",
        ".gif", ".tif", ".tiff", ".raw", ".txt", ".rtf", ".odt", ".ods", ".csv", ".sql", ".db",
        ".mdb", ".accdb", ".zip", ".rar", ".7z", ".eml", ".msg", ".mp3", ".mp4", ".avi", ".wmv",
        ".mkv", ".iso", ".vhd", ".vhdx", ".bak", ".one", ".dwg", ".psd", ".ai", ".indd", ".key"
    };

    public void Start(IEnumerable<string> directories)
    {
        if (_enabled) return;
        _enabled = true;
        _triggered = false;

        foreach (var dir in directories)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                var watcher = new FileSystemWatcher(dir)
                {
                    IncludeSubdirectories = true,
                    InternalBufferSize = 64 * 1024,
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size
                };
                watcher.Changed += OnFileChanged;
                watcher.Created += OnFileChanged;
                watcher.Error += (_, e) => { };
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch { }
        }
    }

    public void Stop()
    {
        foreach (var w in _watchers) w.Dispose();
        _watchers.Clear();
        _enabled = false;
        foreach (var p in _suspendedProcesses)
            ResumeProcess(p);
        _suspendedProcesses.Clear();
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e)
    {
        if (!_enabled) return;
        try
        {
            var ext = Path.GetExtension(e.FullPath).ToLowerInvariant();
            if (!SensitiveExts.Contains(ext)) return;
            if (e.ChangeType == WatcherChangeTypes.Created && !_knownPaths.Add(e.FullPath)) return;

            double entropy = 0;
            if (e.ChangeType != WatcherChangeTypes.Deleted && new FileInfo(e.FullPath).Length > 0)
                entropy = SampleEntropy(e.FullPath);

            bool encryptionSignal = entropy >= HighEntropy;
            if (!encryptionSignal && e.ChangeType == WatcherChangeTypes.Created) return;

            lock (_lock)
            {
                var now = DateTime.Now;
                while (_recentMods.Count > 0 && (now - _recentMods.Peek().Time).TotalSeconds > WindowSeconds)
                    _recentMods.Dequeue();
                _recentMods.Enqueue((now, e.FullPath));
                if (_recentMods.Count >= EncryptionThreshold && !_triggered)
                    _ = TriggerAsync();
            }
        }
        catch { }
    }

    private async Task TriggerAsync()
    {
        await _alertLock.WaitAsync();
        try
        {
            if (_triggered) return;
            _triggered = true;
            _enabled = false;

            var processes = FindSuspiciousProcesses();
            foreach (var p in processes)
            {
                if (SuspendProcess(p.Id))
                    _suspendedProcesses.Add(p.ProcessName);
            }

            lock (_lock)
            {
                ShieldTriggered?.Invoke(new RansomwareAlert
                {
                    Message = "Mass file encryption pattern detected (high-entropy writes). Ransomware shield engaged.",
                    SuspendedProcesses = processes.Select(p => p.ProcessName).ToList(),
                    ModificationsDetected = _recentMods.Count
                });
            }

            await Task.Delay(TimeSpan.FromSeconds(30));
            _enabled = true;
        }
        finally
        {
            _alertLock.Release();
        }
    }

    private static List<Process> FindSuspiciousProcesses()
    {
        var procs = new List<Process>();
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                if (p.Id == Environment.ProcessId) continue;
                try
                {
                    double cpu = EstimateCpu(p);
                    var name = p.ProcessName.ToLowerInvariant();
                    if (cpu > 40 && !name.StartsWith("svchost") && !name.Equals("explorer") &&
                        !name.Equals("system") && !name.Equals("csrss") && !name.Equals("dwm"))
                        procs.Add(p);
                }
                catch { }
            }
        }
        catch { }
        return procs.Take(3).ToList();
    }

    private static double EstimateCpu(Process p)
    {
        try
        {
            var start = p.TotalProcessorTime;
            Thread.Sleep(80);
            var end = p.TotalProcessorTime;
            var elapsed = end - start;
            var wall = TimeSpan.FromMilliseconds(80);
            return elapsed.TotalMilliseconds / Math.Max(1, wall.TotalMilliseconds) / Environment.ProcessorCount * 100;
        }
        catch { return 0; }
    }

    private static double SampleEntropy(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            var buffer = new byte[Math.Min(fs.Length, 128 * 1024)];
            int read = fs.Read(buffer, 0, buffer.Length);
            if (read != buffer.Length) Array.Resize(ref buffer, read);
            return EntropyCalculator.Calculate(buffer);
        }
        catch { return 0; }
    }

    [DllImport("ntdll.dll")]
    private static extern uint NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll")]
    private static extern uint NtResumeProcess(IntPtr processHandle);

    private static bool SuspendProcess(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return NtSuspendProcess(p.Handle) == 0;
        }
        catch { return false; }
    }

    private static void ResumeProcess(string processName)
    {
        try
        {
            foreach (var p in Process.GetProcessesByName(processName))
            {
                try { NtResumeProcess(p.Handle); } catch { }
            }
        }
        catch { }
    }

    public void Dispose() => Stop();
}
