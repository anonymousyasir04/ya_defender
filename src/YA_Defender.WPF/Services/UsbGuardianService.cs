using System.IO;

namespace YA_Defender.WPF.Services;

public class UsbDriveAlert
{
    public string DriveName { get; set; } = "";
    public string DriveType { get; set; } = "";
    public bool SuspiciousFilesFound { get; set; }
    public List<string> SuspiciousFiles { get; set; } = new();
}

public class UsbGuardianService : IDisposable
{
    public event Action<UsbDriveAlert>? DriveDetected;

    private HashSet<string> _knownDrives = new();
    private CancellationTokenSource? _cts;
    private readonly Func<string, Task> _scanDrive;
    private bool _enabled;

    public UsbGuardianService(Func<string, Task> scanDrive)
    {
        _scanDrive = scanDrive;
    }

    public void Start()
    {
        if (_enabled) return;
        _enabled = true;
        _knownDrives = new HashSet<string>(GetRemovableDrives());
        _cts = new CancellationTokenSource();
        _ = PollLoopAsync(_cts.Token);
    }

    public void Stop()
    {
        _enabled = false;
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }

    public async Task<UsbDriveAlert> ScanDriveNow(string driveRoot)
    {
        var alert = new UsbDriveAlert { DriveName = driveRoot, DriveType = "Removable" };
        try
        {
            var suspicious = new List<string>();
            foreach (var pattern in new[] { "autorun.inf", "*.exe", "*.scr", "*.vbs", "*.bat", "*.cmd", "*.lnk" })
            {
                try
                {
                    foreach (var file in Directory.GetFiles(driveRoot, pattern, SearchOption.AllDirectories))
                    {
                        var name = Path.GetFileName(file);
                        if (name.Equals("autorun.inf", StringComparison.OrdinalIgnoreCase) ||
                            !IsSystemHelper(file))
                            suspicious.Add(file);
                    }
                }
                catch { }
            }
            alert.SuspiciousFiles = suspicious.Distinct().ToList();
            alert.SuspiciousFilesFound = suspicious.Count > 0;
            if (alert.SuspiciousFilesFound)
                DriveDetected?.Invoke(alert);
        }
        catch { }
        return alert;
    }

    private static bool IsSystemHelper(string path)
    {
        var name = Path.GetFileNameWithoutExtension(path).ToLowerInvariant();
        return name is "desktop" or "autorun" or "indexer";
    }

    private async Task PollLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var current = new HashSet<string>(GetRemovableDrives());
                foreach (var drive in current)
                {
                    if (_knownDrives.Add(drive))
                    {
                        var alert = await ScanDriveNow(drive);
                        DriveDetected?.Invoke(alert);
                        if (_scanDrive != null && alert.SuspiciousFilesFound)
                            await _scanDrive(drive);
                    }
                }
                _knownDrives = current;
            }
            catch { }
            await Task.Delay(TimeSpan.FromSeconds(4), ct);
        }
    }

    private static IEnumerable<string> GetRemovableDrives()
    {
        foreach (var d in DriveInfo.GetDrives())
        {
            if (d.DriveType == DriveType.Removable && d.IsReady)
                yield return d.RootDirectory.FullName;
        }
    }

    public void Dispose() => Stop();
}
