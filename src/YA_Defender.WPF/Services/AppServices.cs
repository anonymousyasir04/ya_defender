using System.IO;
using Serilog;
using YA_Defender.Shared.Database;
using YA_Defender.Shared.Models;
using YA_Defender.Shared.Services;

namespace YA_Defender.WPF.Services;

public class AppServices : IAsyncDisposable
{
    public string AppDataRoot { get; }
    public AppSettings Settings { get; private set; }
    public DatabaseHelper Db { get; private set; }
    public Messenger Bus { get; } = new();
    public CloudScanner Cloud { get; private set; }
    public QuarantineService Quarantine { get; private set; }
    public ScanService Scan { get; private set; }
    public MonitorService Monitor { get; private set; }
    public RansomwareShieldService RansomwareShield { get; private set; }
    public RegistryGuardianService RegistryGuardian { get; private set; }
    public DnsQuarantineService Dns { get; private set; }
    public UsbGuardianService Usb { get; private set; }
    public SystemRepairService Repair { get; } = new();
    public ThreatHunterService Hunter { get; private set; }
    public ReportService Report { get; private set; }
    public LogBufferService LogBuffer { get; } = new();
    private CancellationTokenSource? _schedulerCts;

    public AppServices()
    {
        AppDataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "YA_Defender");
        Directory.CreateDirectory(AppDataRoot);

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.File(Path.Combine(AppDataRoot, "logs", "ya-defender-.log"),
                rollingInterval: RollingInterval.Day, retainedFileCountLimit: 14)
            .CreateLogger();
        Log.Information("YA Defender starting");

        Settings = SettingsService.Load(AppDataRoot);
        Db = new DatabaseHelper(Path.Combine(AppDataRoot, "ya_defender.db"));
        Db.InitializeAsync().GetAwaiter().GetResult();

        Cloud = new CloudScanner(Db);
        Quarantine = new QuarantineService(Db, AppDataRoot);
        Scan = new ScanService(Db, Cloud, Quarantine, Settings);
        Monitor = new MonitorService(Db);
        RansomwareShield = new RansomwareShieldService();
        RegistryGuardian = new RegistryGuardianService(Db);
        Dns = new DnsQuarantineService();
        Usb = new UsbGuardianService(async drive => await ScanDriveAsync(drive));
        Hunter = new ThreatHunterService(Db);
        Report = new ReportService(Db);

        WireEvents();
    }

    private void WireEvents()
    {
        Scan.LogReceived += line => { LogBuffer.Append(line); Bus.Publish(new LogMessage(line)); };
        Monitor.ProcessCreated += e => Bus.Publish(e);
        Monitor.FileChanged += e => Bus.Publish(e);
        Monitor.ConnectionDetected += e => Bus.Publish(e);
        RansomwareShield.ShieldTriggered += a => Bus.Publish(a);
        RegistryGuardian.ChangeDetected += a => Bus.Publish(a);
        Usb.DriveDetected += a => Bus.Publish(a);
        Repair.OutputReceived += line => { LogBuffer.Append(line); Bus.Publish(new LogMessage(line)); };
    }

    private async Task ScanDriveAsync(string driveRoot)
    {
        await Scan.ScanAsync("USB", new[] { driveRoot }, false, null, CancellationToken.None);
    }

    public void ApplyProtectionState()
    {
        Monitor.Stop();
        RansomwareShield.Stop();
        RegistryGuardian.Stop();
        Usb.Stop();

        if (Settings.RealTimeScanning) Monitor.Start();
        if (Settings.RansomwareShield)
        {
            var dirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments)
            };
            RansomwareShield.Start(dirs.Distinct());
        }
        if (Settings.RegistryGuardian) RegistryGuardian.Start();
        if (Settings.UsbDriveScanner) Usb.Start();

        ApplyScheduler();
        SettingsService.Save(AppDataRoot, Settings);
    }

    private void ApplyScheduler()
    {
        _schedulerCts?.Cancel();
        _schedulerCts?.Dispose();
        _schedulerCts = null;
        if (!Settings.ScheduledScans) return;

        _schedulerCts = new CancellationTokenSource();
        _ = SchedulerLoopAsync(_schedulerCts.Token);
    }

    private async Task SchedulerLoopAsync(CancellationToken ct)
    {
        int lastDay = DateTime.Now.Day;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var now = DateTime.Now;
                if (now.Day != lastDay && now.Hour == Settings.ScheduledHour)
                {
                    lastDay = now.Day;
                    LogBuffer.Append($"[{now:HH:mm:ss}] Scheduled scan starting (daily {Settings.ScheduledHour}:00)");
                    Bus.Publish(new LogMessage($"[{now:HH:mm:ss}] Scheduled scan starting"));
                    var paths = new[]
                    {
                        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
                    };
                    await Scan.ScanAsync("Scheduled", paths, false, null, ct);
                }
            }
            catch (OperationCanceledException) { break; }
            catch { }
            await Task.Delay(TimeSpan.FromMinutes(1), ct);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _schedulerCts?.Cancel();
        Monitor.Stop();
        RansomwareShield.Stop();
        RegistryGuardian.Stop();
        Usb.Stop();
        SettingsService.Save(AppDataRoot, Settings);
        await Db.DisposeAsync();
        Log.CloseAndFlush();
        GC.SuppressFinalize(this);
    }
}

public class LogMessage
{
    public string Line { get; }
    public LogMessage(string line) => Line = line;
}

public class LogBufferService
{
    private readonly object _lock = new();
    private readonly List<string> _lines = new();
    private const int MaxLines = 2000;

    public IReadOnlyList<string> Lines
    {
        get { lock (_lock) return _lines.ToList(); }
    }

    public void Append(string line)
    {
        lock (_lock)
        {
            _lines.Add(line);
            if (_lines.Count > MaxLines) _lines.RemoveRange(0, _lines.Count - MaxLines);
        }
    }

    public void Clear()
    {
        lock (_lock) _lines.Clear();
    }
}
