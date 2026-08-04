using System.IO;
using System.Collections.ObjectModel;
using System.Windows.Threading;
using YA_Defender.WPF.Services;

namespace YA_Defender.WPF.ViewModels;

public class ProfileViewModel : ViewModelBase
{
    private readonly MainViewModel _main;
    private readonly Dispatcher _dispatcher;
    private string _statusText = "Settings loaded.";
    private bool _realTime;
    private bool _autoQuarantine;
    private bool _ransomwareShield;
    private bool _registryGuardian;
    private bool _dnsQuarantine;
    private bool _usbScanner;
    private bool _cloudScanning;
    private bool _scheduledScans;
    private string _vtKey = "";
    private string _haKey = "";
    private string _engineStatus = "";

    public ObservableCollection<string> RepairLog { get; } = new();

    public string StatusText { get => _statusText; set => Set(ref _statusText, value); }
    public string VtKey { get => _vtKey; set => Set(ref _vtKey, value); }
    public string HaKey { get => _haKey; set => Set(ref _haKey, value); }
    public string EngineStatus { get => _engineStatus; set => Set(ref _engineStatus, value); }

    public bool RealTime { get => _realTime; set { if (Set(ref _realTime, value)) Save(); } }
    public bool AutoQuarantine { get => _autoQuarantine; set { if (Set(ref _autoQuarantine, value)) Save(); } }
    public bool RansomwareShield { get => _ransomwareShield; set { if (Set(ref _ransomwareShield, value)) Save(); } }
    public bool RegistryGuardian { get => _registryGuardian; set { if (Set(ref _registryGuardian, value)) Save(); } }
    public bool DnsQuarantine { get => _dnsQuarantine; set { if (Set(ref _dnsQuarantine, value)) Save(); } }
    public bool UsbScanner { get => _usbScanner; set { if (Set(ref _usbScanner, value)) Save(); } }
    public bool CloudScanning { get => _cloudScanning; set { if (Set(ref _cloudScanning, value)) Save(); } }
    public bool ScheduledScans { get => _scheduledScans; set { if (Set(ref _scheduledScans, value)) Save(); } }

    private bool _startWithWindows;
    public bool StartWithWindows
    {
        get => _startWithWindows;
        set
        {
            if (!Set(ref _startWithWindows, value)) return;
            SetStartupEntry(value);
            StatusText = value ? "YA Defender will start with Windows." : "Start with Windows disabled.";
        }
    }

    private string _serviceStatus = "Not installed";
    public string ServiceStatus { get => _serviceStatus; set => Set(ref _serviceStatus, value); }

    public AsyncRelayCommand InstallServiceCommand { get; }
    public AsyncRelayCommand UninstallServiceCommand { get; }
    public AsyncRelayCommand RefreshServiceCommand { get; }

    public AsyncRelayCommand SfcCommand { get; }
    public AsyncRelayCommand DismCommand { get; }
    public AsyncRelayCommand ChkdskCommand { get; }
    public AsyncRelayCommand RestorePointCommand { get; }
    public AsyncRelayCommand ExportLogsCommand { get; }
    public AsyncRelayCommand ClearLogsCommand { get; }
    public RelayCommand SaveKeysCommand { get; }

    public ProfileViewModel(MainViewModel main)
    {
        _main = main;
        _dispatcher = System.Windows.Application.Current.Dispatcher;

        var s = _main.Services.Settings;
        _realTime = s.RealTimeScanning;
        _autoQuarantine = s.AutoQuarantine;
        _ransomwareShield = s.RansomwareShield;
        _registryGuardian = s.RegistryGuardian;
        _dnsQuarantine = s.DnsQuarantine;
        _usbScanner = s.UsbDriveScanner;
        _cloudScanning = s.CloudScanning;
        _scheduledScans = s.ScheduledScans;
        _vtKey = s.VirusTotalApiKey;
        _haKey = s.HybridAnalysisApiKey;
        OnPropertyChanged(nameof(RealTime));
        OnPropertyChanged(nameof(AutoQuarantine));
        OnPropertyChanged(nameof(RansomwareShield));
        OnPropertyChanged(nameof(RegistryGuardian));
        OnPropertyChanged(nameof(DnsQuarantine));
        OnPropertyChanged(nameof(UsbScanner));
        OnPropertyChanged(nameof(CloudScanning));
        OnPropertyChanged(nameof(ScheduledScans));
        OnPropertyChanged(nameof(VtKey));
        OnPropertyChanged(nameof(HaKey));

        SfcCommand = new AsyncRelayCommand(async _ => await RunRepairAsync(_main.Services.Repair.RunSfcScanAsync));
        DismCommand = new AsyncRelayCommand(async _ => await RunRepairAsync(_main.Services.Repair.RunDismAsync));
        ChkdskCommand = new AsyncRelayCommand(async _ => await RunRepairAsync(_main.Services.Repair.RunChkdskAsync));
        RestorePointCommand = new AsyncRelayCommand(async _ =>
        {
            await Task.Run(() =>
            {
                bool ok = _main.Services.Repair.CreateRestorePoint();
                StatusText = ok ? "Restore point created." : "Restore point creation failed (System Protection may be disabled).";
            });
        });
        ExportLogsCommand = new AsyncRelayCommand(async _ =>
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "ZIP archive|*.zip",
                FileName = $"YA_Defender_Logs_{DateTime.Now:yyyyMMdd_HHmmss}.zip"
            };
            if (dialog.ShowDialog() != true) return;
            await _main.Services.Report.ExportLogsZipAsync(dialog.FileName);
            StatusText = $"Logs exported to {dialog.FileName}";
        });
        ClearLogsCommand = new AsyncRelayCommand(async _ =>
        {
            await _main.Services.Db.ClearLogs();
            _main.Services.LogBuffer.Clear();
            StatusText = "All logs cleared.";
        });
        SaveKeysCommand = new RelayCommand(() =>
        {
            var s = _main.Services.Settings;
            s.VirusTotalApiKey = VtKey.Trim();
            s.HybridAnalysisApiKey = HaKey.Trim();
            SettingsService.Save(_main.Services.AppDataRoot, s);
            StatusText = "Cloud API keys saved. Cloud scanning uses these for live verdicts.";
        });

        _startWithWindows = RegistryHelper.StartupEntryExists();
        OnPropertyChanged(nameof(StartWithWindows));

        InstallServiceCommand = new AsyncRelayCommand(async _ => await InstallServiceAsync());
        UninstallServiceCommand = new AsyncRelayCommand(async _ => await UninstallServiceAsync());
        RefreshServiceCommand = new AsyncRelayCommand(async _ =>
        {
            ServiceStatus = await Task.Run(RegistryHelper.GetServiceStatus);
            StatusText = "Service status refreshed.";
        });

        RefreshServiceCommand.Execute(null);

        _main.Services.Repair.OutputReceived += line => _dispatcher.BeginInvoke(() =>
        {
            if (RepairLog.Count > 400) RepairLog.RemoveAt(0);
            RepairLog.Add(line);
        });

        EngineStatus = YaraScanner.IsAvailable
            ? "YARA engine: available | Built-in signatures: 40+ rules | Heuristics: active"
            : "YARA engine: unavailable (falling back to built-in signatures) | Heuristics: active";
    }

    private async Task RunRepairAsync(Func<CancellationToken, Task> action)
    {
        StatusText = "Repair tool running - this may take several minutes...";
        using var cts = new CancellationTokenSource();
        try
        {
            await action(cts.Token);
            StatusText = "Repair tool finished. Review the log above.";
        }
        catch (Exception ex)
        {
            StatusText = $"Repair tool failed: {ex.Message}";
        }
    }

    private void Save()
    {
        var s = _main.Services.Settings;
        s.RealTimeScanning = RealTime;
        s.AutoQuarantine = AutoQuarantine;
        s.RansomwareShield = RansomwareShield;
        s.RegistryGuardian = RegistryGuardian;
        s.DnsQuarantine = DnsQuarantine;
        s.UsbDriveScanner = UsbScanner;
        s.CloudScanning = CloudScanning;
        s.ScheduledScans = ScheduledScans;
        _main.Services.ApplyProtectionState();
        StatusText = "Protection settings applied.";
    }

    private static void SetStartupEntry(bool enabled)
    {
        const string keyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        string exe = Environment.ProcessPath ?? "";
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(keyPath, writable: true);
            if (enabled)
                key?.SetValue("YA_Defender", $"\"{exe}\"");
            else
                key?.DeleteValue("YA_Defender", throwOnMissingValue: false);
        }
        catch { }
    }

    private async Task InstallServiceAsync()
    {
        string serviceExe = Path.Combine(AppContext.BaseDirectory, "YA_Defender.Service.exe");
        if (!File.Exists(serviceExe))
        {
            ServiceStatus = "Service binary not found. Build the service project first.";
            return;
        }
        await Task.Run(() =>
        {
            RunSc($"create YA_DefenderService start= auto binPath= \"{serviceExe}\" displayname= \"YA Defender Protection Service\"");
            RunSc("start YA_DefenderService");
        });
        ServiceStatus = await Task.Run(RegistryHelper.GetServiceStatus);
        StatusText = "Service installation requested. Check status below.";
    }

    private async Task UninstallServiceAsync()
    {
        await Task.Run(() =>
        {
            RunSc("stop YA_DefenderService");
            RunSc("delete YA_DefenderService");
        });
        ServiceStatus = "Not installed";
        StatusText = "Service removal requested.";
    }

    private static void RunSc(string args)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = System.Diagnostics.Process.Start(psi);
            p?.WaitForExit(20000);
        }
        catch { }
    }
}

public static class RegistryHelper
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";

    public static bool StartupEntryExists()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RunKeyPath);
            return key?.GetValue("YA_Defender") != null;
        }
        catch { return false; }
    }

    public static string GetServiceStatus()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\YA_DefenderService");
            if (key == null) return "Not installed";
            var start = Convert.ToInt32(key.GetValue("Start") ?? -1);
            return start switch
            {
                2 => "Installed (auto start)",
                3 => "Installed (manual)",
                _ => "Installed"
            };
        }
        catch { return "Unknown"; }
    }
}
