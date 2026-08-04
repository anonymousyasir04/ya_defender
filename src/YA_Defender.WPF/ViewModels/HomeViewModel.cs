using System.IO;
using System.Collections.ObjectModel;
using System.Windows.Threading;
using YA_Defender.Shared.Models;
using YA_Defender.WPF.Services;

namespace YA_Defender.WPF.ViewModels;

public class FeedItem
{
    public string Time { get; set; } = "";
    public string Level { get; set; } = "Info";
    public string Message { get; set; } = "";
    public string Color { get; set; } = "#8892B0";
}

public class HomeViewModel : ViewModelBase
{
    private readonly MainViewModel _main;
    private readonly Dispatcher _dispatcher;
    private string _searchQuery = "";
    private string _searchSummary = "";
    private int _safeCount;
    private int _threatCount;
    private int _cleanCount;
    private double _integrity;
    private string _lastUpdate = "";

    public ObservableCollection<FeedItem> Feed { get; } = new();
    public ObservableCollection<SearchHit> SearchResults { get; } = new();
    public ObservableCollection<string> Terminal { get; } = new();
    public ObservableCollection<NetworkEvent> Connections { get; } = new();

    public string SearchQuery { get => _searchQuery; set => Set(ref _searchQuery, value); }
    public string SearchSummary { get => _searchSummary; set => Set(ref _searchSummary, value); }
    public int SafeCount { get => _safeCount; set => Set(ref _safeCount, value); }
    public int ThreatCount { get => _threatCount; set => Set(ref _threatCount, value); }
    public int CleanCount { get => _cleanCount; set => Set(ref _cleanCount, value); }
    public double Integrity { get => _integrity; set => Set(ref _integrity, value); }
    public string LastUpdate { get => _lastUpdate; set => Set(ref _lastUpdate, value); }

    public RelayCommand SearchCommand { get; }
    public RelayCommand ClearFeedCommand { get; }

    public HomeViewModel(MainViewModel main)
    {
        _main = main;
        _dispatcher = System.Windows.Application.Current.Dispatcher;
        SearchCommand = new RelayCommand(_ => _ = DoSearchAsync());
        ClearFeedCommand = new RelayCommand(() =>
        {
            Feed.Clear();
            _main.Services.LogBuffer.Clear();
        });

        var bus = _main.Services.Bus;
        bus.Subscribe<ProcessEvent>(e => Ui(() => OnProcessEvent(e)));
        bus.Subscribe<FileEvent>(e => Ui(() => OnFileEvent(e)));
        bus.Subscribe<NetworkEvent>(e => Ui(() => OnNetworkEvent(e)));
        bus.Subscribe<YA_Defender.WPF.Services.RegistryChangeAlert>(a => Ui(() => OnRegistryAlert(a)));
        bus.Subscribe<YA_Defender.WPF.Services.RansomwareAlert>(a => Ui(() => OnRansomwareAlert(a)));
        bus.Subscribe<YA_Defender.WPF.Services.UsbDriveAlert>(a => Ui(() => OnUsbAlert(a)));
        bus.Subscribe<YA_Defender.WPF.Services.LogMessage>(m => Ui(() => OnLogMessage(m)));

        AddFeed("System", "YA Defender core engine started. All detection layers armed.", "#00B4D8");
        RefreshStats();
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        timer.Tick += (_, _) => RefreshStats();
        timer.Start();
    }

    private void Ui(Action action) => _dispatcher.BeginInvoke(action);

    private void OnProcessEvent(ProcessEvent e)
    {
        if (e.IsSuspicious)
            AddFeed("Process", $"{e.ProcessName} (PID {e.Pid}) started with suspicious command line: {Truncate(e.CommandLine, 80)}", "#FFD700");
    }

    private void OnFileEvent(FileEvent e)
    {
        if (e.Action == "Created")
            AddFeed("File", $"New file created: {e.FilePath}", "#8892B0");
    }

    private void OnNetworkEvent(NetworkEvent e)
    {
        if (e.IsSuspicious)
            AddFeed("Network", $"{e.ProcessName} -> {e.DestinationIp}:{e.DestinationPort} ({e.ThreatType})", "#FF5252");
        else
            Connections.Add(e);
        if (Connections.Count > 30) Connections.RemoveAt(0);
    }

    private void OnRegistryAlert(YA_Defender.WPF.Services.RegistryChangeAlert a)
    {
        string status = a.Reverted ? "reverted" : "notified";
        AddFeed("Registry", $"{a.Action} on {a.KeyPath} \\ {a.ValueName} ({status})", a.Reverted ? "#FF5252" : "#FFD700");
    }

    private void OnRansomwareAlert(YA_Defender.WPF.Services.RansomwareAlert a)
    {
        AddFeed("Ransomware", a.Message, "#FF5252");
        AddFeed("Ransomware", $"Suspended: {string.Join(", ", a.SuspendedProcesses)}", "#FF5252");
        ThreatCount++;
    }

    private void OnUsbAlert(YA_Defender.WPF.Services.UsbDriveAlert a)
    {
        AddFeed("USB", a.SuspiciousFilesFound
            ? $"Suspicious files on {a.DriveName}: {a.SuspiciousFiles.Count} found"
            : $"USB drive detected: {a.DriveName}", a.SuspiciousFilesFound ? "#FFD700" : "#00B4D8");
    }

    private void OnLogMessage(YA_Defender.WPF.Services.LogMessage m)
    {
        if (Terminal.Count > 400) Terminal.RemoveAt(0);
        Terminal.Add(m.Line);
    }

    private void AddFeed(string level, string message, string color)
    {
        Feed.Insert(0, new FeedItem { Time = DateTime.Now.ToString("HH:mm:ss"), Level = level, Message = message, Color = color });
        if (Feed.Count > 200) Feed.RemoveAt(Feed.Count - 1);
    }

    private async void RefreshStats()
    {
        try
        {
            var db = _main.Services.Db;
            SafeCount = (int)await db.Count("file_events");
            CleanCount = (int)await db.Count("scan_results");
            ThreatCount = (int)await db.Count("quarantine");
            double baseScore = 95.0;
            baseScore -= Math.Min(30, ThreatCount * 2.0);
            Integrity = Math.Clamp(baseScore, 0, 100);
            LastUpdate = DateTime.Now.ToString("HH:mm:ss");
        }
        catch { }
    }

    private async Task DoSearchAsync()
    {
        if (string.IsNullOrWhiteSpace(SearchQuery))
        {
            SearchResults.Clear();
            SearchSummary = "Enter a query. Try process:cmd.exe, file:*.exe, ip:185.*, threat:ransomware";
            return;
        }
        var hits = await _main.Services.Hunter.SearchAsync(SearchQuery);
        SearchResults.ReplaceWith(hits);
        SearchSummary = hits.Count == 0 ? "No matches found." : $"{hits.Count} matches found.";
    }

    private static string Truncate(string value, int max)
    {
        if (string.IsNullOrEmpty(value)) return "";
        return value.Length <= max ? value : value[..max] + "...";
    }
}
