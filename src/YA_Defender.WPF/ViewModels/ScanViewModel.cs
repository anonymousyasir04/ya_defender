using System.IO;
using System.Collections.ObjectModel;
using System.Windows.Threading;
using YA_Defender.Shared.Models;
using YA_Defender.WPF.Models;
using YA_Defender.WPF.Services;

namespace YA_Defender.WPF.ViewModels;

public class ScanViewModel : ViewModelBase
{
    private readonly MainViewModel _main;
    private readonly Dispatcher _dispatcher;
    private readonly CancellationTokenSource _cts = new();
    private bool _isScanning;
    private double _percent;
    private string _currentFile = "";
    private string _etaText = "";
    private string _scanLabel = "";
    private string _statusText = "Ready. Choose a scan type.";

    public ObservableCollection<ScanResultItem> Results { get; } = new();
    public ObservableCollection<string> Terminal { get; } = new();

    public bool IsScanning { get => _isScanning; set => Set(ref _isScanning, value); }
    public double Percent { get => _percent; set => Set(ref _percent, value); }
    public string CurrentFile { get => _currentFile; set => Set(ref _currentFile, value); }
    public string EtaText { get => _etaText; set => Set(ref _etaText, value); }
    public string ScanLabel { get => _scanLabel; set => Set(ref _scanLabel, value); }
    public string StatusText { get => _statusText; set => Set(ref _statusText, value); }

    public AsyncRelayCommand QuickScanCommand { get; }
    public AsyncRelayCommand FullScanCommand { get; }
    public AsyncRelayCommand CustomScanCommand { get; }
    public AsyncRelayCommand UsbScanCommand { get; }
    public AsyncRelayCommand CancelCommand { get; }
    public RelayCommand OpenPathCommand { get; }
    public AsyncRelayCommand QuarantineCommand { get; }
    public AsyncRelayCommand ExportCommand { get; }

    public ScanViewModel(MainViewModel main)
    {
        _main = main;
        _dispatcher = System.Windows.Application.Current.Dispatcher;

        QuickScanCommand = new AsyncRelayCommand(_ => StartScanAsync("Quick", GetQuickScanPaths(), false));
        FullScanCommand = new AsyncRelayCommand(_ => StartScanAsync("Full", new[] { "C:\\" }, true));
        CustomScanCommand = new AsyncRelayCommand(_ => StartCustomScanAsync());
        UsbScanCommand = new AsyncRelayCommand(_ => StartScanAsync("USB", GetRemovableDrives(), false));
        CancelCommand = new AsyncRelayCommand(_ => { _cts.Cancel(); return Task.CompletedTask; });
        OpenPathCommand = new RelayCommand(p => OpenInExplorer(p as string));
        QuarantineCommand = new AsyncRelayCommand(async p =>
        {
            if (p is ScanResultItem item)
                await QuarantineItemAsync(item);
        });
        ExportCommand = new AsyncRelayCommand(async _ => await ExportAsync());

        _main.Services.Scan.LogReceived += line => _dispatcher.BeginInvoke(() =>
        {
            if (Terminal.Count > 400) Terminal.RemoveAt(0);
            Terminal.Add(line);
        });
        _main.Services.Scan.ScanCompleted += s => _dispatcher.BeginInvoke(() => OnScanCompleted(s));
    }

    public async Task ScanDroppedAsync(IEnumerable<string> paths)
    {
        await StartScanAsync("Drag & Drop", paths, false);
    }

    private async Task StartScanAsync(string label, IEnumerable<string> paths, bool full)
    {
        if (IsScanning) return;
        IsScanning = true;
        ScanLabel = label;
        Results.Clear();
        StatusText = $"Scanning...";

        var progress = new Progress<ScanProgress>(p =>
        {
            Percent = p.Percent;
            CurrentFile = p.CurrentFile;
            EtaText = p.Eta.TotalSeconds < 1 ? "calculating..." : $"ETA: {p.Eta.TotalSeconds:F0}s | {p.FilesScanned}/{p.TotalFiles} files";
        });

        try
        {
            await _main.Services.Scan.ScanAsync(label, paths, full, progress, _cts.Token);
        }
        catch (OperationCanceledException)
        {
            StatusText = "Scan cancelled.";
        }
    }

    private async Task StartCustomScanAsync()
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog { Title = "Select folder to scan" };
        if (dialog.ShowDialog() == true)
            await StartScanAsync("Custom", new[] { dialog.FolderName }, false);
    }

    private void OnScanCompleted(ScanSummary summary)
    {
        IsScanning = false;
        Percent = 100;
        EtaText = $"Completed in {summary.Elapsed.TotalSeconds:F1}s";
        if (summary.Cancelled)
        {
            StatusText = $"Scan cancelled after {summary.FilesScanned} files.";
            return;
        }

        var items = summary.Threats.Select(t => new ScanResultItem { Source = t });
        Results.ReplaceWith(items);
        StatusText = $"{summary.FilesScanned} files scanned | {summary.ThreatsFound} threats detected | {summary.Elapsed.TotalSeconds:F1}s";
    }

    private async Task QuarantineItemAsync(ScanResultItem item)
    {
        var q = await _main.Services.Quarantine.QuarantineFileAsync(item.FilePath, item.ThreatType, item.RiskScore, item.Source.FileHash);
        item.Source.IsQuarantined = true;
        StatusText = $"Quarantined: {item.FileName}";
    }

    private static void OpenInExplorer(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        try
        {
            System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{path}\"");
        }
        catch { }
    }

    private async Task ExportAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "HTML Report|*.html|CSV|*.csv|JSON|*.json",
            FileName = $"YA_Defender_Report_{DateTime.Now:yyyyMMdd_HHmmss}"
        };
        if (dialog.ShowDialog() != true) return;
        var summary = new ScanSummary
        {
            ScanType = ScanLabel,
            Threats = Results.Select(r => r.Source).ToList(),
            FilesScanned = Results.Count,
            ThreatsFound = Results.Count(r => r.IsThreat)
        };
        switch (System.IO.Path.GetExtension(dialog.FileName).ToLowerInvariant())
        {
            case ".html":
                await _main.Services.Report.ExportHtmlReportAsync(summary, dialog.FileName);
                break;
            case ".csv":
                await _main.Services.Report.ExportScanCsvAsync(summary.Threats, dialog.FileName);
                break;
            case ".json":
                await _main.Services.Report.ExportJsonAsync(summary.Threats, dialog.FileName);
                break;
        }
        StatusText = $"Report exported to {dialog.FileName}";
    }

    private static IEnumerable<string> GetQuickScanPaths()
    {
        yield return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp");
    }

    private static IEnumerable<string> GetRemovableDrives()
    {
        foreach (var d in System.IO.DriveInfo.GetDrives())
            if (d.DriveType == System.IO.DriveType.Removable && d.IsReady)
                yield return d.RootDirectory.FullName;
    }
}
