using System.IO;
using System.Collections.ObjectModel;
using System.Windows.Threading;
using YA_Defender.Shared.Models;

namespace YA_Defender.WPF.ViewModels;

public class QuarantineViewModel : ViewModelBase
{
    private readonly MainViewModel _main;
    private readonly Dispatcher _dispatcher;
    private string _statusText = "";
    private string _dnsInput = "";
    private bool _dnsEnabled;
    private bool _isBusy;

    public ObservableCollection<QuarantineItem> Items { get; } = new();
    public ObservableCollection<string> BlockedDomains { get; } = new();

    public string StatusText { get => _statusText; set => Set(ref _statusText, value); }
    public string DnsInput { get => _dnsInput; set => Set(ref _dnsInput, value); }
    public bool DnsEnabled { get => _dnsEnabled; set => Set(ref _dnsEnabled, value); }
    public bool IsBusy { get => _isBusy; set => Set(ref _isBusy, value); }

    public AsyncRelayCommand RefreshCommand { get; }
    public AsyncRelayCommand RestoreCommand { get; }
    public AsyncRelayCommand DeleteCommand { get; }
    public AsyncRelayCommand RestoreAllCommand { get; }
    public AsyncRelayCommand DeleteAllCommand { get; }
    public AsyncRelayCommand ExportCommand { get; }
    public RelayCommand AddDomainCommand { get; }
    public RelayCommand RemoveDomainCommand { get; }
    public RelayCommand ApplyBlocklistCommand { get; }

    public QuarantineViewModel(MainViewModel main)
    {
        _main = main;
        _dispatcher = System.Windows.Application.Current.Dispatcher;

        RefreshCommand = new AsyncRelayCommand(_ => LoadAsync());
        RestoreCommand = new AsyncRelayCommand(async p => await RestoreAsync(p as QuarantineItem));
        DeleteCommand = new AsyncRelayCommand(async p => await DeleteAsync(p as QuarantineItem));
        RestoreAllCommand = new AsyncRelayCommand(async _ =>
        {
            var list = Items.ToList();
            foreach (var item in list)
                await RestoreAsync(item);
        });
        DeleteAllCommand = new AsyncRelayCommand(async _ =>
        {
            var list = Items.ToList();
            foreach (var item in list)
                await DeleteAsync(item);
        });
        ExportCommand = new AsyncRelayCommand(async _ => await ExportAsync());
        AddDomainCommand = new RelayCommand(() =>
        {
            if (_main.Services.Dns.AddDomain(DnsInput))
            {
                ReloadDomains();
                StatusText = $"Blocked: {DnsInput.Trim()}";
                DnsInput = "";
            }
            else
            {
                StatusText = "Domain already blocked or invalid.";
            }
        });
        RemoveDomainCommand = new RelayCommand(p =>
        {
            if (p is string domain && _main.Services.Dns.RemoveDomain(domain))
            {
                ReloadDomains();
                StatusText = $"Unblocked: {domain}";
            }
        });
        ApplyBlocklistCommand = new RelayCommand(() =>
        {
            _main.Services.Dns.ApplyDefaultBlocklist();
            ReloadDomains();
            StatusText = "Default blocklist applied to hosts file.";
        });

        _ = LoadAsync();
        ReloadDomains();
    }

    private async Task LoadAsync()
    {
        IsBusy = true;
        try
        {
            var items = await _main.Services.Quarantine.ListAsync();
            Items.ReplaceWith(items);
            StatusText = $"{items.Count} item(s) in quarantine vault (AES-256 encrypted)";
        }
        catch (Exception ex)
        {
            StatusText = $"Failed to load quarantine: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RestoreAsync(QuarantineItem? item)
    {
        if (item == null) return;
        try
        {
            await _main.Services.Quarantine.RestoreAsync(item);
            StatusText = $"Restored: {item.FileName}";
            await LoadAsync();
        }
        catch (Exception ex)
        {
            StatusText = $"Restore failed: {ex.Message}";
        }
    }

    private async Task DeleteAsync(QuarantineItem? item)
    {
        if (item == null) return;
        var result = System.Windows.MessageBox.Show(
            $"Permanently delete quarantined file '{item.FileName}'?\nThis cannot be undone.",
            "YA Defender", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Warning);
        if (result != System.Windows.MessageBoxResult.Yes) return;
        try
        {
            await _main.Services.Quarantine.DeletePermanentlyAsync(item);
            StatusText = $"Deleted: {item.FileName}";
            await LoadAsync();
        }
        catch (Exception ex)
        {
            StatusText = $"Delete failed: {ex.Message}";
        }
    }

    private async Task ExportAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "CSV|*.csv",
            FileName = $"YA_Defender_Quarantine_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
        };
        if (dialog.ShowDialog() != true) return;
        var lines = new System.Text.StringBuilder();
        lines.AppendLine("file_name,original_path,threat_type,risk_score,file_hash,timestamp");
        foreach (var item in Items)
            lines.AppendLine($"{item.FileName},{item.OriginalPath},{item.ThreatType},{item.RiskScore},{item.FileHash},{item.Timestamp:yyyy-MM-dd HH:mm:ss}");
        await File.WriteAllTextAsync(dialog.FileName, lines.ToString());
        StatusText = $"Exported to {dialog.FileName}";
    }

    private void ReloadDomains()
    {
        BlockedDomains.ReplaceWith(_main.Services.Dns.GetBlockedDomains());
        DnsEnabled = BlockedDomains.Count > 0;
    }
}
