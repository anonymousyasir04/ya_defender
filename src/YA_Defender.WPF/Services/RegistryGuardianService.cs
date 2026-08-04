using System.IO;
using Microsoft.Win32;
using YA_Defender.Shared.Database;
using YA_Defender.Shared.Models;

namespace YA_Defender.WPF.Services;

public class RegistryChangeAlert
{
    public string KeyPath { get; set; } = "";
    public string ValueName { get; set; } = "";
    public string ValueData { get; set; } = "";
    public string Action { get; set; } = "";
    public bool Reverted { get; set; }
}

public class RegistryGuardianService : IDisposable
{
    public event Action<RegistryChangeAlert>? ChangeDetected;

    private static readonly string[] WatchKeys =
    {
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    };

    private readonly DatabaseHelper _db;
    private Dictionary<string, Dictionary<string, string>> _baseline = new();
    private CancellationTokenSource? _cts;
    private bool _enabled;

    public RegistryGuardianService(DatabaseHelper db)
    {
        _db = db;
    }

    public void Start()
    {
        if (_enabled) return;
        _enabled = true;
        _baseline = Snapshot();
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

    private async Task PollLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var current = Snapshot();
                foreach (var (key, values) in current)
                {
                    if (!_baseline.TryGetValue(key, out var old)) old = new Dictionary<string, string>();
                    foreach (var (name, data) in values)
                    {
                        if (old.TryGetValue(name, out var oldData))
                        {
                            if (oldData != data && IsSuspicious(data))
                                await HandleChangeAsync(key, name, data, "Modified");
                        }
                        else if (IsSuspicious(data))
                        {
                            await HandleChangeAsync(key, name, data, "Created");
                        }
                    }
                }
                _baseline = current;
            }
            catch { }
            await Task.Delay(TimeSpan.FromSeconds(5), ct);
        }
    }

    private async Task HandleChangeAsync(string key, string name, string data, string action)
    {
        bool reverted = false;
        try
        {
            string[] parts = key.Split('\\', 2);
            var hive = parts[0] switch
            {
                "HKEY_CURRENT_USER" => Registry.CurrentUser,
                "HKEY_LOCAL_MACHINE" => Registry.LocalMachine,
                _ => Registry.CurrentUser
            };
            using var regKey = hive.OpenSubKey(parts.Length > 1 ? parts[1] : "", writable: true);
            if (regKey != null && regKey.GetValue(name) is string current && current == data)
            {
                regKey.DeleteValue(name, throwOnMissingValue: false);
                reverted = true;
            }
        }
        catch { }

        var alert = new RegistryChangeAlert { KeyPath = key, ValueName = name, ValueData = data, Action = action, Reverted = reverted };
        ChangeDetected?.Invoke(alert);

        await _db.LogRegistryEvent(new RegistryEvent
        {
            KeyPath = key,
            ValueName = name,
            ValueData = data,
            Action = action,
            IsSuspicious = reverted,
            RiskScore = reverted ? 75 : 0,
            ThreatType = reverted ? "Persistence" : "Watch"
        });
    }

    private static bool IsSuspicious(string data)
    {
        if (string.IsNullOrEmpty(data)) return false;
        var d = data.ToLowerInvariant();
        if (d.Contains("powershell") && (d.Contains("-enc") || d.Contains("-exec"))) return true;
        if (d.Contains(".vbs") || d.Contains(".vbe") || d.Contains(".hta") || d.Contains(".ps1") ||
            d.Contains(".cmd") || d.Contains(".bat") || d.Contains(".jse") || d.Contains(".scr")) return true;
        if (d.Contains("\\temp\\") || d.Contains("\\appdata\\roaming\\") || d.Contains("\\appdata\\local\\")) return true;
        if (d.Contains("rundll32") && d.Contains(",start")) return true;
        if (d.Contains("mshta") || d.Contains("regsvr32") || d.Contains("wscript") || d.Contains("cscript")) return true;
        return false;
    }

    private static Dictionary<string, Dictionary<string, string>> Snapshot()
    {
        var result = new Dictionary<string, Dictionary<string, string>>();
        foreach (var key in WatchKeys)
        {
            var dict = new Dictionary<string, string>();
            string[] parts = key.Split('\\', 2);
            var hive = parts[0] switch
            {
                "HKEY_CURRENT_USER" => Registry.CurrentUser,
                "HKEY_LOCAL_MACHINE" => Registry.LocalMachine,
                _ => null
            };
            if (hive == null) continue;
            try
            {
                using var regKey = hive.OpenSubKey(parts.Length > 1 ? parts[1] : "");
                if (regKey == null) continue;
                foreach (var name in regKey.GetValueNames())
                {
                    var value = regKey.GetValue(name);
                    if (value != null) dict[name] = value.ToString() ?? "";
                }
            }
            catch { }
            result[key] = dict;
        }
        return result;
    }

    public void Dispose() => Stop();
}
