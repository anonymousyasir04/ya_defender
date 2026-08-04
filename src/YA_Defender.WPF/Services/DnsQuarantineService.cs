using System.IO;
namespace YA_Defender.WPF.Services;

public class DnsQuarantineService
{
    private readonly string _hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
    private const string Marker = "# --- YA Defender Quarantine Start ---";
    private const string MarkerEnd = "# --- YA Defender Quarantine End ---";

    private static readonly string[] DefaultBlocklist =
    {
        "discord.com", "discord.gg", "discordapp.com", "cdn.discordapp.com",
        "telegram.org", "telegram.me", "t.me", "web.telegram.org",
        "pastebin.com", "pastee.org", "hastebin.com", "rentry.co",
        "api.ipify.org", "ip-api.com", "ipinfo.io", "icanhazip.com",
        "checkip.amazonaws.com", "whatismyipaddress.com"
    };

    public string HostsPath => _hostsPath;

    public List<string> GetBlockedDomains()
    {
        try
        {
            if (!File.Exists(_hostsPath)) return new List<string>();
            var lines = File.ReadAllLines(_hostsPath);
            var list = new List<string>();
            bool inside = false;
            foreach (var line in lines)
            {
                if (line.TrimStart().StartsWith(Marker)) { inside = true; continue; }
                if (line.TrimStart().StartsWith(MarkerEnd)) { inside = false; continue; }
                if (!inside) continue;
                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2) list.Add(parts[1]);
            }
            return list;
        }
        catch { return new List<string>(); }
    }

    public bool IsBlocked(string domain) => GetBlockedDomains().Contains(domain, StringComparer.OrdinalIgnoreCase);

    public bool AddDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return false;
        domain = domain.Trim().ToLowerInvariant();
        if (IsBlocked(domain)) return false;
        try
        {
            var list = GetBlockedDomains();
            list.Add(domain);
            WriteHosts(list);
            return true;
        }
        catch { return false; }
    }

    public bool RemoveDomain(string domain)
    {
        var list = GetBlockedDomains();
        var removed = list.RemoveAll(d => d.Equals(domain, StringComparison.OrdinalIgnoreCase)) > 0;
        if (removed) WriteHosts(list);
        return removed;
    }

    public void SetBlocklist(IEnumerable<string> domains)
    {
        WriteHosts(domains.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(d => d).ToList());
    }

    public void ApplyDefaultBlocklist() => SetBlocklist(DefaultBlocklist);

    private void WriteHosts(List<string> domains)
    {
        var preserved = new List<string>();
        if (File.Exists(_hostsPath))
        {
            bool inside = false;
            foreach (var line in File.ReadAllLines(_hostsPath))
            {
                if (line.TrimStart().StartsWith(Marker)) { inside = true; continue; }
                if (line.TrimStart().StartsWith(MarkerEnd)) { inside = false; continue; }
                if (!inside) preserved.Add(line);
            }
        }

        var sb = new System.Text.StringBuilder();
        foreach (var line in preserved)
            sb.AppendLine(line);
        if (preserved.Count > 0 && preserved[^1].Length > 0) sb.AppendLine();
        sb.AppendLine(Marker);
        foreach (var d in domains)
            sb.AppendLine($"0.0.0.0 {d}");
        sb.AppendLine(MarkerEnd);
        File.WriteAllText(_hostsPath, sb.ToString());
    }
}
