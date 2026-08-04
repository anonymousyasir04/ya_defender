using System.IO;
using System.Text.RegularExpressions;

namespace YA_Defender.WPF.Services;

public class SignatureRule
{
    public required string Name { get; init; }
    public required string ThreatType { get; init; }
    public int Weight { get; init; }
    public string? ContentPattern { get; init; }
    public string? FilePattern { get; init; }
    public string? Extension { get; init; }
}

public static class SignatureEngine
{
    private static readonly List<SignatureRule> Rules = BuildRules();

    public static DetectionResult Evaluate(string filePath, string? contentSample = null)
    {
        var result = new DetectionResult();
        var name = Path.GetFileName(filePath);
        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        string sample = contentSample ?? "";

        bool inSystemDir = IsInSystemDirectory(filePath);

        foreach (var rule in Rules)
        {
            if (rule.FilePattern != null && inSystemDir)
                continue;
            if (rule.FilePattern != null && !Regex.IsMatch(name, rule.FilePattern, RegexOptions.IgnoreCase))
                continue;
            if (rule.Extension != null && !ext.Equals(rule.Extension, StringComparison.OrdinalIgnoreCase))
                continue;
            if (rule.ContentPattern != null && !Contains(sample, rule.ContentPattern))
                continue;
            result.Add("Signature", $"matched {rule.Name}", rule.Weight, rule.ThreatType);
        }
        return result;
    }

    private static bool IsInSystemDirectory(string path)
    {
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(windows)) return false;
        string dir = Path.GetDirectoryName(path) ?? "";
        return dir.StartsWith(windows, StringComparison.OrdinalIgnoreCase) ||
               dir.StartsWith(Path.Combine(windows, "System32"), StringComparison.OrdinalIgnoreCase) ||
               dir.StartsWith(Path.Combine(windows, "SysWOW64"), StringComparison.OrdinalIgnoreCase) ||
               dir.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase);
    }

    public static string? FindContentSample(string filePath)
    {
        try
        {
            using var fs = File.OpenRead(filePath);
            if (fs.Length > 300_000)
            {
                fs.Position = 0;
                var head = new byte[Math.Min(fs.Length, 64_000)];
                fs.Read(head, 0, head.Length);
                var text = System.Text.Encoding.ASCII.GetString(head);
                var tail = new byte[Math.Min(fs.Length - head.Length, 32_000)];
                fs.Position = fs.Length - tail.Length;
                fs.Read(tail, 0, tail.Length);
                return text + "\n" + System.Text.Encoding.ASCII.GetString(tail);
            }
            using var ms = new MemoryStream();
            fs.CopyTo(ms);
            return System.Text.Encoding.ASCII.GetString(ms.ToArray());
        }
        catch
        {
            return null;
        }
    }

    private static bool Contains(string haystack, string needle)
    {
        if (haystack.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) return true;
        var hay = haystack.ToLowerInvariant();
        return hay.IndexOf(needle.ToLowerInvariant(), StringComparison.Ordinal) >= 0;
    }

    private static List<SignatureRule> BuildRules() => new()
    {
        new SignatureRule { Name = "WannaCry ransom note marker", ThreatType = "Ransomware", Weight = 95, ContentPattern = "WanaDecryptor" },
        new SignatureRule { Name = "Conti ransom note marker", ThreatType = "Ransomware", Weight = 95, ContentPattern = "CONTI" },
        new SignatureRule { Name = "LockBit ransom note marker", ThreatType = "Ransomware", Weight = 95, ContentPattern = "LockBit" },
        new SignatureRule { Name = "REvil/Sodinokibi marker", ThreatType = "Ransomware", Weight = 95, ContentPattern = "Sodinokibi" },
        new SignatureRule { Name = "NotPetya wipe marker", ThreatType = "Ransomware", Weight = 95, ContentPattern = "C:\\Windows\\system32\\cmd.exe /c dir /s /b %systemdrive%\\*.dll" },
        new SignatureRule { Name = "PowerShell download cradle", ThreatType = "Trojan", Weight = 80, ContentPattern = "IEX(New-Object Net.WebClient).DownloadString" },
        new SignatureRule { Name = "PowerShell download cradle v2", ThreatType = "Trojan", Weight = 80, ContentPattern = "System.Net.WebClient).DownloadString" },
        new SignatureRule { Name = "Invoke-Mimikatz credential theft", ThreatType = "CredentialStealer", Weight = 90, ContentPattern = "Invoke-Mimikatz" },
        new SignatureRule { Name = "Mimikatz sekurlsa module", ThreatType = "CredentialStealer", Weight = 90, ContentPattern = "sekurlsa::logonpasswords" },
        new SignatureRule { Name = "Metasploit meterpreter stage", ThreatType = "Trojan", Weight = 85, ContentPattern = "meterpreter" },
        new SignatureRule { Name = "Metasploit generic stager", ThreatType = "Trojan", Weight = 75, ContentPattern = "metasploit" },
        new SignatureRule { Name = "Reflective DLL loader", ThreatType = "Trojan", Weight = 85, ContentPattern = "ReflectiveLoader" },
        new SignatureRule { Name = "Cobalt Strike beacon", ThreatType = "RAT", Weight = 90, ContentPattern = "Cobalt Strike" },
        new SignatureRule { Name = "Cobalt Strike pipe beacon", ThreatType = "RAT", Weight = 85, ContentPattern = "MSSE-0000-server" },
        new SignatureRule { Name = "Keylogger hook capture", ThreatType = "Spyware", Weight = 70, ContentPattern = "WH_KEYBOARD_LL" },
        new SignatureRule { Name = "Screen capture spyware", ThreatType = "Spyware", Weight = 65, ContentPattern = "CopyFromScreen" },
        new SignatureRule { Name = "VBS obfuscated exec", ThreatType = "Trojan", Weight = 75, ContentPattern = "ExecuteGlobal" },
        new SignatureRule { Name = "VBS WScript drop pattern", ThreatType = "Worm", Weight = 70, ContentPattern = "WScript.Shell" },
        new SignatureRule { Name = "HTA launcher", ThreatType = "Trojan", Weight = 70, ContentPattern = "mshta" },
        new SignatureRule { Name = "AMSI bypass attempt", ThreatType = "Evasion", Weight = 80, ContentPattern = "AmsiUtils" },
        new SignatureRule { Name = "AMSI bypass patch pattern", ThreatType = "Evasion", Weight = 80, ContentPattern = "amsiInitFailed" },
        new SignatureRule { Name = "ETW patch evasion", ThreatType = "Evasion", Weight = 75, ContentPattern = "EtwEventWrite" },
        new SignatureRule { Name = "Windows Defender exclusion abuse", ThreatType = "Evasion", Weight = 75, ContentPattern = "Add-MpPreference -ExclusionPath" },
        new SignatureRule { Name = "Nishang reverse shell", ThreatType = "RAT", Weight = 85, ContentPattern = "Invoke-PowerShellTcp" },
        new SignatureRule { Name = "Empire stager", ThreatType = "RAT", Weight = 85, ContentPattern = "Invoke-Empire" },
        new SignatureRule { Name = "Run key persistence payload", ThreatType = "Persistence", Weight = 60, ContentPattern = "CurrentVersion\\Run" },
        new SignatureRule { Name = "Scheduled task persistence", ThreatType = "Persistence", Weight = 55, ContentPattern = "schtasks /create" },
        new SignatureRule { Name = "WMI persistence", ThreatType = "Persistence", Weight = 60, ContentPattern = "__EventFilter" },
        new SignatureRule { Name = "Adware toolbar bundle", ThreatType = "Adware", Weight = 45, ContentPattern = "Conduit" },
        new SignatureRule { Name = "Adware dealply", ThreatType = "Adware", Weight = 45, ContentPattern = "Dealply" },
        new SignatureRule { Name = "Crypto miner pool", ThreatType = "Miner", Weight = 75, ContentPattern = "stratum+tcp" },
        new SignatureRule { Name = "Crypto miner coinHive", ThreatType = "Miner", Weight = 75, ContentPattern = "coinhive" },
        new SignatureRule { Name = "Ransomware extension append loop", ThreatType = "Ransomware", Weight = 70, ContentPattern = ".locked" },
        new SignatureRule { Name = "Polymorphic junk code", ThreatType = "Trojan", Weight = 55, ContentPattern = "0x90" },
        new SignatureRule { Name = "Autorun worm marker", ThreatType = "Worm", Weight = 80, ContentPattern = "open=" },
        new SignatureRule { Name = "Double-extension exe", ThreatType = "Trojan", Weight = 60, FilePattern = @".+\..+\.(exe|scr|bat|cmd|pif)$" },
        new SignatureRule { Name = "Suspicious high-number exe name", ThreatType = "Trojan", Weight = 40, FilePattern = @"^\d{5,}\.exe$" },
        new SignatureRule { Name = "System binary impersonation", ThreatType = "Trojan", Weight = 55, FilePattern = @"^(svchost|csrss|winlogon|services|lsass|wininit|smss|conhost)\.(exe|dll)$" },
        new SignatureRule { Name = "WindowsApp spoofed folder", ThreatType = "Adware", Weight = 45, FilePattern = @"^WindowsApp.*\.exe$" },
    };
}
