using System.Collections.Generic;
using System.IO;
using YaraSharp;

namespace YA_Defender.WPF.Services;

public static class YaraScanner
{
    public static bool IsAvailable { get; private set; }
    private static YSRules? _rules;

    static YaraScanner()
    {
        try
        {
            var ruleDir = Path.Combine(Path.GetTempPath(), "YA_Defender_rules");
            Directory.CreateDirectory(ruleDir);
            var ruleFile = Path.Combine(ruleDir, "builtin.yar");
            File.WriteAllText(ruleFile, BuiltInRules);

            var ys = new YSInstance();
            var compiler = ys.CompileFromFiles(new List<string> { ruleFile }, new Dictionary<string, object>());
            var errors = compiler.GetErrors();
            if (errors != null && !errors.IsEmpty())
            {
                _rules = null;
                IsAvailable = false;
                return;
            }
            _rules = compiler.GetRules();
            IsAvailable = _rules != null;
        }
        catch
        {
            _rules = null;
            IsAvailable = false;
        }
    }

    public static DetectionResult Scan(string filePath, byte[]? data = null)
    {
        var result = new DetectionResult();
        if (!IsAvailable || _rules == null)
        {
            result.Reasons.Add("YARA engine unavailable; built-in signatures still applied");
            return result;
        }

        try
        {
            var ys = new YSInstance();
            List<YSMatches> matches;
            if (data != null)
                matches = ys.ScanMemory(data, _rules, new Dictionary<string, object>(), 5);
            else
                matches = ys.ScanFile(filePath, _rules, new Dictionary<string, object>(), 5);

            foreach (var m in matches)
            {
                string ruleName = m.Rule?.Identifier ?? "unknown";
                string category = Categorize(ruleName);
                result.Add("YARA", $"rule '{ruleName}'", 70, category);
            }
        }
        catch
        {
            result.Reasons.Add("YARA scan failed; ignored");
        }
        return result;
    }

    private static string Categorize(string rule)
    {
        var r = rule.ToLowerInvariant();
        if (r.Contains("ransom") || r.Contains("wanna") || r.Contains("locky") || r.Contains("crypt")) return "Ransomware";
        if (r.Contains("trojan")) return "Trojan";
        if (r.Contains("spy") || r.Contains("keylog")) return "Spyware";
        if (r.Contains("worm")) return "Worm";
        if (r.Contains("adware") || r.Contains("pua")) return "Adware";
        if (r.Contains("rat") || r.Contains("backdoor") || r.Contains("beacon")) return "RAT";
        if (r.Contains("miner") || r.Contains("coin")) return "Miner";
        if (r.Contains("rootkit")) return "Rootkit";
        return "Malware";
    }

    private const string BuiltInRules = """
        rule YA_Defender_Ransomware_Generic {
            meta: author = "YA Defender" type = "ransomware"
            strings:
                $a = "WanaDecryptor" nocase
                $b = "locker" nocase
                $c = ".encrypted" ascii
            condition:
                (uint16(0) == 0x5A4D and 1 of ($a, $b, $c)) or (2 of them)
        }

        rule YA_Defender_Mimikatz {
            meta: author = "YA Defender" type = "credential-stealer"
            strings:
                $a = "sekurlsa::logonpasswords" ascii
                $b = "Invoke-Mimikatz" nocase
                $c = "privilege::debug" ascii
            condition: any of them
        }

        rule YA_Defender_Meterpreter {
            meta: author = "YA Defender" type = "trojan"
            strings:
                $a = "meterpreter" ascii nocase
                $b = "reflective_dll_injection" ascii nocase
            condition: any of them
        }

        rule YA_Defender_AMSI_Bypass {
            meta: author = "YA Defender" type = "evasion"
            strings:
                $a = "amsiInitFailed" ascii
                $b = "AmsiScanBuffer" ascii
                $c = "AmsiUtils" ascii
            condition: any of them
        }

        rule YA_Defender_C2_Beacon {
            meta: author = "YA Defender" type = "rat"
            strings:
                $a = "MSSE-0000-server" ascii
                $b = "Cobalt Strike" ascii nocase
                $c = "/__admin" ascii
            condition: any of them
        }

        rule YA_Defender_Suspicious_PE {
            meta: author = "YA Defender" type = "suspicious"
            strings:
                $a = "UPX0" ascii
                $b = "UPX1" ascii
                $c = "This program cannot be run in DOS mode" ascii
            condition: uint16(0) == 0x5A4D and ($a or $b) and $c
        }
        """;
}
