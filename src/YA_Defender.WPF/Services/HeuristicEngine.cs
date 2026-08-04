using System.IO;
using YA_Defender.Shared.Utils;

namespace YA_Defender.WPF.Services;

public static class HeuristicEngine
{
    private static readonly HashSet<string> DangerousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".scr", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".bat", ".cmd",
        ".jar", ".reg", ".msi", ".com", ".pif", ".lnk", ".exe", ".dll", ".docm", ".xlsm", ".pptm"
    };

    private static readonly HashSet<string> MacroExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".docm", ".xlsm", ".pptm"
    };

    public static DetectionResult Evaluate(string filePath, long size, PeFeatures? pe)
    {
        var result = new DetectionResult();
        var name = Path.GetFileName(filePath);
        var dir = Path.GetDirectoryName(filePath) ?? "";
        var ext = Path.GetExtension(filePath).ToLowerInvariant();

        if (string.Equals(name, "autorun.inf", StringComparison.OrdinalIgnoreCase))
        {
            result.Add("Heuristic", "autorun.inf present in drive root (USB spread indicator)", 65, "Worm");
            return result;
        }

        if (name.Equals("update.exe", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("setup.exe", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("installer.exe", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("patch.exe", StringComparison.OrdinalIgnoreCase))
        {
            if (dir.Contains("Temp", StringComparison.OrdinalIgnoreCase) ||
                dir.Contains("AppData", StringComparison.OrdinalIgnoreCase) ||
                dir.Contains("Downloads", StringComparison.OrdinalIgnoreCase))
                result.Add("Heuristic", "generic installer name dropped into a high-risk location", 35, "Trojan");
        }

        if (dir.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StringComparison.OrdinalIgnoreCase))
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (dir.StartsWith(localAppData, StringComparison.OrdinalIgnoreCase) &&
                name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                !dir.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) &&
                !dir.Contains("JetBrains", StringComparison.OrdinalIgnoreCase) &&
                !dir.Contains("GitHub", StringComparison.OrdinalIgnoreCase))
                result.Add("Heuristic", $"unsigned executable running from {Path.GetFileName(localAppData)}", 30, "Trojan");
        }

        if (IsSystemDirHidden(name, ext, dir))
            result.Add("Heuristic", "file impersonates a Windows system binary name", 45, "Trojan");

        if (DangerousExtensions.Contains(ext) && name.Length > 30)
            result.Add("Heuristic", "suspiciously long file name with script/executable extension", 25, "Adware");

        if (name.IndexOf(" ", StringComparison.Ordinal) > 0 && DangerousExtensions.Contains(ext) &&
            char.IsLower(name[0]) && name[0] == name[0] && count(name, '.') > 1)
            result.Add("Heuristic", "double-extension disguise (e.g. invoice.pdf.exe)", 50, "Trojan");

        if (MacroExtensions.Contains(ext) && size > 0 && size < 500_000)
            result.Add("Heuristic", "small office macro file (macro dropper pattern)", 20, "MacroVirus");

        if (pe != null && pe.IsValid)
            EvaluatePe(pe, result);

        return result;

        static int count(string s, char c)
        {
            int n = 0;
            foreach (var ch in s) if (ch == c) n++;
            return n;
        }
    }

    private static bool IsSystemDirHidden(string name, string ext, string dir)
    {
        if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && !name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            return false;

        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrEmpty(windows) &&
            dir.StartsWith(windows, StringComparison.OrdinalIgnoreCase))
            return false;

        string bare = Path.GetFileNameWithoutExtension(name);
        string[] systemBinaries =
        {
            "svchost", "csrss", "winlogon", "services", "lsass", "explorer", "wininit",
            "smss", "conhost", "cmd", "powershell", "taskhost", "dwm", "runtimebroker"
        };
        foreach (var sys in systemBinaries)
            if (bare.Equals(sys, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    private static void EvaluatePe(PeFeatures pe, DetectionResult result)
    {
        var compileDate = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(pe.TimeDateStamp);

        if (pe.PackerIndicators.Count > 0)
            result.Add("Heuristic", $"packer indicators: {string.Join(", ", pe.PackerIndicators.Take(3))}", 30, "Packed");

        if (pe.SuspiciousImports.Count >= 3)
            result.Add("Heuristic", $"suspicious API combination: {string.Join(", ", pe.SuspiciousImports.Take(4))}", 40, "Trojan");
        else if (pe.SuspiciousImports.Count >= 1)
            result.Add("Heuristic", $"suspicious API: {pe.SuspiciousImports[0]}", 15, "Suspicious");

        if (compileDate.Year < 2008)
            result.Add("Heuristic", $"PE compiled {compileDate.Year} (typical of packers/legacy malware)", 10, "Suspicious");

        if (pe.ImageBase != 0 && pe.ImageBase != 0x400000 && pe.ImageBase != 0x140000000)
            result.Add("Heuristic", $"unusual ImageBase 0x{pe.ImageBase:X}", 5, "Suspicious");

        if (pe.NumberOfSections > 20)
            result.Add("Heuristic", $"abnormally high section count ({pe.NumberOfSections})", 15, "Packed");

        if (pe.HasTls && pe.Packer != "")
            result.Add("Heuristic", "TLS callback + packed code (hidden execution flow)", 20, "Rootkit");

        if (pe.OverlaySize > 1_000_000)
            result.Add("Heuristic", $"large overlay payload ({pe.OverlaySize / 1024} KB) appended to PE", 15, "Trojan");

        if (pe.CodeSectionEntropy > 7.5)
            result.Add("Heuristic", $"code section entropy {pe.CodeSectionEntropy:F2} (encrypted/compressed body)", 25, "Packed");
    }
}
