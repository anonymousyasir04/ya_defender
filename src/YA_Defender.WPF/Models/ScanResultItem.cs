using System.IO;
using YA_Defender.Shared.Models;

namespace YA_Defender.WPF.Models;

public class ScanResultItem
{
    public ScanResult Source { get; set; } = new();
    public string FilePath => Source.FilePath;
    public string FileName => System.IO.Path.GetFileName(Source.FilePath);
    public string ThreatType => Source.ThreatType;
    public int RiskScore => Source.RiskScore;
    public string Method => Source.DetectionMethod;
    public string SizeLabel => FormatSize(Source.FileSize);
    public string DetectedAt => Source.Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
    public bool IsThreat => Source.RiskScore >= 50;
    public string RiskColor => RiskScore switch
    {
        >= 75 => "#FF5252",
        >= 50 => "#FFD700",
        _ => "#2ECC71"
    };
    public string Icon => Source.RiskScore >= 75 ? "\uE711" : Source.RiskScore >= 50 ? "\uE7BA" : "\uE930";

    private static string FormatSize(long bytes)
    {
        if (bytes >= 1024 * 1024 * 1024) return $"{bytes / 1024.0 / 1024 / 1024:F1} GB";
        if (bytes >= 1024 * 1024) return $"{bytes / 1024.0 / 1024:F1} MB";
        if (bytes >= 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes} B";
    }
}
