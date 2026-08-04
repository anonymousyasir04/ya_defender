namespace YA_Defender.Shared.Models;

public class ThreatModel
{
    public string Name { get; set; } = "";
    public string FilePath { get; set; } = "";
    public string ThreatType { get; set; } = "";
    public int RiskScore { get; set; }
    public string DetectionMethod { get; set; } = "";
    public string MitreTechnique { get; set; } = "";
    public DateTime DetectedAt { get; set; } = DateTime.Now;
    public string Severity => RiskScore switch
    {
        >= 75 => "Critical",
        >= 50 => "High",
        >= 25 => "Medium",
        _ => "Low"
    };
}

public class CloudVerdict
{
    public string Source { get; set; } = "";
    public bool Detected { get; set; }
    public string Category { get; set; } = "";
    public int Score { get; set; }
    public string Detail { get; set; } = "";
}

public class AppSettings
{
    public bool RealTimeScanning { get; set; } = true;
    public bool AutoQuarantine { get; set; } = false;
    public bool RansomwareShield { get; set; } = true;
    public bool RegistryGuardian { get; set; } = true;
    public bool DnsQuarantine { get; set; } = false;
    public bool UsbDriveScanner { get; set; } = true;
    public bool CloudScanning { get; set; } = true;
    public bool ScheduledScans { get; set; } = false;
    public int ScheduledHour { get; set; } = 3;

    public string VirusTotalApiKey { get; set; } = "";
    public string HybridAnalysisApiKey { get; set; } = "";
    public bool AlwaysListening { get; set; } = false;
    public bool AlwaysSpeaking { get; set; } = false;
    public string Language { get; set; } = "en";

    public const int ScanFileThresholdMs = 200;
    public const int MaxConcurrentScans = 4;
}
