namespace YA_Defender.Shared.Models;

public class ProcessEvent
{
    public long Id { get; set; }
    public string ProcessName { get; set; } = "";
    public int Pid { get; set; }
    public int ParentPid { get; set; }
    public string CommandLine { get; set; } = "";
    public string User { get; set; } = "";
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public bool IsSuspicious { get; set; }
    public int RiskScore { get; set; }
    public string ThreatType { get; set; } = "";
}

public class FileEvent
{
    public long Id { get; set; }
    public string FilePath { get; set; } = "";
    public string Action { get; set; } = "";
    public long Size { get; set; }
    public double Entropy { get; set; }
    public int ProcessPid { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public bool IsSuspicious { get; set; }
    public int RiskScore { get; set; }
    public string ThreatType { get; set; } = "";
}

public class RegistryEvent
{
    public long Id { get; set; }
    public string KeyPath { get; set; } = "";
    public string ValueName { get; set; } = "";
    public string ValueData { get; set; } = "";
    public string Action { get; set; } = "";
    public int ProcessPid { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public bool IsSuspicious { get; set; }
    public int RiskScore { get; set; }
    public string ThreatType { get; set; } = "";
}

public class NetworkEvent
{
    public long Id { get; set; }
    public string DestinationIp { get; set; } = "";
    public int DestinationPort { get; set; }
    public string Protocol { get; set; } = "";
    public int ProcessPid { get; set; }
    public string ProcessName { get; set; } = "";
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public bool IsSuspicious { get; set; }
    public int RiskScore { get; set; }
    public string ThreatType { get; set; } = "";
}

public class ScanResult
{
    public long Id { get; set; }
    public string FilePath { get; set; } = "";
    public string FileHash { get; set; } = "";
    public int RiskScore { get; set; }
    public string ThreatType { get; set; } = "";
    public string DetectionMethod { get; set; } = "";
    public bool IsQuarantined { get; set; }
    public long FileSize { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.Now;
}

public class QuarantineItem
{
    public long Id { get; set; }
    public string OriginalPath { get; set; } = "";
    public string FileName { get; set; } = "";
    public string FileHash { get; set; } = "";
    public string ThreatType { get; set; } = "";
    public int RiskScore { get; set; }
    public string QuarantinePath { get; set; } = "";
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public bool Restored { get; set; }
}

public class BreachCheck
{
    public long Id { get; set; }
    public string EmailOrPasswordHash { get; set; } = "";
    public bool BreachFound { get; set; }
    public string BreachDetails { get; set; } = "";
    public DateTime Timestamp { get; set; } = DateTime.Now;
}
