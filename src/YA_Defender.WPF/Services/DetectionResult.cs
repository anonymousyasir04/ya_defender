using System.IO;
namespace YA_Defender.WPF.Services;

public class DetectionResult
{
    public bool Malicious { get; set; }
    public int RiskScore { get; set; }
    public string ThreatType { get; set; } = "Unknown";
    public List<string> DetectionMethods { get; set; } = new();
    public List<string> Reasons { get; set; } = new();
    public string Method => DetectionMethods.Count > 0 ? string.Join("+", DetectionMethods.Distinct()) : "Clean";
    public string Summary => Malicious ? $"Risk {RiskScore}/100 | {ThreatType}" : "Clean";

    public void Add(string method, string reason, int weight, string threatType)
    {
        DetectionMethods.Add(method);
        Reasons.Add(reason);
        RiskScore = Math.Min(100, RiskScore + weight);
        if (weight >= 20 || (Malicious && RiskScore >= 40))
            ThreatType = threatType;
        Malicious = Malicious || RiskScore >= 50;
    }
}
