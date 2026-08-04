using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using YA_Defender.Shared.Database;
using YA_Defender.Shared.Models;

namespace YA_Defender.WPF.Services;

public class ReportService
{
    private readonly DatabaseHelper _db;

    public ReportService(DatabaseHelper db)
    {
        _db = db;
    }

    public async Task<string> ExportScanCsvAsync(IEnumerable<ScanResult> results, string? path = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("file_path,file_hash,risk_score,threat_type,detection_method,is_quarantined,file_size,timestamp");
        foreach (var r in results)
            sb.AppendLine($"{Csv(r.FilePath)},{r.FileHash},{r.RiskScore},{Csv(r.ThreatType)},{Csv(r.DetectionMethod)},{r.IsQuarantined},{r.FileSize},{r.Timestamp:yyyy-MM-dd HH:mm:ss}");
        string content = sb.ToString();
        if (path != null) await File.WriteAllTextAsync(path, content);
        return content;
    }

    public async Task<string> ExportJsonAsync(IEnumerable<ScanResult> results, string? path = null)
    {
        string json = JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true });
        if (path != null) await File.WriteAllTextAsync(path, json);
        return json;
    }

    public async Task<string> ExportHtmlReportAsync(ScanSummary summary, string? path = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>YA Defender Report</title></head>");
        sb.AppendLine("<body style=\"font-family:Segoe UI,sans-serif;background:#0A192F;color:#e6f1ff;padding:24px;\">");
        sb.AppendLine($"<h1 style=\"color:#FFD700;\">YA Defender Scan Report</h1>");
        sb.AppendLine($"<p>Scan type: <b>{summary.ScanType}</b> | Files: {summary.FilesScanned} | Threats: {summary.ThreatsFound} | Duration: {summary.Elapsed.TotalSeconds:F1}s</p>");
        sb.AppendLine($"<p>Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss} | Created by Yasir Abbas</p>");
        sb.AppendLine("<table border=\"1\" cellpadding=\"6\" cellspacing=\"0\" style=\"border-collapse:collapse;width:100%;\">");
        sb.AppendLine("<tr style=\"background:#112240;\"><th>File</th><th>Threat</th><th>Risk</th><th>Method</th><th>Detected</th></tr>");
        foreach (var t in summary.Threats)
            sb.AppendLine($"<tr><td>{t.FilePath}</td><td>{t.ThreatType}</td><td>{t.RiskScore}</td><td>{t.DetectionMethod}</td><td>{t.Timestamp:yyyy-MM-dd HH:mm:ss}</td></tr>");
        sb.AppendLine("</table></body></html>");
        string html = sb.ToString();
        if (path != null) await File.WriteAllTextAsync(path, html);
        return html;
    }

    public async Task<string> ExportLogsZipAsync(string path)
    {
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (table, sql) in new[]
        {
            ("process_events", "SELECT * FROM process_events ORDER BY timestamp DESC"),
            ("file_events", "SELECT * FROM file_events ORDER BY timestamp DESC"),
            ("registry_events", "SELECT * FROM registry_events ORDER BY timestamp DESC"),
            ("network_events", "SELECT * FROM network_events ORDER BY timestamp DESC"),
            ("scan_results", "SELECT * FROM scan_results ORDER BY timestamp DESC"),
            ("quarantine", "SELECT * FROM quarantine ORDER BY timestamp DESC")
        })
        {
            try
            {
                var rows = await _db.QueryAsync(sql);
                var entry = zip.CreateEntry($"{table}.csv");
                await using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
                if (rows.Count == 0) continue;
                await writer.WriteLineAsync(string.Join(",", rows[0].Keys.Select(Csv)));
                foreach (var row in rows)
                    await writer.WriteLineAsync(string.Join(",", row.Values.Select(v => Csv(v?.ToString() ?? ""))));
            }
            catch { }
        }
        return path;
    }

    private static string Csv(string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        return value;
    }
}
