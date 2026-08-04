using System.IO;
using YA_Defender.Shared.Database;

namespace YA_Defender.WPF.Services;

public class SearchHit
{
    public string Table { get; set; } = "";
    public string Detail { get; set; } = "";
    public string Risk { get; set; } = "";
    public DateTime Timestamp { get; set; }
}

public class ThreatHunterService
{
    private readonly DatabaseHelper _db;

    public ThreatHunterService(DatabaseHelper db)
    {
        _db = db;
    }

    public async Task<List<SearchHit>> SearchAsync(string query, int limit = 500)
    {
        var hits = new List<SearchHit>();
        if (string.IsNullOrWhiteSpace(query)) return hits;
        query = query.Trim();

        string lower = query.ToLowerInvariant();
        if (lower.StartsWith("process:"))
            hits.AddRange(await SearchProcesses(query["process:".Length..], limit));
        else if (lower.StartsWith("file:"))
            hits.AddRange(await SearchFiles(query["file:".Length..], limit));
        else if (lower.StartsWith("ip:"))
            hits.AddRange(await SearchNetworks(query["ip:".Length..], limit));
        else if (lower.StartsWith("registry:"))
            hits.AddRange(await SearchRegistry(query["registry:".Length..], limit));
        else if (lower.StartsWith("threat:"))
            hits.AddRange(await SearchScans(query["threat:".Length..], limit));
        else
        {
            hits.AddRange(await SearchProcesses(query, limit / 4));
            hits.AddRange(await SearchFiles(query, limit / 4));
            hits.AddRange(await SearchNetworks(query, limit / 4));
            hits.AddRange(await SearchScans(query, limit / 4));
        }
        return hits.OrderByDescending(h => h.Timestamp).Take(limit).ToList();
    }

    private async Task<List<SearchHit>> SearchProcesses(string term, int limit)
    {
        var rows = await _db.QueryAsync(
            "SELECT process_name, command_line, timestamp, risk_score, threat_type FROM process_events WHERE process_name LIKE $t OR command_line LIKE $t ORDER BY timestamp DESC LIMIT $l",
            new[] { ("$t", (object?)("%" + term + "%")), ("$l", limit) });
        return rows.Select(r => new SearchHit
        {
            Table = "Process",
            Detail = $"{r["process_name"]} | {r["command_line"]}",
            Risk = Risk(r),
            Timestamp = ParseTs(r["timestamp"])
        }).ToList();
    }

    private async Task<List<SearchHit>> SearchFiles(string term, int limit)
    {
        var rows = await _db.QueryAsync(
            "SELECT file_path, action, timestamp, risk_score, threat_type FROM file_events WHERE file_path LIKE $t ORDER BY timestamp DESC LIMIT $l",
            new[] { ("$t", (object?)("%" + term + "%")), ("$l", limit) });
        return rows.Select(r => new SearchHit
        {
            Table = "File",
            Detail = $"{r["file_path"]} ({r["action"]})",
            Risk = Risk(r),
            Timestamp = ParseTs(r["timestamp"])
        }).ToList();
    }

    private async Task<List<SearchHit>> SearchNetworks(string term, int limit)
    {
        var rows = await _db.QueryAsync(
            "SELECT destination_ip, destination_port, process_name, timestamp, risk_score, threat_type FROM network_events WHERE destination_ip LIKE $t OR process_name LIKE $t ORDER BY timestamp DESC LIMIT $l",
            new[] { ("$t", (object?)("%" + term + "%")), ("$l", limit) });
        return rows.Select(r => new SearchHit
        {
            Table = "Network",
            Detail = $"{r["destination_ip"]}:{r["destination_port"]} via {r["process_name"]}",
            Risk = Risk(r),
            Timestamp = ParseTs(r["timestamp"])
        }).ToList();
    }

    private async Task<List<SearchHit>> SearchRegistry(string term, int limit)
    {
        var rows = await _db.QueryAsync(
            "SELECT key_path, value_name, value_data, timestamp, risk_score, threat_type FROM registry_events WHERE key_path LIKE $t OR value_name LIKE $t ORDER BY timestamp DESC LIMIT $l",
            new[] { ("$t", (object?)("%" + term + "%")), ("$l", limit) });
        return rows.Select(r => new SearchHit
        {
            Table = "Registry",
            Detail = $"{r["key_path"]} \\ {r["value_name"]} = {r["value_data"]}",
            Risk = Risk(r),
            Timestamp = ParseTs(r["timestamp"])
        }).ToList();
    }

    private async Task<List<SearchHit>> SearchScans(string term, int limit)
    {
        var rows = await _db.QueryAsync(
            "SELECT file_path, threat_type, risk_score, detection_method, timestamp FROM scan_results WHERE threat_type LIKE $t OR detection_method LIKE $t OR file_path LIKE $t ORDER BY timestamp DESC LIMIT $l",
            new[] { ("$t", (object?)("%" + term + "%")), ("$l", limit) });
        return rows.Select(r => new SearchHit
        {
            Table = "Scan",
            Detail = $"{r["file_path"]} [{r["threat_type"]}] via {r["detection_method"]}",
            Risk = Risk(r),
            Timestamp = ParseTs(r["timestamp"])
        }).ToList();
    }

    private static string Risk(Dictionary<string, object?> row)
    {
        int score = Convert.ToInt32(row["risk_score"] ?? 0);
        string type = row["threat_type"] as string ?? "";
        return score >= 50 || type != "" ? $"{score}/100 {type}".Trim() : "low";
    }

    private static DateTime ParseTs(object? value) =>
        DateTime.TryParse(value as string, out var dt) ? dt : DateTime.MinValue;
}
