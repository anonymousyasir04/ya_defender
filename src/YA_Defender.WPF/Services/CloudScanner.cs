using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using YA_Defender.Shared.Database;
using YA_Defender.Shared.Models;
using YA_Defender.Shared.Utils;

namespace YA_Defender.WPF.Services;

public class CloudScanner
{
    private readonly DatabaseHelper _db;
    private readonly HttpClient _http;

    public CloudScanner(DatabaseHelper db)
    {
        _db = db;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("YA_Defender/1.0");
    }

    public async Task<List<CloudVerdict>> ScanAsync(string fileHash, string vtKey, string haKey, CancellationToken ct = default)
    {
        var tasks = new List<Task<CloudVerdict?>>
        {
            QueryCachedOrLive("VirusTotal", fileHash, TimeSpan.FromHours(24), () => QueryVirusTotalAsync(fileHash, vtKey, ct)),
            QueryCachedOrLive("MalwareBazaar", fileHash, TimeSpan.FromDays(7), () => QueryMalwareBazaarAsync(fileHash, ct)),
            QueryCachedOrLive("HybridAnalysis", fileHash, TimeSpan.FromHours(24), () => QueryHybridAnalysisAsync(fileHash, haKey, ct))
        };

        var results = new List<CloudVerdict>();
        foreach (var task in tasks)
        {
            try
            {
                var v = await task;
                if (v != null) results.Add(v);
            }
            catch { }
        }
        return results;
    }

    private async Task<CloudVerdict?> QueryCachedOrLive(string source, string hash, TimeSpan maxAge, Func<Task<CloudVerdict?>> live)
    {
        var cached = await _db.GetCloudCache(hash, source, maxAge);
        if (cached != null) return cached;

        try
        {
            var verdict = await live();
            if (verdict != null)
                await _db.SetCloudCache(hash, source, verdict);
            return verdict;
        }
        catch
        {
            return null;
        }
    }

    private async Task<CloudVerdict?> QueryVirusTotalAsync(string hash, string apiKey, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(apiKey)) return null;
        using var req = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{hash}");
        req.Headers.TryAddWithoutValidation("x-apikey", apiKey);
        using var resp = await _http.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode) return null;

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var stats = doc.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("last_analysis_stats");
        long malicious = stats.GetProperty("malicious").GetInt64();
        long suspicious = stats.GetProperty("suspicious").GetInt64();
        long undetected = stats.GetProperty("undetected").GetInt64();
        double reputation = doc.RootElement.GetProperty("data").GetProperty("attributes").TryGetProperty("reputation", out var rep) ? rep.GetDouble() : 0;

        if (malicious == 0 && suspicious == 0 && undetected == 0) return null;
        var verdict = new CloudVerdict { Source = "VirusTotal", Detected = malicious > 0 };
        if (malicious > 0)
        {
            verdict.Category = "Malware";
            verdict.Score = Math.Min(100, (int)(malicious * 8 + suspicious * 4 + Math.Max(0, reputation) * 2));
            verdict.Detail = $"{malicious} engines malicious, {suspicious} suspicious, reputation {reputation}";
        }
        else
        {
            verdict.Score = Math.Min(30, (int)(suspicious * 4));
            verdict.Detail = $"{suspicious} engines suspicious, {undetected} undetected";
        }
        return verdict;
    }

    private async Task<CloudVerdict?> QueryMalwareBazaarAsync(string hash, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "https://mb-api.abuse.ch/api/v1/")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["query"] = "get_info", ["hash"] = hash })
        };
        using var resp = await _http.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode) return null;

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        string status = doc.RootElement.GetProperty("query_status").GetString() ?? "";
        if (status != "ok") return null;

        var verdict = new CloudVerdict { Source = "MalwareBazaar", Detected = true, Score = 85, Category = "Malware" };
        var data = doc.RootElement.GetProperty("data");
        if (data.GetArrayLength() > 0)
        {
            var first = data[0];
            var sig = first.TryGetProperty("signature", out var s) ? s.GetString() : "";
            verdict.Category = string.IsNullOrEmpty(sig) ? "Malware" : sig;
            verdict.Detail = first.TryGetProperty("file_name", out var fn) ? $"file: {fn.GetString()}" : "";
            if (first.TryGetProperty("tags", out var tags))
                verdict.Detail += " | " + string.Join(", ", tags.EnumerateArray().Select(t => t.GetString()));
        }
        return verdict;
    }

    private async Task<CloudVerdict?> QueryHybridAnalysisAsync(string hash, string apiKey, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(apiKey)) return null;
        using var req = new HttpRequestMessage(HttpMethod.Get, $"https://www.hybrid-analysis.com/api/v2/search/hash?hash={hash}");
        req.Headers.TryAddWithoutValidation("api-key", apiKey);
        using var resp = await _http.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode) return null;

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var verdict = new CloudVerdict { Source = "HybridAnalysis", Detected = false, Score = 0 };
        if (doc.RootElement.ValueKind != JsonValueKind.Array) return verdict;
        foreach (var item in doc.RootElement.EnumerateArray())
        {
            var v = item.GetProperty("verdict").GetString() ?? "";
            if (!v.Equals("clean", StringComparison.OrdinalIgnoreCase))
            {
                verdict.Detected = true;
                verdict.Score = v.Equals("malicious", StringComparison.OrdinalIgnoreCase) ? 80 : 50;
                verdict.Category = v;
                verdict.Detail = item.TryGetProperty("threat_level", out var tl) ? $"threat level {tl.GetInt32()}" : "";
                break;
            }
        }
        return verdict;
    }
}
