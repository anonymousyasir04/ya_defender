using System.IO;
using System.Collections.Concurrent;
using YA_Defender.Shared.Database;
using YA_Defender.Shared.Models;
using YA_Defender.Shared.Utils;

namespace YA_Defender.WPF.Services;

public class ScanProgress
{
    public int FilesScanned { get; set; }
    public int TotalFiles { get; set; }
    public string CurrentFile { get; set; } = "";
    public int ThreatsFound { get; set; }
    public TimeSpan Elapsed { get; set; }
    public TimeSpan Eta { get; set; }
    public double Percent => TotalFiles <= 0 ? 0 : Math.Round(100.0 * FilesScanned / TotalFiles, 1);
}

public class ScanSummary
{
    public int FilesScanned { get; set; }
    public int ThreatsFound;
    public int CleanFiles { get; set; }
    public List<ScanResult> Threats { get; set; } = new();
    public TimeSpan Elapsed { get; set; }
    public string ScanType { get; set; } = "";
    public bool Cancelled { get; set; }
}

public class ScanService
{
    public event Action<string>? LogReceived;
    public event Action<ScanSummary>? ScanCompleted;

    private readonly DatabaseHelper _db;
    private readonly CloudScanner _cloud;
    private readonly QuarantineService _quarantine;
    private readonly AppSettings _settings;

    public ScanService(DatabaseHelper db, CloudScanner cloud, QuarantineService quarantine, AppSettings settings)
    {
        _db = db;
        _cloud = cloud;
        _quarantine = quarantine;
        _settings = settings;
    }

    public async Task<ScanSummary> ScanAsync(string scanType, IEnumerable<string> paths, bool fullScan,
        IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var files = new List<string>();
        foreach (var path in paths)
        {
            try
            {
                if (Directory.Exists(path))
                    files.AddRange(EnumerateFiles(path, fullScan));
                else if (File.Exists(path))
                    files.Add(path);
            }
            catch (Exception ex)
            {
                Log($"skip path {path}: {ex.Message}");
            }
        }

        var distinct = files.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        int total = distinct.Count;
        Log($"Scan '{scanType}' started: {total} files");

        var summary = new ScanSummary { ScanType = scanType };
        var scanned = 0;
        var threats = new ConcurrentBag<ScanResult>();
        var throttled = new SemaphoreSlim(AppSettings.MaxConcurrentScans);

        await Parallel.ForEachAsync(distinct, new ParallelOptions
        {
            MaxDegreeOfParallelism = AppSettings.MaxConcurrentScans,
            CancellationToken = ct
        }, async (file, token) =>
        {
            await throttled.WaitAsync(token);
            try
            {
                var result = await ScanFileAsync(file, token);
                if (result != null)
                {
                    summary.ThreatsFound = Interlocked.Increment(ref summary.ThreatsFound);
                    threats.Add(result);
                    if (_settings.AutoQuarantine && result.RiskScore >= 50)
                    {
                        try
                        {
                            await _quarantine.QuarantineFileAsync(result.FilePath, result.ThreatType, result.RiskScore, result.FileHash);
                            result.IsQuarantined = true;
                        }
                        catch (Exception ex)
                        {
                            Log($"quarantine failed for {result.FilePath}: {ex.Message}");
                        }
                    }
                }
                int done = Interlocked.Increment(ref scanned);
                progress?.Report(new ScanProgress
                {
                    FilesScanned = done,
                    TotalFiles = total,
                    CurrentFile = file,
                    ThreatsFound = summary.ThreatsFound,
                    Elapsed = stopwatch.Elapsed,
                    Eta = total <= 0 || done <= 0 ? TimeSpan.Zero : TimeSpan.FromMilliseconds(stopwatch.Elapsed.TotalMilliseconds / done * (total - done))
                });
            }
            finally
            {
                throttled.Release();
            }
        });

        stopwatch.Stop();
        summary.FilesScanned = scanned;
        summary.CleanFiles = scanned - summary.ThreatsFound;
        summary.Threats = threats.OrderByDescending(t => t.RiskScore).ToList();
        summary.Elapsed = stopwatch.Elapsed;
        summary.Cancelled = ct.IsCancellationRequested;

        ScanCompleted?.Invoke(summary);
        Log($"Scan '{scanType}' finished: {summary.FilesScanned} files, {summary.Threats.Count} threats in {summary.Elapsed.TotalSeconds:F1}s");
        return summary;
    }

    private async Task<ScanResult?> ScanFileAsync(string file, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            var fi = new FileInfo(file);
            if (!fi.Exists || fi.Length == 0) return null;

            byte[]? hashData = null;
            string hash;
            if (fi.Length <= 100 * 1024 * 1024)
            {
                hashData = await File.ReadAllBytesAsync(file, ct);
                hash = HashHelper.Sha256(hashData);
            }
            else
            {
                using var fs = File.OpenRead(file);
                var head = new byte[5 * 1024 * 1024];
                int hr = fs.Read(head, 0, head.Length);
                fs.Position = Math.Max(0, fs.Length - 5 * 1024 * 1024);
                var tail = new byte[fs.Length - fs.Position];
                fs.Read(tail, 0, tail.Length);
                var combined = new byte[hr + tail.Length];
                Array.Copy(head, 0, combined, 0, hr);
                Array.Copy(tail, 0, combined, hr, tail.Length);
                hash = HashHelper.Sha256(combined);
                hashData = combined;
            }

            var result = new DetectionResult();
            var ext = Path.GetExtension(file).ToLowerInvariant();
            bool isPe = fi.Extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                        fi.Extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                        fi.Extension.Equals(".scr", StringComparison.OrdinalIgnoreCase) ||
                        fi.Extension.Equals(".sys", StringComparison.OrdinalIgnoreCase);

            if (isPe && hashData != null && hashData.Length >= 0x40 && hashData[0] == 'M' && hashData[1] == 'Z')
            {
                string tempPath = Path.Combine(Path.GetTempPath(), "ya_defender_" + Guid.NewGuid().ToString("N"));
                await File.WriteAllBytesAsync(tempPath, hashData, ct);
                var pe = PeAnalyzerService.Analyze(tempPath);
                var peResult = HeuristicEngine.Evaluate(file, fi.Length, pe);
                Merge(result, peResult);
                var sigResult = SignatureEngine.Evaluate(file, SignatureEngine.FindContentSample(tempPath));
                Merge(result, sigResult);
                try { File.Delete(tempPath); } catch { }
            }
            else
            {
                var heur = HeuristicEngine.Evaluate(file, fi.Length, null);
                Merge(result, heur);
                var sig = SignatureEngine.Evaluate(file, hashData != null ? System.Text.Encoding.ASCII.GetString(hashData.Take(64_000).ToArray()) : null);
                Merge(result, sig);
            }

            var yara = YaraScanner.Scan(file, hashData);
            Merge(result, yara);

            if (_settings.CloudScanning && result.RiskScore >= 35 && hashData != null)
            {
                var verdicts = await _cloud.ScanAsync(hash, _settings.VirusTotalApiKey, _settings.HybridAnalysisApiKey, ct);
                foreach (var v in verdicts)
                {
                    if (v.Detected)
                    {
                        result.Add("Cloud", $"{v.Source}: {v.Detail}", Math.Min(60, v.Score), v.Category);
                    }
                }
            }

            var scanResult = new ScanResult
            {
                FilePath = file,
                FileHash = hash,
                RiskScore = result.RiskScore,
                ThreatType = result.Malicious ? result.ThreatType : "Clean",
                DetectionMethod = result.Malicious ? result.Method : "Clean",
                FileSize = fi.Length,
                Timestamp = DateTime.Now,
                IsQuarantined = false
            };
            await _db.SaveScanResult(scanResult);
            if (result.Malicious)
                Log($"THREAT: {file} [{result.ThreatType}] {result.RiskScore}/100 via {result.Method}");
            return result.Malicious ? scanResult : null;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    private static void Merge(DetectionResult target, DetectionResult source)
    {
        target.RiskScore = Math.Min(100, target.RiskScore + source.RiskScore);
        target.DetectionMethods.AddRange(source.DetectionMethods);
        target.Reasons.AddRange(source.Reasons);
        target.Malicious = target.Malicious || source.Malicious;
        if (source.Malicious) target.ThreatType = source.ThreatType;
    }

    private static IEnumerable<string> EnumerateFiles(string root, bool fullScan)
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var stack = new Stack<string>();
        stack.Push(root);
        int limit = 0;
        while (stack.Count > 0)
        {
            string dir = stack.Pop();
            if (!visited.Add(dir)) continue;
            if (limit++ > 250_000) yield break;

            string[] subDirs;
            string[] filePaths;
            try
            {
                subDirs = Directory.GetDirectories(dir);
                filePaths = Directory.GetFiles(dir);
            }
            catch
            {
                continue;
            }

            foreach (var file in filePaths)
            {
                if (!fullScan && ShouldSkipPath(file)) continue;
                yield return file;
            }

            foreach (var sub in subDirs)
            {
                if (!fullScan && ShouldSkipDir(sub)) continue;
                stack.Push(sub);
            }
        }
    }

    private static bool ShouldSkipDir(string dir)
    {
        string d = dir.ToLowerInvariant();
        return d.Contains(@"\windows\") ||
               d.Contains(@"\program files\") ||
               d.Contains(@"\program files (x86)\") ||
               d.Contains("\\$recycle.bin") ||
               d.Contains("\\system volume information") ||
               d.Contains("\\node_modules") ||
               d.Contains("\\python\\lib") ||
               d.Contains("\\nvidia") ||
               d.Contains("\\perflogs") ||
               d.Contains("\\winsxs");
    }

    private static bool ShouldSkipPath(string file)
    {
        var ext = Path.GetExtension(file).ToLowerInvariant();
        if (ext is ".dll" or ".sys" or ".mui" or ".exe") return false;
        if (ext is ".jpg" or ".jpeg" or ".png" or ".gif" or ".mp4" or ".mp3" or ".avi" or ".mkv" or ".iso" or ".zip" or ".rar" or ".7z" or ".wav" or ".flac" or ".mov") return true;
        return false;
    }

    private void Log(string message) => LogReceived?.Invoke($"[{DateTime.Now:HH:mm:ss}] {message}");
}
