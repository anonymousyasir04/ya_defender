using System.Globalization;
using Microsoft.Data.Sqlite;
using YA_Defender.Shared.Models;

namespace YA_Defender.Shared.Database;

public class DatabaseHelper : IAsyncDisposable
{
    private readonly string _connectionString;
    private SqliteConnection? _connection;

    public string DbPath { get; }

    public DatabaseHelper(string dbPath)
    {
        DbPath = dbPath;
        Directory.CreateDirectory(Path.GetDirectoryName(dbPath) ?? ".");
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true
        }.ToString();
    }

    public async Task InitializeAsync()
    {
        _connection = new SqliteConnection(_connectionString);
        await _connection.OpenAsync();

        await ExecuteAsync(@"
            CREATE TABLE IF NOT EXISTS process_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_name TEXT, pid INTEGER, parent_pid INTEGER,
                command_line TEXT, user TEXT, timestamp TEXT,
                is_suspicious INTEGER, risk_score INTEGER, threat_type TEXT);

            CREATE TABLE IF NOT EXISTS file_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT, action TEXT, size INTEGER, entropy REAL,
                process_pid INTEGER, timestamp TEXT,
                is_suspicious INTEGER, risk_score INTEGER, threat_type TEXT);

            CREATE TABLE IF NOT EXISTS registry_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_path TEXT, value_name TEXT, value_data TEXT, action TEXT,
                process_pid INTEGER, timestamp TEXT,
                is_suspicious INTEGER, risk_score INTEGER, threat_type TEXT);

            CREATE TABLE IF NOT EXISTS network_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                destination_ip TEXT, destination_port INTEGER, protocol TEXT,
                process_pid INTEGER, process_name TEXT, timestamp TEXT,
                is_suspicious INTEGER, risk_score INTEGER, threat_type TEXT);

            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT, file_hash TEXT, risk_score INTEGER,
                threat_type TEXT, detection_method TEXT, is_quarantined INTEGER,
                file_size INTEGER, timestamp TEXT);

            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT, file_name TEXT, file_hash TEXT,
                threat_type TEXT, risk_score INTEGER, quarantine_path TEXT,
                timestamp TEXT, restored INTEGER);

            CREATE TABLE IF NOT EXISTS breach_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_or_password_hash TEXT, breach_found INTEGER,
                breach_details TEXT, timestamp TEXT);

            CREATE TABLE IF NOT EXISTS cloud_cache (
                hash TEXT PRIMARY KEY, source TEXT, verdict TEXT,
                checked_at TEXT);

            CREATE TABLE IF NOT EXISTS app_state (
                key TEXT PRIMARY KEY, value TEXT);");
    }

    public async Task<int> ExecuteAsync(string sql, IEnumerable<(string, object?)>? parameters = null)
    {
        if (_connection == null) throw new InvalidOperationException("Database not initialized.");
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = sql;
        if (parameters != null)
        {
            foreach (var (name, value) in parameters)
                cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }
        return await cmd.ExecuteNonQueryAsync();
    }

    public async Task<object?> ScalarAsync(string sql, IEnumerable<(string, object?)>? parameters = null)
    {
        if (_connection == null) throw new InvalidOperationException("Database not initialized.");
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = sql;
        if (parameters != null)
        {
            foreach (var (name, value) in parameters)
                cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }
        return await cmd.ExecuteScalarAsync();
    }

    public async Task<List<Dictionary<string, object?>>> QueryAsync(string sql, IEnumerable<(string, object?)>? parameters = null)
    {
        if (_connection == null) throw new InvalidOperationException("Database not initialized.");
        var rows = new List<Dictionary<string, object?>>();
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = sql;
        if (parameters != null)
        {
            foreach (var (name, value) in parameters)
                cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var row = new Dictionary<string, object?>();
            for (int i = 0; i < reader.FieldCount; i++)
                row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            rows.Add(row);
        }
        return rows;
    }

    private static string Fmt(DateTime dt) => dt.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);

    private static DateTime Parse(DateTime dt) => dt;

    public Task LogProcessEvent(ProcessEvent e) =>
        ExecuteAsync("INSERT INTO process_events (process_name, pid, parent_pid, command_line, user, timestamp, is_suspicious, risk_score, threat_type) VALUES ($n,$p,$pp,$c,$u,$t,$s,$r,$th)",
            new[] { ("$n", (object?)e.ProcessName), ("$p", e.Pid), ("$pp", e.ParentPid), ("$c", e.CommandLine), ("$u", e.User), ("$t", Fmt(e.Timestamp)), ("$s", e.IsSuspicious ? 1 : 0), ("$r", e.RiskScore), ("$th", e.ThreatType) });

    public Task LogFileEvent(FileEvent e) =>
        ExecuteAsync("INSERT INTO file_events (file_path, action, size, entropy, process_pid, timestamp, is_suspicious, risk_score, threat_type) VALUES ($f,$a,$s,$en,$p,$t,$i,$r,$th)",
            new[] { ("$f", (object?)e.FilePath), ("$a", e.Action), ("$s", e.Size), ("$en", e.Entropy), ("$p", e.ProcessPid), ("$t", Fmt(e.Timestamp)), ("$i", e.IsSuspicious ? 1 : 0), ("$r", e.RiskScore), ("$th", e.ThreatType) });

    public Task LogRegistryEvent(RegistryEvent e) =>
        ExecuteAsync("INSERT INTO registry_events (key_path, value_name, value_data, action, process_pid, timestamp, is_suspicious, risk_score, threat_type) VALUES ($k,$v,$d,$a,$p,$t,$i,$r,$th)",
            new[] { ("$k", (object?)e.KeyPath), ("$v", e.ValueName), ("$d", e.ValueData), ("$a", e.Action), ("$p", e.ProcessPid), ("$t", Fmt(e.Timestamp)), ("$i", e.IsSuspicious ? 1 : 0), ("$r", e.RiskScore), ("$th", e.ThreatType) });

    public Task LogNetworkEvent(NetworkEvent e) =>
        ExecuteAsync("INSERT INTO network_events (destination_ip, destination_port, protocol, process_pid, process_name, timestamp, is_suspicious, risk_score, threat_type) VALUES ($ip,$port,$proto,$p,$pn,$t,$i,$r,$th)",
            new[] { ("$ip", (object?)e.DestinationIp), ("$port", e.DestinationPort), ("$proto", e.Protocol), ("$p", e.ProcessPid), ("$pn", e.ProcessName), ("$t", Fmt(e.Timestamp)), ("$i", e.IsSuspicious ? 1 : 0), ("$r", e.RiskScore), ("$th", e.ThreatType) });

    public Task SaveScanResult(ScanResult r) =>
        ExecuteAsync("INSERT INTO scan_results (file_path, file_hash, risk_score, threat_type, detection_method, is_quarantined, file_size, timestamp) VALUES ($f,$h,$r,$t,$d,$q,$s,$ts)",
            new[] { ("$f", (object?)r.FilePath), ("$h", r.FileHash), ("$r", r.RiskScore), ("$t", r.ThreatType), ("$d", r.DetectionMethod), ("$q", r.IsQuarantined ? 1 : 0), ("$s", r.FileSize), ("$ts", Fmt(r.Timestamp)) });

    public Task AddQuarantine(QuarantineItem q) =>
        ExecuteAsync("INSERT INTO quarantine (original_path, file_name, file_hash, threat_type, risk_score, quarantine_path, timestamp, restored) VALUES ($o,$fn,$h,$t,$r,$qp,$ts,$res)",
            new[] { ("$o", (object?)q.OriginalPath), ("$fn", q.FileName), ("$h", q.FileHash), ("$t", q.ThreatType), ("$r", q.RiskScore), ("$qp", q.QuarantinePath), ("$ts", Fmt(q.Timestamp)), ("$res", q.Restored ? 1 : 0) });

    public async Task<List<QuarantineItem>> GetQuarantineItems(bool includeRestored = false)
    {
        var sql = includeRestored
            ? "SELECT * FROM quarantine ORDER BY timestamp DESC"
            : "SELECT * FROM quarantine WHERE restored = 0 ORDER BY timestamp DESC";
        var rows = await QueryAsync(sql);
        return rows.Select(r => new QuarantineItem
        {
            Id = (long)r["id"]!,
            OriginalPath = r["original_path"] as string ?? "",
            FileName = r["file_name"] as string ?? "",
            FileHash = r["file_hash"] as string ?? "",
            ThreatType = r["threat_type"] as string ?? "",
            RiskScore = Convert.ToInt32(r["risk_score"] ?? 0),
            QuarantinePath = r["quarantine_path"] as string ?? "",
            Timestamp = DateTime.TryParse(r["timestamp"] as string, out var dt) ? dt : DateTime.MinValue,
            Restored = Convert.ToInt32(r["restored"] ?? 0) == 1
        }).ToList();
    }

    public Task UpdateQuarantineRestored(long id, bool restored) =>
        ExecuteAsync("UPDATE quarantine SET restored = $r WHERE id = $id",
            new[] { ("$r", (object?)(restored ? 1 : 0)), ("$id", (object?)id) });

    public Task DeleteQuarantineRow(long id) =>
        ExecuteAsync("DELETE FROM quarantine WHERE id = $id", new[] { ("$id", (object?)id) });

    public Task SaveBreachCheck(BreachCheck b) =>
        ExecuteAsync("INSERT INTO breach_checks (email_or_password_hash, breach_found, breach_details, timestamp) VALUES ($h,$f,$d,$t)",
            new[] { ("$h", (object?)b.EmailOrPasswordHash), ("$f", b.BreachFound ? 1 : 0), ("$d", b.BreachDetails), ("$t", Fmt(b.Timestamp)) });

    public async Task<string?> GetState(string key)
    {
        var rows = await QueryAsync("SELECT value FROM app_state WHERE key = $k", new[] { ("$k", (object?)key) });
        return rows.Count > 0 ? rows[0]["value"] as string : null;
    }

    public Task SetState(string key, string value) =>
        ExecuteAsync("INSERT INTO app_state (key, value) VALUES ($k,$v) ON CONFLICT(key) DO UPDATE SET value = $v",
            new[] { ("$k", (object?)key), ("$v", value) });

    public async Task<CloudVerdict?> GetCloudCache(string hash, string source, TimeSpan maxAge)
    {
        var rows = await QueryAsync("SELECT * FROM cloud_cache WHERE hash = $h AND source = $s",
            new[] { ("$h", (object?)hash), ("$s", source) });
        if (rows.Count == 0) return null;
        var checkedAt = DateTime.TryParse(rows[0]["checked_at"] as string, out var dt) ? dt : DateTime.MinValue;
        if (DateTime.Now - checkedAt > maxAge) return null;
        var json = rows[0]["verdict"] as string ?? "";
        try
        {
            var v = System.Text.Json.JsonSerializer.Deserialize<CloudVerdict>(json);
            return v;
        }
        catch
        {
            return null;
        }
    }

    public Task SetCloudCache(string hash, string source, CloudVerdict verdict) =>
        ExecuteAsync("INSERT INTO cloud_cache (hash, source, verdict, checked_at) VALUES ($h,$s,$v,$t) ON CONFLICT(hash, source) DO UPDATE SET verdict = $v, checked_at = $t",
            new[] { ("$h", (object?)hash), ("$s", source), ("$v", System.Text.Json.JsonSerializer.Serialize(verdict)), ("$t", Fmt(DateTime.Now)) });

    public async Task<long> Count(string table)
    {
        var result = await ScalarAsync($"SELECT COUNT(*) FROM {table}");
        return Convert.ToInt64(result ?? 0);
    }

    public Task ClearLogs() =>
        ExecuteAsync("DELETE FROM process_events; DELETE FROM file_events; DELETE FROM registry_events; DELETE FROM network_events; DELETE FROM scan_results;");

    public async ValueTask DisposeAsync()
    {
        if (_connection != null)
        {
            await _connection.DisposeAsync();
            _connection = null;
        }
        GC.SuppressFinalize(this);
    }
}
