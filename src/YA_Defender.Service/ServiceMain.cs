using System.Diagnostics;
using System.Net.Sockets;
using System.ServiceProcess;
using YA_Defender.Shared.Database;
using YA_Defender.Shared.Models;
using YA_Defender.Shared.Services;

namespace YA_Defender.Service;

public class ServiceMain : ServiceBase, IDisposable
{
    private CancellationTokenSource? _cts;
    private DatabaseHelper? _db;
    private MonitorService? _monitor;
    private TcpListener? _controlListener;

    public ServiceMain()
    {
        ServiceName = "YA_DefenderService";
        CanStop = true;
        CanShutdown = true;
        AutoLog = true;
    }

    protected override void OnStart(string[] args)
    {
        var dataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "YA_Defender");
        Directory.CreateDirectory(dataRoot);
        _cts = new CancellationTokenSource();
        _db = new DatabaseHelper(Path.Combine(dataRoot, "ya_defender_service.db"));
        _db.InitializeAsync().GetAwaiter().GetResult();

        _monitor = new MonitorService(_db);
        _monitor.Start();
        _monitor.ProcessCreated += e => EventLog.WriteEntry("YA Defender", $"Process started: {e.ProcessName} ({e.CommandLine})", EventLogEntryType.Information);
        _monitor.ConnectionDetected += e =>
        {
            if (e.IsSuspicious)
                EventLog.WriteEntry("YA Defender", $"Suspicious connection: {e.ProcessName} -> {e.DestinationIp}:{e.DestinationPort}", EventLogEntryType.Warning);
        };

        _ = StartControlServerAsync(_cts.Token);
        EventLog.WriteEntry("YA Defender", "Protection service started.", EventLogEntryType.Information);
    }

    protected override void OnStop()
    {
        _cts?.Cancel();
        _monitor?.Stop();
        _monitor?.Dispose();
        _db?.DisposeAsync().AsTask().GetAwaiter().GetResult();
        EventLog.WriteEntry("YA Defender", "Protection service stopped.", EventLogEntryType.Information);
    }

    protected override void OnShutdown() => OnStop();

    private async Task StartControlServerAsync(CancellationToken ct)
    {
        _controlListener = new TcpListener(System.Net.IPAddress.Loopback, 48327);
        _controlListener.Start();
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var client = await _controlListener.AcceptTcpClientAsync(ct);
                using var stream = client.GetStream();
                var buffer = new byte[256];
                int read = await stream.ReadAsync(buffer, ct);
                if (read <= 0) continue;
                string cmd = System.Text.Encoding.ASCII.GetString(buffer, 0, read).Trim();
                string response = cmd switch
                {
                    "PING" => "YA_DEFENDER_OK",
                    "STATUS" => _monitor != null && _cts != null && !_cts.IsCancellationRequested ? "RUNNING" : "STOPPED",
                    "THREATS_TODAY" => await CountThreatsAsync(),
                    _ => "UNKNOWN_CMD"
                };
                var reply = System.Text.Encoding.ASCII.GetBytes(response);
                await stream.WriteAsync(reply, ct);
            }
            catch (OperationCanceledException) { break; }
            catch { }
        }
    }

    private async Task<string> CountThreatsAsync()
    {
        try
        {
            long count = _db != null ? await _db.Count("quarantine") : 0;
            return count.ToString();
        }
        catch { return "0"; }
    }

    public async Task RunConsoleAsync()
    {
        OnStart(Array.Empty<string>());
        Console.WriteLine("Press Ctrl+C to stop.");
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; OnStop(); };
        await Task.Delay(Timeout.InfiniteTimeSpan);
    }

    public new void Dispose()
    {
        _monitor?.Dispose();
        _cts?.Dispose();
        _controlListener?.Stop();
        base.Dispose();
    }
}
