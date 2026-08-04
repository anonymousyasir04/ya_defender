using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace YA_Defender.WPF.Services;

public class SystemRepairService
{
    public event Action<string>? OutputReceived;

    public bool IsAdmin()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    public async Task RunSfcScanAsync(CancellationToken ct = default) =>
        await RunAsync("sfc", "/scannow", ct);

    public async Task RunDismAsync(CancellationToken ct = default) =>
        await RunAsync("DISM", "/Online /Cleanup-Image /RestoreHealth", ct);

    public async Task RunChkdskAsync(CancellationToken ct = default) =>
        await RunAsync("chkdsk", "C: /f /r", ct);

    public async Task RunAsync(string exe, string args, CancellationToken ct = default)
    {
        Output($"Starting: {exe} {args}");
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            if (process == null) { Output("Failed to start process."); return; }

            var readOut = ReadLinesAsync(process.StandardOutput, Output, ct);
            var readErr = ReadLinesAsync(process.StandardError, Output, ct);
            await Task.WhenAll(readOut, readErr);
            await process.WaitForExitAsync(ct);
            Output($"{exe} exited with code {process.ExitCode}");
        }
        catch (Exception ex)
        {
            Output($"Repair tool error: {ex.Message}");
        }
    }

    private static async Task ReadLinesAsync(StreamReader reader, Action<string> output, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var buffer = new char[256];
            while (!ct.IsCancellationRequested)
            {
                int read = await reader.ReadAsync(buffer, 0, buffer.Length);
                if (read <= 0) break;
                sb.Append(buffer, 0, read);
                string text = sb.ToString();
                int nl = text.LastIndexOf('\n');
                if (nl >= 0)
                {
                    string complete = text.Substring(0, nl).Replace("\r", "");
                    foreach (var line in complete.Split('\n'))
                        output(line);
                    sb.Clear().Append(text.Substring(nl + 1));
                }
            }
        }
        catch { }
    }

    public bool CreateRestorePoint(string description = "YA Defender restore point")
    {
        try
        {
            var status = new RestorePointInfo
            {
                dwEventType = BeginSystemChange,
                dwRestorePtType = ModifySettings,
                llSequenceNumber = 0,
                szDescription = description
            };
            bool ok = SrSetRestorePointW(ref status, out var mgr);
            if (!ok || mgr.llSequenceNumber == 0) return false;
            Output($"Restore point created: {description}");
            return true;
        }
        catch (Exception ex)
        {
            Output($"Restore point failed: {ex.Message}");
            return false;
        }
    }

    private void Output(string line) => OutputReceived?.Invoke($"[{DateTime.Now:HH:mm:ss}] {line}");

    private const int BeginSystemChange = 100;
    private const int ModifySettings = 100;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RestorePointInfo
    {
        public int dwEventType;
        public int dwRestorePtType;
        public long llSequenceNumber;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szDescription;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Stats
    {
        public long llSequenceNumber;
    }

    [DllImport("srclient.dll", CharSet = CharSet.Unicode)]
    private static extern bool SrSetRestorePointW(ref RestorePointInfo rpi, out Stats pStatus);
}
