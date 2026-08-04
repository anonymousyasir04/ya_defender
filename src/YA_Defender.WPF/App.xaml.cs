using System.IO;
using System.Windows;
using YA_Defender.WPF.Services;

namespace YA_Defender.WPF;

public partial class App : Application
{
    public static AppServices Services { get; private set; } = null!;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        Services = new AppServices();
        Services.ApplyProtectionState();
        DispatcherUnhandledException += (_, args) =>
        {
            try
            {
                Services.LogBuffer.Append($"[FATAL] {args.Exception.Message}");
                Serilog.Log.Error(args.Exception, "Unhandled exception");
            }
            catch { }
            MessageBox.Show($"An unexpected error occurred:\n{args.Exception.Message}",
                "YA Defender", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            Services?.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
        catch { }
        base.OnExit(e);
    }
}
