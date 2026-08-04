using System.ServiceProcess;

namespace YA_Defender.Service;

internal static class Program
{
    private static void Main(string[] args)
    {
        if (args.Contains("--console"))
        {
            Console.WriteLine("YA Defender Service (console mode)");
            using var main = new ServiceMain();
            main.RunConsoleAsync().GetAwaiter().GetResult();
            return;
        }

        ServiceBase.Run(new ServiceBase[] { new ServiceMain() });
    }
}
