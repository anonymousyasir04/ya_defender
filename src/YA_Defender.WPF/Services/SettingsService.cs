using System.IO;
using System.Text.Json;
using YA_Defender.Shared.Database;
using YA_Defender.Shared.Models;

namespace YA_Defender.WPF.Services;

public static class SettingsService
{
    public static AppSettings Load(string appDataRoot)
    {
        string path = Path.Combine(appDataRoot, "settings.json");
        try
        {
            if (File.Exists(path))
            {
                var s = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path));
                if (s != null) return s;
            }
        }
        catch { }
        return new AppSettings();
    }

    public static void Save(string appDataRoot, AppSettings settings)
    {
        Directory.CreateDirectory(appDataRoot);
        string path = Path.Combine(appDataRoot, "settings.json");
        string tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(tmp, path, true);
    }
}
