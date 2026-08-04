using System.IO;
using System.Security.Cryptography;
using YA_Defender.Shared.Database;
using YA_Defender.Shared.Models;
using YA_Defender.Shared.Utils;

namespace YA_Defender.WPF.Services;

public class QuarantineService
{
    private readonly DatabaseHelper _db;
    private readonly string _quarantineRoot;
    private readonly byte[] _key;

    public string QuarantineRoot => _quarantineRoot;

    public QuarantineService(DatabaseHelper db, string appDataRoot)
    {
        _db = db;
        _quarantineRoot = Path.Combine(appDataRoot, "Quarantine");
        Directory.CreateDirectory(_quarantineRoot);
        _key = LoadOrCreateKey(appDataRoot);
    }

    private static byte[] LoadOrCreateKey(string appDataRoot)
    {
        string keyFile = Path.Combine(appDataRoot, "quarantine.key");
        byte[] key;
        if (File.Exists(keyFile))
        {
            key = ProtectedData.Unprotect(File.ReadAllBytes(keyFile), null, DataProtectionScope.CurrentUser);
        }
        else
        {
            key = RandomNumberGenerator.GetBytes(32);
            File.WriteAllBytes(keyFile, ProtectedData.Protect(key, null, DataProtectionScope.CurrentUser));
        }
        if (key.Length != 32)
            throw new CryptographicException("Quarantine key has invalid length.");
        return key;
    }

    public async Task<QuarantineItem> QuarantineFileAsync(string filePath, string threatType, int riskScore, string fileHash)
    {
        if (!File.Exists(filePath)) throw new FileNotFoundException("File not found", filePath);

        var fi = new FileInfo(filePath);
        string fileName = fi.Name;
        string vaultName = $"{Guid.NewGuid():N}.enc";
        string vaultPath = Path.Combine(_quarantineRoot, vaultName);

        byte[] plain = await File.ReadAllBytesAsync(filePath);
        byte[] encrypted = EncryptionHelper.EncryptToBlob(plain, _key);
        await File.WriteAllBytesAsync(vaultPath, encrypted);

        var item = new QuarantineItem
        {
            OriginalPath = filePath,
            FileName = fileName,
            FileHash = string.IsNullOrEmpty(fileHash) ? HashHelper.Sha256(plain) : fileHash,
            ThreatType = threatType,
            RiskScore = riskScore,
            QuarantinePath = vaultPath,
            Timestamp = DateTime.Now
        };
        await _db.AddQuarantine(item);
        TryDeleteOriginal(filePath);
        return item;
    }

    public async Task RestoreAsync(QuarantineItem item)
    {
        if (!File.Exists(item.QuarantinePath)) throw new FileNotFoundException("Quarantined file missing", item.QuarantinePath);
        byte[] encrypted = await File.ReadAllBytesAsync(item.QuarantinePath);
        byte[] plain = EncryptionHelper.DecryptFromBlob(encrypted, _key);

        string dest = item.OriginalPath;
        string dir = Path.GetDirectoryName(dest) ?? Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        Directory.CreateDirectory(dir);

        int n = 1;
        string name = item.FileName;
        while (File.Exists(dest))
        {
            string bare = Path.GetFileNameWithoutExtension(name);
            string ext = Path.GetExtension(name);
            dest = Path.Combine(dir, $"{bare}({n++}){ext}");
        }
        await File.WriteAllBytesAsync(dest, plain);
        item.OriginalPath = dest;
        await _db.UpdateQuarantineRestored(item.Id, true);
    }

    public async Task DeletePermanentlyAsync(QuarantineItem item)
    {
        try
        {
            if (File.Exists(item.QuarantinePath))
            {
                byte[] encrypted = await File.ReadAllBytesAsync(item.QuarantinePath);
                Array.Clear(encrypted);
                File.Delete(item.QuarantinePath);
            }
        }
        catch { }
        await _db.DeleteQuarantineRow(item.Id);
    }

    public async Task<List<QuarantineItem>> ListAsync() => await _db.GetQuarantineItems();

    private static void TryDeleteOriginal(string path)
    {
        try
        {
            File.SetAttributes(path, FileAttributes.Normal);
            File.Delete(path);
        }
        catch { }
    }
}
