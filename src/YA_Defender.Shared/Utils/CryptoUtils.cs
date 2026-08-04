using System.Security.Cryptography;

namespace YA_Defender.Shared.Utils;

public static class EntropyCalculator
{
    public static double Calculate(byte[] data, int maxBytes = 1_048_576)
    {
        if (data.Length == 0) return 0.0;
        var sample = data.Length > maxBytes ? data.AsSpan(0, maxBytes).ToArray() : data;

        var counts = new int[256];
        foreach (var b in sample) counts[b]++;

        double entropy = 0.0;
        var len = sample.Length;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0) continue;
            double p = (double)counts[i] / len;
            entropy -= p * Math.Log2(p);
        }
        return Math.Round(entropy, 4);
    }

    public static double Calculate(Stream stream, int maxBytes = 1_048_576)
    {
        var buffer = new byte[Math.Min(stream.Length > 0 ? stream.Length : 0, maxBytes)];
        int read = stream.Read(buffer, 0, buffer.Length);
        if (read != buffer.Length)
            Array.Resize(ref buffer, read);
        return Calculate(buffer);
    }
}

public static class HashHelper
{
    public static string Sha256(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data));

    public static string Sha256(Stream stream)
    {
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(stream));
    }

    public static string Sha256(string text) =>
        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text)));

    public static string Sha1Hex(byte[] data) =>
        Convert.ToHexString(SHA1.HashData(data)).ToLowerInvariant();

    public static string Md5(byte[] data) =>
        Convert.ToHexString(MD5.HashData(data)).ToLowerInvariant();
}

public static class EncryptionHelper
{
    public static byte[] EncryptToBlob(byte[] plain, byte[] key)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var cipher = new byte[plain.Length];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plain, cipher, tag);

        var blob = new byte[12 + 16 + cipher.Length];
        Buffer.BlockCopy(nonce, 0, blob, 0, 12);
        Buffer.BlockCopy(tag, 0, blob, 12, 16);
        Buffer.BlockCopy(cipher, 0, blob, 28, cipher.Length);
        return blob;
    }

    public static byte[] DecryptFromBlob(byte[] blob, byte[] key)
    {
        if (blob.Length <= 28) throw new CryptographicException("Invalid encrypted blob.");
        var nonce = blob.AsSpan(0, 12).ToArray();
        var tag = blob.AsSpan(12, 16).ToArray();
        var cipher = blob.AsSpan(28).ToArray();
        var plain = new byte[cipher.Length];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, cipher, tag, plain);
        return plain;
    }

    public static byte[] DeriveKey(string secret, byte[] salt, int iterations = 100_000)
    {
        return Rfc2898DeriveBytes.Pbkdf2(secret, salt, iterations, HashAlgorithmName.SHA256, 32);
    }
}
