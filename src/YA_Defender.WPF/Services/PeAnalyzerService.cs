using System.IO;
using System.Text;

namespace YA_Defender.WPF.Services;

public class PeFeatures
{
    public bool IsValid { get; set; }
    public bool Is32Bit { get; set; }
    public bool Is64Bit { get; set; }
    public string Machine { get; set; } = "";
    public uint TimeDateStamp { get; set; }
    public uint AddressOfEntryPoint { get; set; }
    public ulong ImageBase { get; set; }
    public uint SizeOfImage { get; set; }
    public int NumberOfSections { get; set; }
    public List<string> SectionNames { get; set; } = new();
    public List<string> ImportedDlls { get; set; } = new();
    public List<string> ImportedFunctions { get; set; } = new();
    public List<string> SuspiciousImports { get; set; } = new();
    public List<string> PackerIndicators { get; set; } = new();
    public string Packer { get; set; } = "";
    public bool HasDebugInfo { get; set; }
    public bool HasTls { get; set; }
    public bool HasValidChecksum { get; set; } = true;
    public double CodeSectionEntropy { get; set; }
    public long OverlaySize { get; set; }
    public bool IsSigned { get; set; }
}

public static class PeAnalyzerService
{
    private static readonly string[] PackerSectionNames =
    {
        "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".nsp0", ".nsp1", ".themida", ".enigma",
        ".mpress", ".mpress1", ".petite", ".pe", ".pec", ".vmp0", ".vmp1", ".vmp2", ".yP", ".maskpe",
        ".ccg", ".jv", ".winlice", ".kkrunchy", ".packed", ".ares", ".cnp", ".mew", ".morphine"
    };

    private static readonly HashSet<string> InjectionImports = new(StringComparer.OrdinalIgnoreCase)
    {
        "VirtualAllocEx", "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC",
        "SetThreadContext", "GetThreadContext", "NtCreateThreadEx", "NtMapViewOfSection", "ZwMapViewOfSection",
        "VirtualProtectEx", "RtlCreateUserThread", "NtQueueApcThread", "NtWriteVirtualMemory", "NtReadVirtualMemory"
    };

    private static readonly HashSet<string> PersistenceImports = new(StringComparer.OrdinalIgnoreCase)
    {
        "RegSetValueEx", "RegCreateKeyEx", "RegOpenKeyEx", "RegSetValue", "RegCreateKey", "SHGetFolderPath",
        "SHGetSpecialFolderPath", "GetEnvironmentVariable"
    };

    private static readonly HashSet<string> EvasionImports = new(StringComparer.OrdinalIgnoreCase)
    {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "GetTickCount",
        "QueryPerformanceCounter", "OutputDebugString", "NtSetInformationThread", "ZwSetInformationThread",
        "GetProcAddress", "LoadLibrary", "LoadLibraryEx", "VirtualProtect"
    };

    private static readonly HashSet<string> SuspiciousDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "wininet.dll", "urlmon.dll", "ws2_32.dll", "winhttp.dll", "secur32.dll", "winmm.dll",
        "ntdll.dll", "advapi32.dll", "crypt32.dll", "oleaut32.dll", "shell32.dll", "dnsapi.dll"
    };

    public static PeFeatures Analyze(string filePath)
    {
        var f = new PeFeatures();
        try
        {
            byte[] data = File.ReadAllBytes(filePath);
            if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z')
            {
                f.IsValid = false;
                return f;
            }

            uint peOffset = BitConverter.ToUInt32(data, 0x3C);
            if (peOffset + 24 > data.Length || data[peOffset] != 'P' || data[peOffset + 1] != 'E')
            {
                f.IsValid = false;
                return f;
            }

            ushort machine = BitConverter.ToUInt16(data, (int)peOffset + 4);
            int numberOfSections = BitConverter.ToUInt16(data, (int)peOffset + 6);
            uint timeDateStamp = BitConverter.ToUInt32(data, (int)peOffset + 8);
            ushort sizeOfOptionalHeader = BitConverter.ToUInt16(data, (int)peOffset + 20);

            f.Machine = machine switch
            {
                0x014c => "x86",
                0x8664 => "x64",
                0xAA64 => "ARM64",
                _ => $"0x{machine:X4}"
            };

            int optStart = (int)peOffset + 24;
            if (optStart + 2 > data.Length) { f.IsValid = false; return f; }

            ushort magic = BitConverter.ToUInt16(data, optStart);
            f.Is32Bit = magic == 0x10B;
            f.Is64Bit = magic == 0x20B;
            if (!f.Is32Bit && !f.Is64Bit) { f.IsValid = false; return f; }

            f.TimeDateStamp = timeDateStamp;
            f.AddressOfEntryPoint = BitConverter.ToUInt32(data, optStart + 16);
            f.ImageBase = f.Is64Bit ? BitConverter.ToUInt64(data, optStart + 24) : BitConverter.ToUInt32(data, optStart + 28);
            f.SizeOfImage = BitConverter.ToUInt32(data, optStart + 56);
            f.NumberOfSections = numberOfSections;

            int dataDirOffset = optStart + (f.Is64Bit ? 112 : 96);
            int numDirs = BitConverter.ToUInt32(data, optStart + 92) > 0
                ? Math.Min((int)BitConverter.ToUInt32(data, optStart + 92), 16)
                : 16;
            if (dataDirOffset + numDirs * 8 > data.Length) numDirs = Math.Max(0, (data.Length - dataDirOffset) / 8);

            var dataDirs = new List<(uint Rva, uint Size)>();
            for (int i = 0; i < numDirs; i++)
            {
                uint rva = BitConverter.ToUInt32(data, dataDirOffset + i * 8);
                uint size = BitConverter.ToUInt32(data, dataDirOffset + i * 8 + 4);
                dataDirs.Add((rva, size));
            }

            f.HasDebugInfo = dataDirs.Count > 6 && dataDirs[6].Rva != 0;
            f.HasTls = dataDirs.Count > 9 && dataDirs[9].Rva != 0;

            int sectionTable = optStart + sizeOfOptionalHeader;
            var sections = new List<(string Name, uint VSize, uint Rva, uint RawSize, uint RawOffset)>();
            for (int i = 0; i < numberOfSections && sectionTable + 40 <= data.Length; i++)
            {
                int s = sectionTable + i * 40;
                string name = Encoding.ASCII.GetString(data, s, 8).TrimEnd('\0');
                uint vsize = BitConverter.ToUInt32(data, s + 8);
                uint rva = BitConverter.ToUInt32(data, s + 12);
                uint rawSize = BitConverter.ToUInt32(data, s + 16);
                uint rawOffset = BitConverter.ToUInt32(data, s + 20);
                sections.Add((name, vsize, rva, rawSize, rawOffset));
            }

            foreach (var s in sections)
            {
                f.SectionNames.Add(s.Name);
                if (PackerSectionNames.Contains(s.Name))
                {
                    f.PackerIndicators.Add($"packer section '{s.Name}'");
                    f.Packer = s.Name.TrimStart('.');
                }
            }

            var codeSection = sections.FirstOrDefault(s => s.Name is ".text" or "CODE" or "UPX1" or ".upx1");
            if (codeSection.RawSize > 0 && codeSection.RawOffset + codeSection.RawSize <= data.Length)
            {
                var codeBytes = new byte[codeSection.RawSize];
                Array.Copy(data, codeSection.RawOffset, codeBytes, 0, codeSection.RawSize);
                f.CodeSectionEntropy = Shared.Utils.EntropyCalculator.Calculate(codeBytes);
                if (f.CodeSectionEntropy > 7.2)
                    f.PackerIndicators.Add($"code entropy {f.CodeSectionEntropy:F2} > 7.2 (compressed/packed)");
            }

            uint importRva = dataDirs.Count > 1 ? dataDirs[1].Rva : 0;
            if (importRva != 0)
                ParseImports(data, sections, importRva, f);

            f.IsValid = true;
            if (f.Packer == "") f.Packer = f.PackerIndicators.Count > 0 ? "packed" : "";
            f.HasValidChecksum = true;
            f.IsSigned = HasSecurityDirectory(dataDirs, f);
        }
        catch
        {
            f.IsValid = false;
        }
        return f;
    }

    private static bool HasSecurityDirectory(List<(uint Rva, uint Size)> dirs, PeFeatures f) =>
        dirs.Count > 4 && dirs[4].Rva != 0 && dirs[4].Size > 8;

    private static void ParseImports(byte[] data, List<(string Name, uint VSize, uint Rva, uint RawSize, uint RawOffset)> sections, uint importRva, PeFeatures f)
    {
        uint importOffset = RvaToOffset(sections, importRva);
        if (importOffset == 0 || importOffset >= (uint)data.Length) return;

        for (int i = 0; ; i++)
        {
            uint entry = importOffset + (uint)(i * 20);
            if (entry + 20 > (uint)data.Length) break;
            uint nameRva = BitConverter.ToUInt32(data, (int)entry + 12);
            uint thunkRva = BitConverter.ToUInt32(data, (int)entry + 16);
            if (nameRva == 0 && thunkRva == 0) break;

            uint nameOffset = RvaToOffset(sections, nameRva);
            if (nameOffset == 0 || nameOffset >= (uint)data.Length) continue;
            string dllName = ReadAscii(data, nameOffset);
            if (dllName.Length == 0) continue;
            f.ImportedDlls.Add(dllName);

            uint thunkOffset = RvaToOffset(sections, thunkRva);
            if (thunkOffset == 0) continue;
            bool is64 = f.Is64Bit;
            int funcSize = is64 ? 8 : 4;
            for (int j = 0; ; j++)
            {
                uint ft = thunkOffset + (uint)(j * funcSize);
                if (ft + (uint)funcSize > (uint)data.Length) break;
                ulong val = is64 ? BitConverter.ToUInt64(data, (int)ft) : BitConverter.ToUInt32(data, (int)ft);
                if (val == 0) break;
                if ((val & (is64 ? 0x8000000000000000UL : 0x80000000UL)) != 0) continue;
                uint hintNameRva = (uint)(val & 0x7FFFFFFF);
                uint hintOffset = RvaToOffset(sections, hintNameRva);
                if (hintOffset == 0 || hintOffset + 2 >= (uint)data.Length) continue;
                string func = ReadAscii(data, hintOffset + 2);
                if (func.Length == 0) continue;
                f.ImportedFunctions.Add(func);
                if (InjectionImports.Contains(func) && !f.SuspiciousImports.Contains(func))
                    f.SuspiciousImports.Add($"{dllName}!{func} (injection)");
                else if (PersistenceImports.Contains(func) && !f.SuspiciousImports.Contains(func))
                    f.SuspiciousImports.Add($"{dllName}!{func} (persistence)");
                else if (EvasionImports.Contains(func) && !f.SuspiciousImports.Contains(func))
                    f.SuspiciousImports.Add($"{dllName}!{func} (evasion)");
            }
        }
    }

    private static uint RvaToOffset(List<(string Name, uint VSize, uint Rva, uint RawSize, uint RawOffset)> sections, uint rva)
    {
        if (rva < 0x1000) return rva;
        foreach (var s in sections)
        {
            if (rva >= s.Rva && rva < s.Rva + Math.Max(s.VSize, s.RawSize))
                return s.RawOffset + (rva - s.Rva);
        }
        return 0;
    }

    private static string ReadAscii(byte[] data, uint offset)
    {
        int end = (int)offset;
        int max = Math.Min(data.Length, end + 256);
        while (end < max && data[end] != 0) end++;
        return Encoding.ASCII.GetString(data, (int)offset, end - (int)offset);
    }
}
