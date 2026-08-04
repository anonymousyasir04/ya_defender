# YA Defender — Build & Run Guide

YA Defender is a Windows malware-defense system built with C# / .NET 8 and WPF (MVVM).
It must be **built on Windows** — WPF and the security APIs (ETW/WMI/AMSI/DNS) are Windows-only.

## Requirements

- Windows 10 1709+ or Windows 11
- Visual Studio 2022 (17.8+) with the **.NET desktop development** workload
- .NET 8 SDK
- Administrator rights (the app runs elevated — UAC prompt on launch)

## Build

1. Open `YA_Defender.sln` in Visual Studio 2022.
2. Restore NuGet packages (right-click solution -> Restore NuGet Packages).
3. Set `YA_Defender.WPF` as the startup project.
4. Build the solution (Ctrl+Shift+B). Both `YA_Defender.WPF` and `YA_Defender.Shared`
   build together; `YA_Defender.Service` builds the optional Windows service.

## Run

- Press F5. The app requires elevation (UAC prompt).
- On first run it creates its data folder at `%AppData%\YA_Defender`:
  - `ya_defender.db` — SQLite database (7 event tables + cloud cache)
  - `settings.json` — your configuration
  - `Quarantine/` — AES-256 encrypted vault (DPAPI-protected key)
  - `logs/` — Serilog rolling logs

## Windows Service (optional, off by default)

Build the service first, then in the app: **Profile -> Self-Defense & Startup -> Install Service**.

Manual commands:

```text
sc.exe create YA_DefenderService start= auto binPath= "C:\Program Files\YA_Defender\YA_Defender.Service.exe"
sc.exe start YA_DefenderService
sc.exe stop YA_DefenderService
sc.exe delete YA_DefenderService
```

Test the service standalone:

```text
YA_Defender.Service.exe --console
```

## Cloud API keys (optional)

Add your own keys in **Profile -> Cloud API Keys**:

- VirusTotal: https://www.virustotal.com (free tier)
- Hybrid Analysis: https://www.hybrid-analysis.com (free tier)
- MalwareBazaar needs no key.

Without keys, the app still works: heuristics + signatures + YARA + local monitoring
run fully offline. Cloud results are cached in SQLite (24h/7d TTL).

## YARA engine (optional)

The YaraSharp NuGet package ships only the managed wrapper — the native engine must be
provided separately. To enable YARA scanning, download `yara.dll` (64-bit, matching the
app build) from https://github.com/VirusTotal/yara/releases and place it **next to
`YA_Defender.exe`**.

Without `yara.dll` the app still works normally: the built-in signature engine
(40+ rules incl. packer/impersonation detection) continues to run, and the YARA engine
simply reports "unavailable".

## Installer

Install Inno Setup 6, then compile `installer/setup.iss`. Point the `[Files]` sources
at your publish output first:

```text
dotnet publish src\YA_Defender.WPF -c Release -r win-x64 --self-contained true -o publish
```

## Project layout

```text
YA_Defender.sln
src/
  YA_Defender.Shared/   Models, SQLite schema, monitor service, crypto/entropy utils
  YA_Defender.WPF/      WPF app: 4-tab UI, scan engine, protection services
  YA_Defender.Service/  Optional Windows service (background monitor + control port)
installer/setup.iss     Inno Setup installer script
```

## Feature status

Phase 1 (shipped): PE analyzer, heuristic engine, signature/YARA engine, cloud scanning,
quick/full/custom/USB/drag-drop scans, AES-256 quarantine, real-time monitoring
(process/file/network), registry guardian, ransomware shield, DNS quarantine,
USB guardian, system repair (SFC/DISM/CHKDSK), restore points, threat hunter search,
report export (HTML/CSV/JSON/ZIP), scheduled scans, dark-theme 4-tab UI.

Phase 2 (future): voice control (Rhino/Kokoro or Windows Speech), process tree
visualizer, gaming/idle mode, HaveIBeenPwned, ETW-level event sourcing, AI ONNX models.
