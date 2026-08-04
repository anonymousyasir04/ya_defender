; YA Defender - Inno Setup installer script
; Build with Inno Setup 6 (https://jrsoftware.org/isinfo.php)
; Requires: compiled binaries from src/YA_Defender.WPF and src/YA_Defender.Service

#define AppName "YA Defender"
#define AppVersion "1.0.0"
#define AppPublisher "Yasir Abbas"
#define AppExeName "YA_Defender.exe"

[Setup]
AppId={{D1E6A5B4-2C8F-4E7A-9B3D-8F2A6C4E5B7A}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\YA_Defender
DefaultGroupName=YA Defender
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=YA_Defender_Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
SetupIconFile=..\src\YA_Defender.WPF\Resources\Icons\shield.ico
UninstallDisplayIcon={app}\{#AppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "startwithwindows"; Description: "Start with Windows (recommended)"; GroupDescription: "Startup:"

[Files]
Source: "..\src\YA_Defender.WPF\bin\Release\net8.0-windows\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\src\YA_Defender.Service\bin\Release\net8.0-windows\publish\YA_Defender.Service.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\YA Defender"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\YA Defender"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; \
    ValueName: "YA_Defender"; ValueData: """{app}\{#AppExeName}"""; Tasks: startwithwindows; Flags: uninsdeletevalue

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{userappdata}\YA_Defender"

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    Log('YA Defender installed successfully');
end;
