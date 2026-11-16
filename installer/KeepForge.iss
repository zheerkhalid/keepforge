; KeepForge installer (Inno Setup 6). Per-user: no administrator rights needed.
; Vault files (.kfv), backups and key files are never installed, touched or
; removed by Setup or by the uninstaller.

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

[Setup]
AppId={{6F3A9C12-58D4-4B7E-A1C6-2E9D7B4F8035}
AppName=KeepForge
AppVersion={#AppVersion}
AppVerName=KeepForge {#AppVersion}
AppPublisher=Zheer Khalid
AppPublisherURL=https://zheer.dev
AppSupportURL=https://github.com/zheerkhalid/keepforge
AppUpdatesURL=https://github.com/zheerkhalid/keepforge/releases
DefaultDirName={autopf}\KeepForge
DefaultGroupName=KeepForge
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=KeepForge-Setup
SetupIconFile=..\target\keepforge.ico
UninstallDisplayIcon={app}\KeepForge.exe
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
; KeepForge holds this mutex while it runs, so Setup and the uninstaller can
; ask for it to be closed first (it protects itself against being ended by
; other programs).
AppMutex=KeepForge-app-running
CloseApplications=yes
RestartApplications=no
ChangesAssociations=yes
LicenseFile=..\LICENSE
VersionInfoVersion={#AppVersion}
VersionInfoCompany=Zheer Khalid (zheer.dev)
VersionInfoDescription=KeepForge Setup

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "associate"; Description: "Open .kfv vault files with KeepForge"; GroupDescription: "File types:"

[Files]
Source: "..\target\release\KeepForge.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion
Source: "..\NOTICE"; DestDir: "{app}"; DestName: "NOTICE.txt"; Flags: ignoreversion

[Icons]
Name: "{group}\KeepForge"; Filename: "{app}\KeepForge.exe"
Name: "{group}\Uninstall KeepForge"; Filename: "{uninstallexe}"
Name: "{autodesktop}\KeepForge"; Filename: "{app}\KeepForge.exe"; Tasks: desktopicon

[Registry]
; Per-user file association for .kfv. Removed again on uninstall; the vault
; files themselves are left alone.
Root: HKA; Subkey: "Software\Classes\.kfv"; ValueType: string; ValueName: ""; ValueData: "KeepForge.Vault"; Flags: uninsdeletevalue; Tasks: associate
Root: HKA; Subkey: "Software\Classes\KeepForge.Vault"; ValueType: string; ValueName: ""; ValueData: "KeepForge vault"; Flags: uninsdeletekey; Tasks: associate
Root: HKA; Subkey: "Software\Classes\KeepForge.Vault\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\KeepForge.exe,0"; Tasks: associate
Root: HKA; Subkey: "Software\Classes\KeepForge.Vault\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\KeepForge.exe"" ""%1"""; Tasks: associate

[Run]
Filename: "{app}\KeepForge.exe"; Description: "{cm:LaunchProgram,KeepForge}"; Flags: nowait postinstall skipifsilent

; There is deliberately no [UninstallDelete] section: settings in
; %APPDATA%\KeepForge and every vault, backup and key file stay where they are.
