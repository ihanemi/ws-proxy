#define MyAppName "WS VPN"
#define MyAppVersion "0.1.0-alpha.1"
#define MyAppPublisher "ihanemi"
#define MyAppExeName "WsVpn.exe"

[Setup]
AppId={{4B6ED901-717D-4B01-9C61-01EAA188D5B8}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
VersionInfoVersion=0.1.0.1
AppPublisher={#MyAppPublisher}
AppPublisherURL=https://github.com/ihanemi/ws-proxy
AppSupportURL=https://github.com/ihanemi/ws-proxy/issues
AppUpdatesURL=https://github.com/ihanemi/ws-proxy/releases
DefaultDirName={autopf}\WS VPN
DefaultGroupName=WS VPN
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=WsVpn-Setup-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
Source: "..\dist\WsVpn.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\third_party\licenses\tun2socks-LICENSE.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion
Source: "..\third_party\licenses\Wintun-LICENSE.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\WS VPN"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\WS VPN"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch WS VPN"; Flags: nowait postinstall skipifsilent

[Code]
function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
  ClientPath: String;
begin
  ClientPath := ExpandConstant('{app}\{#MyAppExeName}');
  Result := (not FileExists(ClientPath)) or
    (Exec(ClientPath, '--cleanup', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and
     (ResultCode = 0));
  if not Result then
    MsgBox(
      'WS VPN could not safely clean its recorded networking state. ' +
      'Disconnect the running client or repair recovery first, then uninstall again. ' +
      'The recovery executable has been kept installed.',
      mbError,
      MB_OK
    );
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  { Never execute an older, unverified cleanup implementation during upgrade. }
  if FileExists(ExpandConstant('{commonappdata}\WsVpn\state.json')) then
    Result :=
      'An existing WS VPN networking session or crash journal is present. ' +
      'Disconnect or recover it with the currently installed version before upgrading.';
end;
