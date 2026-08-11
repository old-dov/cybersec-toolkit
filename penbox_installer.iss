; Installeur Windows pour PenBox (GUI PySide6 de la suite cybersécurité).
; Empaquette un runtime Python autonome (penbox_runtime\, voir build ci-dessous)
; plutôt que de figer le code avec PyInstaller : PenBox lance chaque script du
; catalogue via subprocess.Popen([sys.executable, ...]), ce qui casserait avec
; un exécutable figé sans réécriture de runner.py.
;
; penbox_runtime\ N'EST PAS .venv-penbox : un venv créé par `uv venv` sur
; Windows a un python.exe/pythonw.exe qui n'est qu'un stub relais (~46 Ko) —
; il relit pyvenv.cfg et relance un second process vers l'interpréteur "home"
; enregistré à un CHEMIN ABSOLU propre à la machine où le venv a été créé,
; donc pas redistribuable tel quel. penbox_runtime\ est une vraie distribution
; Python autonome (python-build-standalone, récupérée via le cache uv) avec
; les paquets de requirements.txt installés directement dedans (pas de venv,
; pas de pyvenv.cfg, pas de relais) — pour la reconstruire :
;   uv pip install --python penbox_runtime\python.exe -r requirements.txt
; (après avoir copié une distribution cpython-*-windows-x86_64-none\ fraîche
; depuis %APPDATA%\uv\python\ et supprimé son Lib\EXTERNALLY-MANAGED).
;
; Compiler avec : "C:\Program Files\Inno Setup 7\ISCC.exe" penbox_installer.iss

#define MyAppName "PenBox"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Jean Dovy"
#define MyAppExeDesc "PenBox — Cybersec Script Suite"

[Setup]
AppId={{07CA7F7D-1B81-44A4-8386-8D77033F2E6F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\PenBox
DefaultGroupName=PenBox
DisableProgramGroupPage=yes
; {localappdata} est toujours accessible en écriture par l'utilisateur courant
; (nécessaire : PenBox écrit penbox.db, .penbox_runs/, .penbox_vault.enc... à
; la racine de son propre dossier d'installation) — pas besoin d'élévation.
PrivilegesRequired=lowest
OutputDir=installer_output
OutputBaseFilename=PenBox-Setup-{#MyAppVersion}
SetupIconFile=penbox.ico
UninstallDisplayIcon={app}\penbox.ico
Compression=lzma2/normal
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "Créer un raccourci sur le Bureau"; GroupDescription: "Raccourcis supplémentaires :"

[Files]
; Runtime Python autonome (voir note en tête de fichier) — inclut PySide6,
; paramiko, cryptography, psutil, etc. déjà installés dedans. pythonw.exe y
; est nativement en subsystem GUI (aucun patch nécessaire, contrairement au
; stub d'un venv `uv venv`).
Source: "penbox_runtime\*"; DestDir: "{app}\penbox_runtime"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__,__pycache__\*,*.pyc"

; Code PenBox
Source: "penbox\*"; DestDir: "{app}\penbox"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__,__pycache__\*,*.pyc"
Source: "penbox_app.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "penbox.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "penbox_notice.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "PenBox_Notice_Utilisation.pdf"; DestDir: "{app}"; Flags: ignoreversion
Source: "requirements.txt"; DestDir: "{app}"; Flags: ignoreversion

; Scripts du catalogue (catégories référencées par penbox/catalog.yaml, plus
; 06_Reporting utilisé en CLI par les pipelines documentés dans les README).
; 13_File_Upload_Bypass_Access (webshells de test) volontairement exclu : ce
; sont des payloads à déposer manuellement pendant un test, pas des scripts
; que PenBox exécute lui-même.
Source: "01_Reconnaissance\*"; DestDir: "{app}\01_Reconnaissance"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__,__pycache__\*,*.pyc"
Source: "02_Network_Analysis\*"; DestDir: "{app}\02_Network_Analysis"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__,__pycache__\*,*.pyc"
Source: "03_Vulnerability_Assessment\*"; DestDir: "{app}\03_Vulnerability_Assessment"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__,__pycache__\*,*.pyc"
Source: "04_Log_Analysis\*"; DestDir: "{app}\04_Log_Analysis"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__,__pycache__\*,*.pyc"
Source: "05_Cryptography\*"; DestDir: "{app}\05_Cryptography"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__,__pycache__\*,*.pyc"
Source: "06_Reporting\*"; DestDir: "{app}\06_Reporting"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__,__pycache__\*,*.pyc"
Source: "07_Remediation\*"; DestDir: "{app}\07_Remediation"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__,__pycache__\*,*.pyc"
Source: "08_Exploitation\*"; DestDir: "{app}\08_Exploitation"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__,__pycache__\*,*.pyc"
Source: "09_Post_Exploitation\*"; DestDir: "{app}\09_Post_Exploitation"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__,__pycache__\*,*.pyc"
Source: "10_Web_Security\*"; DestDir: "{app}\10_Web_Security"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__,__pycache__\*,*.pyc"
Source: "11_OSINT\*"; DestDir: "{app}\11_OSINT"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__,__pycache__\*,*.pyc"
Source: "12_Forensic_IR\*"; DestDir: "{app}\12_Forensic_IR"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__,__pycache__\*,*.pyc"

[Icons]
Name: "{group}\PenBox"; Filename: "{app}\penbox_runtime\pythonw.exe"; Parameters: """{app}\penbox_app.py"""; WorkingDir: "{app}"; IconFilename: "{app}\penbox.ico"; Comment: "{#MyAppExeDesc}"
Name: "{group}\Notice d'utilisation"; Filename: "{app}\PenBox_Notice_Utilisation.pdf"
Name: "{group}\Désinstaller PenBox"; Filename: "{uninstallexe}"
Name: "{userdesktop}\PenBox"; Filename: "{app}\penbox_runtime\pythonw.exe"; Parameters: """{app}\penbox_app.py"""; WorkingDir: "{app}"; IconFilename: "{app}\penbox.ico"; Tasks: desktopicon; Comment: "{#MyAppExeDesc}"

[Run]
Filename: "{app}\penbox_runtime\pythonw.exe"; Parameters: """{app}\penbox_app.py"""; WorkingDir: "{app}"; Description: "Lancer PenBox"; Flags: nowait postinstall skipifsilent
