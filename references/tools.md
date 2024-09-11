# <center> Tools </center>

## Introduction

The following is a list of tools and the suggestion on when to use them.  This was put together by laz0rshi.  There are oviously a lot more tools, but these are some I have researched, and found usefull.

## Table of Contents

- [ Tools ](#-tools-)
  - [Introduction](#introduction)
  - [Table of Contents](#table-of-contents)
  - [Information Gathering \& Reconnaissance](#information-gathering--reconnaissance)
    - [Host Discovery](#host-discovery)
    - [Port Scanning](#port-scanning)
    - [OS Fingerprinting](#os-fingerprinting)
    - [DNS Enumeration](#dns-enumeration)
    - [SMB Enumeration](#smb-enumeration)
    - [NFS Enumeration](#nfs-enumeration)
    - [LDAP Enumeration](#ldap-enumeration)
    - [SNMP Enumeration](#snmp-enumeration)
    - [FTP Enumeration](#ftp-enumeration)
    - [RDP Enumeration](#rdp-enumeration)
    - [POP Enumeration](#pop-enumeration)
    - [SMTP Enumeration](#smtp-enumeration)
    - [Web Reconnaissance](#web-reconnaissance)
    - [Vulnerablity Scanning/Finding](#vulnerablity-scanningfinding)
  - [Initial Access](#initial-access)
  - [Enumeration \& Escalation](#enumeration--escalation)
    - [Linux](#linux)
    - [Windows](#windows)
  - [Active Directory Enumeration](#active-directory-enumeration)
  - [Shells](#shells)
  - [Password Attacks/Cracking](#password-attackscracking)
  - [Tunnels](#tunnels)
  - [C2](#c2)
  - [Other](#other)
    - [Utilities](#utilities)
    - [OSIT](#osit)
    - [Other](#other-1)

## Information Gathering & Reconnaissance

### Host Discovery

- **[nmap](https://nmap.org)**
- [crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec) - Gathers information on smb amgonst other things.
- [amass](https://github.com/OWASP/Amass) - In-depth Attack Surface Mapping and Asset Discovery.

### Port Scanning

- **[rustscan](https://github.com/RustScan/RustScan)** - RustScan is a modern take on the port scanner. Sleek & fast.
- **[nmapAutomator](https://github.com/21y4d/nmapAutomator)** - Automates the process of enumeration & recon that is run every time. - [cheat sheet](https://www.stationx.net/crackmapexec-cheat-sheet/)
- [AutoRecon](url) - 
- [incursore](url) - Like nmapautomator but without and nikto
- [securitytrails](url) - 
- [AssetFinder](url) - 
- [Uniscan](url) - 
- [Scanless](url) - An open-source network scanning tool
- [Xprobe](url) - An open-source network scanning tool
- [naabu](https://github.com/projectdiscovery/naabu) - Similar to nmap
- [Raccoon](https://github.com/evyatarmeged/Raccoon) - Offensive Security Tool for Reconnaissance and Information Gathering

### OS Fingerprinting

### DNS Enumeration

- [dnsrecon](url) - Dns zone transfer
- [dnsenum](https://github.com/fwaeytens/dnsenum) - Multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip block
- [dnscan](https://github.com/rbsec/dnscan) - A python wordlist-based DNS subdomain scanner.

### SMB Enumeration


### NFS Enumeration


### LDAP Enumeration


### SNMP Enumeration


### FTP Enumeration


### RDP Enumeration


### POP Enumeration


### SMTP Enumeration


### Web Reconnaissance

- [SharpWeb](https://github.com/djhohnstein/SharpWeb) - SharpWeb is a compliant project that can retrieve saved logins from a browser
- [Nikto]
- [jok3r]

- [GoBuster]
- [dirb]
- [feroxbuster]
- [ffuf]

### Vulnerablity Scanning/Finding

- nmap-scripts-nse*
  
## Initial Access

## Enumeration & Escalation

- https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet

### Linux

- [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) - Linux Privilege Escalation Awesome Script
- [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration) - Linux Smart Enumeration
- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester) - LES: Linux privilege escalation auditing tool
- [pspy](https://github.com/DominicBreuker/pspy) - unprivileged Linux process snooping

### Windows

- [WinPwn](https://github.com/S3cur3Th1sSh1t/WinPwn) -  Powershell Recon / Exploitation scripts
- [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)* - Windows Privilege Escalation Awesome Scripts
- [SharpUp](https://github.com/GhostPack/SharpUp)  - SharpUp is a C# port of various PowerUp functionality
- [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) - Sysinternals
- [Rubeus](https://github.com/GhostPack/Rubeus)* - Rubeus is a C# toolset for raw Kerberos interaction and abuses
- [SharpHound](https://github.com/BloodHoundAD/SharpHound3)* - AD Escalation
- [Procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)* - SysInternals
- [RoguePotato](https://github.com/antonioCoco/RoguePotato) - Windows Local Privilege Escalation
- [GodPodtato] - 
- [JuicyPotato](https://github.com/ohpe/juicy-potato) - Windows Local Privilege Escalation
- [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)* - Windows Local Privilege Escalation

## Active Directory Enumeration

> [!NOTE]
> Some of these tools can may also help with windows escalation 

- [Powerview v.3.0](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)* -

## Shells

- [mkpsrevshell](https://gist.github.com/tothi/ab288fb523a4b32b51a53e542d40fe58) - reverse powershell cmdline payload generator (base64 encoded)

## Password Attacks/Cracking

- [Mimikatz](https://github.com/gentilkiwi/mimikatz)* - Password cracking
- [creddump7](https://github.com/CiscoCXSecurity/creddump7) - Dumps Windows creds
- [mongodb2hashcat](https://github.com/philsmd/mongodb2hashcat) - Extract hashes from the MongoDB database server

## Tunnels

- [Plink](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)* - Windows Tunnels
- [ligolo-ng](https://github.com/nicocha30/ligolo-ng) - Agent based -unnelling with admin rights
- proxychains (B)-

## C2

- [Villain](https://github.com/t3l3machus/Villain) - Villain is a high level C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells, enhance their functionality with additional features (commands, utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
- [BlackMamba](https://github.com/loseys/BlackMamba) - Black Mamba is a Comman- and Control (C2) that works with multiple connections at same time. It was developed with Python and with Qt -ramework and have multiples features for a post-exploitation step.

## Other

- [Probable-Wordlists](https://github.com/berzerk0/Probable-Wordlists)
- [Payloadbox](https://github.com/payloadbox)
- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)



### Utilities

- [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)
- [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
- [mkpsrevshell](https://gist.github.com/tothi/ab288fb523a4b32b51a53e542d40fe58)
- [SharpUp](https://github.com/GhostPack/SharpUp)
- [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)
- [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
- [Seatbelt](https://github.com/GhostPack/Seatbelt)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [SharpHound](https://github.com/BloodHoundAD/SharpHound3)
- [Procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)
- [creddump7](https://github.com/CiscoCXSecurity/creddump7)
- [Plink](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)
- [HotPotato](https://github.com/foxglovesec/Potato)
- [RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [JuicyPotato](https://github.com/ohpe/juicy-potato)
- [incognito](https://github.com/FSecureLABS/incognito)
- [SharpWeb](https://github.com/djhohnstein/SharpWeb)
- [pspy](https://github.com/DominicBreuker/pspy)
- [mongodb2hashcat](https://github.com/philsmd/mongodb2hashcat)
- [Probable-Wordlists](https://github.com/berzerk0/Probable-Wordlists)
- [Payloadbox](https://github.com/payloadbox)
- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

### OSIT

- [recon-ng](https://github.com/lanmaster53/recon-ng) - Aimed at reducing the time spent harvesting information from open sources.
- [Osmedeus](https://github.com/j3ssie/osmedeus) - A Workflow Engine for Offensive Security. It was designed to build a foundation with the capability and flexibility that allows you to build your own reconnaissance system and run it on a large number of targets.

### Other
<!-- Move Down -->

- [reconftw](https://github.com/six2dez/reconftw) - Automates the entire process of reconnaissance for you. It outperforms the work of subdomain enumeration along with various vulnerability checks and obtaining maximum information about your target.
- [BBOT](https://github.com/blacklanternsecurity/bbot) - Recursive internet scanner inspired by Spiderfoot, but designed to be faster, more reliable, and friendlier to pentesters, bug bounty hunters, and developers.

