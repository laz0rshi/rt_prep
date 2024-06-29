# Tools
- [Tools](#tools)
  - [Recon](#recon)
  - [Web Application Exploit](#web-application-exploit)
  - [Vulnerablity Scanning/Finding](#vulnerablity-scanningfinding)
  - [Escalation](#escalation)
    - [Linux](#linux)
    - [Windows](#windows)
  - [Active Directory Enumeration](#active-directory-enumeration)
  - [Shells](#shells)
  - [Password Attacks/Cracking](#password-attackscracking)
  - [Tunnels](#tunnels)
    - [Other](#other)
  - [C2](#c2)

## Recon

+ [AutoRecon] - 
+ [incursore] - like nmapautomator but without and nikto
+ [nmapAutomator.sh] - 
+ [securitytrails]
+ [AssetFinder]
+ [Uniscan]
+ [rustscan]
+ [recon-ng]
+ [Scanless] - (an open-source network scanning tool)
+ [Xprobe]- (an open-source network scanning tool)
+ [naabu] - (https://github.com/projectdiscovery/naabu) - Similar to nmap
+ [reconftw] - (https://github.com/six2dez/reconftw) - reconFTW automates the entire process of reconnaissance for you. It outperforms the work of subdomain enumeration along with various vulnerability checks and obtaining maximum information about your target.
+ [Osmedeus] - (https://github.com/j3ssie/osmedeus) - Osmedeus is a Workflow Engine for Offensive Security. It was designed to build a foundation with the capability and flexibility that allows you to build your own reconnaissance system and run it on a large number of targets.
+ [Raccoon] - (https://github.com/evyatarmeged/Raccoon) - Offensive Security Tool for Reconnaissance and Information Gathering

## Web Application Exploit

+ [SharpWeb](https://github.com/djhohnstein/SharpWeb) - SharpWeb is a compliant project that can retrieve saved logins from a browser
+ [Nikto]
+ [jok3r]


## Vulnerablity Scanning/Finding

+ nmap-scripts-nse*

## Escalation

- https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet

### Linux

+ [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)* - Linux Privilege Escalation Awesome Script
+ [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration) - Linux Smart Enumeration
+ [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester) - LES: Linux privilege escalation auditing tool
+ [pspy](https://github.com/DominicBreuker/pspy) - unprivileged Linux process snooping
  
### Windows
+ [WinPwn] - (https://github.com/S3cur3Th1sSh1t/WinPwn) -  Powershell Recon / Exploitation scripts
+ [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)* - Windows Privilege Escalation Awesome Scripts
+ [SharpUp](https://github.com/GhostPack/SharpUp)  - SharpUp is a C# port of various PowerUp functionality
+ [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) - Sysinternals
+ [Rubeus](https://github.com/GhostPack/Rubeus)* - Rubeus is a C# toolset for raw Kerberos interaction and abuses
+ [SharpHound](https://github.com/BloodHoundAD/SharpHound3)* - AD Escalation
+ [Procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)* - SysInternals
+ [RoguePotato](https://github.com/antonioCoco/RoguePotato) - Windows Local Privilege Escalation
+ [GodPodtato] - 
+ [JuicyPotato](https://github.com/ohpe/juicy-potato) - Windows Local Privilege Escalation
+ [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)* - Windows Local Privilege Escalation

## Active Directory Enumeration

> [!NOTE]
> Some of these tools can may also help with windows escalation 
+ [Powerview v.3.0](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)* -

## Shells

+ [mkpsrevshell](https://gist.github.com/tothi/ab288fb523a4b32b51a53e542d40fe58) - reverse powershell cmdline payload generator (base64 encoded)

## Password Attacks/Cracking

+ [Mimikatz](https://github.com/gentilkiwi/mimikatz)* - Password cracking
+ [creddump7](https://github.com/CiscoCXSecurity/creddump7) - Dumps Windows creds
+ [mongodb2hashcat](https://github.com/philsmd/mongodb2hashcat) - Extract hashes from the MongoDB database server

## Tunnels

+ [Plink](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)* - Windows Tunnels
+ [ligolo-ng](https://github.com/nicocha30/ligolo-ng) - Agent based tunnelling with admin rights
+ proxychains (B)

### Other
+ [Probable-Wordlists](https://github.com/berzerk0/Probable-Wordlists)
+ [Payloadbox](https://github.com/payloadbox)
+ [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

## C2
+ [Villain] - (https://github.com/t3l3machus/Villain) - Villain is a high level C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells, enhance their functionality with additional features (commands, utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
+ [BlackMamba] - (https://github.com/loseys/BlackMamba) - Black Mamba is a Command and Control (C2) that works with multiple connections at same time. It was developed with Python and with Qt Framework and have multiples features for a post-exploitation step.