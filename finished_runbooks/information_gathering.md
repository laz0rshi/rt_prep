# OSCP Information Gathering

## Introduction

## Table of Content

- [OSCP Information Gathering](#oscp-information-gathering)
  - [Introduction](#introduction)
  - [Table of Content](#table-of-content)
  - [Host Discovery](#host-discovery)
    - [nmap](#nmap)
    - [crackmapexec](#crackmapexec)
    - [powershell](#powershell)
    - [bash](#bash)
  - [Port Scanning](#port-scanning)
    - [bash](#bash-1)
    - [netcat](#netcat)
    - [nmap](#nmap-1)
    - [powershell](#powershell-1)
    - [rustscan](#rustscan)
        - [Note :](#note-)
    - [Scanless (an open-source network scanning tool)](#scanless-an-open-source-network-scanning-tool)
    - [Xprobe (an open-source network scanning tool)](#xprobe-an-open-source-network-scanning-tool)
  - [OS Fingerprinting Tools](#os-fingerprinting-tools)
    - [nmap](#nmap-2)
    - [Os-fingerprint (an open-source OS fingerprinting tool)](#os-fingerprint-an-open-source-os-fingerprinting-tool)
    - [OS-Scanner (an open-source OS scanner)](#os-scanner-an-open-source-os-scanner)
  - [DNS Enumeration](#dns-enumeration)
    - [Bash](#bash-2)
    - [dnsrecon - dns zone transfer](#dnsrecon---dns-zone-transfer)
    - [dnsenum](#dnsenum)
  - [SMB Enumeration](#smb-enumeration)
    - [nmap](#nmap-3)
    - [nbtscan](#nbtscan)
    - [enum4linux](#enum4linux)
    - [Windows](#windows)
  - [NFS Enumeration](#nfs-enumeration)
    - [nmap](#nmap-4)
    - [rpcinfo](#rpcinfo)
    - [showmounts](#showmounts)
    - [Mounts](#mounts)
    - [config files](#config-files)
  - [LDAP Enumeration](#ldap-enumeration)
    - [nmap](#nmap-5)
    - [ldapsearch](#ldapsearch)
  - [SNMP Enumeration](#snmp-enumeration)
    - [nmap](#nmap-6)
    - [onesixyone](#onesixyone)
    - [snmpwalk - Enumerate the entire MIB tree](#snmpwalk---enumerate-the-entire-mib-tree)
    - [snmpwalk - Enumerate windows users](#snmpwalk---enumerate-windows-users)
    - [snmpwalk - Lists running processes](#snmpwalk---lists-running-processes)
    - [snmpwalk - Lists open TCP ports](#snmpwalk---lists-open-tcp-ports)
    - [snmpwalk - Enumerate installed software](#snmpwalk---enumerate-installed-software)
  - [FTP Enumeration](#ftp-enumeration)
    - [netcat - check ftp version](#netcat---check-ftp-version)
    - [nmap](#nmap-7)
    - [binary transfer](#binary-transfer)
    - [ascii transfer](#ascii-transfer)
  - [RDP enumeration](#rdp-enumeration)
    - [nmap](#nmap-8)
    - [Connect to RDP](#connect-to-rdp)
    - [Check credentials via RDP](#check-credentials-via-rdp)
  - [POP Enumeration](#pop-enumeration)
    - [nmap](#nmap-9)
    - [telnet](#telnet)
    - [messages](#messages)
  - [SMTP Enumeration](#smtp-enumeration)
    - [nmap](#nmap-10)
    - [email](#email)
    - [hyrda](#hyrda)
  - [Recon Web](#recon-web)
    - [nmap](#nmap-11)
    - [Wappalyzer](#wappalyzer)
    - [Whatweb](#whatweb)
    - [fuzzing](#fuzzing)
      - [GoBuster](#gobuster)
      - [dirb](#dirb)
      - [feroxbuster](#feroxbuster)
      - [ffuf](#ffuf)
    - [Nikto - Web Server Scanner](#nikto---web-server-scanner)
    - [CMS](#cms)
      - [wpscan](#wpscan)
      - [Juumla](#juumla)
      - [Sroopescan](#sroopescan)
      - [Magescan](#magescan)
  - [nmap blast](#nmap-blast)

## Host Discovery

This is only to discover host in get an understanding of the network.

### nmap
```sh
nmap -sn <ip-range> -oG nmap/ping-sweep.txt
grep Up ping-sweep.txt | cut -d " " -f 2
```

### crackmapexec  
```sh
crackmapexec smb <ip-range>
```

### powershell
```cmd
for ($i=1;$i -lt 255;$i++) { ping -n 1 <ip_3_oct>.$i| findstr "TTL"}
```

### bash
```sh
for i in {1..255};do (ping -c 1 <ip_3_oct>.$i | grep "bytes from" &); done
```

## Port Scanning

### bash
```sh
for i in {1..65535}; do (echo > /dev/tcp/<ip_4_oct/$i) >/dev/null 2>&1 && echo $i is open; done
```

### netcat
```sh
nc -zvn <ip> 1-1000
```

### nmap
```sh 
nmap -sC -sV -A -Pn -T5 -p- <ip> -oN <IP>/nmap
sudo nmap -sC -sV <IP> -oN <IP>/nmap
# Connected scan
nmap -sT 192.168.50.149
# UDP Scan
sudo nmap -sU 192.168.50.149 
# Both TCP and UDP
sudo nmap -sU -sS 192.168.50.149
# Top Ports
nmap -sT -A --top-ports=20 192.168.50.1-253 -oG top-port-sweep.txt
# All 
nmap -sT -A 192.168.50.14 - all 
# scans with http-headers
nmap --script http-headers 192.168.50.6
```
```sh
 
  nmap -p 80 192.168.50.1-253 -oG web-sweep.txt
  grep open web-sweep.txt | cut -d" " -f2

```

### powershell
```powershell
Test-NetConnection -Port 445 192.168.50.151
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $*)) "TCP port $* is open"} 2>$null
```

### rustscan
##### Note :
sudo docker pull rustscan/rustscan:2.1.1
alias rustscan='sudo docker run -it --rm --name rustscan rustscan/rustscan:2.1.1'
```sh
rustscan -a <ip> -- -A -Pn
```

### Scanless (an open-source network scanning tool)

### Xprobe (an open-source network scanning tool)

## OS Fingerprinting Tools

### nmap 
```cmd
sudo nmap -O 192.168.50.14 --osscan-guess - OS fingeprint
```

### Os-fingerprint (an open-source OS fingerprinting tool)

### OS-Scanner (an open-source OS scanner)

## DNS Enumeration

Locates the host records for the domain
### Bash
```sh
host <domain>
host -t mx <domain>
host -t txt <domain>
```

dns brute force forward
```bash
for ip in $(cat list.txt); do host $ip.url.com; done
```

dns brute force reverse
```sh
for ip in $(seq 50 100); do host <ip_3_oct>.$ip; done | grep -v "not found"
```

dns lookup
```sh
host -t ns <domain> | cut -d " " -f 4
```

dns zone transfers
```sh
host -l <domain name> <dns_server_address>
```

dns zone transfer -automatic
```sh
for ns in $(host -t ns $1 | cut -d ' ' -f 4 | cut -d '.' -f 1); do host -l $1 $ns.$1; done
```

### dnsrecon - dns zone transfer

```sh
dnsrecon -d <domain -t axfr
dnsrecon -d <domain> -D wordlist.txt -t brt
```

### dnsenum

## SMB Enumeration

### nmap 
```sh
nmap -v -p 139,445 <ip-range> -oG smb.txt 
nmap -v -p 139,445 --script smb-os-discovery <ip>
```

### nbtscan
```sh
sudo nbtscan -r <ip-range>
```

### enum4linux
```sh
enum4linux <ip>
enum4linux -a -u "" -p "" <ip> && enum4linux -a -u "guest" -p "" <ip>
``` 

### Windows
```cmd
net-view
```

## NFS Enumeration

### nmap
```sh
nmap -sV -p 111 --script=rpcinfo <ip-range>
nmap -p 111 --script nfs* <IP>
```

### rpcinfo
```sh
rpcinfo <IP> | grep nfs
```

### showmounts
```sh
showmount -e <ip>
```

### Mounts
```sh
mkdir /tmp/mounts
sudo mount -t nfs -o vers=4 <IP>:/folder /tmp/mounts -o nolock
```

### config files
```sh
/etc/exports
/etc/lib/nfs/etab
/etc/fstab
```

## LDAP Enumeration

### nmap
```sh
nmap -n -sV --script "ldap* and not brute" <IP>
```

### ldapsearch
```
ldapsearch -h <IP> -bx "DC=domain,DC=com"
```

## SNMP Enumeration

### nmap 
```sh
sudo nmap -sU --open -p 161 <ip-range> -oG open-snmp.txt
```

```sh
echo public > community
echo private >> community
echo manager >> community
```

### onesixyone
```sh
for ip in $(seq 1 243); do echo 192.168.0.$ip; done > ips
onesixtyone -c community -i ips
```

```sh
onesixtyone -c community -i ips
```

### snmpwalk - Enumerate the entire MIB tree
```sh
snmpwalk -c public -v1 -t <ip>
```

### snmpwalk - Enumerate windows users
```sh
snmpwalk -c public -v1 <ip> 1.3.6.1.4.1.77.1.2.25
```

### snmpwalk - Lists running processes
```sh
snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.25.4.2.1.2
```

### snmpwalk - Lists open TCP ports
```sh
snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.6.13.1.3
```

### snmpwalk - Enumerate installed software
```sh
snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.25.6.3.1.2
```

## FTP Enumeration

Default creds  
anonymous : anonymous  
### netcat - check ftp version
```sh
nc <IP> <PORT>
```

### nmap 
```sh
nmap -p 21 --script ftp-* <ip>
```

### binary transfer
```sh
ftp user@port
binary
```

### ascii transfer
```sh
ftp user@port
ascii
```

## RDP enumeration

### nmap
```sh
nmap --script rdp-ntlm-info,rdp-enum-encryption,rdp-vuln-ms12-020 -p 3389 -T4 <IP>
```

### Connect to RDP
```sh
rdesktop -u <username> <IP>
xfreerdp /d:<domain> /u:<username> /p:<password> /v:<IP>
```

### Check credentials via RDP
```sh
rdp_check <domain>/<name>:<password>@<IP>
```

## POP Enumeration

### nmap
```sh
nmap --script pop3-capabilities,pop3-ntlm-info -sV -port <IP>
```

### telnet
```sh
telnet <IP> 110
USER <user>
PASS <password>
```

### messages
```sh
list
retr 1
```

## SMTP Enumeration

### nmap
```sh
nmap -p25 --script smtp-commands,smtp-open-relay <ip>
```

### email
```
nc -C <IP> 25
HELLO
MAIL FROM:user@local
RCPT TO:user2@local
DATA
Subject: approved in the job
http://<IP>/malware.exe
QUIT
```

### hyrda
```sh
hydra smtp-enum://<IP>vrfy -l john -p localhost
hydra smtp-enum://<IP>/vrfy -L "/usr/share/seclists/Usernames/ 
```

## Recon Web

### nmap 
```sh
sudo nmap -p80 --script=http-enum <ip>
```

### Wappalyzer
https://www.wappalyzer.com/

### Whatweb

```sh
whatweb http://<ip> <ip>
```

### fuzzing

#### GoBuster
```sh
gobuster dir -u http://<ip> -w /usr/share/wordlists/dirb/common.txt -t 5 -o <ip>/gobuster -x txt,pdf,config
```
#### dirb
It can go more the one file deep -R??
```sh
└─$ dirb  http://<ip> /usr/share/wordlists/dirb/common.txt -N 403 -o output.dirb
```

#### feroxbuster
```sh
feroxbuster --url http://<ip>
```


#### ffuf
```sh
ffuf -u http://site.com/FUZZ -w /usr/share/wordlists/dirb/big.txt
```
File Extension
```
ffuf -u "https://site.com/indexFUZZ" -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt -fs xxx
```
Parameter GET
```
ffuf -u "https://site.com/index.php?FUZZ=ok" -w wordlist.txt -fs xxx
```
Parameter POST
```
ffuf -u "https://site.com/index.php" -X POST -d 'FUZZ=ok' -H 'Content-Type: application/x-www-form-urlencoded' -w wordlist.txt -fs xxx
```
https://github.com/danielmiessler/SecLists

### Nikto - Web Server Scanner 
```
nikto -h http://site.com
```

### CMS

#### wpscan
```sh
wpscan --url http://site.com/wordpress --api-token <your_token> --enumerate u,vp --plugins-detection aggressive
wpscan --url http://site.com/wordpress --api-token <your_token> --enumerate u,ap
wpscan --url http://<ip> --enumerate p --plugins-detection aggressive -o <ip>/wpscan
```

#### Juumla
```python
python main.py -u <target>
```
https://github.com/oppsec/juumla

#### Sroopescan
```sh
droopescan scan drupal -u <target> -t 32
```
https://github.com/SamJoan/droopescan

#### Magescan
```
php magescan.phar scan:all www.example.com
```
https://github.com/steverobbins/magescan


## nmap blast
This is a self made to get all the information fast
```sh
crackmapexec smb <ip-range> > cracksmb.info
sudo nmap -O <ip-range> --osscan-guess -o OS_fingeprint.info
nmap -v -p 139,445 <ip-range> -o smb.info
nmap -sV -p 111 --script=rpcinfo <ip-range> -o rpc.info
sudo nmap -sU --open -p 161 <ip-range> -o open-snmp.info
nmap -p 21 --script ftp-*  <ip> -o ftp.info
nmap -p 25 --script smtp-commands,smtp-open-relay <ip> -o smtp.info
sudo nmap -p 80,443 --script=http-enum <ip> -o http.info
```