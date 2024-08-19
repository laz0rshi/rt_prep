# Tunneling
<!--- Status 90% --->

## Introduction

This runbook provides a guide to information I want to collect after I get root or post system permisions. It is both for linux and windows.  Most of these steps are else where in the playbooks, but it is consolidated here as well.  It also includes steps you want to do in order to exfiltrate data and clear logs.

## Table of Content

- [Tunneling](#tunneling)
  - [Introduction](#introduction)
  - [Table of Content](#table-of-content)
  - [Post Exploit](#post-exploit)
    - [Gather Hashes](#gather-hashes)
      - [Windows](#windows)
      - [Linux](#linux)
    - [Check home directories](#check-home-directories)
      - [Windows](#windows-1)
      - [Linux](#linux-1)
    - [Logs](#logs)
      - [Windows](#windows-2)
      - [Linux](#linux-2)
    - [Moving forward](#moving-forward)
  - [Clean Up](#clean-up)

## Post Exploit

### Gather Hashes

#### Windows

Mimikats (See Sections)
SAM File (See Sections)

#### Linux

```sh
cat /etc/shadow > shadow.hash
```

### Check home directories

#### Windows

- Check files in all directories

```powershell
  Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue 
```

#### Linux

- Check files in all directories

```sh
find / -type f -name -o -name "*.txt" -o -name "*.kdbx" -o -name "*.zip" 2>/dev/null
```

### Logs

#### Windows

Windows Event Viewer
Include all users command history

#### Linux

/var/log/<log type>
Include all users command history

### Moving forward

Do I need any of the following

- [ ] Evidence for report or proof
- [ ] Tunnels
- [ ] Persistance
- [ ] Covering Tracks

## Clean Up

<!-- Comming soon -- Not really needed for OSCP>
 <!--- Last Updated August 15, 2024 --->