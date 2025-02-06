# Linux Enumeration and Privilege Escalation
<!--- Status 80% --->

## Introduction

This checklist is to help with linux enumeration and privilege escalation, and to ensure I don't get taken down a rabbit hole.  It will include the automated approach at the end. 

## Stabilize Shell  

## Enumeration

- System Information\Environment enumeration
  - OS Version
  - Kernel Version
  - Running Service
- Installed Packages and Versions # Later?
- Logged in Users
- User Home Directories
  - SSH Directory Contents
  - Bash History
- Sudo Privileges
- Configuration Files
- Readable Shadow File
- Password Hashes
- Cron Jobs
- File Systems and Additional Drives
- SETUID and SETGID Permissions
- Writeable Directories

## Automation

- LinPEAS
- LinEnum