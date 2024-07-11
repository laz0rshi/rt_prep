
# Intial Setup Runbook

## Introduction

This runbook provides a comprehensive guide to setting up a virtual machine (VM) tailored for ethical hacking. The instructions DO NOT cover the configuration of VMware, installation of Kali Linux, but do include the configuration of Kali and as well as other essential tools to prepare the VM for penetration testing and security assessments.

## Table of Contents
- [Intial Setup Runbook](#intial-setup-runbook)
  - [Introduction](#introduction)
  - [Table of Contents](#table-of-contents)
  - [Kali Configuration](#kali-configuration)
    - [Updating Kali](#updating-kali)
    - [Setting Scaling](#setting-scaling)
    - [Increasing Display Blanking Timeout](#increasing-display-blanking-timeout)
    - [Configuring Panel](#configuring-panel)
    - [Configuring Firefox](#configuring-firefox)
    - [SSH Configuration](#ssh-configuration)
  - [Installing and Configuring Useful Tools](#installing-and-configuring-useful-tools)
    - [Cross-Compilation Tools](#cross-compilation-tools)
    - [Additional Tool Installations](#additional-tool-installations)

## Kali Configuration

### Updating Kali

Update Kali, and all packages:
```sh
sudo apt update
sudo apt full-upgrade
```

### Setting Scaling

- Enable HiDPI mode: `Applications -> Kali HiDPI Mode`.

### Increasing Display Blanking Timeout

- Navigate to `Settings Manager -> Power Management -> Display`.
- Set the display blanking timeout to "Never".

### Configuring Panel

- Lock the panel at the bottom of the screen.
- Move "Show Desktop" to the far right.
- Remove "Workspace Switcher".
- Add frequently used items in this order: Directory Menu, Firefox, Burp Suite (after installation).

### Configuring Firefox

- Adjust Firefox settings for privacy and security:
  - Disable telemetry and data collection.
  - Enable necessary plugins and extensions for security testing.
  - Add foxy proxy

### SSH Configuration

- Generate SSH keys:
```sh
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
```

- Configure SSH

```sh
vim /etc/ssh/sshd_config
PermitRootLogin prohibit-password
PasswordAuthentication no
sudo systemctl restart ssh
```

## Installing and Configuring Useful Tools

Install the following tools to enhance your toolkit.  It will install the following:

- Visual Studio Code
- Go
- SQLMap
- Metasploit
- Bloodhound
- Rustscan
- Terminator
- Ligolo

```sh
# Visual Studio Code
sudo apt install code
# Go Programming Language
sudo apt install golang
# SQLmap
sudo apt install sqlmap
# Metasploit Framework
sudo apt install mfsconsule
# Bloodhound
sudo apt install blododhoudnd
# Rustscan
sudo apt install rustscan
# Terminator
sudo apt install terminator 
# Ligolo
sudo apt install ligolo
```

Additional Tools
```bash
sudo apt install atftp
sudo apt install -y kali-linux-everything
sudo apt install pure-ftpd
sudo apt install -y mssql-cli redis-tools cmake putty
sudo npm install --global jwt-cracker xls2csv xlsx2csv doc2txt docx2txt
sudo pip3 install droopescan pyftpdlib oletools
sudo gem install evil-winrm highline
```

### Cross-Compilation Tools

For compiling Windows binaries on ARM:
```bash
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt install -y gcc-mingw-w64 g++-mingw-w64 mingw-w64 gcc-multilib g++-multilib libc6-dev:i386
```

### Additional Tool Installations

- **WES.py**:
  ```bash
  wget https://github.com/bitsadmin/wesng/archive/master.zip
  unzip master.zip
  cd wesng-master
  sudo pip3 install .
  ```

- **Impacket**:
  ```bash
  wget https://github.com/SecureAuthCorp/impacket/releases/download/impacket_0_11_0/impacket-0.11.0.tar.gz
  tar -xzf impacket-*.tar.gz
  cd impacket-0.11.0
  sudo pip3 install .
  ```

 <!--- Last Updated July 8, 2024 --->