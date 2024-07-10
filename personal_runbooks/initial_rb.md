
# Ethical Hacking Virtual Machine Setup Runbook

## Introduction
This runbook provides a comprehensive guide to setting up a virtual machine (VM) tailored for ethical hacking. The instructions cover the configuration of VMware, installation of Kali Linux, and essential tool installations to prepare the VM for penetration testing and security assessments.

## Table of Contents
- [Ethical Hacking Virtual Machine Setup Runbook](#ethical-hacking-virtual-machine-setup-runbook)
  - [Introduction](#introduction)
  - [Table of Contents](#table-of-contents)
  - [Kali Configuration](#kali-configuration)
    - [Updating Kali](#updating-kali)
    - [Setting Scaling](#setting-scaling)
    - [Increasing Display Blanking Timeout](#increasing-display-blanking-timeout)
    - [Configuring Panel](#configuring-panel)
    - [Configuring Terminal](#configuring-terminal)
    - [Configuring Firefox](#configuring-firefox)
    - [SSH Configuration](#ssh-configuration)
  - [Installing and Configuring Useful Tools](#installing-and-configuring-useful-tools)
    - [Cross-Compilation Tools](#cross-compilation-tools)
    - [Additional Tool Installations](#additional-tool-installations)
  - [Conclusion](#conclusion)

## Kali Configuration

### Updating Kali
1. Update Kali, and all packages:
    ```bash
    sudo apt update
    sudo apt full-upgrade -y
    ```

### Setting Scaling
- Enable HiDPI mode: `Applications -> Kali HiDPI Mode`.
- Set terminal font to "Hack, 14".

### Increasing Display Blanking Timeout
- Navigate to `Settings Manager -> Power Management -> Display`.
- Set the display blanking timeout to "Never".

### Configuring Panel
- Lock the panel at the bottom of the screen.
- Move "Show Desktop" to the far right.
- Remove "Workspace Switcher".
- Add frequently used items in this order: Directory Menu, Firefox, Burp Suite (after installation).

### Configuring Terminal
- Customize the terminal appearance and behavior to your preference for better usability.

### Configuring Firefox
- Adjust Firefox settings for privacy and security:
  - Disable telemetry and data collection.
  - Enable necessary plugins and extensions for security testing.
  - Add foxy proxy

### SSH Configuration
1. Generate SSH keys:
    ```bash
    ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
    ```
2. Configure SSH: @ /etc/ssh/sshd_config
    ```bash
     PermitRootLogin prohibit-password
     PasswordAuthentication no
    sudo systemctl restart ssh
    ```

## Installing and Configuring Useful Tools
Install the following tools to enhance your ethical hacking toolkit. Run these commands in the terminal:

- **Visual Studio Code**:
  ```bash
  sudo apt install code -y
  ```
- **Go Programming Language**:
  ```bash
  sudo apt install golang -y
  ```
- **SQLmap**:
  ```bash
  sudo apt install sqlmap -y
  ```
- **Metasploit Framework**:
  ```bash
  curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfinstall > msfinstall
  chmod 755 msfinstall
  ./msfinstall
  ```
- **Additional Tools**:
  ```bash
  sudo apt install bloodhound
  apt install atftp
  sudo apt install -y kali-linux-everything
  sudo apt install pure-ftpd
  sudo apt install -y mssql-cli redis-tools cmake putty
  sudo npm install --global jwt-cracker xls2csv xlsx2csv doc2txt docx2txt
  sudo pip3 install droopescan pyftpdlib oletools
  sudo gem install evil-winrm highline
  ```

  sudo apt install bloodhound atftp kali-linux-everything pure-ftpd sqlmap golang

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


## Conclusion
Your virtual machine is now set up and configured for ethical hacking. This guide covered the essential steps to create, configure, and equip your VM with necessary tools. For further customization and advanced configurations, refer to the official documentation of each tool and platform.

---
