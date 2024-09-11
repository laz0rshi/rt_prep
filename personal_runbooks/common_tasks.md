# Common Tasks Guide
<!--- Status 90% --->
<!---Mimikatz how to --->

## Introduction

This runbook provides a guide to help with common tasks that I have came accross and want to document.  Most of the tasks are short and dont fall into the other runbooks.  

## Table of Contents

- [Common Tasks Guide](#common-tasks-guide)
  - [Introduction](#introduction)
  - [Table of Contents](#table-of-contents)
  - [Cracking hashes](#cracking-hashes)
  - [Cracking encrypted files](#cracking-encrypted-files)
  - [Reading Microsoft Compound Files and Office documents](#reading-microsoft-compound-files-and-office-documents)
  - [Catching creds in incoming auth requests](#catching-creds-in-incoming-auth-requests)
  - [Certificates and keys](#certificates-and-keys)

## Cracking hashes

- Identify hash type _(here are some hash examples: https://hashcat.net/wiki/doku.php?id=example_hashes)_:

```bash
hash-identifier
```

- Crack a hash:

```bash
john ./hash --wordlist=/usr/share/wordlists/rockyou.txt
john ./hash --format=<format> --wordlist=/usr/share/wordlists/rockyou.txt
john --show ./hash
```

```bash
hashcat -m <hash_type> -a 0 ./hash /usr/share/wordlists/rockyou.txt
```

## Cracking encrypted files

- Find `2john` converter for required file type:

```bash
locate *2john*
```

- Generate a hash:

```bash
<2john_converter> <some_document> > hash
```

- Crack it:

```bash
john ./hash --wordlist=/usr/share/wordlists/rockyou.txt
```

## Reading Microsoft Compound Files and Office documents

- Read using Apache OpenOffice.
- Analyze files using oletools: https://github.com/decalage2/oletools

## Catching creds in incoming auth requests

- Responder supports many different protocols. Default usage example:
```bash
sudo responder -I tun0
```

## Certificates and keys

- Convert `.ppk` keys to `.pem` _(a text-based container using base-64 encoding)_ or `.key`:

```bash
puttygen my.ppk -O private-openssh -o my.pem
```

- Generate a public key:

```bash
puttygen my.ppk -O public-openssh -o my.pub
puttygen my.ppk -O public -o my.pub
```
