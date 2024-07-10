
#!/bin/bash
# project_build.sh
#####################################################################
# Variables Declaration
# Name of the project
project="relia"
# List of IPs for the initial scan and setup
ip_list=(

)
#####################################################################
# Global Variables
PROJECT_DIR="$HOME/$project"
#####################################################################
# Make directories 
# Network layout
mkdir -p "$PROJECT_DIR/network_layout"
# mkdir $PROJECT_DIR
for i in "${ip_list[@]}" 
do 
    mkdir -p "$PROJECT_DIR/$i"
    touch "$PROJECT_DIR/$i/port_scan"
    echo "$i >> "$PROJECT_DIR/network_layout/ips.txt"
done
# app is dir is for code or exploits
mkdir -p "$PROJECT_DIR/apps"
# workspace is your junk drawer
mkdir -p "$PROJECT_DIR/workspace"
# share is for the directory used for sharing 
mkdir -p "$PROJECT_DIR/share"
# creds is for cracked creds
mkdir -p "$PROJECT_DIR/nmap"
# share is for the directory used for sharing 
touch "$PROJECT_DIR/creds.txt"

```
