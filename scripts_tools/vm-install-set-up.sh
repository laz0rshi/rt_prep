#!/bin/bash
# This script just helps in the automation of deploying a new VM
#####################################################################
# Variables Declaration
# List of packages to install
packages=(
code
golang
sqlmap
mfsconsule
blododhoudnd
rustscan
terminator
ligolo
atftp
kali-linux-everything
pure-ftpd
mssql-cli
redis-tools
cmake
putty
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
    sudo apt install -y "$i"
done

