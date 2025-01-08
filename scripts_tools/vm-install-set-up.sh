#!/bin/bash
# This script just helps in the automation of deploying a new VM
#####################################################################
# Variables Declaration
# List of packages to install
packagelist_1=(
kali-linux-everything
apt-transport-https
sqlmap
mfsconsule
pure-ftpd
mssql-cli
)

packagelist_2=(
code
golang
blododhoudnd
rustscan
terminator
ligolo
atftp
redis-tools
cmake
putty
)

#####################################################################
# Global Variables
PROJECT_DIR="$HOME/$project"
#####################################################################

###########
# Prepare to install VScode
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
sudo install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg
echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" |sudo tee /etc/apt/sources.list.d/vscode.list > /dev/null
rm -f packages.microsoft.gpg
###########

# Update
sudo apt-get update
sudo apt-get upgrade

for i in "${packagelist_1[@]}" 
do 
    sudo apt install -y "$i"
done


for i in "${packagelist_2[@]}" 
do 
    sudo apt install -y "$i"
done



