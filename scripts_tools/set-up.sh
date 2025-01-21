
#!/bin/bash
# project_build.sh
#####################################################################
# Variables Declaration
# Name of the project
PROJECT="b"
PROJECT_DIR=""
# List of IPs for the initial scan and setup
ip_list=(


)

FILE_LAYOUT=(
evidence/credentials
evidence/data
evidence/screenshot
logs
network
scans/nmap
scope
tools
)

#####################################################################
# Make directories 
## File Layout
#└───Project
#    ├───evidence
#    │   ├───credentials
#    │   ├───data
#    │   └───screenshots
#    ├───logs
#    ├───network
#    ├───scans 
#    ├───scope
#    └───tools

read -p "Enter your desired project name: " PROJECT
read -p "Enter your desired project directory: " PROJECT_DIR 

echo -e "Making $PROJECT_DIR directory"
#mkdir -p $PROJECT_DIR

for i in "${FILE_LAYOUT[@]}" 
do 
    echo "Making $PROJECT_DIR/$i directories"
   #mkdir -p "$PROJECT_DIR/$i"
done

for i in "${ip_list[@]}" 
do 
    echo 'Making the "$i" directories'
   #mkdir -p "$PROJECT_DIR/scans/$i" 
    echo "$i" >> "$PROJECT_DIR/network/ips.txt"
done

