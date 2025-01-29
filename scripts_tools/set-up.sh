#!/bin/sh
# project_build.sh
########################################################
# Set Global variables
# Name of the project
PROJECT=""
PROJECT_DIR=""
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
# Set project specfic variables
# List of IPs for the initial scan and setup
ip_list=(
)
############################################################
############################################################
# Help                                                     #
############################################################
Help()
{
   # Display Help
   echo "Creates the folder structure for a target"
   echo
   echo "Syntax: scriptTemplate [-i|h|n|v]"
   echo "options:"
   echo "i                 IP address of host."
   echo "h     Print this Help."
   echo "p                Project name."
   echo "v     Verbose mode."
   echo
}
############################################################
############################################################
# Main program                                             #
############################################################
############################################################
 

############################################################
# Process the input options. Add options as needed.        #
############################################################
# Get the options
while getopts "i:h:p:" option; do
   case $option in
      i) # Enter IP address
         IP=$OPTARG;;
      h) # display Help
         Help
         exit;;
      p) # Enter a name
         PROJECT=$OPTARG
         PROJECT_DIR="$HOME/offsec/tj_list/$PROJECT" ;;
     \?) # Invalid option
         echo "Error: Invalid option"
         exit;;
   esac
done
shift "$(( OPTIND - 1 ))"
if [ -z "$IP" ] || [ -z "$PROJECT" ]; then
        echo 'Missing -i or -p' >&2
        exit 1
fi
 
echo -e "Making $PROJECT_DIR directory"
mkdir -p $PROJECT_DIR
for i in "${FILE_LAYOUT[@]}"
do
    echo "Making $PROJECT_DIR$i directories"
    mkdir -p "$PROJECT_DIR/$i"
done
