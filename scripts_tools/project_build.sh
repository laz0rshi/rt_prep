#!/bin/bash
# project_build.sh
############################################################
# Variables Declaration
# Name of the project
PROJECT=""
PROJECT_DIR=""
MY_IP=$(hostname -I | awk -F' ' '{ print $3}')
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
# List of IPs for the initial scan and setup
ip_list=(

)
############################################################
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
############################################################
############################################################
# Functions                                                #   
############################################################

Help ()
{
  # Display Help
  echo -e "Creates the folder structure for a target"
  echo -e " "
  echo  -e"Syntax: scriptTemplate [-i|h|n|v]"
  echo  -e"options:"
  echo  -e"i                 IP address of host."
  echo  -e"h     Print this Help."
  echo  -e"p                Project name."
  echo  -e"v     Verbose mode."
  echo -e " "
}

Make_directories ()
{
  echo -e "Making $PROJECT_DIR directory"
  mkdir -p $PROJECT_DIR

   for i in "${FILE_LAYOUT[@]}"
     do
        echo "Making $PROJECT_DIR/$i directories"
        mkdir -p "$PROJECT_DIR/$i"
     done
        echo "My IP is: $MY_IP" > "$PROJECT_DIR/network/$IP"
        echo "Attacking IP is $IP" >> "$PROJECT_DIR/network/$IP"
}

############################################################
# Main program                                             #
############################################################
############################################################
 
# More ?

############################################################
# Process the input options. Add options as needed.        #
############################################################

# Get the options
while getopts ":i:h:p:" opts;
  do
    case $opts in
      i) # Enter IP address
         IP=$OPTARG;;
      h) # display Help
         Help
         exit;;
      p) # Enter a name
         PROJECT="$OPTARG"
         PROJECT_DIR="$HOME/offsec/tj_list/$PROJECT" ;;
      \?) # Invalid option
         echo "Error: Invalid option"
         exit;;
    esac
done
shift "$(( OPTIND - 1 ))"

if [ -z "$IP" ] || [ -z "$PROJECT" ]; then
   echo -e "Missing -i or -p" >&2
     exit 1
fi

Make_directories
