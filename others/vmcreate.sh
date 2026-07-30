#!/bin/bash

#A script to create vms using the cli

#The very first thing is to capture the name, so now I'm wondering if I should prompt the user or have it be part of the cli agruments?


#Let's prompt the user to provide the name using getopts
while getopts ':n:o:d:r:h' opt; do
    case $opt in
        n)
        name="$OPTARG"
        echo "VM Name: $name"
        ;;
        o)
        ostype="$OPTARG"
        echo "OS Type: $ostype"
        ;;
        d)
        disk="$OPTARG"
        echo "Disk Size: $disk MB"
        ;;
        r)
        ram="$OPTARG"
        echo "RAM: $ram MB"
        ;;
        h | *)
        echo "Help: Usage: ./vmcreate.sh -n Win11 -o Win 11 "
        exit 0
        ;;
      esac
    done


echo "Creating VM.."
VBoxManage createvm --name $name --ostype $ostype --register


# read -p 'if you wish to add/modify network adatpters, enter 1' net

# if [ "$net"=="1" ]; then
#     read -a 'Enter the adapter and type you wish to modify: ' type
#     VBoxManage modifyvm --name --nic${type[0]} ${type[1]} --nic\{type[0]\}type

# VBoxMange createvm --name $name ` --register --basefolder '/home/hafsa01/VirtualBox\ VMs'
# read -p 'VM created! If you wish to start the VM now, enter 1'

#One key fact that I've forgotten is the iso, so I have a win11 iso, and a pfsense one, but in that case I cannot allow the user to select just any VM

#So here are the options that I MUST ask the user for:
#Name of the VM
#oS type
#hard disk size and location
#storage size
#specify ram as well, defaul to 2048