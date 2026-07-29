#!/bin/bash

#A script to create vms using the cli

#The very first thing is to capture the name, so now I'm wondering if I should prompt the user or have it be part of the cli agruments?

#Let's prompt the user to provide the name

echo 'Welcome to the VM creation script. We just need a few details from you..'
read -p 'Name: ' name
read -p 'To enter the OStype, press 1, to list OStypes, press 2: ' selection

#Now, what else do we need?
if [ "$selection" = "1" ]; then
    read -p 'OSType: ' ostype
elif [[ "$selection" == "2" ]]; then
    VBoxManage list ostypes
    #Need to add functionality here for if the user wants to now select the ostype??
else 
    echo "Unkown value entered, please re-run script and try again."
    exit 2
fi

read -p 'if you wish to add/modify network adatpters, enter 1' net

if [ "$net"=="1" ]; then
    read -a 'Enter the adapter and type you wish to modify: ' type
    VBoxManage modifyvm --name --nic${type[0]} ${type[1]} --nic\{type[0]\}type

VBoxMange createvm --name $name ` --register --basefolder '/home/hafsa01/VirtualBox\ VMs'
read -p 'VM created! If you wish to start the VM now, enter 1'