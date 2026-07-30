#!/bin/bash

#A script to create vms using the cli

#The very first thing is to capture the name, so now I'm wondering if I should prompt the user or have it be part of the cli agruments?


#Let's prompt the user to provide the name using getopts
while getopts ':n:o:i:d:r:h' opt; do
    case $opt in
        n)
        name="$OPTARG"
        echo "VM Name: $name"
        ;;
        o)
        ostype="$OPTARG"
        echo "OS Type: $ostype"
        ;;
        i)
        iso="$OPTARG"
        echo "iso path: $iso"
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

echo "Creating HDD"
VBoxManage createhd --filename /VirtualBox/$name/$name.vdi --size $disk

echo "Creating SATA controller and attach iso and hdd..." 
VBoxManage storagectl $name 'SATA Controller' --add sata --controller IntelAHCI
VBoxManage storageattach $name --storagectl "SATA Controller" --port 0 --device 0 \ 
--type hdd --medium /VirtualBox/$name/$name.vdi  

VBoxManage storageattach $name --storagectl "SATA Controller" --port 0 --device \
--type dvddrive --medium $iso

echo "Enabling I/O APIC..thank me later"
VBoxManage modifyvm $name --ioapic on

echo "Configuring the boot order.."
VBoxManage modifyvm $name --boot1 dvd --boot2 disk --boot3 none --boot4 none

echo  "Configuring ram.."
VBoxManage modifyvm $name --memory $ram




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