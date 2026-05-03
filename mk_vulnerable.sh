#!/usr/bin/env bash

# ==============================================================================
# Script Name:   mk_vulnerable.sh
# Author:        David H. Isakson II
# Email:         david.isakson.ii@gmail.com
# Date:          2026-05-02
# Version:       1.0
# Description:   Check to see if the algif_aead module has been disabled and
#                re-enables it in order expose the system to CVE-2026-31431
#                for the purpose of testing check_copy_fail.py
#
# Usage:
#   chmod +x mk_vulnerable.sh
#   ./mk_vulnerable.sh
#   or:
#   bash mk_vulnerable.sh
# ==============================================================================

# Define the file path
FILE_PATH="/etc/modprobe.d/disable-algif_aead.conf"

echo "================================================================================"
echo "                           System Hardening Reversal"
echo "================================================================================"
echo "This script performs the following actions:"
echo "1. Checks if the hardening configuration file exists at:"
echo "   $FILE_PATH"
echo "2. If found, it removes the file using superuser (sudo) privileges."
echo "3. Reboots the machine immediately to re-enable the algif_aead module."
echo
echo "WARNING: Re-enabling this module will expose the system to the CVE-2026-31431"
echo "vulnerability if the kernel has not been patched."
echo "================================================================================"
echo

# Prompt the user to proceed
read -p "Do you wish to proceed with removing the configuration and rebooting? (y/N) " -n 1 -r
echo
echo # Move to a new line after the prompt
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    echo "Operation cancelled. No changes were made."
    exit 1
fi

# Check if the file exists
if [ -f "$FILE_PATH" ]; then
    echo "Found $FILE_PATH. Deleting the file..."
    
    # Remove the file using sudo
    sudo rm -f "$FILE_PATH"
    
    # Verify the file was removed
    if [ ! -f "$FILE_PATH" ]; then
        echo "File deleted successfully. Rebooting the machine..."
        # Reboot the system
        sudo reboot
    else
        echo "Error: Failed to delete the file."
        exit 1
    fi
else
    echo "The file $FILE_PATH does not exist. No action taken."
fi