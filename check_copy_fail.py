#!/usr/bin/env python3

# ==============================================================================
# Script Name:   check_copy_fail.py
# Author:        David H. Isakson II
# Email:         david.isakson.ii@gmail.com
# Date:          2026-05-02
# Version:       1.0
# Description:   Check for CVE-2026-31431 a.k.a Copy Fail and fix if required.
#
# Usage:
#   python3 check_copy_fail.py
# Or:
#   chmod +x check_copy_fail.py
#   ./check_copy_fail.py
# ==============================================================================

import socket
import errno
import os
import subprocess

def check_module_blocked():
    """
    Checks if the algif_aead module is blacklisted in /etc/modprobe.d/
    """
    modprobe_dir = "/etc/modprobe.d"
    
    if not os.path.exists(modprobe_dir):
        return False

    for filename in os.listdir(modprobe_dir):
        filepath = os.path.join(modprobe_dir, filename)
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'r') as f:
                    content = f.read()
                    if "algif_aead" in content:
                        print(f"[✓] Hardening detected in {filename}: Interface is already disabled.")
                        return True
            except Exception:
                continue
    return False

def unload_module():
    """
    Unloads the module from memory using sudo rmmod.
    """
    try:
        print("[*] Unloading algif_aead module from memory...")
        result = subprocess.run(
            ["sudo", "rmmod", "algif_aead"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print("[✓] Module successfully unloaded from memory.")
        else:
            print(f"[*] Note during unload attempt: {result.stderr.strip()}")
    except Exception as e:
        print(f"[?] Failed to execute rmmod: {e}")

def harden_system():
    """
    Writes the disable configuration to /etc/modprobe.d/ using subprocess and sudo, 
    then unloads the module.
    """
    config_path = "/etc/modprobe.d/disable-algif_aead.conf"
    
    content = b"""# Disable algif_aead module due to CVE-2026-31431 (AKA copy.fail)
# This will likely be re-enabled in a subsequent update once an updated
# kernel has been deployed.
# Blacklisting the module isn't sufficient, we need to do as below:
install algif_aead /bin/false
"""
    
    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        # Automatically run sudo tee to write the file, prompting for password
        subprocess.run(
            ["sudo", "tee", config_path],
            input=content,
            check=True,
            capture_output=True
        )
        print(f"[✓] System successfully hardened. Created {config_path}")
        
        # Unload the module immediately
        unload_module()
        
    except subprocess.CalledProcessError as e:
        print(f"[!] Sudo execution failed or permission denied: {e.stderr.decode('utf-8').strip()}")
    except Exception as e:
        print(f"[?] Failed to write hardening configuration: {e}")

def check_kernel_patch_status():
    """
    Checks if the system is vulnerable to the Copy Fail exploit (CVE-2026-31431).
    """
    # 1. Check if the blocklist already exists
    if check_module_blocked():
        return

    # 2. Check vulnerability using the kernel socket
    try:
        a = socket.socket(38, 5, 0)
        a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
        
        SOL_ALG = 279
        a.setsockopt(SOL_ALG, 5, None, 4)
        a.close()
        
        print("[!] System appears VULNERABLE: The kernel accepted the invalid parameter.")
        print("[*] Automatically requesting elevated privileges to apply system hardening...")
        
        # Automatically runs sudo
        harden_system()
        
    except OSError as e:
        if e.errno == errno.EINVAL:
            print("[✓] System appears PATCHED: The kernel correctly rejected the invalid parameter. No changes made.")
        elif e.errno == errno.ENOENT:
            print("[?] Could not initialize socket: Interface or module not loaded in memory.")
        else:
            print(f"[?] Unexpected error occurred: {e}")
    except Exception as e:
        print(f"[?] Could not initialize socket: {e}")

if __name__ == "__main__":
    check_kernel_patch_status()