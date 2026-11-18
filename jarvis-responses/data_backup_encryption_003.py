#!/usr/bin/env python3
# Cross-Platform Data Backup & Encryption Script (Python)
# Asset Category: 3. Data & Information Assets - Backups, Archives & Recovery Points
#                & 3. Data & Information Assets - Files, Documents & Intellectual Property
# Purpose: Automated encrypted backup for sensitive data on general computers.
# Requires: pip install cryptography
# Schedule via cron (Linux) or Task Scheduler (Windows)

import os
import shutil
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet
import getpass

print("=== JARVIS PRIME: Encrypted Data Backup Utility ===")

# Configuration - EDIT THESE
SOURCE_DIRS = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    # Add more paths as needed for your asset
]
BACKUP_ROOT = os.path.expanduser("~/SecureBackups")
ENCRYPT = True  # Set False only for testing

os.makedirs(BACKUP_ROOT, exist_ok=True)

def generate_key():
    key = Fernet.generate_key()
    with open(os.path.join(BACKUP_ROOT, "backup.key"), "wb") as f:
        f.write(key)
    return key

def load_key():
    key_path = os.path.join(BACKUP_ROOT, "backup.key")
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return f.read()
    return generate_key()

def backup_and_encrypt():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join(BACKUP_ROOT, f"backup_{timestamp}")
    os.makedirs(backup_dir)
    
    key = load_key() if ENCRYPT else None
    fernet = Fernet(key) if key else None
    
    manifest = []
    
    for src in SOURCE_DIRS:
        if not os.path.exists(src):
            continue
        for root, dirs, files in os.walk(src):
            for file in files:
                src_path = os.path.join(root, file)
                rel_path = os.path.relpath(src_path, src)
                dst_path = os.path.join(backup_dir, rel_path)
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                
                if ENCRYPT:
                    with open(src_path, "rb") as f:
                        data = f.read()
                    encrypted = fernet.encrypt(data)
                    with open(dst_path + ".enc", "wb") as f:
                        f.write(encrypted)
                    manifest.append({"original": src_path, "backup": dst_path + ".enc", "encrypted": True})
                else:
                    shutil.copy2(src_path, dst_path)
                    manifest.append({"original": src_path, "backup": dst_path, "encrypted": False})
    
    # Manifest & hash
    manifest_path = os.path.join(backup_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    
    print(f"[+] Backup completed: {backup_dir}")
    print(f"[+] Files processed: {len(manifest)}")
    if ENCRYPT:
        print("[+] All data encrypted with Fernet (AES-128-CBC). Keep backup.key SECURE and OFFLINE.")

if __name__ == "__main__":
    backup_and_encrypt()
