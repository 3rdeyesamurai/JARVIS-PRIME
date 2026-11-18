#!/usr/bin/env python3
# Local Identity & Privileged Account Audit Script (Python)
# Asset Category: 5. Identity, Access & Human Assets - Standard User Accounts & Identities
#                & 5. Identity, Access & Human Assets - Privileged / Administrative Accounts
# Purpose: Audit local users, groups, and privileged access on general computers.
# Helps detect shadow admins or dormant accounts. Cross-platform friendly.

import os
import pwd
import grp
import json
from datetime import datetime

print("=== JARVIS PRIME: Local Identity & Access Audit ===")

def audit_local_identities():
    results = {
        "timestamp": datetime.now().isoformat(),
        "users": [],
        "groups": [],
        "privileged_users": []
    }
    
    # Linux / Unix style
    try:
        for user in pwd.getpwall():
            user_info = {
                "name": user.pw_name,
                "uid": user.pw_uid,
                "gid": user.pw_gid,
                "home": user.pw_dir,
                "shell": user.pw_shell
            }
            results["users"].append(user_info)
            
            # Simple privileged heuristic (uid 0 or common admin groups)
            if user.pw_uid == 0 or user.pw_name in ["root", "admin", "administrator"]:
                results["privileged_users"].append(user.pw_name)
    except Exception as e:
        print(f"[!] Linux pwd audit skipped or partial: {e}")
    
    # Groups
    try:
        for group in grp.getgrall():
            results["groups"].append({
                "name": group.gr_name,
                "gid": group.gr_gid,
                "members": group.gr_mem
            })
    except Exception as e:
        print(f"[!] Group audit note: {e}")
    
    # Windows note (requires pywin32 or PowerShell call)
    if os.name == 'nt':
        print("[*] Windows detected. For full audit run equivalent PowerShell: Get-LocalUser | Select Name,Enabled,LastLogon")
        print("[*] Privileged: Get-LocalGroupMember -Group 'Administrators'")
    
    output_file = f"identity_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] Audit saved to {output_file}")
    print(f"[+] Total users scanned: {len(results['users'])}")
    print(f"[+] Potential privileged accounts flagged: {results['privileged_users']}")
    print("[!] Review for dormant accounts (last login) and remove unnecessary privileges.")

if __name__ == "__main__":
    audit_local_identities()
