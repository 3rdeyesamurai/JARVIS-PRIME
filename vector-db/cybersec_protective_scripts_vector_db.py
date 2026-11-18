#!/usr/bin/env python3
"""
JARVIS PRIME: Local Vector Database for Cybersecurity Protective Scripting
================================================================================
Purpose: Fully offline Vector DB (ChromaDB) for semantic retrieval of protective
         scripts mapped to comprehensive cybersecurity asset taxonomy.
         Designed for general computers (endpoints, servers, laptops).
         Integrates with local AI setups (Ollama, LM Studio, custom agents).

Usage:
  1. pip install chromadb sentence-transformers  (or use your local env)
  2. python cybersec_protective_scripts_vector_db.py
  3. Query via the example functions or integrate with LangChain/LlamaIndex/RAG pipeline.

Asset Taxonomy: Hierarchical ordered list aligned to NIST CSF 2.0 (ID.AM),
                NCSC, and industry standards for asset management.
                Use metadata["asset_category"] for precise filtering.

Sir, this system is now online for your protective scripting operations.
"""

import chromadb
from chromadb.utils import embedding_functions
import os
import json
from datetime import datetime
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from jarvis_config import VECTOR_DB_DIR

# =============================================================================
# CONFIGURATION
# =============================================================================
DB_PATH = str(VECTOR_DB_DIR)
COLLECTION_NAME = "protective_scripts_v1"

# Lightweight, high-quality local embedding model (CPU-friendly, ~80MB)
# For higher quality on your 6GB+ VRAM setup, swap to "all-mpnet-base-v2" or integrate Ollama embeddings.
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# =============================================================================
# ASSET TAXONOMY (Ordered Hierarchical List - Core of your request)
# =============================================================================
"""
This is the comprehensive, ordered taxonomy of cybersecurity assets.
Use these exact strings (or prefixes) in metadata["asset_category"] for filtering.
Synthesized from NIST CSF 2.0, Huntress, SentinelOne, NCSC guidance.

1. Hardware / Physical Endpoint Assets
2. Software & Application Assets
3. Data & Information Assets
4. Network & Connectivity Assets
5. Identity, Access & Human Assets
6. Cloud, Virtual & Hybrid Assets
7. Supporting Infrastructure & Facility Assets
8. Third-Party, Supply Chain & External Assets
"""

ASSET_CATEGORIES = [
    "1. Hardware / Physical Endpoint Assets - Servers (physical)",
    "1. Hardware / Physical Endpoint Assets - Workstations / Desktops",
    "1. Hardware / Physical Endpoint Assets - Laptops / Portable Devices",
    "1. Hardware / Physical Endpoint Assets - Mobile Devices (smartphones, tablets)",
    "1. Hardware / Physical Endpoint Assets - Network Equipment (routers, switches, firewalls, APs)",
    "1. Hardware / Physical Endpoint Assets - Peripherals (printers, USB, scanners)",
    "1. Hardware / Physical Endpoint Assets - IoT Devices & Sensors",
    "1. Hardware / Physical Endpoint Assets - OT/ICS Components (PLCs, HMIs - where applicable)",
    
    "2. Software & Application Assets - Operating Systems (Windows, Linux, macOS)",
    "2. Software & Application Assets - Productivity & Business Applications",
    "2. Software & Application Assets - Browsers & Communication Tools",
    "2. Software & Application Assets - Firmware, BIOS/UEFI & Drivers",
    "2. Software & Application Assets - Virtual Machines, Containers & Hypervisors",
    "2. Software & Application Assets - Security Tools (EDR, Antivirus, Firewalls)",
    
    "3. Data & Information Assets - Databases & Structured Data Stores",
    "3. Data & Information Assets - Files, Documents & Intellectual Property",
    "3. Data & Information Assets - Credentials, Secrets, Keys & Certificates",
    "3. Data & Information Assets - Logs, Audit Trails & Telemetry",
    "3. Data & Information Assets - Backups, Archives & Recovery Points",
    
    "4. Network & Connectivity Assets - Internal Networks (LAN, VLANs, SDN)",
    "4. Network & Connectivity Assets - External Connectivity (WAN, VPN, Remote Access)",
    "4. Network & Connectivity Assets - Cloud Networking & SD-WAN",
    "4. Network & Connectivity Assets - DNS, IPAM, DHCP Infrastructure",
    "4. Network & Connectivity Assets - APIs, Web Services & Integrations",
    "4. Network & Connectivity Assets - Digital Certificates & PKI Infrastructure",
    
    "5. Identity, Access & Human Assets - Standard User Accounts & Identities",
    "5. Identity, Access & Human Assets - Privileged / Administrative Accounts",
    "5. Identity, Access & Human Assets - Authentication Systems (MFA, SSO, Passwordless)",
    "5. Identity, Access & Human Assets - Access Control Policies & RBAC",
    "5. Identity, Access & Human Assets - Roles, Groups & Permissions",
    "5. Identity, Access & Human Assets - Third-Party / Vendor / Contractor Access",
    
    "6. Cloud, Virtual & Hybrid Assets - IaaS Workloads (VMs, Instances)",
    "6. Cloud, Virtual & Hybrid Assets - PaaS & Container Platforms",
    "6. Cloud, Virtual & Hybrid Assets - SaaS Applications & Tenants",
    "6. Cloud, Virtual & Hybrid Assets - Serverless & Function-as-a-Service",
    "6. Cloud, Virtual & Hybrid Assets - Hybrid Cloud Gateways & Connections",
    
    "7. Supporting Infrastructure & Facility Assets - Power, UPS & Electrical",
    "7. Supporting Infrastructure & Facility Assets - Cooling, HVAC & Environmental",
    "7. Supporting Infrastructure & Facility Assets - Physical Security Controls",
    "7. Supporting Infrastructure & Facility Assets - Cabling, Racks & Data Centers",
    
    "8. Third-Party, Supply Chain & External Assets - Vendor Software & SaaS",
    "8. Third-Party, Supply Chain & External Assets - Outsourced Services & MSPs",
    "8. Third-Party, Supply Chain & External Assets - Shadow IT & Unauthorized Assets",
    "8. Third-Party, Supply Chain & External Assets - External APIs & Partnerships",
    "8. Third-Party, Supply Chain & External Assets - Online Presence (Domains, Social, Certificates)"
]

# =============================================================================
# SEED PROTECTIVE SCRIPTS (Realistic, production-oriented examples)
# =============================================================================
# Each entry: id, document (full script + header/description), metadata
# Scripts are defensive/hardening/monitoring focused for general computers.

SEED_SCRIPTS = [
    {
        "id": "win11_laptop_hardening_001",
        "document": """# Windows 11 Laptop / Portable Device Hardening Script (PowerShell)
# Asset Category: 1. Hardware / Physical Endpoint Assets - Laptops / Portable Devices
# Purpose: Baseline security configuration for general-purpose Windows laptops.
# Run as Administrator. Test in non-production first.
# References: CIS Benchmarks, Microsoft Security Baselines (adapted for general use)

Write-Host "=== JARVIS PRIME: Windows 11 Laptop Protective Hardening ===" -ForegroundColor Cyan

# 1. Enable Windows Firewall (all profiles)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
Write-Host "[+] Windows Firewall enabled on all profiles" -ForegroundColor Green

# 2. Disable unnecessary services (reduce attack surface)
$servicesToDisable = @("Fax", "WSearch", "RemoteRegistry", "SSDPSRV", "upnphost")
foreach ($svc in $servicesToDisable) {
    Get-Service -Name $svc -ErrorAction SilentlyContinue | Stop-Service -Force -ErrorAction SilentlyContinue
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
}
Write-Host "[+] Unnecessary services disabled" -ForegroundColor Green

# 3. Enable BitLocker (if not already) - requires TPM or password
# Uncomment for production: Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly

# 4. Configure UAC to high level
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1
Write-Host "[+] UAC hardened" -ForegroundColor Green

# 5. Disable SMBv1 (legacy protocol)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
Write-Host "[+] SMBv1 disabled" -ForegroundColor Green

# 6. Enable Windows Defender real-time protection & cloud-delivered
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples
Write-Host "[+] Windows Defender real-time & cloud protection enabled" -ForegroundColor Green

# 7. Audit policy for logon events (basic)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>$null
Write-Host "[+] Basic audit logging enabled" -ForegroundColor Green

Write-Host "=== Hardening complete for Laptop asset. Reboot recommended. ===" -ForegroundColor Yellow
""",
        "metadata": {
            "asset_category": "1. Hardware / Physical Endpoint Assets - Laptops / Portable Devices",
            "os": "Windows 11 / Windows 10",
            "script_type": "Hardening",
            "complexity": "Intermediate",
            "risk_reduction": "High - reduces common endpoint attack surface significantly",
            "last_updated": "2026-06-25",
            "source": "JARVIS-adapted from CIS/Microsoft baselines"
        }
    },
    {
        "id": "linux_ubuntu_server_hardening_002",
        "document": """#!/bin/bash
# Ubuntu/Debian Server Hardening Script (Bash)
# Asset Category: 1. Hardware / Physical Endpoint Assets - Servers (physical) 
#                & 2. Software & Application Assets - Operating Systems
# Purpose: Secure baseline for general-purpose Linux servers.
# Run as root or with sudo. Customize for your environment.

echo "=== JARVIS PRIME: Linux Server Protective Hardening ==="

# 1. Update system
apt update && apt upgrade -y
apt install -y ufw fail2ban unattended-upgrades auditd

# 2. Configure UFW Firewall (deny incoming by default)
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh          # Adjust port if non-standard
ufw allow 80/tcp       # HTTP if needed
ufw allow 443/tcp      # HTTPS
ufw --force enable
echo "[+] UFW firewall configured and enabled"

# 3. Fail2Ban for SSH brute-force protection
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sed -i 's/bantime  = 10m/bantime  = 1h/' /etc/fail2ban/jail.local
systemctl enable --now fail2ban
echo "[+] Fail2Ban enabled for SSH protection"

# 4. Disable root SSH login & password auth (key-based only recommended)
sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh
echo "[+] SSH hardened (root login & password auth restricted)"

# 5. Enable automatic security updates
dpkg-reconfigure -plow unattended-upgrades
echo "[+] Unattended security updates enabled"

# 6. Basic sysctl hardening (kernel parameters)
cat >> /etc/sysctl.conf <<EOF
# JARVIS Protective Settings
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
EOF
sysctl -p
echo "[+] Kernel hardening parameters applied"

# 7. Auditd for logging
systemctl enable --now auditd
echo "[+] Audit daemon enabled"

echo "=== Linux Server hardening complete. Review /var/log/ for baseline. ==="
""",
        "metadata": {
            "asset_category": "1. Hardware / Physical Endpoint Assets - Servers (physical)",
            "os": "Ubuntu / Debian Linux",
            "script_type": "Hardening",
            "complexity": "Intermediate",
            "risk_reduction": "High - network, SSH, kernel level protections",
            "last_updated": "2026-06-25",
            "source": "JARVIS standard server baseline"
        }
    },
    {
        "id": "data_backup_encryption_003",
        "document": """#!/usr/bin/env python3
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
""",
        "metadata": {
            "asset_category": "3. Data & Information Assets - Backups, Archives & Recovery Points",
            "os": "Cross-platform (Python 3.8+)",
            "script_type": "Backup & Encryption",
            "complexity": "Intermediate",
            "risk_reduction": "Critical - protects confidentiality and availability of data assets",
            "last_updated": "2026-06-25",
            "source": "JARVIS data protection module"
        }
    },
    {
        "id": "network_firewall_monitor_004",
        "document": """#!/bin/bash
# General Network Protective Monitoring & Basic Firewall Audit (Bash)
# Asset Category: 4. Network & Connectivity Assets - Internal Networks (LAN, VLANs, SDN)
#                & 4. Network & Connectivity Assets - External Connectivity (WAN, VPN, Remote Access)
# Purpose: Quick defensive network posture check and simple iptables/ufw audit for general computers/servers.
# Run periodically or via cron. Extend with your preferred monitoring (e.g., suricata, zeek).

echo "=== JARVIS PRIME: Network Protective Audit ==="

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    OS=$(uname -s)
fi

echo "[*] Detected OS family: $OS"

# UFW / iptables status
if command -v ufw &> /dev/null; then
    echo "[+] UFW Status:"
    ufw status verbose
elif command -v iptables &> /dev/null; then
    echo "[+] iptables rules (filter table):"
    iptables -L -v -n | head -30
fi

# Active connections & listening ports (defensive view)
echo "[+] Current listening ports & established connections (ss -tulnpe):"
ss -tulnpe | head -20

# Basic port scan defensive note (do not scan others without authorization)
echo "[!] NOTE: For authorized internal scanning only. Consider nmap -sV --script vuln on your own assets if needed."

# DNS & gateway check
echo "[+] Default gateway & DNS:"
ip route | grep default
cat /etc/resolv.conf | grep nameserver

echo "=== Network audit complete. Review for unexpected listeners or rules. ==="
""",
        "metadata": {
            "asset_category": "4. Network & Connectivity Assets - Internal Networks (LAN, VLANs, SDN)",
            "os": "Linux (adaptable to Windows with netsh)",
            "script_type": "Monitoring & Audit",
            "complexity": "Basic to Intermediate",
            "risk_reduction": "Medium-High - visibility into network exposure",
            "last_updated": "2026-06-25",
            "source": "JARVIS network visibility module"
        }
    },
    {
        "id": "identity_audit_local_users_005",
        "document": """#!/usr/bin/env python3
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
""",
        "metadata": {
            "asset_category": "5. Identity, Access & Human Assets - Standard User Accounts & Identities",
            "os": "Cross-platform (Linux primary; Windows notes included)",
            "script_type": "Audit & Compliance",
            "complexity": "Basic",
            "risk_reduction": "High - reduces insider threat and privilege escalation surface",
            "last_updated": "2026-06-25",
            "source": "JARVIS identity governance module"
        }
    },
    {
        "id": "general_patching_monitor_006",
        "document": """# Cross-Platform Patching & Update Monitoring Script
# Asset Category: 2. Software & Application Assets - Operating Systems
#                & 1. Hardware / Physical Endpoint Assets (general computers)
# Purpose: Check and report on system update status. Trigger protective patching.
# Windows: PowerShell; Linux: Bash wrapper. Schedule regularly.

Write-Host "=== JARVIS PRIME: Protective Patching Status Check ===" -ForegroundColor Cyan

if ($IsWindows -or $env:OS -like "*Windows*") {
    # Windows Update check (requires PSWindowsUpdate or native)
    Write-Host "[*] Windows Update Status:"
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result = $searcher.Search("IsInstalled=0")
        if ($result.Updates.Count -gt 0) {
            Write-Host "[!] Pending Updates: $($result.Updates.Count)" -ForegroundColor Yellow
            $result.Updates | Select Title, KBArticleIDs | Format-Table -AutoSize
            # To install: $result.Updates | Install-WindowsUpdate -AcceptAll
        } else {
            Write-Host "[+] System is up to date." -ForegroundColor Green
        }
    } catch {
        Write-Host "[!] Windows Update check requires elevation or PSWindowsUpdate module." -ForegroundColor Red
    }
    
    # Quick Defender signature update
    Update-MpSignature -ErrorAction SilentlyContinue
    Write-Host "[+] Windows Defender signatures checked/updated." -ForegroundColor Green
} else {
    # Linux
    if command -v apt &> /dev/null; then
        echo "[*] Checking apt updates..."
        apt update -qq
        updates=$(apt list --upgradable 2>/dev/null | grep -c upgradable || true)
        echo "[*] Available updates: $updates"
        if [ "$updates" -gt 0 ]; then
            echo "[!] Run: sudo apt upgrade -y for protective patching."
        fi
    elif command -v yum &> /dev/null; then
        yum check-update --quiet
    fi
    echo "[+] Linux package check complete."
}

Write-Host "=== Patching status audit finished. Apply updates promptly for asset protection. ===" -ForegroundColor Yellow
""",
        "metadata": {
            "asset_category": "2. Software & Application Assets - Operating Systems (Windows, Linux, macOS)",
            "os": "Cross-platform (PowerShell + Bash logic)",
            "script_type": "Monitoring & Maintenance",
            "complexity": "Basic",
            "risk_reduction": "Critical - closes known vulnerabilities across software assets",
            "last_updated": "2026-06-25",
            "source": "JARVIS maintenance & vulnerability management module"
        }
    }
]

# =============================================================================
# DATABASE INITIALIZATION & POPULATION
# =============================================================================
def initialize_vector_db():
    print("[JARVIS] Initializing local Vector DB for Protective Scripting...")
    
    client = chromadb.PersistentClient(path=DB_PATH)
    
    # Use persistent embedding function
    ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name=EMBEDDING_MODEL)
    
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef,
        metadata={
            "description": "Protective scripts for general computer cybersecurity. Categorized by comprehensive asset taxonomy. Fully offline.",
            "created": datetime.now().isoformat(),
            "version": "1.0-JARVIS",
            "taxonomy_source": "NIST CSF 2.0 + NCSC + Industry Standards (2026)"
        }
    )
    
    # Check if already populated
    existing = collection.count()
    if existing > 0:
        print(f"[JARVIS] Collection already contains {existing} entries. Skipping seed to avoid duplicates.")
        print("[JARVIS] To force re-seed, delete the DB folder or use collection.delete().")
        return collection
    
    print(f"[JARVIS] Seeding {len(SEED_SCRIPTS)} protective scripts into Vector DB...")
    
    ids = []
    documents = []
    metadatas = []
    
    for script in SEED_SCRIPTS:
        ids.append(script["id"])
        documents.append(script["document"])
        metadatas.append(script["metadata"])
    
    collection.add(
        ids=ids,
        documents=documents,
        metadatas=metadatas
    )
    
    print(f"[JARVIS] Successfully seeded {len(ids)} scripts.")
    print(f"[JARVIS] DB persisted at: {DB_PATH}")
    return collection

# =============================================================================
# QUERY & UTILITY FUNCTIONS
# =============================================================================
def query_protective_scripts(query_text, asset_category_filter=None, n_results=5):
    """Semantic search with optional asset category filter."""
    client = chromadb.PersistentClient(path=DB_PATH)
    collection = client.get_collection(COLLECTION_NAME)
    
    where_clause = None
    if asset_category_filter:
        where_clause = {"asset_category": {"$contains": asset_category_filter}}
    
    results = collection.query(
        query_texts=[query_text],
        n_results=n_results,
        where=where_clause,
        include=["documents", "metadatas", "distances"]
    )
    
    return results

def add_custom_script(script_id, document, metadata_dict):
    """Add your own protective script to the DB."""
    client = chromadb.PersistentClient(path=DB_PATH)
    collection = client.get_collection(COLLECTION_NAME)
    
    collection.add(
        ids=[script_id],
        documents=[document],
        metadatas=[metadata_dict]
    )
    print(f"[JARVIS] Custom script '{script_id}' added successfully.")

def list_asset_categories():
    """Return the full ordered taxonomy."""
    return ASSET_CATEGORIES

# =============================================================================
# MAIN EXECUTION
# =============================================================================
if __name__ == "__main__":
    print("\n" + "="*80)
    print("JARVIS PRIME INTELLIGENCE - Cybersecurity Protective Scripting Vector DB")
    print("Sir, your offline asset-categorized protective script retrieval system is ready.")
    print("="*80 + "\n")
    
    collection = initialize_vector_db()
    
    print("\n--- EXAMPLE USAGE ---")
    print("1. List all asset categories:")
    for cat in list_asset_categories()[:5]:  # First 5 for brevity
        print(f"   - {cat}")
    print("   ... (full list in ASSET_CATEGORIES)")
    
    print("\n2. Example semantic query: 'harden Windows laptop firewall and services'")
    example_results = query_protective_scripts(
        "harden Windows laptop firewall and disable unnecessary services",
        asset_category_filter="Laptops",
        n_results=2
    )
    if example_results and example_results["documents"] and example_results["documents"][0]:
        print(f"   Top match distance: {example_results['distances'][0][0]:.4f}")
        print(f"   Category: {example_results['metadatas'][0][0].get('asset_category', 'N/A')}")
    
    print("\n3. To query in your code/agent:")
    print("   from cybersec_protective_scripts_vector_db import query_protective_scripts")
    print("   results = query_protective_scripts('secure my Linux server SSH', asset_category_filter='Servers')")
    
    print("\n[JARVIS] Mission ready. Shall I proceed with generating additional scripts for specific asset categories or integrating with your local RAG agent?")
    print("="*80 + "\n")