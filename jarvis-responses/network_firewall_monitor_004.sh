#!/bin/bash
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
