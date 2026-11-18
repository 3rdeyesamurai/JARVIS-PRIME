#!/bin/bash
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
