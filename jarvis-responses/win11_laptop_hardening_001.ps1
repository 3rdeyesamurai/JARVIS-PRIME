# Windows 11 Laptop / Portable Device Hardening Script (PowerShell)
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
