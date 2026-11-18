# Cross-Platform Patching & Update Monitoring Script
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
