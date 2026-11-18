#Requires -RunAsAdministrator
# Intruder Protocol — detect & auto-respond
# Usage:
#   -Install   : register as scheduled task (runs every 2 min)
#   -Monitor   : run one detection cycle (called by task)
#   -Status    : show recent alerts
#   -Uninstall : remove scheduled task

param(
    [switch]$Install,
    [switch]$Monitor,
    [switch]$Status,
    [switch]$Uninstall
)

$SuiteRoot  = Split-Path -Parent $PSCommandPath
$AlertLog  = Join-Path $SuiteRoot 'intruder-alerts.log'
$TaskName  = 'IntruderProtocol'
$Self      = $MyInvocation.MyCommand.Path

# ── Thresholds ────────────────────────────────────────────────────────────────
$BruteForceThreshold = 5    # failed logins from same source in window
$BruteForceWindowMin = 10   # minutes to look back

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Alert($level, $msg, $detail = '') {
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts][$level] $msg"
    Add-Content $AlertLog $line
    if ($detail) { Add-Content $AlertLog "  >> $detail" }
    Write-Host $line -ForegroundColor $(if ($level -eq 'CRITICAL') {'Red'} elseif ($level -eq 'WARN') {'Yellow'} else {'Cyan'})

    # Windows toast notification (best-effort)
    try {
        [Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime] | Out-Null
        $xml = [Windows.Data.Xml.Dom.XmlDocument]::new()
        $xml.LoadXml("<toast><visual><binding template='ToastText02'><text id='1'>INTRUDER ALERT [$level]</text><text id='2'>$msg</text></binding></visual></toast>")
        $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Intruder Protocol').Show($toast)
    } catch {}
}

function Block-IP($ip, $reason) {
    $ruleName = "IntruderBlock_$ip"
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound -Action Block `
            -RemoteAddress $ip -Protocol Any -Profile Any | Out-Null
        Write-Alert 'CRITICAL' "BLOCKED IP: $ip" "Reason: $reason"
    }
}

function Capture-Forensics($tag) {
    $ts   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $file = "$env:USERPROFILE\forensics_${tag}_${ts}.txt"
    @(
        "=== FORENSIC SNAPSHOT: $tag @ $(Get-Date) ===",
        "",
        "--- Active Network Connections ---",
        (netstat -ano),
        "",
        "--- Logged-On Users ---",
        (query user 2>&1),
        "",
        "--- Running Processes ---",
        (tasklist /v),
        "",
        "--- Recent Security Events (last 50) ---",
        (Get-WinEvent -LogName Security -MaxEvents 50 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, Message |
            ForEach-Object { "$($_.TimeCreated) [$($_.Id)] $($_.Message -replace '\s+', ' ')" })
    ) | Out-File $file -Encoding UTF8
    Write-Alert 'INFO' "Forensic snapshot saved: $file"
    return $file
}

# ── Detection: Brute Force (Event 4625) ───────────────────────────────────────
function Test-BruteForce {
    $since  = (Get-Date).AddMinutes(-$BruteForceWindowMin)
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4625
        StartTime = $since
    } -ErrorAction SilentlyContinue

    if (-not $events) { return }

    # Group by source IP (field varies — try IpAddress field)
    $byIP = $events | ForEach-Object {
        try { $_.Properties[19].Value } catch { $null }
    } | Where-Object { $_ -and $_ -ne '-' -and $_ -ne '::1' -and $_ -ne '127.0.0.1' } |
        Group-Object | Where-Object { $_.Count -ge $BruteForceThreshold }

    foreach ($group in $byIP) {
        $ip  = $group.Name
        $cnt = $group.Count
        Write-Alert 'CRITICAL' "Brute force detected from $ip ($cnt failures in ${BruteForceWindowMin}m)"
        Block-IP $ip "Brute force: $cnt failed logins"
        Capture-Forensics "brute_$ip"
    }
}

# ── Detection: New Admin Account (Event 4728 / 4732) ─────────────────────────
function Test-NewAdminAccount {
    $since  = (Get-Date).AddMinutes(-3)  # task runs every 2 min
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = @(4728, 4732, 4720)
        StartTime = $since
    } -ErrorAction SilentlyContinue

    foreach ($ev in $events) {
        $id   = $ev.Id
        $msg  = $ev.Message -replace '\s+', ' '
        $label = switch ($id) {
            4720 { 'New user account created' }
            4728 { 'User added to global security group' }
            4732 { 'User added to local Administrators group' }
        }
        Write-Alert 'CRITICAL' $label $msg
        Capture-Forensics "new_account_$id"
    }
}

# ── Detection: New Service Installed (Event 7045) ─────────────────────────────
function Test-NewService {
    $since  = (Get-Date).AddMinutes(-3)
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 7045
        StartTime = $since
    } -ErrorAction SilentlyContinue

    foreach ($ev in $events) {
        $msg = $ev.Message -replace '\s+', ' '
        Write-Alert 'WARN' "New service installed" $msg
        Capture-Forensics "new_service"
    }
}

# ── Detection: Suspicious Outbound (uncommon high ports) ─────────────────────
function Test-SuspiciousConnections {
    $conns = netstat -ano | Select-String 'ESTABLISHED' |
        ForEach-Object {
            $parts = ($_ -split '\s+' | Where-Object { $_ })
            [pscustomobject]@{ Foreign = $parts[2]; PID = $parts[4] }
        } | Where-Object {
            $port = ($_.Foreign -split ':')[-1]
            $port -match '^\d+$' -and [int]$port -notin @(80,443,53,22,25,587,465,993,995,8080,8443)
        }

    foreach ($c in $conns) {
        $proc = (Get-Process -Id $c.PID -ErrorAction SilentlyContinue).Name
        # Flag if a non-browser process has an unusual outbound connection
        if ($proc -and $proc -notin @('svchost','chrome','msedge','firefox','brave','SearchApp')) {
            Write-Alert 'WARN' "Unusual outbound: $proc → $($c.Foreign)" "PID $($c.PID)"
        }
    }
}

# ── Monitor Cycle ─────────────────────────────────────────────────────────────
function Invoke-Monitor {
    Test-BruteForce
    Test-NewAdminAccount
    Test-NewService
    Test-SuspiciousConnections
}

# ── Scheduled Task ────────────────────────────────────────────────────────────
function Install-Task {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -NonInteractive -File `"$Self`" -Monitor"
    $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 2) -Once -At (Get-Date)
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host ('[OK] Scheduled task ''{0}'' installed - runs every 2 minutes as SYSTEM.' -f $TaskName) -ForegroundColor Green
    Write-Host "     Alerts log: $AlertLog"
}

function Uninstall-Task {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host ('[OK] Task ''{0}'' removed.' -f $TaskName) -ForegroundColor Green
}

# ── Status ────────────────────────────────────────────────────────────────────
function Show-Status {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Write-Host "Task: $(if ($task) { $task.State } else { 'NOT INSTALLED' })" -ForegroundColor Cyan

    if (Test-Path $AlertLog) {
        Write-Host "`n--- Last 20 alerts ---" -ForegroundColor Cyan
        Get-Content $AlertLog -Tail 20
    } else {
        Write-Host "No alerts yet."
    }

    Write-Host "`n--- Blocked IPs ---" -ForegroundColor Cyan
    Get-NetFirewallRule -DisplayName 'IntruderBlock_*' -ErrorAction SilentlyContinue |
        Select-Object DisplayName, Enabled |
        ForEach-Object { "  $($_.DisplayName) [Enabled=$($_.Enabled)]" }
}

# ── Entry point ───────────────────────────────────────────────────────────────
if     ($Install)   { Install-Task }
elseif ($Monitor)   { Invoke-Monitor }
elseif ($Status)    { Show-Status }
elseif ($Uninstall) { Uninstall-Task }
else {
    Write-Host @"
Intruder Protocol — Usage:
  -Install    Register scheduled task (every 2 min, runs as SYSTEM)
  -Monitor    Run one detection cycle now
  -Status     Show task state, recent alerts, blocked IPs
  -Uninstall  Remove scheduled task

Quick start:
  powershell -ExecutionPolicy Bypass -File "$Self" -Install
"@
}
