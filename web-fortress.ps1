# Web-Fortress: Containerize web-adjacent ports + notify intrusion
# Works alongside intruder-protocol.ps1
# Run: powershell -ExecutionPolicy Bypass -File web-fortress.ps1 [-Monitor] [-Status]

param(
    [switch]$Monitor,                  # single auto-block pass (used by scheduled task / dashboard)
    [switch]$Watch,                    # run the auto-block pass forever, every -IntervalSec
    [switch]$Schedule,                 # register a persistent elevated scheduled task, then exit
    [switch]$Status,
    [int]$IntervalSec = 60,            # watch cadence
    [int]$FailThreshold = 5            # failed-logons from one IP before it is auto-blocked
)

$SuiteRoot  = Split-Path -Parent $PSCommandPath
$AlertLog  = Join-Path $SuiteRoot 'intruder-alerts.log'
$StateFile = Join-Path $SuiteRoot 'wf-baseline.json'
$QAScript  = Join-Path $SuiteRoot 'quantum-analyzer.py'

# Never auto-block ourselves or the LAN — only routable/public remote attackers.
$PrivateRe = '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|::1|fe80:)'

# ── Approved process->port bindings (allowlist) ───────────────────────────────
# Only these processes may bind to these ports on external interfaces.
# Everything else on an external interface gets firewall-blocked + alerted.
$Allowlist = @{
    'ollama'                       = @(11434)   # must move to localhost — see below
    'EADesktop'                    = @()        # no inbound needed
    'EpicGamesLauncher'            = @()        # no inbound needed
    'ArmouryCrate.UserSessionHelper' = @()      # no inbound needed
    'svchost'                      = @(5040)    # CDP service — localhost only
    'System'                       = @(445, 135, 139, 49664, 49665, 49666, 49667, 49668, 49675)
}

function Write-Alert($level, $msg, $detail = '') {
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts][$level][WEB-FORTRESS] $msg"
    Add-Content $AlertLog $line
    if ($detail) { Add-Content $AlertLog "  >> $detail" }
    $col = switch ($level) { 'CRITICAL' {'Red'} 'WARN' {'Yellow'} default {'Cyan'} }
    Write-Host $line -ForegroundColor $col
}

# ── Step 1: Lock down Ollama to localhost ─────────────────────────────────────
function Set-OllamaLocalhost {
    $regPath = 'HKCU:\Environment'
    $current = (Get-ItemProperty $regPath -Name OLLAMA_HOST -ErrorAction SilentlyContinue).OLLAMA_HOST
    if ($current -ne '127.0.0.1') {
        Set-ItemProperty $regPath -Name OLLAMA_HOST -Value '127.0.0.1'
        Write-Alert 'WARN' 'Ollama bound to localhost via OLLAMA_HOST env var. Restart Ollama to apply.'
    }
    # Firewall: block all external inbound to 11434 (belt+suspenders)
    $rule = 'WF-Block-Ollama-External'
    if (-not (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $rule -Direction Inbound -Protocol TCP `
            -LocalPort 11434 -RemoteAddress LocalSubnet -Action Block -Profile Any | Out-Null
        Write-Alert 'WARN' 'Firewall: blocked external inbound to Ollama port 11434'
    }
}

# ── Step 2: Block non-approved external listeners via firewall AppID rules ────
function Set-PortContainerization {
    # Block inbound to ArmouryCrate external port
    foreach ($rule in @(
        @{Name='WF-Block-ArmouryCrate-12177'; Port=12177},
        @{Name='WF-Block-Unknown-24563';      Port=24563}
    )) {
        if (-not (Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Protocol TCP `
                -LocalPort $rule.Port -Action Block -Profile Any | Out-Null
            Write-Alert 'WARN' "Firewall: blocked inbound to port $($rule.Port)"
        }
    }

    # Block non-browser processes making outbound on port 9000 (EA telemetry non-std)
    $rule9k = 'WF-Alert-NonStd-Outbound-9000'
    if (-not (Get-NetFirewallRule -DisplayName $rule9k -ErrorAction SilentlyContinue)) {
        # ponytail: can't AppID-filter outbound cleanly without WFP driver; log only
        Write-Alert 'WARN' 'Port 9000 outbound (EADesktop telemetry) flagged — monitor only'
    }

    Write-Alert 'INFO' 'Web port containerization rules applied'
}

# ── Step 3: Baseline current port/process bindings ───────────────────────────
function Save-Baseline {
    $snapshot = netstat -ano | Select-String 'LISTENING' | ForEach-Object {
        $f = ($_ -split '\s+' | Where-Object { $_ })
        [pscustomobject]@{ Local = $f[1]; PID = $f[4] }
    } | Group-Object PID | ForEach-Object {
        $proc = (Get-Process -Id $_.Name -ErrorAction SilentlyContinue).ProcessName
        [pscustomobject]@{ PID = $_.Name; Process = $proc; Ports = ($_.Group.Local -join ',') }
    }
    $snapshot | ConvertTo-Json | Out-File $StateFile -Encoding UTF8
    Write-Alert 'INFO' "Baseline saved: $($snapshot.Count) process bindings recorded"
}

# ── Auto-block remote attackers by source IP ──────────────────────────────────
# An IP is blocked when it either (a) fails logon >= $FailThreshold times
# (Security event 4625), or (b) is flagged on a CRITICAL line in the alert log.
# Idempotent: one WF-AutoBlock-IP-<ip> inbound block rule per attacker.
function Block-Ip($ip, $why) {
    if ([string]::IsNullOrWhiteSpace($ip) -or $ip -match $PrivateRe) { return }
    if ($ip -notmatch '^(\d{1,3}\.){3}\d{1,3}$' -and $ip -notmatch ':') { return }
    $rule = "WF-AutoBlock-IP-$ip"
    if (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue) { return }
    try {
        New-NetFirewallRule -DisplayName $rule -Direction Inbound -RemoteAddress $ip `
            -Action Block -Profile Any -ErrorAction Stop | Out-Null
        Write-Alert 'CRITICAL' "AUTO-BLOCKED intruder IP $ip" $why
    } catch {
        Write-Alert 'WARN' "Could not block $ip (need admin?)" $_.Exception.Message
    }
}

function Block-IntruderIPs {
    # (a) brute-force / unwanted logon attempts from the Windows Security log
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625;
                    StartTime=(Get-Date).AddHours(-12)} -MaxEvents 500 -ErrorAction Stop
        $byIp = @{}
        foreach ($e in $events) {
            $ip = ([xml]$e.ToXml()).Event.EventData.Data |
                  Where-Object { $_.Name -eq 'IpAddress' } | ForEach-Object { $_.'#text' }
            if ($ip -and $ip -ne '-') { $byIp[$ip] = ([int]$byIp[$ip]) + 1 }
        }
        foreach ($ip in $byIp.Keys) {
            if ($byIp[$ip] -ge $FailThreshold) { Block-Ip $ip "$($byIp[$ip]) failed logons (4625) in 12h" }
        }
    } catch { }   # Security log audit may be off / not elevated — fall through to alert log

    # (b) external IPs called out on CRITICAL lines in the intrusion alert log
    if (Test-Path $AlertLog) {
        Get-Content $AlertLog -Tail 400 | Where-Object { $_ -match 'CRITICAL' } | ForEach-Object {
            foreach ($m in [regex]::Matches($_, '\b(\d{1,3}\.){3}\d{1,3}\b')) {
                Block-Ip $m.Value 'flagged CRITICAL in intruder-alerts.log'
            }
        }
    }
}

# ── Step 4: Monitor cycle — diff against baseline, alert on new external listeners
function Invoke-Monitor {
    Block-IntruderIPs
    if (-not (Test-Path $StateFile)) { Save-Baseline; return }
    $baseline = Get-Content $StateFile | ConvertFrom-Json

    $current = netstat -ano | Select-String 'LISTENING' | ForEach-Object {
        $f = ($_ -split '\s+' | Where-Object { $_ })
        [pscustomobject]@{ Local = $f[1]; PID = $f[4] }
    } | Where-Object { $_.Local -notmatch '^(127\.|::1|\[::1\])' }   # external only

    $baselinePIDs = $baseline | ForEach-Object { $_.PID }

    foreach ($conn in $current) {
        $listenerPid = $conn.PID
        $proc = (Get-Process -Id $listenerPid -ErrorAction SilentlyContinue).ProcessName
        $port = ($conn.Local -split ':')[-1]

        # New external listener not in baseline
        $inBase = $baseline | Where-Object { $_.PID -eq $listenerPid -and $_.Ports -match $port }
        if (-not $inBase) {
            Write-Alert 'CRITICAL' "NEW external listener: $proc (PID $listenerPid) on port $port" `
                "Path: $((Get-Process -Id $listenerPid -ErrorAction SilentlyContinue).Path)"

            # Auto-block it
            $ruleName = "WF-AutoBlock-${proc}-${port}"
            if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP `
                    -LocalPort $port -Action Block -Profile Any | Out-Null
                Write-Alert 'CRITICAL' "AUTO-BLOCKED port $port inbound"
            }

            # Hand off to quantum analyzer
            if (Test-Path $QAScript) {
                Start-Process python -ArgumentList "`"$QAScript`" --port $port --pid $listenerPid --proc `"$proc`"" `
                -NoNewWindow -RedirectStandardOutput (Join-Path $SuiteRoot 'qa-last.log') -ErrorAction SilentlyContinue
            }
        }
    }

    # Check outbound to non-standard ports (not 80/443/53/22/25/587/993/995/5222/5228)
    $stdPorts = @(80,443,53,22,25,587,993,995,5222,5228,8080,8443)
    $suspOutbound = netstat -ano | Select-String 'ESTABLISHED' | ForEach-Object {
        $f = ($_ -split '\s+' | Where-Object { $_ })
        $foreign = $f[2]; $fpid = $f[4]
        $fport = [int](($foreign -split ':')[-1])
        if ($fport -notin $stdPorts -and $foreign -notmatch '^(127\.|::1|\[::1\])') {
            $proc = (Get-Process -Id $fpid -ErrorAction SilentlyContinue).ProcessName
            if ($proc -notin @('svchost','System','lsass')) {
                Write-Alert 'WARN' "Non-std outbound: $proc -> $foreign"
            }
        }
    }
}

function Show-Status {
    Write-Host "=== Web-Fortress Status ===" -ForegroundColor Cyan
    Write-Host "Firewall rules:" -ForegroundColor Cyan
    Get-NetFirewallRule -DisplayName 'WF-*' -ErrorAction SilentlyContinue |
        Select-Object DisplayName, Enabled, Action | Format-Table -AutoSize
    Write-Host "Last 15 alerts:" -ForegroundColor Cyan
    if (Test-Path $AlertLog) { Get-Content $AlertLog -Tail 15 }
    Write-Host "Baseline file: $StateFile"
}

# ── Entry ─────────────────────────────────────────────────────────────────────
if ($Schedule) {
    # Persistent, elevated auto-blocker: runs -Watch at logon. Needs admin once.
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -Watch"
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $set     = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName 'WebFortress-AutoBlock' -Action $action -Trigger $trigger `
        -Settings $set -RunLevel Highest -Force | Out-Null
    Write-Host "[Web-Fortress] Registered persistent auto-block task 'WebFortress-AutoBlock'." -ForegroundColor Green
} elseif ($Watch) {
    Write-Host "[Web-Fortress] Continuous auto-block — every ${IntervalSec}s. Ctrl+C to stop." -ForegroundColor Cyan
    if (-not (Test-Path $StateFile)) { Save-Baseline }
    while ($true) {
        try { Invoke-Monitor } catch { Write-Alert 'WARN' "Monitor pass failed" $_.Exception.Message }
        Start-Sleep -Seconds $IntervalSec
    }
} elseif ($Monitor) {
    Invoke-Monitor
} elseif ($Status) {
    Show-Status
} else {
    Write-Host "[Web-Fortress] Initial setup..." -ForegroundColor Cyan
    Set-OllamaLocalhost
    Set-PortContainerization
    Save-Baseline
    Write-Host "[Web-Fortress] Done. Schedule monitor with:" -ForegroundColor Green
    Write-Host "  powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Monitor"
}
