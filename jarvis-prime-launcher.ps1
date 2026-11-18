<#
.SYNOPSIS
  JARVIS PRIME - Unified Launcher (full security suite)
  Runs non-elevated; firewall-dependent components (web-fortress, intruder)
  apply their rules only when launched from an elevated shell.

.PARAMETER Silent
  Run all components hidden (for Task Scheduler / startup use).

.PARAMETER Install
  Register as a Windows startup task and exit.

.PARAMETER Stop
  Kill all running JARVIS components and exit.
#>
param(
    [switch]$Silent,
    [switch]$Install,
    [switch]$Stop
)

$HOME_DIR  = Split-Path -Parent $PSCommandPath
$PYTHON    = (Get-Command python -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $PYTHON) { $PYTHON = "python" }
if ($PYTHON -ne "python") {
    & $PYTHON -c "import psutil, chromadb, sentence_transformers" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[JARVIS] Missing Python dependencies. Install psutil, chromadb, and sentence-transformers."
        exit 1
    }
}

$COMPONENTS = @(
    @{ Name = "WEB-FORTRESS";  Type = "ps1"; Script = "$HOME_DIR\web-fortress.ps1";                                       Delay = 0 },
    @{ Name = "INTRUDER";      Type = "ps1"; Script = "$HOME_DIR\intruder-protocol.ps1";                                  Delay = 1 },
    @{ Name = "DASHBOARD";     Type = "py";  Script = "$HOME_DIR\security-dashboard.py";                                  Delay = 1 },
    @{ Name = "SEARCH-GUARD";  Type = "py";  Script = "$HOME_DIR\search_guardian.py";                                     Delay = 2 },
    @{ Name = "QUANTUM";       Type = "py";  Script = "$HOME_DIR\quantum-analyzer.py";                                    Delay = 2 },
    @{ Name = "JARVIS-PRIME";  Type = "py";  Script = "$HOME_DIR\jarvis_prime.py";                                        Delay = 3 }
)

$PID_FILE  = "$HOME_DIR\jarvis-prime.pids"
$WIN_STYLE = if ($Silent) { "Hidden" } else { "Minimized" }

# ── Stop ────────────────────────────────────────────────────────────────────────
if ($Stop) {
    if (Test-Path $PID_FILE) {
        Get-Content $PID_FILE | ForEach-Object {
            $pid_ = [int]$_
            $p = Get-Process -Id $pid_ -ErrorAction SilentlyContinue
            if ($p) {
                Stop-Process -Id $pid_ -Force
                Write-Host "[JARVIS] Stopped $($p.ProcessName) (PID $pid_)"
            }
        }
        Remove-Item $PID_FILE -Force
    } else {
        # Fallback: kill by script name
        Get-WmiObject Win32_Process | Where-Object {
            $_.CommandLine -match 'jarvis_prime|security.dashboard|security_research_loop|web-fortress|intruder-protocol|search_guardian|quantum-analyzer'
        } | ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
            Write-Host "[JARVIS] Stopped PID $($_.ProcessId)"
        }
    }
    Write-Host "[JARVIS] All components stopped."
    exit 0
}

# ── Install as startup task ──────────────────────────────────────────────────────
if ($Install) {
    $TaskName = "JARVIS-PRIME-Startup"
    $Launcher = "$HOME_DIR\jarvis-prime-launcher.ps1"
    $Action   = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Launcher`" -Silent"
    $Trigger  = New-ScheduledTaskTrigger -AtLogOn
    $Settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable:$false -MultipleInstances IgnoreNew
    $Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest

    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
        -Settings $Settings -Principal $Principal -Force | Out-Null
    Write-Host "[JARVIS] Startup task '$TaskName' registered. Starts at next logon as Admin."
    exit 0
}

# ── Launch ──────────────────────────────────────────────────────────────────────
Write-Host ("=" * 60)
Write-Host "  JARVIS PRIME - LAUNCHING ALL COMPONENTS"
Write-Host ("  " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
Write-Host ("=" * 60)

$pids = @()
foreach ($comp in $COMPONENTS) {
    if ($comp.Delay -gt 0) { Start-Sleep $comp.Delay }
    if (-not (Test-Path $comp.Script)) {
        Write-Host "[WARN] Missing: $($comp.Script) - skipping $($comp.Name)"
        continue
    }
    if ($comp.Type -eq "ps1") {
        $proc = Start-Process -FilePath "powershell.exe" `
            -ArgumentList "-ExecutionPolicy Bypass -File `"$($comp.Script)`"" `
            -WindowStyle $WIN_STYLE -PassThru
    } else {
        $proc = Start-Process -FilePath $PYTHON `
            -ArgumentList "-u `"$($comp.Script)`"" `
            -WindowStyle $WIN_STYLE -PassThru
    }
    $pids += $proc.Id
    Write-Host "[JARVIS] $($comp.Name) started - PID $($proc.Id)"
}

$pids | Set-Content $PID_FILE

Write-Host ""
Write-Host "  Dashboard : http://localhost:8765"
Write-Host "  PIDs      : $($pids -join ', ')"
Write-Host "  PID file  : $PID_FILE"
Write-Host ""

if (-not $Silent) {
    Write-Host "  Press ENTER to stop all components, or close this window to keep them running."
    Read-Host | Out-Null
    & "$HOME_DIR\jarvis-prime-launcher.ps1" -Stop
}
