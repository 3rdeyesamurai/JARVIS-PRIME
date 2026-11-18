# JARVIS PRIME Auto-Generated: Port Exposure Containment
# Generated: 2026-06-25T07:32:58.905236
$logPath = "$env:USERPROFILE\intruder-alerts.log"
$exposed = netstat -ano | Select-String 'LISTENING' | ForEach-Object {
    $f = ($_ -split '\s+' | Where-Object {$_})
    [pscustomobject]@{ Local=$f[1]; PID=$f[4] }
} | Where-Object { $_.Local -notmatch '^(127\.|\[::1\])' }
foreach ($conn in $exposed) {
    $port = ($conn.Local -split ':')[-1]
    $proc = (Get-Process -Id $conn.PID -EA SilentlyContinue).ProcessName
    $rule = "JARVIS-PortBlock-$port"
    if (-not (Get-NetFirewallRule -DisplayName $rule -EA SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $rule -Direction Inbound -Protocol TCP -LocalPort $port -Action Block | Out-Null
        Add-Content $logPath "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')][WARN][JARVIS-PRIME] Auto-contained port $port ($proc)"
    }
}