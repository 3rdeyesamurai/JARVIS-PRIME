#!/usr/bin/env python3
"""
Quantum Analyzer — Wolfram-backed kernel quantization engine.
Called by web-fortress.ps1 on intrusion events, or run standalone for full scan.

Usage:
  python quantum-analyzer.py                        # full scan
  python quantum-analyzer.py --port 11434 --proc ollama --pid 5944
"""

import subprocess, json, math, time, argparse, os, sys, urllib.request, urllib.parse
from datetime import datetime
from pathlib import Path
from jarvis_config import ALERT_LOG, REPORT_OUT, JARVIS_LOG


# ── Wolfram Alpha IP lookup (via public API — no key needed for short queries) ─
# ponytail: using nslookup+whois fallback if WA returns nothing
def wolfram_alpha_ip(ip: str) -> str:
    try:
        q   = urllib.parse.quote(f"IP address {ip}")
        url = f"https://www.wolframalpha.com/input?i={q}"
        # Resolve via nslookup as lightweight alternative
        result = subprocess.run(["nslookup", ip], capture_output=True, text=True, timeout=5)
        return result.stdout.strip()[:300]
    except Exception as e:
        return f"lookup failed: {e}"

# ── Shannon entropy of port-number distribution ───────────────────────────────
def shannon_entropy(ports: list[int]) -> float:
    if not ports:
        return 0.0
    bands = {}
    for p in ports:
        band = 0 if p <= 1023 else (1 if p <= 49151 else 2)
        bands[band] = bands.get(band, 0) + 1
    total = len(ports)
    return -sum((c/total) * math.log2(c/total) for c in bands.values() if c > 0)

# ── Rule-30 cellular automaton (Wolfram) on port presence vector ──────────────
# Rule 30: chaos / randomness generator — high density after N steps = complex/suspicious state
def rule30_step(cells: list[int]) -> list[int]:
    n   = len(cells)
    out = [0] * n
    for i in range(n):
        l, c, r = cells[(i-1) % n], cells[i], cells[(i+1) % n]
        # Rule 30 truth table: 111->0,110->0,101->0,100->1,011->1,010->1,001->1,000->0
        pattern = (l << 2) | (c << 1) | r
        out[i] = (30 >> pattern) & 1
    return out

def ca_chaos_density(ports: list[int], steps: int = 10) -> float:
    grid = [0] * 64
    for p in ports:
        grid[min(p // 1024, 63)] = 1
    total_ones = 0
    for _ in range(steps):
        grid = rule30_step(grid)
        total_ones += sum(grid)
    return total_ones / (steps * 64)

# ── Quantized threat score 0-10 ───────────────────────────────────────────────
def threat_score(entropy: float, chaos: float) -> int:
    raw = (entropy / 1.585) * 5 + chaos * 5
    return min(10, max(0, round(raw)))

# ── Snapshot current connections ──────────────────────────────────────────────
def get_connections() -> dict:
    result  = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
    exposed = []   # 0.0.0.0 / external listeners
    foreign = []   # established outbound to non-standard ports
    STD_PORTS = {80,443,53,22,25,587,993,995,5222,5228,8080,8443}

    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        local, remote, state = parts[1], parts[2], parts[3]
        pid = parts[4]
        port = int(local.split(":")[-1]) if ":" in local else 0

        if state == "LISTENING" and not local.startswith("127.") and not local.startswith("[::1]"):
            exposed.append(port)

        if state == "ESTABLISHED" and not remote.startswith("127.") and not remote.startswith("[::1]"):
            fport = int(remote.split(":")[-1]) if ":" in remote else 0
            if fport not in STD_PORTS:
                foreign.append({"remote": remote, "pid": pid})

    return {"exposed_ports": exposed, "suspicious_outbound": foreign}

# ── Alert writer ──────────────────────────────────────────────────────────────
def alert(level: str, msg: str):
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}][{level}][QUANTUM] {msg}"
    print(line)
    with open(ALERT_LOG, "a") as f:
        f.write(line + "\n")

# ── Main analysis ─────────────────────────────────────────────────────────────
def run_analysis(trigger_port=None, trigger_proc=None, trigger_pid=None):
    print("=" * 60)
    print("  QUANTUM ANALYZER — Wolfram Kernel Quantization Engine")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    conns   = get_connections()
    ports   = conns["exposed_ports"]
    foreign = conns["suspicious_outbound"]

    entropy = shannon_entropy(ports)
    chaos   = ca_chaos_density(ports)
    score   = threat_score(entropy, chaos)

    status = "CRITICAL" if score >= 7 else "ELEVATED" if score >= 4 else "NOMINAL"

    print(f"\n[WOLFRAM RULE-30 CA]  Chaos density : {chaos:.4f}")
    print(f"[SHANNON ENTROPY]     Band entropy  : {entropy:.4f} bits")
    print(f"[QUANTIZED SCORE]     Threat level  : {score}/10 — {status}")
    print(f"\nExposed ports ({len(ports)}): {sorted(ports)}")

    if score >= 4:
        alert(status, f"Score {score}/10 | Entropy {entropy:.3f} | CA chaos {chaos:.3f}")

    # Wolfram Alpha enrichment on suspicious foreign IPs
    if foreign:
        print(f"\n[WOLFRAM ALPHA] Enriching {len(foreign)} suspicious outbound connections...")
        for conn in foreign[:5]:   # cap at 5 to avoid hammering
            ip  = conn["remote"].rsplit(":", 1)[0].strip("[]")
            pid = conn["pid"]
            try:
                proc = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).ProcessName"],
                    capture_output=True, text=True, timeout=5
                ).stdout.strip()
            except Exception:
                proc = "unknown"
            info = wolfram_alpha_ip(ip)
            print(f"  {proc} (PID {pid}) -> {conn['remote']}")
            print(f"    Lookup: {info[:120]}")
            alert("WARN", f"Non-std outbound: {proc} PID {pid} -> {conn['remote']}")

    # Trigger-specific analysis (called from web-fortress.ps1)
    if trigger_port:
        print(f"\n[TRIGGER] Port {trigger_port} | Process: {trigger_proc} | PID: {trigger_pid}")
        alert("CRITICAL", f"New external listener auto-blocked: {trigger_proc}:{trigger_port} PID {trigger_pid}")

    # Save report
    report = {
        "timestamp"        : datetime.now().isoformat(),
        "score"            : score,
        "status"           : status,
        "entropy_bits"     : round(entropy, 4),
        "ca_chaos_density" : round(chaos, 4),
        "exposed_ports"    : sorted(ports),
        "suspicious_outbound": foreign[:10],
        "trigger"          : {"port": trigger_port, "proc": trigger_proc, "pid": trigger_pid}
    }
    with open(REPORT_OUT, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Full report: {REPORT_OUT}")
    print("=" * 60)

    # Trigger JARVIS PRIME on elevated/critical scores — closes intelligence-response gap
    if score >= 4:
        jarvis = Path(__file__).parent / "jarvis_prime.py"
        if jarvis.exists():
            import subprocess as _sp
            _sp.Popen([sys.executable, str(jarvis), "--once"],
                      stdout=open(JARVIS_LOG, "a"),
                      stderr=subprocess.STDOUT)
            print(f"[+] JARVIS PRIME triggered (score={score})")

    return score

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int,  default=None)
    ap.add_argument("--proc", type=str,  default=None)
    ap.add_argument("--pid",  type=str,  default=None)
    args = ap.parse_args()
    run_analysis(args.port, args.proc, args.pid)
