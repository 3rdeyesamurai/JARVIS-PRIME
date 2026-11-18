#!/usr/bin/env python3
"""
JARVIS PRIME — Intelligence-Response Bridge
Mission: Close the gap between the vector DB and active defense.

Every new threat detected:
  1. Parse threat from intruder-alerts.log
  2. Query vector DB for top-5 mitigations
  3. Apply Wolfram Rule-30 CA scramble to select response order (unpredictable)
  4. Execute selected mitigation
  5. If no good DB match (distance > NOVELTY_THRESHOLD): auto-generate + seed new script
  6. Amend DB — system learns every cycle

Run: python jarvis_prime.py [--once] [--dry-run]
"""

import os, sys, json, math, hashlib, time, subprocess, argparse, textwrap, threading
from datetime import datetime, timedelta
from pathlib import Path
from jarvis_config import (
    ALERT_LOG, REPORT_OUT, JARVIS_LOG, VECTOR_DB_DIR, VECTOR_DB_PY,
    RESPONSE_DIR, STATE_FILE, execution_policy,
)

# ── Paths ─────────────────────────────────────────────────────────────────────
NOVELTY_THRESHOLD = 0.80   # DB distance above this = novel threat, auto-generate
# ponytail: was 0.65 — port_exposure DB distances consistently land ~0.72 with all-MiniLM-L6-v2,
# causing every alert to generate a new script. 0.80 lets existing DB entries match.
POLL_INTERVAL     = 3.0      # seconds between log checks
TOP_N             = 8      # candidates to fetch from vector DB

# ── Runtime clock ─────────────────────────────────────────────────────────────
_START_TIME: datetime | None = None

def elapsed() -> str:
    if _START_TIME is None:
        return "00:00:00"
    delta = datetime.now() - _START_TIME
    h, rem = divmod(int(delta.total_seconds()), 3600)
    m, s   = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"

def _clock_tick(stop_event: threading.Event):
    """Prints a live clock line to stdout every second while running."""
    while not stop_event.is_set():
        sys.stdout.write(f"\r  [T]  Runtime: {elapsed()}  | Threats processed: {_clock_tick.threats}  | Amendments: {_clock_tick.amendments}  ")
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\n")

_clock_tick.threats    = 0
_clock_tick.amendments = 0

# ── Logger ────────────────────────────────────────────────────────────────────
def jlog(level: str, msg: str, detail: str = ""):
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rt   = elapsed()
    line = f"[{ts}][+{rt}][{level}][JARVIS-PRIME] {msg}"
    sys.stdout.write(f"\r{line}\n")
    sys.stdout.flush()
    with open(JARVIS_LOG, "a") as f:
        f.write(line + "\n")
        if detail:
            f.write(f"  >> {detail}\n")
    with open(ALERT_LOG, "a") as f:
        f.write(line + "\n")
        if detail:
            f.write(f"  >> {detail}\n")

# ── State (last-read log position + known threat hashes) ─────────────────────
def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {"log_offset": 0, "seen_hashes": [], "amendment_count": 0, "response_count": 0}

def save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")

# ── Threat Parser ─────────────────────────────────────────────────────────────
THREAT_SIGNATURES = {
    "brute_force"        : ["Brute force detected", "failed logins", "4625"],
    "new_admin"          : ["New user account", "Administrators group", "4728", "4732", "4720"],
    "new_service"        : ["New service installed", "7045"],
    "port_exposure"      : ["NEW external listener", "AUTO-BLOCKED port", "exposed"],
    "suspicious_outbound": ["Non-std outbound", "Unusual outbound", "non-standard port"],
    "high_entropy"       : ["Score", "ELEVATED", "CRITICAL", "Entropy", "chaos"],
}

def classify_threat(line: str) -> tuple[str, str]:
    """Returns (threat_type, query_string) for vector DB."""
    line_lower = line.lower()
    for ttype, keywords in THREAT_SIGNATURES.items():
        if any(k.lower() in line_lower for k in keywords):
            queries = {
                "brute_force"        : "block brute force SSH login attack firewall",
                "new_admin"          : "detect unauthorized admin account privilege escalation",
                "new_service"        : "detect malicious service persistence new service installed",
                "port_exposure"      : "block unexpected external listener port containerization",
                "suspicious_outbound": "block suspicious outbound connection non-standard port",
                "high_entropy"       : "harden Windows endpoint high threat score entropy",
            }
            return ttype, queries[ttype]
    return "unknown", "general Windows security hardening protective script"

def is_actionable(line: str) -> bool:
    return "[CRITICAL]" in line or "[WARN]" in line

# ── Scramble-diversity remix (mirrors scramble_diversity.wl) ──────────────────
# The base hash collapses identical threats inside one minute_bucket to ONE seed
# (measured: 12 scrambles / 2 unique). The bijective fmix32 avalanche + a
# per-event counter decorrelates repeats so the seed stream's entropy stays high.
# The salt is chosen by the Wolfram optimizer and cached in scramble-salt.json.
_SALT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scramble-salt.json")
_M32 = 1 << 32
_scramble_counter = 0

def _scramble_salt() -> int:
    try:
        return int(json.load(open(_SALT_FILE))["salt"], 16) & 0xFFFFFFFF
    except Exception:
        return 0x9E3779B1  # golden-ratio default until the optimizer runs

def _fmix32(h: int) -> int:
    h &= 0xFFFFFFFF
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h

def threat_hash(ttype: str, line: str) -> int:
    """Deterministic base hash, then diversity remix (bijective, lossless)."""
    global _scramble_counter
    minute_bucket = datetime.now().strftime("%Y%m%d%H%M")
    raw  = f"{ttype}|{line[:80]}|{minute_bucket}"
    seed = int(hashlib.sha256(raw.encode()).hexdigest()[:8], 16)
    i    = _scramble_counter
    _scramble_counter += 1
    salt = _scramble_salt()
    return _fmix32(((seed ^ ((salt * 2654435761 + i * 2654435761) % _M32)) + i) % _M32)

# ── Wolfram Rule-30 Scrambler (Python port of the Wolfram Language algorithm) ─
def rule30_step(cells: list) -> list:
    n = len(cells)
    return [(cells[(i-1)%n] ^ (cells[i] | cells[(i+1)%n])) for i in range(n)]

def wolfram_scramble(seed_hash: int, n: int) -> tuple[list, list]:
    """
    Returns (scramble_order, weights) using Rule-30 CA seeded with threat hash.
    Same algorithm verified by Wolfram Language Evaluator — densities drive weights.
    """
    bits = [(seed_hash >> i) & 1 for i in range(32)]
    grid = bits + [0] * 32          # 64-cell grid
    densities = []
    for _ in range(n):
        grid = rule30_step(grid)
        densities.append(sum(grid) / 64.0)

    weights = [math.exp(2.0 * d) for d in densities]
    total   = sum(weights)
    weights = [w / total for w in weights]

    # Weighted sampling without replacement
    remaining = list(range(n))
    order     = []
    rem_w     = list(weights)
    for _ in range(n):
        cum, r = 0.0, __import__('random').random() * sum(rem_w)
        for idx, w in zip(remaining, rem_w):
            cum += w
            if cum >= r:
                order.append(idx)
                pos = remaining.index(idx)
                remaining.pop(pos)
                rem_w.pop(pos)
                break

    return order, weights

# ── Vector DB Bridge ──────────────────────────────────────────────────────────
_collection = None

def get_collection():
    global _collection
    if _collection is not None:
        return _collection
    try:
        import chromadb
        from chromadb.utils import embedding_functions
        client = chromadb.PersistentClient(path=str(VECTOR_DB_DIR))
        ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
        try:
            _collection = client.get_collection("protective_scripts_v1", embedding_function=ef)
        except Exception:
            if not VECTOR_DB_PY.exists():
                raise RuntimeError(f"Vector DB bridge is missing: {VECTOR_DB_PY}")
            import importlib.util
            spec = importlib.util.spec_from_file_location("jarvis_vector_db", VECTOR_DB_PY)
            if not spec or not spec.loader:
                raise RuntimeError(f"Unable to load vector DB bridge: {VECTOR_DB_PY}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.initialize_vector_db()
            _collection = client.get_collection("protective_scripts_v1", embedding_function=ef)
        return _collection
    except Exception as e:
        jlog("WARN", f"Vector DB unavailable: {e}")
        return None

def query_db(query: str, n: int = TOP_N) -> list[dict]:
    """Returns list of {id, document, distance, metadata}."""
    col = get_collection()
    if not col:
        return []
    try:
        r = col.query(query_texts=[query], n_results=min(n, col.count()),
                      include=["documents", "metadatas", "distances"])
        results = []
        for i in range(len(r["ids"][0])):
            results.append({
                "id"       : r["ids"][0][i],
                "document" : r["documents"][0][i],
                "distance" : r["distances"][0][i],
                "metadata" : r["metadatas"][0][i],
            })
        return results
    except Exception as e:
        jlog("WARN", f"DB query failed: {e}")
        return []

def seed_to_db(script_id: str, document: str, metadata: dict):
    """Amend the vector DB with a newly generated mitigation."""
    global _collection
    col = get_collection()
    if not col:
        return False
    try:
        existing = col.get(ids=[script_id])
        if existing["ids"]:
            col.update(ids=[script_id], documents=[document], metadatas=[metadata])
            jlog("INFO", f"DB amended (updated): {script_id}")
        else:
            col.add(ids=[script_id], documents=[document], metadatas=[metadata])
            jlog("INFO", f"DB amended (new entry): {script_id}")
        _collection = None   # reset so next query re-opens with fresh data
        return True
    except Exception as e:
        jlog("WARN", f"DB seed failed: {e}")
        return False

# ── Auto-Research: Novel Threat Script Generator ──────────────────────────────
SCRIPT_TEMPLATES = {
    "brute_force": (
        "powershell",
        lambda ctx: textwrap.dedent(f"""
        # JARVIS PRIME Auto-Generated: Brute Force Response
        # Generated: {datetime.now().isoformat()}  Threat: {ctx}
        $ip = "{ctx.get('source_ip','UNKNOWN')}"
        $logPath = "$env:USERPROFILE\\intruder-alerts.log"
        # Block source IP
        $rule = "JARVIS-BruteBlock-$ip"
        if (-not (Get-NetFirewallRule -DisplayName $rule -EA SilentlyContinue)) {{
            New-NetFirewallRule -DisplayName $rule -Direction Inbound -Action Block -RemoteAddress $ip -Protocol Any | Out-Null
            Add-Content $logPath "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')][CRITICAL][JARVIS-PRIME] AUTO-BLOCKED brute force IP: $ip"
        }}
        # Increase audit granularity
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
        Write-Host "[JARVIS] Brute force containment applied for $ip"
        """).strip()
    ),
    "new_admin": (
        "powershell",
        lambda ctx: textwrap.dedent(f"""
        # JARVIS PRIME Auto-Generated: Privilege Escalation Response
        # Generated: {datetime.now().isoformat()}
        $logPath = "$env:USERPROFILE\\intruder-alerts.log"
        $admins = Get-LocalGroupMember -Group "Administrators" -EA SilentlyContinue
        $admins | ForEach-Object {{
            $name = $_.Name
            Add-Content $logPath "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')][WARN][JARVIS-PRIME] Admin account present: $name"
        }}
        # Snapshot current privileged state for forensics
        $out = "$env:USERPROFILE\\jarvis-admin-snapshot-$(Get-Date -f yyyyMMdd_HHmmss).json"
        $admins | ConvertTo-Json | Out-File $out
        Write-Host "[JARVIS] Admin snapshot saved: $out"
        """).strip()
    ),
    "new_service": (
        "powershell",
        lambda ctx: textwrap.dedent(f"""
        # JARVIS PRIME Auto-Generated: Malicious Service Response
        # Generated: {datetime.now().isoformat()}
        $logPath = "$env:USERPROFILE\\intruder-alerts.log"
        $recent = Get-WinEvent -FilterHashtable @{{LogName='System';Id=7045;StartTime=(Get-Date).AddMinutes(-5)}} -EA SilentlyContinue
        foreach ($ev in $recent) {{
            $svcName = ($ev.Message | Select-String 'Service Name:\\s+(\\S+)').Matches.Groups[1].Value
            if ($svcName) {{
                $svc = Get-Service -Name $svcName -EA SilentlyContinue
                if ($svc -and $svc.StartType -ne 'Disabled') {{
                    Stop-Service $svcName -Force -EA SilentlyContinue
                    Set-Service $svcName -StartupType Disabled -EA SilentlyContinue
                    Add-Content $logPath "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')][CRITICAL][JARVIS-PRIME] DISABLED suspicious service: $svcName"
                }}
            }}
        }}
        """).strip()
    ),
    "port_exposure": (
        "powershell",
        lambda ctx: textwrap.dedent(f"""
        # JARVIS PRIME Auto-Generated: Port Exposure Containment
        # Generated: {datetime.now().isoformat()}
        $logPath = "$env:USERPROFILE\\intruder-alerts.log"
        $exposed = netstat -ano | Select-String 'LISTENING' | ForEach-Object {{
            $f = ($_ -split '\\s+' | Where-Object {{$_}})
            [pscustomobject]@{{ Local=$f[1]; PID=$f[4] }}
        }} | Where-Object {{ $_.Local -notmatch '^(127\\.|\\[::1\\])' }}
        foreach ($conn in $exposed) {{
            $port = ($conn.Local -split ':')[-1]
            $proc = (Get-Process -Id $conn.PID -EA SilentlyContinue).ProcessName
            $rule = "JARVIS-PortBlock-$port"
            if (-not (Get-NetFirewallRule -DisplayName $rule -EA SilentlyContinue)) {{
                New-NetFirewallRule -DisplayName $rule -Direction Inbound -Protocol TCP -LocalPort $port -Action Block | Out-Null
                Add-Content $logPath "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')][WARN][JARVIS-PRIME] Auto-contained port $port ($proc)"
            }}
        }}
        """).strip()
    ),
    "suspicious_outbound": (
        "powershell",
        lambda ctx: textwrap.dedent(f"""
        # JARVIS PRIME Auto-Generated: Suspicious Outbound Containment
        # Generated: {datetime.now().isoformat()}
        $logPath = "$env:USERPROFILE\\intruder-alerts.log"
        $stdPorts = @(80,443,53,22,25,587,993,995,5222,5228,8080,8443)
        netstat -ano | Select-String 'ESTABLISHED' | ForEach-Object {{
            $f = ($_ -split '\\s+' | Where-Object {{$_}})
            $foreign = $f[2]; $pid_ = $f[4]
            $fport = [int](($foreign -split ':')[-1])
            if ($fport -notin $stdPorts -and $foreign -notmatch '^(127\\.|\\[::1\\])') {{
                $proc = (Get-Process -Id $pid_ -EA SilentlyContinue).ProcessName
                if ($proc -and $proc -notin @('svchost','System','lsass','MsMpEng')) {{
                    Add-Content $logPath "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')][WARN][JARVIS-PRIME] Flagged: $proc -> $foreign"
                    $rule = "JARVIS-OutBlock-$proc-$fport"
                    if (-not (Get-NetFirewallRule -DisplayName $rule -EA SilentlyContinue)) {{
                        New-NetFirewallRule -DisplayName $rule -Direction Outbound -Protocol TCP -RemotePort $fport -Action Block | Out-Null
                    }}
                }}
            }}
        }}
        """).strip()
    ),
    "high_entropy": (
        "python",
        lambda ctx: textwrap.dedent(f"""
        #!/usr/bin/env python3
        # JARVIS PRIME Auto-Generated: High-Entropy Lockdown
        # Generated: {datetime.now().isoformat()}
        import subprocess, json, os
        from pathlib import Path
        from datetime import datetime

        log = Path.home() / "intruder-alerts.log"
        ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        def alert(msg):
            line = f"[{{ts}}][CRITICAL][JARVIS-PRIME] {{msg}}"
            print(line)
            with open(log, "a") as f: f.write(line + "\\n")

        # Re-run quantum analyzer for fresh score
        result = subprocess.run(["python", str(Path.home() / "quantum-analyzer.py")],
                                capture_output=True, text=True, timeout=30)
        report_path = Path.home() / "quantum-report.json"
        if report_path.exists():
            report = json.loads(report_path.read_text())
            score = report.get("score", 0)
            alert(f"High-entropy lockdown triggered. Score={{score}}/10")
            if score >= 8:
                # Emergency: block all non-standard inbound
                alert("SCORE>=8: Activating emergency inbound block on non-standard ports")
                subprocess.run(["powershell", "-NoProfile", "-Command",
                    "New-NetFirewallRule -DisplayName 'JARVIS-Emergency-Block' "
                    "-Direction Inbound -Action Block -Protocol TCP "
                    "-LocalPort 1024-65535 -Profile Any -EA SilentlyContinue"],
                    capture_output=True)
        """).strip()
    ),
}

def generate_novel_script(ttype: str, context: dict, script_id: str) -> tuple[str, dict]:
    """Generate a new mitigation script for an unrecognized threat type."""
    kind = ttype if ttype in SCRIPT_TEMPLATES else "high_entropy"
    lang, builder = SCRIPT_TEMPLATES[kind]
    script_body   = builder(context)

    # Write to disk
    ext  = ".ps1" if lang == "powershell" else ".py"
    path = RESPONSE_DIR / f"{script_id}{ext}"
    path.write_text(script_body, encoding="utf-8")

    # DB document — include query text so semantic search finds it next time
    queries = {
        "brute_force"        : "block brute force SSH login attack firewall",
        "new_admin"          : "detect unauthorized admin account privilege escalation",
        "new_service"        : "detect malicious service persistence new service installed",
        "port_exposure"      : "block unexpected external listener port containerization",
        "suspicious_outbound": "block suspicious outbound connection non-standard port",
        "high_entropy"       : "harden Windows endpoint high threat score entropy",
    }
    query_hint = queries.get(ttype, "general Windows security hardening protective script")
    doc = (f"# JARVIS PRIME Auto-Research Script\n"
           f"# Threat type: {ttype}\n"
           f"# Query: {query_hint}\n"
           f"# Generated: {datetime.now().isoformat()}\n\n"
           + script_body)

    meta = {
        "asset_category" : "2. Software & Application Assets - Security Tools (EDR, Antivirus, Firewalls)",
        "os"             : "Windows 11",
        "script_type"    : "Auto-Generated Response",
        "complexity"     : "Intermediate",
        "threat_type"    : ttype,
        "risk_reduction" : "High - auto-generated containment",
        "last_updated"   : datetime.now().strftime("%Y-%m-%d"),
        "source"         : "JARVIS-PRIME Auto-Research",
        "script_path"    : str(path),
    }
    return str(path), meta, doc

# ── Response Executor ─────────────────────────────────────────────────────────
def resolve_response_path(path: str | None) -> str | None:
    """Resolve stale/absolute response paths into the bundled response directory."""
    if not path:
        return None

    candidate = Path(path)
    bundled = RESPONSE_DIR / candidate.name
    if candidate.name and bundled.exists():
        candidate = bundled.resolve()
    elif candidate.suffix.lower() == ".py":
        sh_candidate = RESPONSE_DIR / f"{candidate.stem}.sh"
        ps1_candidate = RESPONSE_DIR / f"{candidate.stem}.ps1"
        if sh_candidate.exists():
            candidate = sh_candidate.resolve()
        elif ps1_candidate.exists():
            candidate = ps1_candidate.resolve()
        elif candidate.exists():
            candidate = candidate.resolve()
        else:
            return None
    elif candidate.exists():
        candidate = candidate.resolve()
    else:
        return None

    if candidate.suffix.lower() == ".py":
        try:
            body = candidate.read_text(encoding="utf-8")[:500]
        except OSError:
            body = ""
        if body.startswith("#!/bin/bash") or body.startswith("#!/bin/sh"):
            normalized = candidate.with_suffix(".sh")
            normalized.write_text(candidate.read_text(encoding="utf-8"), encoding="utf-8")
            return str(normalized)
        if "Write-Host" in body or body.lstrip().startswith("# Cross-Platform"):
            normalized = candidate.with_suffix(".ps1")
            normalized.write_text(candidate.read_text(encoding="utf-8"), encoding="utf-8")
            return str(normalized)
    if candidate.suffix.lower() in {".ps1", ".sh"}:
        return str(candidate)
    return None


def execute_script(path: str, dry_run: bool = False) -> str:
    """Run a .ps1 or .py script and return output."""
    policy = execution_policy()
    if dry_run or policy["mode"] == "review_dry_run" or not policy["allow_live"]:
        jlog("INFO", f"[DRY-RUN] Would execute: {path}")
        return "[dry-run]"
    try:
        if path.lower().endswith(".ps1"):
            cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path]
        elif path.lower().endswith(".sh"):
            cmd = ["bash", path]
        else:
            cmd = ["python", path]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return (r.stdout + r.stderr).strip()[:500]
    except (OSError, subprocess.SubprocessError) as e:
        jlog("ERROR", f"Response execution failed: {path}", str(e))
        return f"execution error: {e}"

# ── Core Mission Loop ─────────────────────────────────────────────────────────
def process_threat(line: str, state: dict, dry_run: bool):
    ttype, query = classify_threat(line)
    seed         = threat_hash(ttype, line)

    jlog("INFO", f"Threat classified: [{ttype}]", f"Line: {line[:120]}")

    # ── Step 1: Query vector DB ────────────────────────────────────────────────
    candidates = query_db(query, TOP_N)
    if not candidates:
        jlog("WARN", "Vector DB returned no results — using template fallback")

    # ── Step 2: Wolfram Rule-30 scramble ───────────────────────────────────────
    n_cands = max(len(candidates), 1)
    order, weights = wolfram_scramble(seed, n_cands)

    jlog("INFO",
         f"Wolfram scramble applied (seed=0x{seed:08X})",
         f"Selection order: {order} | Weights: {[round(w,3) for w in weights]}")

    # ── Step 3: Check best candidate distance ──────────────────────────────────
    best_dist   = candidates[0]["distance"] if candidates else 1.0
    is_novel    = best_dist > NOVELTY_THRESHOLD
    script_path = None
    executed_id = None

    if is_novel:
        # ── Step 4a: Novel threat — auto-research & amend DB ──────────────────
        ts_tag    = datetime.now().strftime("%Y%m%d_%H%M%S")
        script_id = f"jarvis_auto_{ttype}_{ts_tag}"
        ctx       = {"threat_type": ttype, "source_ip": "UNKNOWN", "line": line[:100]}

        script_path, meta, doc = generate_novel_script(ttype, ctx, script_id)

        jlog("CRITICAL",
             f"NOVEL THREAT — auto-researching [{ttype}] (best dist={best_dist:.3f})",
             f"Generated script: {script_path}")

        if seed_to_db(script_id, doc, meta):
            state["amendment_count"] += 1
            jlog("INFO", f"DB amended #{state['amendment_count']} — {script_id}")

        executed_id = script_id

    else:
        # ── Step 4b: Known threat — execute scrambled DB selection ────────────
        scrambled_candidates = [candidates[i] for i in order if i < len(candidates)]
        chosen     = scrambled_candidates[0]
        script_id  = chosen["id"]
        script_path = resolve_response_path(chosen["metadata"].get("script_path"))

        jlog("INFO",
             f"DB match: [{script_id}] dist={chosen['distance']:.3f} (scramble slot {order[0]})",
             f"Category: {chosen['metadata'].get('asset_category','?')}")

        # If DB match has no script path, write the document as a temp script
        if not script_path:
            ext = ".ps1" if "PowerShell" in chosen["document"][:200] or "Write-Host" in chosen["document"][:200] else ".py"
            script_path = str(RESPONSE_DIR / f"{script_id}{ext}")
            Path(script_path).write_text(chosen["document"], encoding="utf-8")

        executed_id = script_id

    # ── Step 5: Execute ────────────────────────────────────────────────────────
    if script_path:
        jlog("INFO", f"Executing response: {Path(script_path).name}")
        output = execute_script(script_path, dry_run)
        state["response_count"] += 1
        jlog("INFO",
             f"Response #{state['response_count']} complete: {executed_id}",
             output[:300] if output else "(no output)")

def watch_log(dry_run: bool):
    """Tail intruder-alerts.log, process new actionable lines."""
    global _START_TIME
    _START_TIME = datetime.now()
    state = load_state()

    stop_clock = threading.Event()
    clock_thread = threading.Thread(target=_clock_tick, args=(stop_clock,), daemon=True)
    clock_thread.start()

    jlog("INFO", f"JARVIS PRIME online. Watching: {ALERT_LOG}")
    jlog("INFO", f"Mode: {'DRY-RUN' if dry_run else 'LIVE'} | DB: {VECTOR_DB_DIR.name} | Offset: {state['log_offset']}")

    while True:
        try:
            if ALERT_LOG.exists():
                with open(ALERT_LOG, encoding="utf-8", errors="ignore") as f:
                    f.seek(state["log_offset"])
                    new_lines = f.readlines()
                    state["log_offset"] = f.tell()

                for line in new_lines:
                    line = line.strip()
                    if not line or "[JARVIS-PRIME]" in line:
                        continue

                    if is_actionable(line):
                        h = hashlib.md5(line.encode()).hexdigest()
                        if h in state["seen_hashes"]:
                            continue
                        state["seen_hashes"].append(h)
                        if len(state["seen_hashes"]) > 500:
                            state["seen_hashes"] = state["seen_hashes"][-200:]

                        process_threat(line, state, dry_run)
                        _clock_tick.threats    = state["response_count"]
                        _clock_tick.amendments = state["amendment_count"]
                        save_state(state)

            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            stop_clock.set()
            jlog("INFO",
                 f"JARVIS PRIME offline after {elapsed()}",
                 f"Amendments: {state['amendment_count']} | Responses: {state['response_count']}")
            save_state(state)
            break
        except Exception as e:
            jlog("WARN", f"Loop error: {e}")
            time.sleep(POLL_INTERVAL)

def run_once(dry_run: bool):
    """Process all current unread alerts then exit — for cron/task use."""
    global _START_TIME
    _START_TIME = datetime.now()
    state = load_state()

    if not ALERT_LOG.exists():
        jlog("WARN", "No alert log found. Run intruder-protocol.ps1 -Monitor or quantum-analyzer.py first.")
        return
    with open(ALERT_LOG, encoding="utf-8", errors="ignore") as f:
        f.seek(state["log_offset"])
        lines = f.readlines()
        state["log_offset"] = f.tell()

    processed = 0
    for line in lines:
        line = line.strip()
        if not line or "[JARVIS-PRIME]" in line:
            continue
        if is_actionable(line):
            h = hashlib.md5(line.encode()).hexdigest()
            if h not in state["seen_hashes"]:
                state["seen_hashes"].append(h)
                process_threat(line, state, dry_run)
                processed += 1

    jlog("INFO",
         f"One-shot complete in {elapsed()}",
         f"Processed: {processed} | Amendments: {state['amendment_count']} | Responses: {state['response_count']}")
    save_state(state)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="JARVIS PRIME — Intelligence-Response Bridge")
    ap.add_argument("--once",    action="store_true", help="Process current log and exit")
    ap.add_argument("--dry-run", action="store_true", help="Classify and plan but do not execute scripts")
    args = ap.parse_args()

    _start = datetime.now()
    print("=" * 64)
    print("  JARVIS PRIME — Intelligence-Response Bridge")
    print(f"  Started : {_start.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Mode    : {'one-shot' if args.once else 'daemon (Ctrl-C to stop)'}")
    print(f"  Dry-run : {args.dry_run}")
    print("=" * 64)

    if args.once:
        run_once(args.dry_run)
    else:
        watch_log(args.dry_run)
