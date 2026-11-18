#!/usr/bin/env python3
"""
Security Dashboard v2 — Real-time kernel I/O monitor + security tool control.
Serves on http://localhost:8765  |  SSE stream: /api/stream
"""

import http.server, json, os, sys, subprocess, threading, webbrowser, time, collections, re, sqlite3, signal, socket
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from pathlib import Path
import psutil
from jarvis_config import (
    BASE_DIR, ALERT_LOG, REPORT_OUT, PIPELINE_LOG, MEMORY_DB, IO_DB,
    dashboard_token,
)

# ── Single-instance guard — kill any stale dashboard on port 8765 ─────────────
_PID_FILE = BASE_DIR / "runtime" / ".jarvis-dashboard.pid"

def _kill_stale():
    """Kill any Python processes already listening on port 8765."""
    killed = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if getattr(c.laddr, "port", None) == 8765 and c.status in ("LISTEN",""):
                if c.pid and c.pid != os.getpid():
                    try:
                        p = psutil.Process(c.pid)
                        if "python" in (p.name() or "").lower():
                            p.terminate()
                            killed.append(c.pid)
                    except Exception:
                        pass
    except Exception:
        pass
    if killed:
        time.sleep(0.8)   # give them time to close
    return killed

_stale_pids = _kill_stale()
_PID_FILE.write_text(str(os.getpid()))

# ── Pipeline transmission log — JSON chain map of every SSE hop ───────────────
_PIPELINE_LOG_PATH = PIPELINE_LOG
_pipeline_stats: dict = {
    "server_pid"        : os.getpid(),
    "port"              : 8765,
    "stale_killed"      : _stale_pids,
    "started"           : datetime.now().isoformat(timespec="seconds"),
    "hops": {
        "0_kernel_collect": {
            "id": "KERNEL_COLLECT",
            "name": "KernelMonitor._collect()",
            "role": "source",
            "trigger": "1.0s daemon thread",
            "outputs": ["io_event", "proc_table"],
            "tick_count"  : 0,
            "last_tick_ts": None,
            "error_count" : 0,
        },
        "1_push_to_queues": {
            "id": "PUSH_TO_QUEUES",
            "name": "KernelMonitor._push()",
            "role": "fan-out",
            "outputs": "deque[maxlen=200] per subscriber",
            "push_count"       : 0,
            "last_push_ts"     : None,
            "subscriber_count" : 0,
            "dropped_count"    : 0,
        },
        "2_sse_handler": {
            "id": "SSE_HANDLER",
            "name": "Handler.do_GET(/api/stream)",
            "role": "stream",
            "reads_from"      : "deque",
            "writes_to"       : "HTTP 1.0 chunked text/event-stream",
            "active_conn"     : 0,
            "total_conn"      : 0,
            "total_bytes_sent": 0,
            "last_send_ts"    : None,
            "disconnect_count": 0,
        },
        "3_browser_sse": {
            "id": "BROWSER_SSE",
            "name": "EventSource('/api/stream')",
            "role": "sink",
            "listens_for": ["proc_table", "io_event"],
            "note": "Browser-side; polled via /api/pipeline-log",
        },
    },
}
_pipeline_lock = threading.Lock()

def _pl_update(hop_key: str, **kwargs):
    with _pipeline_lock:
        hop = _pipeline_stats["hops"].get(hop_key, {})
        hop.update(kwargs)
        _pipeline_stats["hops"][hop_key] = hop
    # Write non-blocking
    def _w():
        try:
            _PIPELINE_LOG_PATH.write_text(
                json.dumps(_pipeline_stats, indent=2, default=str))
        except Exception:
            pass
    threading.Thread(target=_w, daemon=True).start()

# ── Analytics SQLite DB ────────────────────────────────────────────────────────
_DB_PATH  = str(IO_DB)
_MEM_PATH = str(MEMORY_DB)
_db_lock  = threading.Lock()

def _db_init():
    with sqlite3.connect(_DB_PATH) as cx:
        cx.execute("""CREATE TABLE IF NOT EXISTS io_log(
            ts INTEGER, component TEXT, name TEXT, pid INTEGER,
            read_bytes INTEGER, write_bytes INTEGER,
            net_in INTEGER, net_out INTEGER,
            cpu_pct REAL, mem_mb REAL)""")
        cx.execute("CREATE INDEX IF NOT EXISTS io_log_ts ON io_log(ts)")
        cx.commit()

def _db_write(rows: list[dict]):
    if not rows: return
    ts = int(time.time())
    vals = [(ts, r.get("component","?"), r.get("name","?"), r.get("pid",0),
             r.get("read_delta",0), r.get("write_delta",0),
             r.get("read_rate",0), r.get("write_rate",0),
             r.get("cpu",0.0), r.get("mem_mb",0.0)) for r in rows]
    with _db_lock:
        try:
            with sqlite3.connect(_DB_PATH) as cx:
                cx.executemany(
                    "INSERT INTO io_log VALUES(?,?,?,?,?,?,?,?,?,?)", vals)
                # keep only last 24h
                cx.execute("DELETE FROM io_log WHERE ts < ?", (ts - 86400,))
                cx.commit()
        except Exception: pass

def _db_query(window_s: int) -> dict:
    cutoff = int(time.time()) - window_s
    with _db_lock:
        try:
            with sqlite3.connect(_DB_PATH) as cx:
                rows = cx.execute("""
                    SELECT component,
                      SUM(read_bytes)   as rd,
                      SUM(write_bytes)  as wr,
                      SUM(net_in)       as ni,
                      SUM(net_out)      as no_,
                      AVG(cpu_pct)      as cpu,
                      AVG(mem_mb)       as mem,
                      COUNT(DISTINCT name) as procs
                    FROM io_log WHERE ts >= ?
                    GROUP BY component ORDER BY rd+wr DESC
                """, (cutoff,)).fetchall()
                total_row = cx.execute("""
                    SELECT SUM(read_bytes),SUM(write_bytes),
                           SUM(net_in),SUM(net_out)
                    FROM io_log WHERE ts >= ?
                """, (cutoff,)).fetchone()
            return {"by_component": [
                {"component":r[0],"read":r[1],"write":r[2],
                 "net_in":r[3],"net_out":r[4],"cpu":r[5],"mem":r[6],"procs":r[7]}
                for r in rows],
                "totals": {"read":total_row[0]or 0,"write":total_row[1]or 0,
                           "net_in":total_row[2]or 0,"net_out":total_row[3]or 0}}
        except Exception:
            return {"by_component":[],"totals":{}}

_db_init()

# ── Memory DB — persistent security/performance history ───────────────────────
def _mem_init():
    with sqlite3.connect(_MEM_PATH) as cx:
        cx.executescript("""
        CREATE TABLE IF NOT EXISTS security_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER, event_type TEXT, severity TEXT,
            component TEXT, message TEXT, detail TEXT);
        CREATE TABLE IF NOT EXISTS metrics_history(
            ts INTEGER PRIMARY KEY,
            security_score REAL, perf_score REAL,
            violation_rate REAL, refusal_rate REAL,
            scramble_diversity REAL, privacy_score REAL,
            cpu_pct REAL, mem_pct REAL, net_out_kbps REAL);
        CREATE TABLE IF NOT EXISTS session_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_start INTEGER, session_end INTEGER,
            notes TEXT);
        CREATE INDEX IF NOT EXISTS ev_ts   ON security_events(ts);
        CREATE INDEX IF NOT EXISTS ev_type ON security_events(event_type);
        CREATE INDEX IF NOT EXISTS mh_ts   ON metrics_history(ts);
        """)
        cx.commit()

def mem_log_event(event_type: str, severity: str, component: str,
                  message: str, detail: str = ""):
    with _db_lock:
        try:
            with sqlite3.connect(_MEM_PATH) as cx:
                cx.execute(
                    "INSERT INTO security_events(ts,event_type,severity,component,message,detail)"
                    " VALUES(?,?,?,?,?,?)",
                    (int(time.time()), event_type, severity, component, message, detail))
                # keep 7 days
                cx.execute("DELETE FROM security_events WHERE ts < ?",
                           (int(time.time()) - 604800,))
                cx.commit()
        except Exception: pass

def mem_log_metrics(scores: dict):
    with _db_lock:
        try:
            with sqlite3.connect(_MEM_PATH) as cx:
                cx.execute(
                    "INSERT OR REPLACE INTO metrics_history VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (int(time.time()),
                     scores.get("security_score", 0),
                     scores.get("perf_score", 0),
                     scores.get("violation_rate", 0),
                     scores.get("refusal_rate", 0),
                     scores.get("scramble_diversity", 0),
                     scores.get("privacy_score", 0),
                     scores.get("cpu_pct", 0),
                     scores.get("mem_pct", 0),
                     scores.get("net_out_kbps", 0)))
                # keep 30 days
                cx.execute("DELETE FROM metrics_history WHERE ts < ?",
                           (int(time.time()) - 2592000,))
                cx.commit()
        except Exception: pass

def mem_query(window_s: int = 86400, limit: int = 200) -> dict:
    cutoff = int(time.time()) - window_s
    with _db_lock:
        try:
            with sqlite3.connect(_MEM_PATH) as cx:
                events = cx.execute(
                    "SELECT ts,event_type,severity,component,message,detail"
                    " FROM security_events WHERE ts>=? ORDER BY ts DESC LIMIT ?",
                    (cutoff, limit)).fetchall()
                metrics = cx.execute(
                    "SELECT ts,security_score,perf_score,violation_rate,refusal_rate,"
                    "scramble_diversity,privacy_score,cpu_pct,mem_pct,net_out_kbps"
                    " FROM metrics_history WHERE ts>=? ORDER BY ts DESC LIMIT 500",
                    (cutoff,)).fetchall()
                total_events = cx.execute(
                    "SELECT COUNT(*) FROM security_events").fetchone()[0]
                by_type = cx.execute(
                    "SELECT event_type,COUNT(*) as n FROM security_events"
                    " WHERE ts>=? GROUP BY event_type ORDER BY n DESC",
                    (cutoff,)).fetchall()
            from datetime import datetime as _dt
            return {
                "events": [{"ts": _dt.fromtimestamp(r[0]).strftime("%m-%d %H:%M:%S"),
                             "type":r[1],"severity":r[2],"component":r[3],
                             "message":r[4],"detail":r[5]} for r in events],
                "metrics": [{"ts": _dt.fromtimestamp(r[0]).strftime("%m-%d %H:%M"),
                              "sec":round(r[1],2),"perf":round(r[2],2),
                              "vr":round((r[3] or 0)*100,1),
                              "rr":round((r[4] or 0)*100,1),
                              "cpu":round(r[7] or 0,1),
                              "mem":round(r[8] or 0,1)} for r in metrics],
                "total_events": total_events,
                "by_type": [{"type":r[0],"count":r[1]} for r in by_type],
            }
        except Exception as e:
            return {"events":[],"metrics":[],"total_events":0,"by_type":[],"error":str(e)}

_mem_init()
# Seed a startup event
mem_log_event("STARTUP","INFO","DASHBOARD","Security Dashboard started",
              f"port=8765 pid={os.getpid()}")

PORT      = 8765
BASE      = str(BASE_DIR)
REPORT    = str(REPORT_OUT)
ALERT_LOG = str(ALERT_LOG)
_DASHBOARD_TOKEN = dashboard_token()

try:
    import graph_hypotheses as _gh
    _WOLFRAMSCRIPT = _gh._wolframscript() or "wolframscript"
except Exception:
    _WOLFRAMSCRIPT = "wolframscript"

SCRIPTS = {
    "quantum"          : ["python", os.path.join(BASE, "quantum-analyzer.py")],
    "scramble-tune"    : [_WOLFRAMSCRIPT, "-file", os.path.join(BASE, "scramble_diversity.wl")],
    "fortress"         : ["powershell", "-ExecutionPolicy", "Bypass", "-File", os.path.join(BASE, "web-fortress.ps1")],
    "fortress-monitor" : ["powershell", "-ExecutionPolicy", "Bypass", "-File", os.path.join(BASE, "web-fortress.ps1"), "-Monitor"],
    "fortress-autoblock": ["powershell", "-ExecutionPolicy", "Bypass", "-File", os.path.join(BASE, "web-fortress.ps1"), "-Schedule"],
    "intruder-install" : ["powershell", "-ExecutionPolicy", "Bypass", "-File", os.path.join(BASE, "intruder-protocol.ps1"), "-Install"],
    "intruder-monitor" : ["powershell", "-ExecutionPolicy", "Bypass", "-File", os.path.join(BASE, "intruder-protocol.ps1"), "-Monitor"],
    "harden"           : ["powershell", "-ExecutionPolicy", "Bypass", "-File", os.path.join(BASE, "harden-windows.ps1")],
    "jarvis"           : ["python", os.path.join(BASE, "jarvis_prime.py"), "--once"],
    "jarvis-daemon"    : ["python", os.path.join(BASE, "jarvis_prime.py")],
    "autoresearch"     : ["python", os.path.join(BASE, "AndroidStudioProjects", "autoresearch", "security_research_loop.py"), "--once"],
    "autoresearch-daemon": ["python", os.path.join(BASE, "AndroidStudioProjects", "autoresearch", "security_research_loop.py")],
    "search-guardian"  : ["python", os.path.join(BASE, "search_guardian.py")],
    "throttle"         : ["python", os.path.join(BASE, "upload_throttle.py"), "--dry-run"],
    "throttle-live"    : ["python", os.path.join(BASE, "upload_throttle.py")],
}

# ── Component classifier ───────────────────────────────────────────────────────
_comp_cache: dict[str, str] = {}

def classify_component(name: str, cmdline: list) -> str:
    # Cache by name — cmdline only matters for Python processes, checked below
    cached = _comp_cache.get(name)
    if cached:
        return cached

    cmd = " ".join(cmdline).lower()
    n   = name.lower()
    if "python" in n:
        if "jarvis_prime"           in cmd: return "JARVIS-PRIME"
        if "security_research_loop" in cmd: return "AUTORESEARCH"
        if "security-dashboard"     in cmd: return "DASHBOARD"
        if "quantum-analyzer"       in cmd: return "QUANTUM-ANALYZER"
        if "web-fortress"           in cmd: return "WEB-FORTRESS"
        if "cybersec_protective"    in cmd: return "VECTOR-DB"
        if "graphify"               in cmd: return "GRAPHIFY"
        if "intruder"               in cmd: return "INTRUDER-PROTOCOL"
        return "PYTHON"
    MAP = {
        "msmpeng"            : "DEFENDER",
        "securityhealthsvc"  : "WIN-SECURITY",
        "securityhealthhost" : "WIN-SECURITY",
        "system"             : "KERNEL",
        "svchost"            : "SVCHOST",
        "ollama"             : "OLLAMA-AI",
        "searchindexer"      : "SEARCH-INDEX",
        "searchhost"         : "SEARCH-HOST",
        "taskhostw"          : "TASK-HOST",
        "explorer"           : "EXPLORER",
        "lsass"              : "LSA-AUTH",
        "winlogon"           : "WINLOGON",
        "csrss"              : "WIN32-SUBSYS",
        "wininit"            : "WIN-INIT",
        "dwm"                : "COMPOSITOR",
        "audiodg"            : "AUDIO",
        "smss"               : "SESSION-MGR",
        "spoolsv"            : "PRINT-SPOOLER",
        "wuauclt"            : "WIN-UPDATE",
        "trustedinstaller"   : "WIN-UPDATE",
        "vmmem"              : "HYPERVISOR",
        "nvidia"             : "GPU-DRIVER",
        "code"               : "VS-CODE",
        "chrome"             : "BROWSER",
        "firefox"            : "BROWSER",
        "msedge"             : "BROWSER",
        "discord"            : "DISCORD",
        "steam"              : "STEAM",
        "epicgames"          : "EPIC-GAMES",
        "armourycrate"       : "ARMORY-CRATE",
        "eadesktop"          : "EA-DESKTOP",
    }
    result = None
    for k, v in MAP.items():
        if k in n:
            result = v
            break
    if result is None:
        result = name.upper().replace(".EXE", "")[:16]
    if "python" not in n:  # don't cache python — varies by cmdline
        _comp_cache[name] = result
    return result

# ── Byte derivation from extension / context ───────────────────────────────────
# Flat ext → derivation label
_EXT_FLAT = {}
for raw_ext, label in {
    ".log":"LOG",".txt":"LOG",".json":"LOG",".xml":"LOG",".csv":"LOG",
    ".exe":"EXEC",".dll":"EXEC",".sys":"EXEC",".drv":"EXEC",
    ".py":"SCRIPT",".ps1":"SCRIPT",".js":"SCRIPT",".ts":"SCRIPT",
    ".db":"DB",".sqlite":"DB",".chroma":"DB",".parquet":"DB",
    ".jpg":"MEDIA",".jpeg":"MEDIA",".png":"MEDIA",".gif":"MEDIA",
    ".bmp":"MEDIA",".webp":"MEDIA",".heic":"MEDIA",".mp4":"MEDIA",
    ".mkv":"MEDIA",".mp3":"MEDIA",".flac":"MEDIA",".avi":"MEDIA",
    ".pdf":"DOC",".docx":"DOC",".xlsx":"DOC",".pptx":"DOC",
    ".tmp":"CACHE",".cache":"CACHE",
    ".reg":"CONFIG",".ini":"CONFIG",".conf":"CONFIG",".inf":"CONFIG",
}.items():
    _EXT_FLAT[raw_ext] = label

def derive_bytes(component: str, read_delta: int, write_delta: int,
                 net_in: int, net_out: int, open_ext: str | None) -> str:
    """Returns a short derivation label for what these bytes represent."""
    parts = []
    if read_delta > 0:
        label = _EXT_FLAT.get(open_ext, "DATA") if open_ext else "DATA"
        if component in ("DEFENDER", "WIN-SECURITY"):      label = "AV-SCAN"
        elif component == "SEARCH-INDEX":                  label = "INDEX"
        elif component in ("JARVIS-PRIME","VECTOR-DB"):    label = "DB"
        elif component == "QUANTUM-ANALYZER":              label = "NETSTAT"
        parts.append(f"READ:{label}")
    if write_delta > 0:
        label = _EXT_FLAT.get(open_ext, "DATA") if open_ext else "DATA"
        if component in ("JARVIS-PRIME","INTRUDER-PROTOCOL","QUANTUM-ANALYZER","WEB-FORTRESS"):
            label = "LOG"
        elif component == "VECTOR-DB":                     label = "DB"
        parts.append(f"WRITE:{label}")
    if net_in  > 0: parts.append("NET:IN")
    if net_out > 0: parts.append("NET:OUT")
    return " | ".join(parts) if parts else "IDLE"

# ── Flag logic ─────────────────────────────────────────────────────────────────
SENSITIVE_PATHS = ("credential", "password", "vault", "wallet", "keystore",
                   "id_rsa", ".ssh", "shadow", "ntds.dit", "sam ", "lsass")

def compute_flags(component: str, name: str, read_d: int, write_d: int,
                  cpu: float, mem_mb: float, net_conns: int,
                  open_paths: list[str], interval_s: float) -> list[str]:
    flags = []
    read_rate  = read_d  / interval_s if interval_s else 0
    write_rate = write_d / interval_s if interval_s else 0

    if write_rate > 10_000_000:   flags.append("WRITE-SPIKE")
    if read_rate  > 50_000_000:   flags.append("READ-SPIKE")
    if read_rate  > 5_000_000 and cpu < 5.0 and component not in ("DEFENDER","SEARCH-INDEX"):
        flags.append("SCAN-DETECTED")
    if mem_mb > 800:              flags.append("HIGH-MEM")
    if mem_mb > 200 and cpu < 1.0 and read_d == 0 and write_d == 0:
        flags.append("IDLE-BLOAT → consider restart")
    if read_rate > 100_000_000:   flags.append("PERF:DISK-BOUND → check SSD health")
    if write_rate > 50_000_000 and component not in ("DEFENDER","WIN-UPDATE","SEARCH-INDEX"):
        flags.append("PERF:HEAVY-WRITER → caching may help")
    if component == "GRAPHIFY" and read_rate > 1_000_000:
        flags.append("ORPHAN-SCAN → kill if unneeded")
    if component == "OLLAMA-AI" and net_conns > 0:
        flags.append("AI-EXPOSED → verify OLLAMA_HOST=127.0.0.1")
    for p in open_paths:
        if any(s in p.lower() for s in SENSITIVE_PATHS):
            flags.append(f"SENSITIVE-PATH:{Path(p).name}")
            break
    return flags

# ── Kernel I/O Monitor ─────────────────────────────────────────────────────────
class KernelMonitor:
    INTERVAL = 1.0   # seconds — process_iter takes ~1.5s on Windows; 1s keeps UI responsive

    def __init__(self):
        self._prev: dict[int, dict] = {}
        self._prev_net = psutil.net_io_counters()
        self._prev_t   = time.monotonic()
        self._procs:   list[dict] = []
        self._events:  collections.deque = collections.deque(maxlen=500)
        self._lock     = threading.Lock()
        self._sse_queues: list[collections.deque] = []
        self._sse_lock    = threading.Lock()
        self._db_tick  = 0
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def subscribe(self) -> collections.deque:
        q: collections.deque = collections.deque(maxlen=200)
        with self._sse_lock:
            self._sse_queues.append(q)
        return q

    def unsubscribe(self, q: collections.deque):
        with self._sse_lock:
            try: self._sse_queues.remove(q)
            except ValueError: pass

    def _push(self, event_type: str, data: object):
        msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
        ts_str = datetime.now().isoformat(timespec="milliseconds")
        with self._sse_lock:
            n_subs = len(self._sse_queues)
            for q in self._sse_queues:
                q.append(msg)
        h = _pipeline_stats["hops"]["1_push_to_queues"]
        _pl_update("1_push_to_queues",
                   push_count=h["push_count"]+1,
                   subscriber_count=n_subs,
                   last_push_ts=ts_str)

    def _loop(self):
        # Clocking quantization: phase-lock each tick to a fixed INTERVAL grid so
        # metric pushes land on aligned boundaries regardless of how long collect
        # took (collect ~1.5s would otherwise make the cadence drift every cycle).
        while True:
            try:
                self._collect()
            except Exception:
                pass
            now = time.monotonic()
            next_tick = (int(now / self.INTERVAL) + 1) * self.INTERVAL
            time.sleep(max(0.0, next_tick - now))  # sleep to next quantum; releases GIL

    def _collect(self):
        now   = time.monotonic()
        delta = max(now - self._prev_t, 0.001)
        self._prev_t = now
        ts_str = datetime.now().isoformat(timespec="milliseconds")
        _pl_update("0_kernel_collect",
                   tick_count=_pipeline_stats["hops"]["0_kernel_collect"]["tick_count"]+1,
                   last_tick_ts=ts_str)
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # — Network totals (system-wide)
        net_now  = psutil.net_io_counters()
        net_in_d  = max(net_now.bytes_recv - self._prev_net.bytes_recv, 0)
        net_out_d = max(net_now.bytes_sent - self._prev_net.bytes_sent, 0)
        self._prev_net = net_now

        # — One global net_connections() call instead of per-process proc.connections()
        #   Groups by PID, skips loopback. Cost: O(1) syscall instead of O(n_procs).
        _pid_conns: dict[int, int] = {}
        try:
            LOCAL = {None, "127.0.0.1", "::1", ""}
            for c in psutil.net_connections(kind="inet"):
                if c.pid and getattr(c.raddr, "ip", None) not in LOCAL:
                    _pid_conns[c.pid] = _pid_conns.get(c.pid, 0) + 1
        except Exception:
            pass

        proc_rows = []
        # Drop cmdline — most expensive attr on Windows (requires ReadProcessMemory per proc)
        attrs = ["pid","name","cpu_percent","memory_info","io_counters",
                 "num_threads","status"]

        batch = 0
        for proc in psutil.process_iter(attrs, ad_value=None):
            # Yield GIL every 20 processes so HTTP threads can respond
            batch += 1
            if batch % 20 == 0:
                time.sleep(0)

            info = proc.info
            if info["pid"] is None: continue
            pid  = info["pid"]
            name = info["name"] or "?"
            ioc  = info["io_counters"]
            mem  = info["memory_info"]
            cpu  = info["cpu_percent"] or 0.0
            stat = info["status"] or "?"
            conns_count = _pid_conns.get(pid, 0)

            # Component classification cached by name (classification is pure Python, expensive if called per-proc)
            comp   = classify_component(name, [])
            mem_mb = (mem.rss / 1_048_576) if mem else 0.0

            prev = self._prev.get(pid, {})
            if ioc and prev.get("rc") is not None:
                read_d  = max(ioc.read_bytes  - prev["rc"], 0)
                write_d = max(ioc.write_bytes  - prev["wc"], 0)
            else:
                read_d = write_d = 0

            self._prev[pid] = {
                "rc": ioc.read_bytes  if ioc else 0,
                "wc": ioc.write_bytes if ioc else 0,
            }

            # Open file hint (best-effort, non-blocking, avoid sensitive content)
            open_ext  = None
            open_paths: list[str] = []
            if (read_d + write_d) > 4096:
                try:
                    files = proc.open_files()
                    for f in files[:5]:
                        p = f.path
                        open_paths.append(p)
                        ext = Path(p).suffix.lower()
                        if ext in _EXT_FLAT and open_ext is None:
                            open_ext = ext
                except Exception:
                    pass

            derivation = derive_bytes(comp, read_d, write_d, 0, 0, open_ext)
            flags      = compute_flags(comp, name, read_d, write_d, cpu, mem_mb,
                                       conns_count, open_paths, delta)

            status_str = "FLAGGED" if flags else ("ACTIVE" if (read_d+write_d+cpu > 0.5) else "NOMINAL")

            row = {
                "pid"       : pid,
                "name"      : name,
                "component" : comp,
                "status"    : status_str,
                "cpu"       : round(cpu, 1),
                "mem_mb"    : round(mem_mb, 1),
                "read_bytes": ioc.read_bytes  if ioc else 0,
                "write_bytes": ioc.write_bytes if ioc else 0,
                "read_delta": read_d,
                "write_delta": write_d,
                "read_rate" : round(read_d / delta),
                "write_rate": round(write_d / delta),
                "threads"   : info["num_threads"] or 0,
                "net_conns" : conns_count,
                "derivation": derivation,
                "flags"     : flags,
                "ts"        : ts,
            }
            proc_rows.append(row)

            # Emit an I/O event to the log stream for active processes
            if read_d + write_d > 512 or flags:
                evt = {
                    "ts"        : ts,
                    "pid"       : pid,
                    "name"      : name,
                    "component" : comp,
                    "op"        : ("R/W" if read_d and write_d else
                                   "READ"  if read_d else
                                   "WRITE" if write_d else "NET"),
                    "read_b"    : read_d,
                    "write_b"   : write_d,
                    "rate_rbs"  : round(read_d  / delta),
                    "rate_wbs"  : round(write_d / delta),
                    "derivation": derivation,
                    "flags"     : flags,
                    "open_hint" : Path(open_paths[0]).name if open_paths else None,
                }
                with self._lock:
                    self._events.appendleft(evt)
                self._push("io_event", evt)

        # Sort by total I/O delta descending, then CPU
        proc_rows.sort(key=lambda r: -(r["read_delta"] + r["write_delta"] + r["cpu"] * 1000))

        with self._lock:
            self._procs = proc_rows

        # Write to analytics DB every 20 cycles (~10s)
        self._db_tick += 1
        if self._db_tick >= 20:
            self._db_tick = 0
            _db_write(proc_rows)

        # Log security flags to memory DB (non-blocking, separate thread)
        flagged = [(r["name"], r["component"], r["flags"]) for r in proc_rows if r["flags"]]
        if flagged:
            def _log_flags(rows):
                for name, comp, flags in rows:
                    for flag in flags:
                        sev = "CRITICAL" if any(x in flag for x in ("SENSITIVE","SCAN","LSASS")) else \
                              "WARN"     if any(x in flag for x in ("SPIKE","BLOAT","EXPOSED")) else "INFO"
                        mem_log_event("SECURITY_FLAG", sev, comp, flag, f"process={name}")
            threading.Thread(target=_log_flags, args=(flagged,), daemon=True).start()

        self._push("proc_table", {
            "ts": ts,
            "net_in_rate" : round(net_in_d  / delta),
            "net_out_rate": round(net_out_d / delta),
            "procs": proc_rows,
        })

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self._procs)

    def events(self, n=200) -> list[dict]:
        with self._lock:
            return list(self._events)[:n]

_monitor = KernelMonitor()

# ── Job management (unchanged) ─────────────────────────────────────────────────
_jobs: dict = {}
_jobs_lock  = threading.Lock()

def run_job(name, cmd):
    with _jobs_lock:
        if name in _jobs and not _jobs[name]["done"]:
            return
        _jobs[name] = {"output": "", "done": False, "started": datetime.now().isoformat()}
    try:
        r   = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        out = (r.stdout + r.stderr).strip()
    except Exception as e:
        out = str(e)
    with _jobs_lock:
        _jobs[name]["output"] = out
        _jobs[name]["done"]   = True

# ── HTML ───────────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JARVIS PRIME — Security Dashboard</title>
<style>
:root{
  --bg:#2eb38e;--card:#d9fff0;--card2:#c8f9e4;--border:#4b9d7a;
  --green:#2ecc71;--yellow:#f39c12;--red:#e74c3c;--blue:#3498db;
  --purple:#9b59b6;--teal:#1abc9c;--dim:#fb6e2b;--text:#473756;
  --font:'Courier New',monospace;
  --primary:#e67e22;--secondary:#2ecc71;--accent:#1abc9c}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:13px;font-weight:700;
     display:flex;flex-direction:column}
header{background:#c8f9e4;border-bottom:2px solid var(--primary);padding:10px 18px;
       display:flex;align-items:center;gap:16px;flex-shrink:0}
header h1{color:var(--primary);font-size:15px;letter-spacing:2px;font-weight:bold}
#clock{margin-left:auto;color:var(--dim);font-size:11px}
#net-badge{font-size:11px;color:var(--accent)}

/* tabs */
nav{display:flex;gap:0;border-bottom:2px solid var(--border);background:#c8f9e4;flex-shrink:0}
nav button{background:none;border:none;border-bottom:3px solid transparent;font-weight:700;
           color:var(--dim);cursor:pointer;font-family:var(--font);font-size:12px;
           font-weight:bold;padding:8px 16px;transition:.15s}
nav button.active{color:var(--primary);border-bottom-color:var(--primary)}
nav button:hover{color:var(--text)}

/* all tabs fill the remaining viewport; only analytics uses flex-col */
.tab{display:none;overflow-y:auto;flex:1;padding:12px}
.tab.active{display:block}
#tab-analytics.active{display:flex;flex-direction:column;overflow:hidden;padding:8px;gap:6px}

/* cards */
.card{background:var(--card);border:1px solid var(--border);border-radius:4px;
      margin-bottom:10px;padding:12px;box-shadow:0 2px 6px rgba(0,0,0,.4)}
.card h2{color:var(--primary);font-size:11px;letter-spacing:1px;margin-bottom:10px;
         border-bottom:1px solid var(--border);padding-bottom:6px}

/* process table */
#proc-table{width:100%;border-collapse:collapse;font-size:11px}
#proc-table th{color:var(--dim);text-align:left;padding:4px 6px;
               border-bottom:1px solid var(--border);position:sticky;top:0;
               background:var(--card2);white-space:nowrap}
#proc-table td{padding:3px 6px;border-bottom:1px solid #0c3a1e;
               white-space:nowrap;max-width:180px;overflow:hidden;
               text-overflow:ellipsis}
#proc-table tr:hover td{background:#174d2e}
.tbl-wrap{max-height:calc(100vh - 220px);overflow-y:auto}

/* status badges */
.badge{font-size:10px;padding:1px 6px;border-radius:3px;font-weight:bold}
.badge-green {background:#0d3d20;color:#2ecc71;border:1px solid #2ecc71}
.badge-yellow{background:#3d2a00;color:#f39c12;border:1px solid #f39c12}
.badge-red   {background:#3d0d0d;color:#e74c3c;border:1px solid #e74c3c}
.badge-blue  {background:#0d2a3d;color:#3498db;border:1px solid #3498db}
.badge-purple{background:#2a0d3d;color:#9b59b6;border:1px solid #9b59b6}
.badge-teal  {background:#0d3d35;color:#1abc9c;border:1px solid #1abc9c}
.badge-dim   {background:#0f3a22;color:#fb6e2b;border:1px solid #fb6e2b}

/* derivation label */
.deriv{color:var(--accent);font-size:10px;font-weight:bold}
.flag-pill{font-size:10px;background:#3d0d0d;color:#e74c3c;border:1px solid #e74c3c;
           padding:1px 6px;border-radius:3px;margin-right:3px;white-space:nowrap}
.flag-perf{background:#0d3d20;color:#2ecc71;border:1px solid #2ecc71}
.flag-warn{background:#3d2a00;color:#f39c12;border:1px solid #f39c12}

/* I/O log stream */
#io-log{height:calc(100vh - 260px);overflow-y:auto;font-size:11px;
        background:#082a1a;border:1px solid var(--border);border-radius:3px;padding:6px}
.log-row{display:grid;grid-template-columns:80px 55px 140px 100px 90px 90px 100px 1fr;
         gap:6px;padding:2px 0;border-bottom:1px solid #0f3a22;align-items:center}
.log-row:hover{background:#0f4a2e}
.log-ts  {color:var(--dim)}
.log-op  {text-align:center}
.log-comp{color:var(--blue);font-weight:bold}
.log-bytes{text-align:right;color:#fff19b}
.log-rate {text-align:right;color:#fff19b}
.log-hint {color:var(--dim);overflow:hidden;text-overflow:ellipsis}
.kernel-read-write{color:#fff19b!important}
.kernel-header{background:linear-gradient(90deg,#000000,#1a0a2e,#3b0764,#581c87,#1a0a2e,#000000);
               background-size:300% 100%;-webkit-background-clip:text;background-clip:text;
               color:transparent!important;-webkit-text-fill-color:transparent;
               font-size:11px;font-weight:900;
               text-shadow:0 2px 1px rgba(88,28,135,.95),0 0 8px rgba(168,85,247,.95),
                           0 0 16px rgba(59,7,100,.85);
               animation:kernel-header-wave 2.4s linear infinite}
.kernel-header:hover{text-shadow:0 0 7px rgba(217,70,239,1),0 0 16px rgba(168,85,247,.9)}
@keyframes kernel-header-wave{
  0%{background-position:0% 50%}
  100%{background-position:300% 50%}
}

/* overview */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
.grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
.stat-val{font-size:26px;color:var(--primary);margin:4px 0;font-weight:bold}
.stat-lbl{font-size:10px;color:var(--dim)}
.score-bar{height:8px;background:#0c3a1e;border-radius:4px;margin-top:8px}
.score-fill{height:8px;border-radius:4px;transition:width .5s}
pre.output{background:#082a1a;border:1px solid var(--border);border-radius:3px;
           padding:8px;font-size:11px;max-height:200px;overflow-y:auto;
           white-space:pre-wrap;word-break:break-all;color:var(--text)}
.tool-row{display:flex;align-items:center;gap:8px;margin-bottom:6px}
.tool-row span{flex:1;color:var(--text);font-size:11px}
button.run{background:#082a1a;border:2px solid var(--primary);color:var(--primary);
           cursor:pointer;font-family:var(--font);font-size:11px;font-weight:bold;
           padding:4px 12px;border-radius:3px;transition:.15s}
button.run:hover{background:var(--primary);color:#082a1a}
button.run:disabled{opacity:.35;cursor:not-allowed}
button.run.danger{border-color:var(--bad);color:var(--bad);background:#2a0808}
button.run.danger:hover{background:var(--bad);color:#000}
.alert-line{padding:3px 0;border-bottom:1px solid var(--border);font-size:11px}
.alert-crit{color:#e74c3c}
.alert-warn{color:#f39c12}
.alert-info{color:var(--dim)}
#fw-list{font-size:11px}
.fw-row{display:flex;justify-content:space-between;padding:4px 0;
        border-bottom:1px solid var(--border)}
.port-table{width:100%;border-collapse:collapse;font-size:11px}
.port-table th{color:var(--dim);text-align:left;border-bottom:1px solid var(--border);padding:7px 6px}
.port-table td{border-bottom:1px solid rgba(42,74,58,.55);padding:7px 6px;vertical-align:middle}
.port-table select{background:#07110b;color:var(--text);border:1px solid var(--border);font-family:var(--font);padding:4px}
.port-risk{font-size:10px;font-weight:bold;padding:2px 6px;border-radius:3px}
.port-risk-normal{background:#0d3d20;color:#2ecc71}
.port-risk-watch{background:#3d2a00;color:#f39c12}
.port-risk-malicious{background:#3d0d0d;color:#e74c3c}
.rag-green{background:#0d3d20;color:#2ecc71;border:1px solid #2ecc71}
.rag-amber{background:#3d2a00;color:#f39c12;border:1px solid #f39c12}
.rag-red{background:#3d0d0d;color:#e74c3c;border:1px solid #e74c3c}
.rag-badge{display:inline-block;min-width:48px;text-align:center;font-size:10px;font-weight:bold;padding:3px 7px;border-radius:3px}
.port-explanation{color:var(--text);font-size:10px;margin-top:4px;max-width:420px;line-height:1.35}

/* security research metrics */
.sec-metric{display:flex;justify-content:space-between;align-items:center;
            padding:5px 0;border-bottom:1px solid #0f3a22;font-size:11px}
.sec-metric-label{color:var(--dim)}
.sec-metric-val{color:var(--primary);font-weight:bold;min-width:80px;text-align:right}
.sec-bar-wrap{flex:1;margin:0 10px;height:5px;background:#0c3a1e;border-radius:3px}
.sec-bar-fill{height:5px;border-radius:3px;transition:width .6s}
.finding-auto{color:var(--secondary);font-size:10px;padding:2px 0}
.finding-prompt{color:var(--yellow);font-size:10px;padding:2px 0}

/* process table */
#proc-table th{background:var(--card2)}
#proc-table tr:hover td{background:#174d2e}

/* filter input */
#proc-filter{background:#082a1a;border:1px solid var(--border);color:var(--text);
             font-family:var(--font);font-size:11px;padding:2px 6px;border-radius:2px;width:180px}

/* Analytics tab layout — everything in viewport, zero page scroll */
.ana-toolbar{display:flex;align-items:center;gap:10px;
             padding:6px 10px;background:var(--card2);
             border:1px solid var(--border);border-radius:4px;
             flex-shrink:0}
.ana-charts{flex:1;min-height:0;display:flex;flex-direction:column;gap:6px}
.ana-row{flex:1;min-height:0;display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px}
.ana-card{background:var(--card);border:1px solid var(--border);border-radius:4px;
          padding:8px;display:flex;flex-direction:column;min-height:0;overflow:hidden}
.ana-card h2{color:var(--primary);font-size:10px;letter-spacing:1px;
             margin-bottom:4px;padding-bottom:4px;
             border-bottom:1px solid var(--border);flex-shrink:0}
.ana-canvas-wrap{flex:1;min-height:0;position:relative}
.ana-canvas-wrap canvas{position:absolute;inset:0;width:100%!important;height:100%!important}
.ana-table-card{flex-shrink:0;height:180px;background:var(--card);
                border:1px solid var(--border);border-radius:4px;
                display:flex;flex-direction:column;overflow:hidden}
.ana-table-header{display:flex;align-items:center;justify-content:space-between;
                  padding:6px 10px;border-bottom:1px solid var(--border);flex-shrink:0}
.ana-table-body{flex:1;overflow-y:auto;overflow-x:auto;font-size:10px}
.ana-table-body table{width:100%;border-collapse:collapse}
.ana-table-body th{color:var(--dim);text-align:left;padding:3px 8px;
                   border-bottom:1px solid var(--border);
                   position:sticky;top:0;background:var(--card2);white-space:nowrap}
.ana-table-body td{padding:3px 8px;border-bottom:1px solid #0c3a1e;white-space:nowrap}

/* sortable table headers */
th[data-col]{cursor:pointer;user-select:none;position:relative;padding-right:18px!important}
th[data-col]:hover{color:var(--primary)}
th[data-col]::after{content:' \2195';color:var(--dim);font-size:9px;position:absolute;right:4px}
th[data-col].sort-asc::after{content:' \2191';color:var(--primary)}
th[data-col].sort-desc::after{content:' \2193';color:var(--primary)}

/* throttle tab table */
#thr-table th,#thr-table td{padding:3px 7px;border-bottom:1px solid #0c3a1e;
                             white-space:nowrap;text-align:left;font-size:11px}
#thr-table th{color:var(--dim);background:var(--card2);position:sticky;top:0}
#thr-table tr:hover td{background:#174d2e}

/* allow list items */
.allow-item{display:flex;align-items:center;gap:8px;padding:4px 0;
            border-bottom:1px solid #0c3a1e}
.allow-item label{flex:1;color:var(--text);cursor:pointer}
.allow-item input[type=checkbox]{accent-color:var(--primary);width:14px;height:14px}

/* scrollbar */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:#082a1a}
::-webkit-scrollbar-thumb{background:#1e6b40;border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--accent)}
</style>
</head>
<body>
<header>
  <h1>&#9632; JARVIS PRIME — SECURITY DASHBOARD</h1>
  <span id="net-badge">NET &#8595;—  &#8593;—</span>
  <span id="sse-status" style="font-size:10px;color:var(--dim);margin-left:8px">[CONNECTING]</span>
  <span id="clock">—</span>
</header>

<nav>
  <button class="active" onclick="switchTab('overview',this)">OVERVIEW</button>
  <button onclick="switchTab('kernel',this)">&#9654; KERNEL I/O</button>
  <button onclick="switchTab('procs',this)">PROCESSES</button>
  <button onclick="switchTab('alerts',this)">ALERTS</button>
  <button onclick="switchTab('firewall',this)">FIREWALL</button>
  <button onclick="switchTab('research',this)">AUTORESEARCH</button>
  <button onclick="switchTab('analytics',this)">ANALYTICS</button>
  <button onclick="switchTab('throttle',this)">THROTTLE</button>
  <button onclick="switchTab('memory',this)">MEMORY DB</button>
</nav>

<!-- OVERVIEW TAB -->
<div id="tab-overview" class="tab active">
  <div id="stasis-bar" style="font-size:11px;color:var(--dim);margin-bottom:10px;padding:6px 10px;background:rgba(255,255,255,.03);border-radius:4px">stasis: starting…</div>
  <div class="grid3">
    <div class="card">
      <h2>THREAT SCORE</h2>
      <div id="ov-score" class="stat-val">—</div>
      <div id="ov-status" class="stat-lbl">loading…</div>
      <div class="score-bar"><div id="score-fill" class="score-fill" style="width:0%;background:var(--green)"></div></div>
    </div>
    <div class="card">
      <h2>ENTROPY / CHAOS</h2>
      <div id="ov-entropy" class="stat-val">—</div>
      <div id="ov-chaos"   class="stat-lbl">—</div>
    </div>
    <div class="card">
      <h2>EXPOSED PORTS</h2>
      <div id="ov-ports"   class="stat-val">—</div>
      <div id="ov-foreign" class="stat-lbl">—</div>
    </div>
  </div>

  <!-- Security research summary row -->
  <div class="grid4" style="margin-bottom:10px">
    <div class="card" style="padding:10px">
      <h2>SEC SCORE</h2>
      <div id="sec-score" class="stat-val" style="font-size:22px">--</div>
      <div class="score-bar"><div id="sec-score-fill" class="score-fill" style="width:0%;background:var(--secondary)"></div></div>
      <div id="sec-score-lbl" class="stat-lbl" style="margin-top:4px">autoresearch</div>
    </div>
    <div class="card" style="padding:10px">
      <h2>VIOLATION RATE</h2>
      <div id="sec-vr" class="stat-val" style="font-size:22px">--</div>
      <div id="sec-vr-lbl" class="stat-lbl">blocked / detected</div>
    </div>
    <div class="card" style="padding:10px">
      <h2>REFUSAL RATE</h2>
      <div id="sec-rr" class="stat-val" style="font-size:22px">--</div>
      <div id="sec-rr-lbl" class="stat-lbl">novel / total responses</div>
    </div>
    <div class="card" style="padding:10px">
      <h2>SCRAMBLE DIVERSITY</h2>
      <div id="sec-sd" class="stat-val" style="font-size:22px">--</div>
      <div id="sec-sd-lbl" class="stat-lbl">unique CA seeds</div>
    </div>
  </div>

  <div class="grid2">
    <div class="card">
      <h2>TOOLS</h2>
      <div id="tools-list"></div>
    </div>
    <div class="card">
      <h2>JOB OUTPUT</h2>
      <pre class="output" id="job-output">Select a tool to run.</pre>
    </div>
  </div>
</div>

<!-- KERNEL I/O TAB -->
<div id="tab-kernel" class="tab">
  <div class="card" style="margin-bottom:6px;padding:8px 12px">
    <span style="color:var(--dim);font-size:11px">
      Live kernel I/O stream &mdash; one row per active process event &mdash; 500ms resolution
      &nbsp;&nbsp;
      <span id="evt-count" style="color:var(--green)">0</span> events captured
      &nbsp;&nbsp;
      <label style="color:var(--dim)">
        <input type="checkbox" id="auto-scroll" checked> auto-scroll
      </label>
      &nbsp;&nbsp;
      <label style="color:var(--dim)">
        <input type="checkbox" id="filter-idle"> hide IDLE
      </label>
    </span>
  </div>
  <div style="display:grid;grid-template-columns:80px 55px 140px 100px 90px 90px 100px 1fr;
              gap:6px;padding:4px 6px;font-size:11px;letter-spacing:.5px;
              border-bottom:1px solid var(--border)">
    <span class="kernel-header">TIME</span><span class="kernel-header">OP</span><span class="kernel-header">COMPONENT</span>
    <span class="kernel-header" style="text-align:right">BYTES READ</span>
    <span class="kernel-header" style="text-align:right">RD RATE</span>
    <span class="kernel-header" style="text-align:right">BYTES WRITE</span>
    <span class="kernel-header" style="text-align:right">WR RATE</span>
    <span class="kernel-header">DERIVATION / FLAGS / HINT</span>
  </div>
  <div id="io-log"></div>
</div>

<!-- PROCESS TABLE TAB -->
<div id="tab-procs" class="tab">
  <div class="card" style="margin-bottom:6px;padding:8px 12px">
    <span style="color:var(--dim);font-size:11px">
      All components &mdash; sorted by I/O activity &mdash; updates every 500ms
      &nbsp;&nbsp;
      <input id="proc-filter" class="proc-filter" placeholder="filter component / name…">
    </span>
  </div>
  <div class="tbl-wrap">
  <table id="proc-table">
    <thead><tr>
      <th data-col="0">#</th><th data-col="1">COMPONENT</th><th data-col="2">PROCESS</th><th data-col="3">PID</th>
      <th data-col="4">STATUS</th><th data-col="5">CPU%</th><th data-col="6">MEM MB</th>
      <th data-col="7" style="text-align:right">READ TOTAL</th>
      <th data-col="8" style="text-align:right">WRITE TOTAL</th>
      <th data-col="9" style="text-align:right">RD RATE/s</th>
      <th data-col="10" style="text-align:right">WR RATE/s</th>
      <th data-col="11">THREADS</th><th data-col="12">NET</th>
      <th>DERIVATION</th><th>FLAGS</th>
    </tr></thead>
    <tbody id="proc-tbody"></tbody>
  </table>
  </div>
</div>

<!-- ALERTS TAB -->
<div id="tab-alerts" class="tab">
  <div class="card">
    <h2>ALERT LOG (live)</h2>
    <div id="alert-box" style="max-height:calc(100vh - 200px);overflow-y:auto"></div>
  </div>
</div>

<!-- FIREWALL TAB -->
<div id="tab-firewall" class="tab">
  <div class="card">
    <h2>EXPOSED PORTS / MANIPULATION WATCH</h2>
    <div id="port-status-summary" class="port-explanation" style="margin-bottom:8px">
      Checking each open port and explaining what is happening.
    </div>
    <div style="overflow-x:auto">
      <table class="port-table">
        <thead><tr>
          <th>PORT</th><th>SERVICE / LABEL</th><th>PROCESS</th><th>PID</th>
          <th>ADDRESS</th><th>RISK</th><th>ACTION</th>
        </tr></thead>
        <tbody id="port-list">
          <tr><td colspan="7" style="color:var(--dim)">Loading listeners…</td></tr>
        </tbody>
      </table>
    </div>
  </div>
  <div class="card">
    <h2>ACTIVE WF-* RULES</h2>
    <div id="fw-list"></div>
  </div>
</div>

<!-- AUTORESEARCH TAB -->
<div id="tab-research" class="tab">
  <div class="grid2">
    <div class="card">
      <h2>SECURITY METRICS DETAIL</h2>
      <div id="res-metrics"></div>
    </div>
    <div class="card">
      <h2>PERF FINDINGS</h2>
      <div id="res-findings"></div>
    </div>
  </div>
  <div class="card">
    <h2>WOLFRAM GRAPH HYPOTHESES — auto-generated every 20s from graph.json</h2>
    <div id="gh-metrics" style="font-size:11px;color:var(--dim);margin-bottom:8px"></div>
    <div id="gh-list"></div>
  </div>
  <div class="card">
    <h2>RESEARCH LOG (security_results.tsv) — last 10 iterations</h2>
    <div id="res-tsv" style="font-size:11px;overflow-x:auto"></div>
  </div>
</div>

<!-- ANALYTICS TAB — fixed to viewport, no page scroll -->
<div id="tab-analytics" class="tab">

  <!-- toolbar row: fixed height -->
  <div class="ana-toolbar">
    <span style="color:var(--dim);font-size:11px;font-weight:bold">WINDOW:</span>
    <button class="run" id="w300"   onclick="setWindow(300)">5 MIN</button>
    <button class="run" id="w3600"  onclick="setWindow(3600)">1 HR</button>
    <button class="run" id="w86400" onclick="setWindow(86400)">24 HR</button>
    <span id="ana-updated" style="margin-left:auto;color:var(--dim);font-size:10px">--</span>
  </div>

  <!-- 2×3 chart grid fills all remaining space above the table -->
  <div class="ana-charts">
    <div class="ana-row">
      <div class="ana-card"><h2>DISK READS</h2><div class="ana-canvas-wrap"><canvas id="chart-reads"></canvas></div></div>
      <div class="ana-card"><h2>DISK WRITES</h2><div class="ana-canvas-wrap"><canvas id="chart-writes"></canvas></div></div>
      <div class="ana-card"><h2>ALL DISK I/O</h2><div class="ana-canvas-wrap"><canvas id="chart-total"></canvas></div></div>
    </div>
    <div class="ana-row">
      <div class="ana-card"><h2>NETWORK</h2><div class="ana-canvas-wrap"><canvas id="chart-net"></canvas></div></div>
      <div class="ana-card"><h2>CPU SHARE</h2><div class="ana-canvas-wrap"><canvas id="chart-cpu"></canvas></div></div>
      <div class="ana-card"><h2>KERNEL vs USER</h2><div class="ana-canvas-wrap"><canvas id="chart-kernel"></canvas></div></div>
    </div>
  </div>

  <!-- table pinned at bottom — fixed height, internal scroll -->
  <div class="ana-table-card">
    <div class="ana-table-header">
      <h2 style="border:none;margin:0;padding:0;font-size:11px;color:var(--primary);letter-spacing:1px">COMPONENT I/O LOG</h2>
      <label style="display:flex;align-items:center;gap:5px;color:var(--dim);font-size:10px;cursor:pointer">
        <input type="checkbox" id="ana-autoscroll" checked> auto-scroll
      </label>
    </div>
    <div id="ana-table" class="ana-table-body"></div>
  </div>

</div>

<!-- THROTTLE TAB -->
<div id="tab-throttle" class="tab">
  <div class="grid2" style="margin-bottom:8px">

    <!-- Live throttle status table -->
    <div class="card" style="display:flex;flex-direction:column;max-height:calc(100vh - 200px)">
      <h2>OUTBOUND THROTTLE STATUS
        <span id="thr-count" style="color:var(--red);margin-left:8px">0 throttled</span>
        <span style="float:right;font-size:10px;color:var(--dim)" id="thr-ts">--</span>
      </h2>
      <div style="font-size:10px;color:var(--dim);margin-bottom:6px">
        Wolfram Rule-30 CA  |  D&#x2248;0.4743  |  baseline <span id="thr-baseline">50</span> KB/s  |  max 128:1 compression
        &nbsp;&nbsp;<span style="color:var(--accent)">&#9711; Browser-Grace: 30 min auto-exempt</span>
      </div>
      <div style="flex:1;overflow-y:auto">
        <table id="thr-table" style="width:100%;border-collapse:collapse;font-size:11px">
          <thead><tr>
            <th data-col="0">PROCESS</th>
            <th data-col="1">PID</th>
            <th data-col="2">UPLOAD KB/s</th>
            <th data-col="3">Q LEVEL</th>
            <th data-col="4">COMPRESSION</th>
            <th data-col="5">THROTTLED TO</th>
            <th data-col="6">STATUS</th>
          </tr></thead>
          <tbody id="thr-tbody"></tbody>
        </table>
      </div>
    </div>

    <!-- Allow list panel -->
    <div class="card" style="display:flex;flex-direction:column;max-height:calc(100vh - 200px)">
      <h2>ALLOW LIST
        <button class="run" style="float:right;padding:2px 10px;font-size:10px"
                onclick="saveAllowList()">SAVE</button>
      </h2>
      <div style="font-size:10px;color:var(--dim);margin-bottom:6px">
        Checked = allowed (no throttle). Vital system processes are pre-pruned.
      </div>
      <input id="allow-filter" placeholder="filter programs..."
             oninput="filterAllow(this.value)"
             style="background:#082a1a;border:1px solid var(--border);color:var(--text);
                    font-family:var(--font);font-size:11px;padding:4px 8px;
                    border-radius:3px;width:100%;margin-bottom:8px">
      <div style="flex:1;overflow-y:auto" id="allow-list-wrap">
        <div id="allow-list" style="font-size:11px"></div>
      </div>
    </div>
  </div>
</div>

<!-- MEMORY DB TAB -->
<div id="tab-memory" class="tab">
  <div class="card" style="margin-bottom:8px;padding:8px">
    <h2 style="margin-bottom:4px">SSE TRANSMISSION PIPELINE</h2>
    <div id="pipeline-status" style="font-size:11px;color:var(--dim)">Loading...</div>
  </div>
  <div class="grid2" style="margin-bottom:8px">
    <div class="card" style="display:flex;flex-direction:column;max-height:calc(100vh - 200px)">
      <h2>MEMORY DATABASE
        <span style="float:right;font-size:10px">
          <select id="mem-window" onchange="loadMemory()" style="background:#082a1a;border:1px solid var(--border);color:var(--text);font-family:var(--font);font-size:10px;padding:2px">
            <option value="6">6 h</option>
            <option value="24" selected>24 h</option>
            <option value="168">7 d</option>
            <option value="720">30 d</option>
          </select>
        </span>
      </h2>
      <div style="display:flex;gap:8px;margin-bottom:8px">
        <div class="card" style="flex:1;padding:8px;text-align:center">
          <div style="font-size:18px;color:var(--primary)" id="mem-total">0</div>
          <div style="font-size:10px;color:var(--dim)">TOTAL EVENTS</div>
        </div>
        <div class="card" style="flex:1;padding:8px;text-align:center">
          <div style="font-size:18px;color:var(--accent)" id="mem-types">0</div>
          <div style="font-size:10px;color:var(--dim)">EVENT TYPES</div>
        </div>
      </div>
      <div style="flex:1;overflow-y:auto">
        <table id="mem-tbl" style="width:100%;border-collapse:collapse;font-size:11px">
          <thead><tr>
            <th data-col="0">TIMESTAMP</th>
            <th data-col="1">TYPE</th>
            <th data-col="2">SEVERITY</th>
            <th data-col="3">COMPONENT</th>
            <th data-col="4">MESSAGE</th>
          </tr></thead>
          <tbody id="mem-tbody"></tbody>
        </table>
      </div>
    </div>
    <div class="card" style="display:flex;flex-direction:column;max-height:calc(100vh - 200px)">
      <h2>METRICS TREND</h2>
      <div style="flex:1;overflow-y:auto">
        <table id="mem-metrics-tbl" style="width:100%;border-collapse:collapse;font-size:11px">
          <thead><tr>
            <th data-col="0">TIME</th>
            <th data-col="1">SEC SCORE</th>
            <th data-col="2">PERF</th>
            <th data-col="3">VIOLATIONS %</th>
            <th data-col="4">REFUSALS %</th>
            <th data-col="5">CPU %</th>
            <th data-col="6">MEM %</th>
          </tr></thead>
          <tbody id="mem-metrics-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<script>
let _dashboardToken='';
const _nativeFetch=window.fetch.bind(window);
window.fetch=async function(input, init={}){
  if(!_dashboardToken && !String(input).includes('/api/token')){
    const tokenResponse=await _nativeFetch('/api/token');
    _dashboardToken=(await tokenResponse.json()).token;
  }
  const headers=new Headers(init.headers||{});
  if(_dashboardToken) headers.set('Authorization','Bearer '+_dashboardToken);
  return _nativeFetch(input,{...init,headers});
};
// ── Utilities ──────────────────────────────────────────────────────────────────
const fmt = {
  bytes(n){if(!n)return'0 B';const u=['B','KB','MB','GB'];let i=0;
    while(n>=1024&&i<3){n/=1024;i++}return n.toFixed(i?1:0)+' '+u[i]},
  rate(n){return fmt.bytes(n)+'/s'},
  num(n){return n?.toLocaleString()??'—'}
};

function el(id){return document.getElementById(id)}
function switchTab(id,btn){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b=>b.classList.remove('active'));
  el('tab-'+id).classList.add('active');
  btn.classList.add('active');
  localStorage.setItem('jp_tab', id);
  if(id==='analytics') loadAnalytics();
  if(id==='research'){loadSecMetrics();loadResearchTsv();loadGraphHypotheses();}
  if(id==='throttle'){loadThrottle();loadAllowList();}
  if(id==='memory'){loadMemory();loadPipelineLog();}
}

// Restore active tab on load
(function restoreTab(){
  const t = localStorage.getItem('jp_tab')||'overview';
  const btn = document.querySelector(`nav button[onclick*="'${t}'"]`);
  if(btn && t !== 'overview') btn.click();
})();

// ── Clock ──────────────────────────────────────────────────────────────────────
setInterval(()=>{el('clock').textContent=new Date().toLocaleTimeString()},1000);

// ── Overview: score + tools ────────────────────────────────────────────────────
// One row per tool family; modes are buttons. No more duplicate labels or
// 13 flat near-identical buttons — each pair (once/daemon, dry-run/live) is
// now a single labelled row.  [label, [[mode, scriptKey, danger?], ...]]
const TOOLS = [
  ['Quantum Scan',      [['Run','quantum']]],
  ['Scramble Tune',     [['Optimize','scramble-tune']]],
  ['Web Fortress',      [['Setup','fortress'], ['Monitor','fortress-monitor'], ['Auto-Block','fortress-autoblock']]],
  ['Intruder Protocol', [['Install','intruder-install'], ['Monitor','intruder-monitor']]],
  ['Harden Windows',    [['Run','harden']]],
  ['JARVIS Prime',      [['Once','jarvis'], ['Daemon','jarvis-daemon']]],
  ['AutoResearch',      [['Once','autoresearch'], ['Daemon','autoresearch-daemon']]],
  ['Search Guardian',   [['Run','search-guardian']]],
  ['Upload Throttle',   [['Dry Run','throttle'], ['LIVE','throttle-live', true]]],
];

(function buildTools(){
  const c=el('tools-list');
  for(const[label,modes] of TOOLS){
    const row=document.createElement('div');
    row.className='tool-row';
    const btns=modes.map(([mode,key,danger])=>
      `<button class="run${danger?' danger':''}" id="btn-${key}" `+
      `onclick="runTool('${key}',this)">${mode}</button>`).join('');
    row.innerHTML=`<span>${label}</span><span style="display:flex;gap:6px">${btns}</span>`;
    c.appendChild(row);
  }
})();

let _activeJob=null;
function runTool(name,btn){
  _activeJob=name;
  document.querySelectorAll('button.run').forEach(b=>b.disabled=true);
  el('job-output').textContent='Starting '+name+'…';
  fetch('/api/run/'+name,{method:'POST'}).then(()=>pollJob(name));
}
function pollJob(name){
  fetch('/api/job/'+name).then(r=>r.json()).then(d=>{
    el('job-output').textContent=d.output||'Running…';
    if(!d.done){setTimeout(()=>pollJob(name),800)}
    else{document.querySelectorAll('button.run').forEach(b=>b.disabled=false)}
  });
}

// Overview reads the 1 Hz stasis snapshot (every script's data, with freshness).
function _fresh(src){
  if(!src||!src._ok) return ' <span style="color:var(--bad)">⚠ no data</span>';
  if(src._stale) return ` <span style="color:#e0a800">stale ${src._age_s|0}s</span>`;
  return ` <span style="color:var(--good)">·${src._age_s|0}s</span>`;
}
async function loadStatus(){
  try{
    const r=await fetch('/api/stasis');
    const st=await r.json();
    const q=st.sources?.quantum||{}, rs=st.sources?.research||{};
    const score=q.score??0;
    el('ov-score').textContent=score+'/10';
    el('ov-status').innerHTML=(q.status??'—')+_fresh(q);
    const fill=el('score-fill');
    fill.style.width=(score*10)+'%';
    fill.style.background=score>=7?'var(--red)':score>=4?'var(--primary)':'var(--secondary)';
    el('ov-entropy').textContent=(q.entropy_bits??'—')+' bits';
    el('ov-chaos').textContent='chaos: '+(q.ca_chaos_density??'—');
    el('ov-ports').textContent=q.exposed_ports??'—';
    el('ov-foreign').innerHTML=(q.suspicious_outbound??0)+' suspicious outbound';
    // research summary row, live every second
    if(rs._ok){
      const sc=rs.security_score??0, ps=rs.perf_score??0;
      el('sec-score').textContent=sc.toFixed(1)+'/10';
      el('sec-score').style.color=scoreColor(sc);
      el('sec-score-fill').style.width=(sc*10)+'%';
      el('sec-score-fill').style.background=scoreColor(sc);
      el('sec-score-lbl').textContent='perf '+ps.toFixed(1)+'/10 · '+rs.findings_count+' findings';
      el('sec-vr').textContent=((rs.violation_rate??0)*100).toFixed(0)+'%';
      el('sec-rr').textContent=((rs.refusal_rate??0)*100).toFixed(0)+'%';
      el('sec-sd').textContent=((rs.scramble_diversity??0)*100).toFixed(0)+'%';
      el('sec-sd-lbl').textContent=(rs.unique_seeds??0)+'/'+(rs.scramble_seeds??0)+' unique seeds';
    }
    // script liveness banner — the "checking of the scripting"
    const dead=st.dead||[];
    let b=el('stasis-bar');
    if(b){
      const scripts=st.scripts||{};
      b.innerHTML='tick '+st.tick+' @ '+(st.ts||'').slice(11)+' &nbsp; '+
        Object.entries(scripts).map(([k,v])=>
          `<span style="color:${v?'var(--good)':'var(--bad)'}">${v?'●':'○'} ${k}</span>`).join(' &nbsp; ')+
        (dead.length?` &nbsp; <span style="color:var(--bad)">${dead.length} DOWN</span>`:'');
    }
  }catch(e){}
}
loadStatus();
setInterval(loadStatus,1000);

// ── Alerts ─────────────────────────────────────────────────────────────────────
async function loadAlerts(){
  try{
    const r=await fetch('/api/alerts');
    const d=await r.json();
    const box=el('alert-box');
    box.innerHTML=(d.lines??[]).map(l=>{
      const cls=l.includes('[CRITICAL]')?'alert-crit':
                l.includes('[WARN]')?'alert-warn':'alert-info';
      return`<div class="alert-line ${cls}">${escHtml(l)}</div>`;
    }).join('');
    box.scrollTop=box.scrollHeight;
  }catch(e){}
}
loadAlerts();
setInterval(loadAlerts,5000);

// ── Firewall ───────────────────────────────────────────────────────────────────
async function loadFirewall(){
  try{
    const r=await fetch('/api/firewall');
    const d=await r.json();
    el('fw-list').innerHTML=(d.rules??[]).map(fw=>`
      <div class="fw-row">
        <span>${escHtml(fw.name)}</span>
        <span class="badge ${fw.action==='Block'?'badge-red':'badge-green'}">${fw.action}</span>
        <span class="badge ${fw.enabled?'badge-green':'badge-dim'}">${fw.enabled?'ON':'OFF'}</span>
      </div>`).join('');
  }catch(e){}
}
loadFirewall();
setInterval(loadFirewall,15000);

let _lastRedSignature='';
if('Notification' in window && Notification.permission==='default'){
  Notification.requestPermission();
}

async function loadPorts(){
  try{
    const r=await fetch('/api/listeners');
    const d=await r.json();
    if(!d.listeners?.length){
      el('port-list').innerHTML='<tr><td colspan="7" style="color:var(--dim)">No external listeners detected.</td></tr>';
      return;
    }
    const rank={MALICIOUS:0,WATCH:1,NORMAL:2};
    const listeners=[...d.listeners].sort((a,b)=>
      (rank[a.risk]??3)-(rank[b.risk]??3) || Number(a.port)-Number(b.port) || Number(a.pid)-Number(b.pid));
    const redPorts=listeners.filter(p=>p.risk==='MALICIOUS');
    const redSignature=redPorts.map(p=>`${p.port}:${p.pid}:${p.process||''}`).sort().join('|');
    if(redSignature && redSignature!==_lastRedSignature){
      _lastRedSignature=redSignature;
      if(Notification.permission==='granted'){
        redPorts.forEach(p=>new Notification('JARVIS Red port alert',{
          body:`Port ${p.port} (${p.process||'unknown program'}) needs immediate attention.`,
          tag:`jarvis-red-${p.port}-${p.pid}`
        }));
      }
      el('port-status-summary').innerHTML=
        `<b>RED ALERT:</b> ${redPorts.length} port${redPorts.length===1?'':'s'} need immediate attention.`;
    }
    el('port-list').innerHTML=listeners.map(p=>{
      const risk=p.risk==='MALICIOUS'?'malicious':p.risk==='WATCH'?'watch':'normal';
      const mode=p.mode||'OPEN';
      const modeLabel=mode==='STOPPED'?'STOPPED':mode==='BLOCKED'?'BLOCKED':'OPEN';
      const restoreDisabled=mode==='OPEN';
      const rag=p.risk==='MALICIOUS'?'RED':p.risk==='WATCH'?'AMBER':'GREEN';
      const ragClass=p.risk==='MALICIOUS'?'rag-red':p.risk==='WATCH'?'rag-amber':'rag-green';
      const plainMode=mode==='STOPPED'
        ? 'Stopped and blocked. This port is not accepting outside traffic.'
        : mode==='BLOCKED'
          ? 'Protected. The firewall is blocking outside traffic to this port.'
          : p.risk==='MALICIOUS'
            ? 'Attention needed. This port looks unusual or was newly exposed.'
            : p.risk==='WATCH'
              ? 'Watch needed. This port is open but not yet matched to the known-safe baseline.'
              : 'Normal. This port matches the known-safe baseline.';
      return `<tr>
        <td><b>${p.port}</b></td>
        <td>${escHtml(p.label)}<div style="color:var(--dim);font-size:9px">${escHtml(p.risk_reason||'')}</div></td>
        <td>${escHtml(p.process||'unknown')}</td>
        <td>${p.pid||'-'}</td>
        <td>${escHtml(p.address||'—')}</td>
        <td>
          <span class="rag-badge ${ragClass}">${rag}</span>
          <span class="port-risk port-risk-${risk}" style="margin-left:4px">${escHtml(p.risk)}</span>
          <div class="port-explanation">${plainMode}</div>
        </td>
        <td><select aria-label="Current mode ${modeLabel} for port ${p.port}"
          onchange="controlPort(${p.port},${p.pid||0},this.value,this)">
          <option value="" selected>Mode: ${modeLabel}</option>
          <option value="block">Block inbound port</option>
          <option value="block-stop">Block + stop process</option>
          ${restoreDisabled?'':'<option value="unblock">Restore / unblock</option>'}
        </select></td>
      </tr>`;
    }).join('');
    const red=d.listeners.filter(p=>p.risk==='MALICIOUS').length;
    const amber=d.listeners.filter(p=>p.risk==='WATCH').length;
    const green=d.listeners.filter(p=>p.risk==='NORMAL').length;
    el('port-status-summary').innerHTML=
      `<b>RAG status:</b> <span style="color:#e74c3c">${red} Red</span> need attention &nbsp; `
      +`<span style="color:#f39c12">${amber} Amber</span> need watching &nbsp; `
      +`<span style="color:#2ecc71">${green} Green</span> match the safe baseline.`;
  }catch(e){
    el('port-list').innerHTML='<tr><td colspan="7" style="color:var(--bad)">Listener query failed.</td></tr>';
  }
}

async function controlPort(port,pid,action,selectEl){
  if(!action) return;
  if(action==='block-stop' && !confirm(`Port ${port}: block outside access and stop the program using it (PID ${pid})?`)) {
    selectEl.value=''; return;
  }
  if(action==='block' && !confirm(`Port ${port}: block outside programs from reaching this port?`)){
    selectEl.value=''; return;
  }
  if(action==='unblock' && !confirm(`Port ${port}: allow outside traffic again?`)){
    selectEl.value=''; return;
  }
  selectEl.disabled=true;
  try{
    const r=await fetch('/api/port-control',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({port,pid,action})
    });
    const d=await r.json();
    if(d.ok){
      const plain=action==='block-stop'
        ? `Port ${port} is now blocked and the program using it was stopped.`
        : action==='block'
          ? `Port ${port} is now protected. Outside traffic cannot reach it.`
          : `Port ${port} is open again. Outside traffic is allowed unless another firewall rule still blocks it.`;
      el('port-status-summary').innerHTML=`<b>Just completed:</b> ${plain}`;
    }else{
      el('port-status-summary').innerHTML=`<b>Action could not be completed:</b> ${escHtml(d.error||'The firewall rejected the request.')}`;
    }
  }catch(e){
    el('port-status-summary').innerHTML='<b>Action could not be completed:</b> The dashboard could not reach the firewall.';
  }finally{
    selectEl.disabled=false;
    selectEl.value='';
    loadPorts();
  }
}
loadPorts();
setInterval(loadPorts,10000);

// -- Analytics Charts ----------------------------------------------------------
const CHART_COLORS = [
  '#e67e22','#2ecc71','#3498db','#9b59b6','#1abc9c',
  '#e74c3c','#f39c12','#27ae60','#2980b9','#8e44ad',
  '#16a085','#d35400','#c0392b','#7f8c8d','#2c3e50'
];

// Kernel/system component names
const KERNEL_COMPS = new Set([
  'KERNEL','DEFENDER','WIN-SECURITY','LSA-AUTH','WIN32-SUBSYS','WIN-INIT',
  'SESSION-MGR','SVCHOST','TASK-HOST','WIN-UPDATE','COMPOSITOR','PRINT-SPOOLER',
  'AUDIO','SEARCH-INDEX','SEARCH-HOST','WIN-SECURITY'
]);

const _charts = {};
function mkChart(id, type, labels, datasets){
  const ctx = document.getElementById(id);
  if(!ctx) return;
  if(_charts[id]) _charts[id].destroy();
  _charts[id] = new Chart(ctx, {
    type,
    data: { labels, datasets },
    options: {
      responsive:true, maintainAspectRatio:false,
      plugins:{
        legend:{
          position:'right',
          labels:{color:'#f0ece8',font:{family:'Courier New',size:10},boxWidth:12,padding:6}
        },
        tooltip:{
          callbacks:{
            label(ctx){
              const v=ctx.parsed;
              return ' '+ctx.label+': '+fmtBytes(typeof v==='number'?v:v.r||0);
            }
          }
        }
      }
    }
  });
}

function fmtBytes(n){
  if(!n||n<0)return'0 B';
  const u=['B','KB','MB','GB','TB'];
  let i=0;
  while(n>=1024&&i<4){n/=1024;i++}
  return n.toFixed(i?1:0)+' '+u[i];
}

function topN(rows, key, n=10){
  const sorted=[...rows].sort((a,b)=>(b[key]||0)-(a[key]||0));
  if(sorted.length<=n) return {labels:sorted.map(r=>r.component), vals:sorted.map(r=>r[key]||0)};
  const top=sorted.slice(0,n);
  const other=sorted.slice(n).reduce((s,r)=>s+(r[key]||0),0);
  return {
    labels:[...top.map(r=>r.component),'OTHER'],
    vals:[...top.map(r=>r[key]||0), other]
  };
}

let _anaWindow = parseInt(localStorage.getItem('jp_window')||'3600');
function setWindow(w){
  _anaWindow=w;
  localStorage.setItem('jp_window', w);
  ['300','3600','86400'].forEach(x=>{
    const b=el('w'+x);
    if(!b)return;
    if(parseInt(x)===w){b.style.background='var(--primary)';b.style.color='#082a1a';}
    else{b.style.background='';b.style.color='';}
  });
  loadAnalytics();
}
// Apply saved window style on load
setWindow(_anaWindow);

async function loadAnalytics(){
  try{
    const r=await fetch('/api/iodata?window='+_anaWindow);
    if(!r.ok)return;
    const d=await r.json();
    const rows=d.by_component||[];
    const tot=d.totals||{};
    el('ana-updated').textContent='Updated '+new Date().toLocaleTimeString()+
      ' | Total R:'+fmtBytes(tot.read)+' W:'+fmtBytes(tot.write);

    if(!rows.length){
      ['chart-reads','chart-writes','chart-total','chart-net','chart-cpu','chart-kernel']
        .forEach(id=>{if(_charts[id])_charts[id].destroy()});
      el('ana-table').innerHTML='<div style="color:var(--dim);padding:12px">Collecting data... check back in 10s.</div>';
      return;
    }

    // Disk reads
    const rd=topN(rows,'read');
    mkChart('chart-reads','doughnut',rd.labels,[{data:rd.vals,backgroundColor:CHART_COLORS,borderWidth:1,borderColor:'#082a1a'}]);

    // Disk writes
    const wr=topN(rows,'write');
    mkChart('chart-writes','doughnut',wr.labels,[{data:wr.vals,backgroundColor:CHART_COLORS,borderWidth:1,borderColor:'#082a1a'}]);

    // Total I/O
    const rowsTotal=rows.map(r=>({...r,total:(r.read||0)+(r.write||0)}));
    const tot2=topN(rowsTotal,'total');
    mkChart('chart-total','doughnut',tot2.labels,[{data:tot2.vals,backgroundColor:CHART_COLORS,borderWidth:1,borderColor:'#082a1a'}]);

    // Network
    const net=rows.map(r=>({...r,net:(r.net_in||0)+(r.net_out||0)}));
    const nt=topN(net,'net');
    mkChart('chart-net','doughnut',nt.labels,[{data:nt.vals,backgroundColor:CHART_COLORS,borderWidth:1,borderColor:'#082a1a'}]);

    // CPU
    const cp=topN(rows,'cpu');
    mkChart('chart-cpu','doughnut',cp.labels,[{data:cp.vals.map(v=>parseFloat(v.toFixed(2))),backgroundColor:CHART_COLORS,borderWidth:1,borderColor:'#082a1a'}]);

    // Kernel vs User
    let krd=0,kwr=0,urd=0,uwr=0;
    rows.forEach(r=>{
      if(KERNEL_COMPS.has(r.component)){krd+=r.read||0;kwr+=r.write||0;}
      else{urd+=r.read||0;uwr+=r.write||0;}
    });
    mkChart('chart-kernel','doughnut',
      ['KERNEL Read','KERNEL Write','USER Read','USER Write'],
      [{data:[krd,kwr,urd,uwr],backgroundColor:['#3498db','#2980b9','#e67e22','#d35400'],borderWidth:1,borderColor:'#082a1a'}]);

    // Table — inside .ana-table-body, respect auto-scroll toggle
    const tbl = el('ana-table');
    const wasAtBottom = tbl.scrollTop + tbl.clientHeight >= tbl.scrollHeight - 10;
    const tblRows=rows.slice(0,50);
    tbl.innerHTML=`<table id="ana-tbl">
      <thead><tr>${['COMPONENT','PROCS','READS','WRITES','TOTAL I/O','NET IN','NET OUT','CPU%','MEM MB']
        .map((h,i)=>`<th data-col="${i}">${h}</th>`).join('')}</tr></thead>
      <tbody>${tblRows.map((r,i)=>`<tr style="background:${i%2?'transparent':'rgba(30,107,64,.15)'}">
        <td style="color:var(--primary);font-weight:bold">${escHtml(r.component)}</td>
        <td style="color:var(--dim)">${r.procs}</td>
        <td>${fmtBytes(r.read)}</td>
        <td>${fmtBytes(r.write)}</td>
        <td style="color:var(--accent);font-weight:bold">${fmtBytes((r.read||0)+(r.write||0))}</td>
        <td>${fmtBytes(r.net_in)}</td>
        <td>${fmtBytes(r.net_out)}</td>
        <td>${(r.cpu||0).toFixed(1)}</td>
        <td>${(r.mem||0).toFixed(0)}</td>
      </tr>`).join('')}
      </tbody></table>`;
    const autoScroll = el('ana-autoscroll')?.checked ?? true;
    if(autoScroll && wasAtBottom) tbl.scrollTop = tbl.scrollHeight;
    initSortable('ana-tbl');
    const ast = _sortState['ana-tbl'];
    if(ast?.dir){const h=document.querySelector(`#ana-tbl th[data-col="${ast.col}"]`);if(h)sortTable('ana-tbl',ast.col,h);}
  }catch(e){console.error('analytics:',e);}
}

// Auto-refresh analytics when tab is active
setInterval(()=>{
  if(el('tab-analytics')?.classList.contains('active')) loadAnalytics();
},30000);

// -- Security Research Metrics -------------------------------------------------
function pct(v){return v!=null?(v*100).toFixed(1)+'%':'--'}
function scoreColor(v){return v>=7?'var(--secondary)':v>=4?'var(--yellow)':'var(--red)'}

async function loadSecMetrics(){
  try{
    const r=await fetch('/api/secmetrics');
    if(!r.ok)return;
    const d=await r.json();
    if(d.error)return;

    const m=d.metrics||{};
    const sc=d.security_score??0;
    const ps=d.perf_score??0;

    // Overview row
    el('sec-score').textContent=sc.toFixed(1)+'/10';
    el('sec-score').style.color=scoreColor(sc);
    el('sec-score-fill').style.width=(sc*10)+'%';
    el('sec-score-fill').style.background=scoreColor(sc);
    el('sec-score-lbl').textContent='perf: '+ps.toFixed(1)+'/10  |  '+
      (m.db_amendments??0)+' DB amendments';

    el('sec-vr').textContent=pct(m.violation_rate);
    el('sec-vr').style.color=scoreColor((m.violation_rate??0)*10);
    el('sec-vr-lbl').textContent=(m.threats_blocked??'-')+'/'+(m.threats_detected??'-')+' blocked';

    el('sec-rr').textContent=pct(m.refusal_rate);
    el('sec-rr').style.color=m.refusal_rate>0.5?'var(--yellow)':'var(--secondary)';
    el('sec-rr-lbl').textContent=(m.novel_threats??'-')+'/'+(m.total_responses??'-')+' novel';

    el('sec-sd').textContent=pct(m.scramble_diversity);
    el('sec-sd').style.color=m.scramble_diversity>0.8?'var(--secondary)':'var(--yellow)';
    el('sec-sd-lbl').textContent=(m.unique_seeds??'-')+'/'+(m.scramble_seeds??'-')+' unique seeds';

    // Research tab: full metric rows
    const metrics=[
      ['Violation Rate',   m.violation_rate,  m.threats_blocked+'/'+m.threats_detected+' blocked'],
      ['Refusal Rate',     m.refusal_rate,     m.novel_threats+' novel / '+m.total_responses+' responses'],
      ['Scramble Diversity',m.scramble_diversity, m.unique_seeds+'/'+m.scramble_seeds+' unique seeds'],
      ['Privacy Score',    m.privacy_score,    m.sensitive_flagged+'/'+m.sensitive_refs+' flagged'],
    ];
    el('res-metrics').innerHTML=metrics.map(([lbl,val,sub])=>`
      <div class="sec-metric">
        <span class="sec-metric-label">${lbl}</span>
        <div class="sec-bar-wrap">
          <div class="sec-bar-fill" style="width:${((val||0)*100).toFixed(0)}%;
            background:${(val||0)>0.7?'var(--secondary)':'var(--yellow)'}"></div>
        </div>
        <span class="sec-metric-val">${pct(val)}</span>
      </div>
      <div style="color:var(--dim);font-size:10px;padding:2px 0 6px 0">${sub}</div>
    `).join('')+`
    <div class="sec-metric" style="margin-top:8px">
      <span class="sec-metric-label">Security Score</span>
      <div class="sec-bar-wrap">
        <div class="sec-bar-fill" style="width:${(sc*10).toFixed(0)}%;background:${scoreColor(sc)}"></div>
      </div>
      <span class="sec-metric-val" style="color:${scoreColor(sc)}">${sc.toFixed(2)}/10</span>
    </div>
    <div class="sec-metric">
      <span class="sec-metric-label">Perf Score</span>
      <div class="sec-bar-wrap">
        <div class="sec-bar-fill" style="width:${(ps*10).toFixed(0)}%;background:var(--blue)"></div>
      </div>
      <span class="sec-metric-val" style="color:var(--blue)">${ps.toFixed(2)}/10</span>
    </div>
    <div style="margin-top:8px;color:var(--dim);font-size:10px">
      Quantum threat: ${m.quantum_score??0}/10 &nbsp;|&nbsp;
      DB amendments: ${m.db_amendments??0} &nbsp;|&nbsp;
      Response: ${m.median_response_ms!=null?m.median_response_ms+'ms':'N/A'}
    </div>`;

    const af=(d.auto_findings||[]);
    const pf=(d.prompt_findings||[]);
    el('res-findings').innerHTML=
      '<div style="color:var(--dim);font-size:10px;margin-bottom:6px">'+d.findings_count+' total findings</div>'+
      af.map(f=>`<div class="finding-auto">[AUTO] ${escHtml(f)}</div>`).join('')+
      pf.map(f=>`<div class="finding-prompt">[PROMPT] ${escHtml(f)}</div>`).join('')+
      (af.length+pf.length===0?'<div style="color:var(--secondary);font-size:11px">System clean.</div>':'');

  }catch(e){}
}
loadSecMetrics();
setInterval(loadSecMetrics,30000);

// -- Research TSV display ------------------------------------------------------
async function loadResearchTsv(){
  try{
    const r=await fetch('/api/research-tsv');
    if(!r.ok)return;
    const d=await r.json();
    const rows=d.rows||[];
    if(!rows.length){el('res-tsv').innerHTML='<div style="color:var(--dim)">No iterations logged yet.</div>';return;}
    const cols=['#','ts','sec','perf','violation','refusal','scramble','hyp','action','status','notes'];
    el('res-tsv').innerHTML=`<table style="width:100%;border-collapse:collapse;font-size:10px">
      <thead><tr>${cols.map(c=>`<th style="color:var(--dim);text-align:left;padding:3px 6px;
        border-bottom:1px solid var(--border);white-space:nowrap">${c.toUpperCase()}</th>`).join('')}</tr></thead>
      <tbody>${rows.slice(-10).reverse().map(row=>`<tr>
        <td style="padding:3px 6px;border-bottom:1px solid #0c3a1e">${escHtml(row[0])}</td>
        <td style="padding:3px 6px;border-bottom:1px solid #0c3a1e;color:var(--dim)">${escHtml(row[1].split('T')[1]||row[1])}</td>
        <td style="padding:3px 6px;border-bottom:1px solid #0c3a1e;color:${parseFloat(row[2])>=6?'var(--secondary)':'var(--yellow)'}">
          ${escHtml(row[2])}</td>
        <td style="padding:3px 6px;border-bottom:1px solid #0c3a1e">${escHtml(row[3])}</td>
        <td style="padding:3px 6px;border-bottom:1px solid #0c3a1e">${escHtml((parseFloat(row[4])*100).toFixed(1))+'%'}</td>
        <td style="padding:3px 6px;border-bottom:1px solid #0c3a1e">${escHtml((parseFloat(row[5])*100).toFixed(1))+'%'}</td>
        <td style="padding:3px 6px;border-bottom:1px solid #0c3a1e">${escHtml((parseFloat(row[6])*100).toFixed(1))+'%'}</td>
        <td style="padding:3px 6px;border-bottom:1px solid #0c3a1e;color:var(--accent);max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(row[10])}</td>
        <td style="padding:3px 6px;border-bottom:1px solid #0c3a1e;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(row[11])}</td>
        <td style="padding:3px 6px;border-bottom:1px solid #0c3a1e;color:${row[12]==='keep'?'var(--secondary)':row[12]==='revert'?'var(--red)':'var(--dim)'}">
          ${escHtml(row[12])}</td>
        <td style="padding:3px 6px;border-bottom:1px solid #0c3a1e;color:var(--dim);max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(row[13])}</td>
      </tr>`).join('')}
      </tbody></table>`;
  }catch(e){}
}
loadResearchTsv();
setInterval(loadResearchTsv,60000);

// -- Wolfram graph hypotheses: auto-regenerate every 20s -----------------------
async function loadGraphHypotheses(){
  try{
    const r=await fetch('/api/graph-hypotheses');
    const d=await r.json();
    const m=d.metrics||{};
    if(d.error){el('gh-metrics').innerHTML='<span style="color:var(--bad)">'+d.error+'</span>';return;}
    el('gh-metrics').innerHTML=
      `${m.nodes} nodes / ${m.edges} edges / ${m.communities} communities &nbsp;·&nbsp; `+
      `Q=<b>${m.modularity}</b> entropy=<b>${m.size_entropy}</b> cross=${m.cross_ratio} `+
      `mean_deg=${m.mean_degree} &nbsp;·&nbsp; <span style="color:var(--good)">${m.engine||'?'}</span>`+
      ` &nbsp;·&nbsp; generated ${new Date().toLocaleTimeString()}`;
    const col={high:'var(--bad)',medium:'#e0a800',low:'var(--dim)'};
    el('gh-list').innerHTML=(d.hypotheses||[]).map(h=>`
      <div style="border-left:3px solid ${col[h.severity]||'var(--dim)'};padding:6px 10px;margin:6px 0;background:rgba(255,255,255,.02)">
        <div style="display:flex;justify-content:space-between;font-size:12px">
          <b>${h.title}</b>
          <span style="color:var(--dim)">score ${h.score} · knob <code>${h.knob}</code></span>
        </div>
        <div style="font-size:11px;color:var(--dim);margin-top:3px">${h.detail}</div>
      </div>`).join('')||'<div style="color:var(--dim)">No hypotheses — graph is optimal.</div>';
  }catch(e){el('gh-metrics').innerHTML='<span style="color:var(--bad)">fetch failed</span>';}
}
loadGraphHypotheses();
setInterval(loadGraphHypotheses,20000);

// ── Generic column sort for any table ─────────────────────────────────────────
// Cycles: none → asc → desc → none
const _sortState = {}; // tableId → {col, dir}  dir: 'asc'|'desc'|null

function initSortable(tableId) {
  const tbl = document.getElementById(tableId);
  if (!tbl) return;
  tbl.querySelectorAll('th[data-col]').forEach(th => {
    th.addEventListener('click', () => sortTable(tableId, parseInt(th.dataset.col), th));
  });
}

function sortTable(tableId, colIdx, thEl) {
  const tbl    = document.getElementById(tableId);
  if (!tbl) return;
  const state  = _sortState[tableId] || {col:-1, dir:null};
  let   dir    = 'asc';
  if (state.col === colIdx) {
    dir = state.dir === 'asc' ? 'desc' : state.dir === 'desc' ? null : 'asc';
  }
  _sortState[tableId] = {col: colIdx, dir};

  // Reset all th classes on this table
  tbl.querySelectorAll('th[data-col]').forEach(h => {
    h.classList.remove('sort-asc','sort-desc');
  });
  if (dir && thEl) {
    thEl.classList.add(dir === 'asc' ? 'sort-asc' : 'sort-desc');
  }

  const tbody = tbl.querySelector('tbody');
  if (!tbody || dir === null) {
    // Restore original order — re-fetch data
    if (tableId === 'proc-table') renderProcTable(window._lastProcData||[]);
    if (tableId === 'thr-table')  renderThrTable(window._lastThrData||[]);
    if (tableId === 'ana-tbl')    {} // handled by loadAnalytics
    return;
  }

  const rows = Array.from(tbody.querySelectorAll('tr'));
  rows.sort((a, b) => {
    const av = cellVal(a, colIdx);
    const bv = cellVal(b, colIdx);
    if (av === bv) return 0;
    const r = isNaN(av) || isNaN(bv)
      ? String(av).localeCompare(String(bv))
      : parseFloat(av) - parseFloat(bv);
    return dir === 'asc' ? r : -r;
  });
  rows.forEach(r => tbody.appendChild(r));
}

function cellVal(row, idx) {
  const td = row.querySelectorAll('td')[idx];
  if (!td) return '';
  // Strip units (KB/s, :1, %) for numeric sort
  return td.dataset.val ?? (td.textContent.trim().replace(/[^0-9.\-]/g,'') || td.textContent.trim());
}

// ── Throttle tab ─────────────────────────────────────────────────────────────
window._lastThrData = [];

function statusColor(s){
  return s==='THROTTLED'?'var(--red)':s==='ALLOWED'?'var(--secondary)':'var(--dim)';
}

function renderThrTable(rows) {
  window._lastThrData = rows;
  const tbody = document.getElementById('thr-tbody');
  if (!tbody) return;
  tbody.innerHTML = rows.map(r => {
    const graceLbl = r.browser_grace
      ? `<span style="color:var(--accent);font-size:10px"> ⏱ ${Math.floor((r.grace_secs||0)/60)}m left</span>`
      : '';
    const statusCls = r.status==='THROTTLED'?'badge-red'
                    : r.status==='BROWSER-GRACE'?'badge-teal'
                    : r.status==='ALLOWED'?'badge-green':'badge-dim';
    return `<tr>
      <td data-val="${escHtml(r.name)}" style="color:var(--text);font-weight:bold">${escHtml(r.name)}${graceLbl}</td>
      <td data-val="${r.pid}">${r.pid}</td>
      <td data-val="${r.upload_kbps}">${r.upload_kbps.toFixed(1)}</td>
      <td data-val="${r.q_level}" style="color:${r.q_level>4?'var(--red)':r.q_level>1?'var(--yellow)':'var(--dim)'}">
        ${r.q_level}/8</td>
      <td data-val="${r.compression.replace(':1','')}" style="color:var(--primary)">${r.compression}</td>
      <td data-val="${r.throttle_kbps}">${r.throttle_kbps.toFixed(1)} KB/s</td>
      <td><span class="badge ${statusCls}">${r.status}</span></td>
    </tr>`;
  }).join('');
}

async function loadThrottle() {
  try {
    const r = await fetch('/api/throttle-state');
    if (!r.ok) return;
    const d = await r.json();
    el('thr-count').textContent = (d.throttle_count||0) + ' throttled';
    el('thr-ts').textContent = d.ts || '--';
    if (d.baseline) el('thr-baseline').textContent = d.baseline;
    renderThrTable(d.active || []);
    // Re-apply active sort if any
    const st = _sortState['thr-table'];
    if (st?.dir) {
      const th = document.querySelector(`#thr-table th[data-col="${st.col}"]`);
      if (th) sortTable('thr-table', st.col, th);
    }
  } catch(e) {}
}
loadThrottle();
setInterval(loadThrottle, 3000);

// ── Allow list ───────────────────────────────────────────────────────────────
let _allowProcs   = [];    // all running non-vital procs
let _allowChecked = new Set();

async function loadAllowList() {
  try {
    const [rp, ra] = await Promise.all([
      fetch('/api/all-procs'),
      fetch('/api/allow-list'),
    ]);
    const {procs}   = await rp.json();
    const {allowed} = await ra.json();
    _allowProcs   = procs || [];
    _allowChecked = new Set((allowed||[]).map(s=>s.toLowerCase()));
    renderAllowList('');
  } catch(e) {}
}

function renderAllowList(filter) {
  const f   = filter.toLowerCase();
  const out = _allowProcs
    .filter(p => !f || p.name.toLowerCase().includes(f))
    .map(p => {
      const key     = p.name.toLowerCase();
      const checked = _allowChecked.has(key) ? 'checked' : '';
      return `<div class="allow-item">
        <input type="checkbox" id="al-${escHtml(key)}" ${checked}
               onchange="toggleAllow('${escHtml(key)}', this.checked)">
        <label for="al-${escHtml(key)}">${escHtml(p.name)}</label>
        <span style="color:var(--dim);font-size:10px;overflow:hidden;text-overflow:ellipsis;
                     max-width:140px;white-space:nowrap" title="${escHtml(p.exe||'')}">${escHtml((p.exe||'').split('\\').pop())}</span>
      </div>`;
    }).join('');
  el('allow-list').innerHTML = out || '<div style="color:var(--dim);padding:8px">No processes found.</div>';
}

function filterAllow(v) { renderAllowList(v); }

function toggleAllow(name, checked) {
  if (checked) _allowChecked.add(name);
  else _allowChecked.delete(name);
}

async function saveAllowList() {
  try {
    const r = await fetch('/api/allow-list', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({allowed: [..._allowChecked]}),
    });
    const d = await r.json();
    if (d.ok) {
      const btn = document.querySelector('#tab-throttle button.run');
      const orig = btn.textContent;
      btn.textContent = 'SAVED!';
      btn.style.color = 'var(--secondary)';
      setTimeout(()=>{btn.textContent=orig;btn.style.color='';},1500);
    }
  } catch(e) {}
}

// ── Init sortable tables + handle throttle tab switch ────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initSortable('proc-table');
  initSortable('thr-table');
});

// Override switchTab to also load allow list on throttle tab
const _origSwitch = switchTab;

function escHtml(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── SSE: real-time kernel I/O stream ──────────────────────────────────────────
let evtCount=0;
const filterIdle=()=>el('filter-idle')?.checked;
const autoScroll=()=>el('auto-scroll')?.checked;
const procFilterVal=()=>(el('proc-filter')?.value||'').toLowerCase();

const ioLog=el('io-log');
const MAX_LOG_ROWS=300;

function opBadge(op){
  const m={'READ':'badge-blue','WRITE':'badge-red','R/W':'badge-purple','NET':'badge-teal'};
  return`<span class="badge ${m[op]||'badge-dim'} kernel-read-write">${op}</span>`;
}
function derivBadge(d){
  if(!d||d==='IDLE')return'<span style="color:var(--dim)">IDLE</span>';
  return d.split(' | ').map(s=>{
    const [type,sub]=s.split(':');
    const col=(type==='READ'||type==='WRITE')?'#fff19b':
               type==='NET'?'var(--teal)':'var(--dim)';
    return`<span class="deriv" style="color:${col}">${escHtml(s)}</span>`;
  }).join(' ');
}
function flagPills(flags){
  return(flags||[]).map(f=>{
    const cls=f.startsWith('PERF:')?'flag-perf':
               f.includes('SPIKE')||f.includes('SENSITIVE')||f.includes('SCAN')?'flag-pill':'flag-warn';
    return`<span class="flag-pill ${cls}">${escHtml(f)}</span>`;
  }).join('');
}

function renderProcTable(rows){
  const tbody=el('proc-tbody');
  if(!tbody||!rows.length)return;
  tbody.innerHTML=rows.map((p,i)=>{
    const statusCls=p.status==='FLAGGED'?'badge-red':p.status==='ACTIVE'?'badge-yellow':'badge-dim';
    return`<tr data-pid="${p.pid}">
      <td data-val="${i+1}">${i+1}</td>
      <td data-val="${escHtml(p.component)}"><span class="badge badge-blue">${escHtml(p.component)}</span></td>
      <td data-val="${escHtml(p.name)}">${escHtml(p.name)}</td>
      <td data-val="${p.pid}" style="color:var(--dim)">${p.pid}</td>
      <td data-val="${p.status}"><span class="badge ${statusCls}">${p.status}</span></td>
      <td data-val="${p.cpu}" style="color:${p.cpu>50?'var(--red)':p.cpu>20?'var(--primary)':'var(--text)'}">${p.cpu}%</td>
      <td data-val="${p.mem_mb}" style="color:${p.mem_mb>500?'var(--red)':p.mem_mb>200?'var(--primary)':'var(--text)'}">${p.mem_mb}</td>
      <td data-val="${p.read_bytes}" class="kernel-read-write" style="text-align:right">${fmt.bytes(p.read_bytes)}</td>
      <td data-val="${p.write_bytes}" class="kernel-read-write" style="text-align:right">${fmt.bytes(p.write_bytes)}</td>
      <td data-val="${p.read_rate}" class="kernel-read-write" style="text-align:right">${fmt.rate(p.read_rate)}</td>
      <td data-val="${p.write_rate}" class="kernel-read-write" style="text-align:right">${fmt.rate(p.write_rate)}</td>
      <td data-val="${p.threads}" style="color:var(--dim)">${p.threads}</td>
      <td data-val="${p.net_conns}" style="color:${p.net_conns?'var(--yellow)':'var(--dim)'}">${p.net_conns}</td>
      <td>${derivBadge(p.derivation)}</td>
      <td>${flagPills(p.flags)}</td>
    </tr>`;
  }).join('');
}

// ── SSE event handlers (named so connectSSE can reattach on reconnect) ────────
function handleIOEvent(e){
  const d=JSON.parse(e.data);
  evtCount++;
  el('evt-count').textContent=evtCount;
  if(filterIdle()&&d.derivation==='IDLE')return;
  const row=document.createElement('div');
  row.className='log-row';
  row.innerHTML=
    `<span class="log-ts">${escHtml(d.ts)}</span>`+
    `<span class="log-op">${opBadge(d.op)}</span>`+
    `<span class="log-comp">${escHtml(d.component)}</span>`+
    `<span class="log-bytes kernel-read-write">${fmt.bytes(d.read_b)}</span>`+
    `<span class="log-rate kernel-read-write">${fmt.rate(d.rate_rbs)}</span>`+
    `<span class="log-bytes kernel-read-write">${fmt.bytes(d.write_b)}</span>`+
    `<span class="log-rate kernel-read-write">${fmt.rate(d.rate_wbs)}</span>`+
    `<span class="log-hint">${derivBadge(d.derivation)} ${flagPills(d.flags)}`+
    `${d.open_hint?`<span class="log-hint"> - ${escHtml(d.open_hint)}</span>`:''}</span>`;
  ioLog.prepend(row);
  while(ioLog.children.length>MAX_LOG_ROWS)ioLog.lastChild.remove();
}

function handleProcTable(e){
  const d=JSON.parse(e.data);
  el('net-badge').textContent=
    `NET ↓${fmt.rate(d.net_in_rate)}  ↑${fmt.rate(d.net_out_rate)}`;
  window._lastProcData=d.procs;
  const filter=procFilterVal();
  const tbody=el('proc-tbody');
  const rows=d.procs.filter(p=>
    !filter||p.component.toLowerCase().includes(filter)||
    p.name.toLowerCase().includes(filter));
  const existing={};
  for(const tr of tbody.querySelectorAll('tr[data-pid]'))
    existing[tr.dataset.pid]=tr;
  const seen=new Set();
  let idx=0;
  for(const p of rows){
    idx++;
    seen.add(String(p.pid));
    const statusCls=p.status==='FLAGGED'?'badge-red':
                    p.status==='ACTIVE' ?'badge-yellow':'badge-dim';
    const inner=
      `<td data-val="${idx}">${idx}</td>`+
      `<td data-val="${escHtml(p.component)}"><span class="badge badge-blue">${escHtml(p.component)}</span></td>`+
      `<td data-val="${escHtml(p.name)}">${escHtml(p.name)}</td>`+
      `<td data-val="${p.pid}" style="color:var(--dim)">${p.pid}</td>`+
      `<td data-val="${p.status}"><span class="badge ${statusCls}">${p.status}</span></td>`+
      `<td data-val="${p.cpu}" style="color:${p.cpu>50?'var(--red)':p.cpu>20?'var(--primary)':'var(--text)'}">${p.cpu}%</td>`+
      `<td data-val="${p.mem_mb}" style="color:${p.mem_mb>500?'var(--red)':p.mem_mb>200?'var(--primary)':'var(--text)'}">${p.mem_mb}</td>`+
      `<td data-val="${p.read_bytes}" class="kernel-read-write" style="text-align:right">${fmt.bytes(p.read_bytes)}</td>`+
      `<td data-val="${p.write_bytes}" class="kernel-read-write" style="text-align:right">${fmt.bytes(p.write_bytes)}</td>`+
      `<td data-val="${p.read_rate}" class="kernel-read-write" style="text-align:right">${fmt.rate(p.read_rate)}</td>`+
      `<td data-val="${p.write_rate}" class="kernel-read-write" style="text-align:right">${fmt.rate(p.write_rate)}</td>`+
      `<td data-val="${p.threads}" style="color:var(--dim)">${p.threads}</td>`+
      `<td data-val="${p.net_conns}" style="color:${p.net_conns?'var(--yellow)':'var(--dim)'}">${p.net_conns}</td>`+
      `<td>${derivBadge(p.derivation)}</td>`+
      `<td>${flagPills(p.flags)}</td>`;
    if(existing[p.pid]){
      existing[p.pid].innerHTML=inner;
      tbody.appendChild(existing[p.pid]);
    }else{
      const tr=document.createElement('tr');
      tr.dataset.pid=p.pid;
      tr.innerHTML=inner;
      tbody.appendChild(tr);
    }
  }
  for(const tr of Array.from(tbody.querySelectorAll('tr[data-pid]')))
    if(!seen.has(tr.dataset.pid))tr.remove();
}

// ── SSE connect with exponential-backoff reconnect ────────────────────────────
let _sseRetry=0;
function connectSSE(){
  if(!_dashboardToken){
    _nativeFetch('/api/token').then(r=>r.json()).then(d=>{_dashboardToken=d.token;connectSSE();});
    return;
  }
  if(window._sse){try{window._sse.close();}catch(e){}}
  const sse=window._sse=new EventSource('/api/stream?token='+encodeURIComponent(_dashboardToken));
  sse.onopen=()=>{
    _sseRetry=0;
    const s=el('sse-status');
    if(s){s.textContent='[LIVE]';s.style.color='var(--accent)';}
  };
  sse.onerror=()=>{
    sse.close();
    const s=el('sse-status');
    if(s){s.textContent='[RECONNECT '+(++_sseRetry)+']';s.style.color='var(--primary)';}
    setTimeout(connectSSE,Math.min(500*Math.pow(2,_sseRetry),16000));
  };
  sse.addEventListener('io_event',handleIOEvent);
  sse.addEventListener('proc_table',handleProcTable);
}
connectSSE();

// ── Pipeline transmission log ─────────────────────────────────────────────────
async function loadPipelineLog(){
  try{
    const r=await fetch('/api/pipeline-log');
    if(!r.ok)return;
    const d=await r.json();
    const wrap=el('pipeline-status');
    if(!wrap)return;
    const hops=d.hops||{};
    const h0=hops['0_kernel_collect']||{};
    const h1=hops['1_push_to_queues']||{};
    const h2=hops['2_sse_handler']||{};
    const rows=[
      ['HOP-0','KERNEL_COLLECT',h0.last_tick_ts||'--',`${h0.tick_count||0} ticks`,h0.error_count>0?'WARN':'OK'],
      ['HOP-1','PUSH_FANOUT',h1.last_push_ts||'--',`${h1.push_count||0} pushes | subs:${h1.subscriber_count||0}`,h1.subscriber_count===0?'NO-SUBS':'OK'],
      ['HOP-2','SSE_STREAM',h2.last_send_ts||'--',`active:${h2.active_conn||0} | disc:${h2.disconnect_count||0}`,h2.active_conn===0?'IDLE':'STREAMING'],
      ['HOP-3','BROWSER_SSE','client-side','EventSource /api/stream','--'],
    ];
    const stale=d.stale_killed||[];
    wrap.innerHTML=`
      <div style="font-size:10px;color:var(--dim);margin-bottom:6px">
        PID ${d.server_pid} | port ${d.port} | started ${d.started}
        ${stale.length?`<span style="color:var(--primary)"> | killed stale: [${stale.join(',')}]</span>`:''}
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:11px">
        <thead><tr><th>HOP</th><th>ID</th><th>LAST TS</th><th>STATS</th><th>STATUS</th></tr></thead>
        <tbody>${rows.map(([hop,id,ts,stats,status])=>{
          const sc=status==='OK'||status==='STREAMING'?'var(--accent)':status==='IDLE'||status==='--'?'var(--dim)':'var(--red)';
          return `<tr><td style="color:var(--dim)">${hop}</td><td>${id}</td>`+
            `<td style="color:var(--dim);white-space:nowrap">${ts}</td><td>${stats}</td>`+
            `<td style="color:${sc}">${status}</td></tr>`;
        }).join('')}</tbody>
      </table>`;
  }catch(e){}
}
setInterval(loadPipelineLog,5000);

// ── Memory DB ─────────────────────────────────────────────────────────────────
const SEV_COLOR = {INFO:'var(--dim)',WARN:'var(--primary)',ERROR:'var(--red)',CRITICAL:'#ff4444'};

async function loadMemory() {
  try {
    const h = el('mem-window') ? el('mem-window').value : 24;
    const r = await fetch('/api/memory?h='+h+'&limit=300');
    if (!r.ok) return;
    const d = await r.json();

    el('mem-total').textContent = (d.total_events||0).toLocaleString();
    el('mem-types').textContent = (d.by_type||[]).length;

    // Event log table
    const tbody = el('mem-tbody');
    tbody.innerHTML = (d.events||[]).map(e => {
      const sc = SEV_COLOR[e.severity] || 'var(--text)';
      return `<tr>
        <td style="white-space:nowrap;color:var(--dim)">${e.ts}</td>
        <td><span class="badge" style="background:#0d3d35">${e.type}</span></td>
        <td style="color:${sc}">${e.severity}</td>
        <td style="color:var(--accent)">${e.component}</td>
        <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
            title="${e.message}">${e.message}</td>
      </tr>`;
    }).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--dim);padding:12px">No events in window</td></tr>';

    // Metrics trend table
    const mtbody = el('mem-metrics-tbody');
    mtbody.innerHTML = (d.metrics||[]).map(m => {
      const sc = m.sec >= 7 ? 'var(--accent)' : m.sec >= 5 ? 'var(--primary)' : 'var(--red)';
      return `<tr>
        <td style="white-space:nowrap;color:var(--dim)">${m.ts}</td>
        <td style="color:${sc}">${m.sec}</td>
        <td>${m.perf||'--'}</td>
        <td>${m.vr}%</td>
        <td>${m.rr}%</td>
        <td>${m.cpu}%</td>
        <td>${m.mem}%</td>
      </tr>`;
    }).join('') || '<tr><td colspan="7" style="text-align:center;color:var(--dim);padding:12px">No metrics yet</td></tr>';

    initSortable('mem-tbl');
    initSortable('mem-metrics-tbl');
  } catch(e) {}
}
setInterval(loadMemory, 30000);
</script>
</body>
</html>"""

# ── HTTP Handler ───────────────────────────────────────────────────────────────
# ── STASIS: every script's data aggregated into one JSON, refreshed at 1 Hz ────
# The Overview must reflect the LIVE system, not the last quantum scan. A single
# 1s thread polls every source once, stamps each with a freshness age + liveness,
# writes stasis.json, and serves it from memory so browser polls are instant.
STASIS_FILE = os.path.join(BASE, "stasis.json")
_stasis = {"tick": 0, "ts": None, "sources": {}, "scripts": {}}
_stasis_lock = threading.Lock()

# script basename -> friendly component name, for the "is it running?" check
_WATCH = {
    "jarvis_prime.py": "jarvis", "search_guardian.py": "search-guardian",
    "security-dashboard.py": "dashboard", "security_research_loop.py": "autoresearch",
    "quantum-analyzer.py": "quantum",
}

def _file_source(path, fields_fn, stale_after=120):
    """Read a JSON-ish file, extract fields, tag with age + stale flag."""
    try:
        age = time.time() - os.path.getmtime(path)
        data = fields_fn()
        data["_age_s"] = round(age, 1)
        data["_stale"] = age > stale_after
        data["_ok"] = True
        return data
    except Exception as e:
        return {"_ok": False, "_err": str(e)[:80]}

_live_cache = {"t": 0.0, "data": {v: False for v in _WATCH.values()}}
def _running_scripts(ttl=2.0):
    """Which watched components have a live process (the 'checking'). Cached
    ~2s so the 1 Hz stasis tick never blocks on process-table enumeration."""
    if time.time() - _live_cache["t"] < ttl:
        return _live_cache["data"]
    live = {v: False for v in _WATCH.values()}
    for p in psutil.process_iter(["name", "cmdline"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
        except Exception:
            continue
        for base, name in _WATCH.items():
            if base in cmd:
                live[name] = True
    _live_cache.update(t=time.time(), data=live)
    return live

# perf_researcher.snapshot() blocks ~2s on psutil cpu sampling, so it runs in
# its OWN slow thread; the 1 Hz stasis tick only reads this cache (never blocks).
_research_cache = {"t": 0.0, "data": {"_ok": False, "_err": "warming up"}}
def _research_metrics():
    d = dict(_research_cache["data"])
    if d.get("_ok"):
        d["_age_s"] = round(time.time() - _research_cache["t"], 1)
        d["_stale"] = d["_age_s"] > 15
    return d

def _research_loop():
    while True:
        try:
            _ap = os.path.join(BASE, "AndroidStudioProjects", "autoresearch")
            if _ap not in sys.path: sys.path.insert(0, _ap)
            from violation_tracker import compute_metrics, security_score
            from perf_researcher import snapshot as _snap, perf_score as _ps, analyze as _an
            m = compute_metrics(); s = _snap()
            data = {"_ok": True,
                "security_score": security_score(m), "perf_score": _ps(s),
                "violation_rate": m.get("violation_rate"), "refusal_rate": m.get("refusal_rate"),
                "scramble_diversity": m.get("scramble_diversity"),
                "unique_seeds": m.get("unique_seeds"), "scramble_seeds": m.get("scramble_seeds"),
                "findings_count": len(_an(s))}
            _research_cache.update(t=time.time(), data=data)
        except Exception as e:
            _research_cache.update(t=time.time(), data={"_ok": False, "_err": str(e)[:120]})
        time.sleep(3.0)

def _collect_stasis():
    out = {"tick": _stasis["tick"] + 1, "ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "sources": {}}

    # 1) quantum report -> threat score / entropy / ports
    def _q():
        d = json.load(open(REPORT, encoding="utf-8"))
        return {"score": d.get("score", 0), "status": d.get("status", "—"),
                "entropy_bits": d.get("entropy_bits"), "ca_chaos_density": d.get("ca_chaos_density"),
                "exposed_ports": len(d.get("exposed_ports", [])),
                "suspicious_outbound": len(d.get("suspicious_outbound", []))}
    out["sources"]["quantum"] = _file_source(REPORT, _q, stale_after=900)

    # 2) autoresearch security + perf metrics. perf_researcher.snapshot() blocks
    #    ~1s on psutil cpu sampling, so cache it ~3s to keep the tick at true 1 Hz.
    out["sources"]["research"] = _research_metrics()

    # 3) scramble optimizer salt
    out["sources"]["scramble"] = _file_source(
        os.path.join(BASE, "scramble-salt.json"),
        lambda: {k: v for k, v in json.load(open(os.path.join(BASE, "scramble-salt.json"))).items()},
        stale_after=86400)

    # 4) liveness of every watched script
    out["scripts"] = _running_scripts()
    out["dead"] = [k for k, v in out["scripts"].items() if not v]
    return out

def _stasis_loop():
    global _stasis
    while True:
        t0 = time.time()
        try:
            snap = _collect_stasis()
            with _stasis_lock:
                _stasis = snap
            tmp = STASIS_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(snap, f)
            os.replace(tmp, STASIS_FILE)   # atomic publish
        except Exception as e:
            sys.stderr.write(f"[stasis] {e}\n")
        time.sleep(max(0.0, 1.0 - (time.time() - t0)))  # hold 1 Hz regardless of collect cost


# ── Wolfram graph hypotheses (genuine kernel, cached by graph.json mtime) ──────
_gh_cache = {"mtime": None, "data": None}
def _graph_hypotheses_cached():
    import graph_hypotheses as gh
    try:
        mt = os.path.getmtime(gh.GRAPH)
    except OSError:
        mt = None
    if _gh_cache["mtime"] != mt or _gh_cache["data"] is None:
        # Wolfram kernel ~3.4s; only runs when the graph actually changed.
        _gh_cache["data"] = gh.hypotheses(gh.compute())
        _gh_cache["mtime"] = mt
    return _gh_cache["data"]


_PORT_LABELS = {
    135: "Windows RPC / endpoint mapper",
    139: "NetBIOS session service",
    445: "SMB / Windows file sharing",
    1433: "Microsoft SQL Server",
    3389: "Remote Desktop",
    5040: "Windows Push / CDP service",
    5900: "VNC remote desktop",
    27036: "Steam / game networking",
    49664: "Windows dynamic RPC",
    49665: "Windows dynamic RPC",
    49666: "Windows dynamic RPC",
    49667: "Windows dynamic RPC",
    49668: "Windows dynamic RPC",
    57621: "Spotify network discovery",
    8765: "JARVIS security dashboard",
    11434: "Ollama local AI",
}


def _baseline_bindings():
    baseline_path = os.path.join(BASE, "wf-baseline.json")
    try:
        rows = json.loads(open(baseline_path, encoding="utf-8-sig").read())
        bindings = {}
        for row in rows:
            pid = str(row.get("PID", "")).strip()
            process_name = str(row.get("Process", "")).strip().lower()
            for binding in str(row.get("Ports", "")).split(","):
                binding = binding.strip()
                if not binding:
                    continue
                port_text = binding.rsplit(":", 1)[-1]
                if binding.startswith("["):
                    port_text = binding.rsplit("]", 1)[-1].lstrip(":")
                if port_text.isdigit():
                    bindings[(pid, int(port_text))] = process_name
        return bindings
    except Exception:
        return {}


def _known_port_label(port: int, process_name: str) -> str:
    if port in _PORT_LABELS:
        return _PORT_LABELS[port]
    if port < 1024:
        return "Well-known system/service port"
    if port < 49152:
        return "Registered application port"
    return "Dynamic/private application port"


def _notify_red_ports(red_items):
    if not red_items:
        return
    state_path = os.path.join(BASE, "runtime", "jarvis-red-alerts.json")
    signature = "|".join(sorted({
        f"{item['port']}:{item['pid']}:{item['process']}"
        for item in red_items
    }))
    try:
        saved = open(state_path, encoding="utf-8").read().strip()
    except Exception:
        saved = ""
    if saved == signature:
        return
    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    open(state_path, "w", encoding="utf-8").write(signature)

    summaries = "; ".join(
        f"Port {item['port']} ({item['process'] or 'unknown program'}) needs attention"
        for item in red_items[:5]
    )
    escaped = (summaries.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
               .replace("'", "&apos;").replace('"', "&quot;"))
    command = (
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
        "ContentType = WindowsRuntime] | Out-Null; "
        "$xml=[Windows.Data.Xml.Dom.XmlDocument]::new(); "
        "$xml.LoadXml(\"<toast><visual><binding template='ToastText02'>"
        "<text id='1'>JARVIS RED PORT ALERT</text>"
        "<text id='2'>" + escaped + "</text>"
        "</binding></visual></toast>\"); "
        "$toast=[Windows.UI.Notifications.ToastNotification]::new($xml); "
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('JARVIS PRIME').Show($toast)"
    )
    subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)


def _port_modes():
    modes = {}
    mode_path = os.path.join(BASE, "jarvis-port-modes.json")
    try:
        modes = json.loads(open(mode_path, encoding="utf-8").read())
    except Exception:
        modes = {}
    return modes if isinstance(modes, dict) else {}


def _blocked_firewall_ports():
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
             "Get-NetFirewallRule -Action Block -Enabled True -ErrorAction SilentlyContinue | "
             "ForEach-Object { $rule=$_; Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule "
             "-ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{"
             "DisplayName=$rule.DisplayName;LocalPort=$_.LocalPort} } } | ConvertTo-Json -Compress"],
            capture_output=True, text=True, timeout=10)
        raw = json.loads(r.stdout or "[]")
        if isinstance(raw, dict):
            raw = [raw]
        blocked = set()
        for item in raw:
            if not isinstance(item, dict):
                continue
            local_port = str(item.get("LocalPort", ""))
            display_name = str(item.get("DisplayName", ""))
            if "-" in local_port:
                continue
            if "," in local_port:
                for port in local_port.split(","):
                    port = port.strip()
                    if port.isdigit():
                        blocked.add(int(port))
            elif local_port.isdigit():
                blocked.add(int(local_port))
            elif display_name.startswith("WF-Dashboard-Port-"):
                suffix = display_name.rsplit("-", 1)[-1]
                if suffix.isdigit():
                    blocked.add(int(suffix))
        return blocked
    except Exception:
        return set()


def listener_inventory():
    baseline = _baseline_bindings()
    saved_modes = _port_modes()
    blocked_ports = _blocked_firewall_ports()
    alert_text = ""
    try:
        alert_text = open(ALERT_LOG, encoding="utf-8", errors="ignore").read()[-30000:].lower()
    except Exception:
        pass

    listeners = {}
    for conn in psutil.net_connections(kind="inet"):
        if conn.status != psutil.CONN_LISTEN or not conn.laddr:
            port = getattr(conn.laddr, "port", None)
            address = getattr(conn.laddr, "ip", "")
            if not port or address in ("127.0.0.1", "::1", "localhost"):
                continue
            pid = conn.pid or 0
            process_name = "unknown"
            exe = ""
            try:
                proc = psutil.Process(pid)
                process_name = proc.name() or "unknown"
                exe = proc.exe() or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                pass

            key = (port, pid, address)
            baseline_match = (str(pid), int(port)) in baseline
            if not baseline_match:
                risk, reason = "WATCH", "Not matched to the saved Web-Fortress baseline"
            else:
                risk, reason = "NORMAL", "Matched to the saved listener baseline"

            alert_match = f"new external listener" in alert_text and f" on port {port}" in alert_text
            if alert_match:
                risk, reason = "MALICIOUS", "Manipulation signal: newly exposed listener or auto-block event"
            elif process_name.lower() in {"powershell", "pwsh", "cmd", "rundll32", "regsvr32"}:
                risk, reason = "MALICIOUS", "Unexpected shell/interpreter exposing a network port"

            saved_mode = str(saved_modes.get(str(port), {}).get("mode", "OPEN"))
            current_mode = "STOPPED" if saved_mode == "STOPPED" else (
                "BLOCKED" if port in blocked_ports else "OPEN"
            )
            listeners[key] = {
                "port": port,
                "label": _known_port_label(port, process_name),
                "process": process_name,
                "exe": exe,
                "pid": pid,
                "address": address,
                "risk": risk,
                "risk_reason": reason,
                "mode": current_mode
            }

    inventory = sorted(listeners.values(), key=lambda item: (
        0 if item["risk"] == "MALICIOUS" else 1 if item["risk"] == "WATCH" else 2,
        item["port"], item["pid"]))
    _notify_red_ports([item for item in inventory if item["risk"] == "MALICIOUS"])
    return inventory


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass   # suppress access log noise

    def authorized(self) -> bool:
        supplied = self.headers.get("Authorization", "")
        query_token = parse_qs(urlparse(self.path).query).get("token", [""])[0]
        return supplied == f"Bearer {_DASHBOARD_TOKEN}" or query_token == _DASHBOARD_TOKEN

    def require_auth(self) -> bool:
        if self.authorized():
            return True
        self.send_json({"error": "authorization required"}, 401)
        return False

    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        request_path = urlparse(self.path).path
        if request_path == "/":
            body = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if request_path == "/api/token":
            self.send_json({"token": _DASHBOARD_TOKEN})
            return
        if not self.require_auth():
            return
        # ── SSE stream ──────────────────────────────────────────────────────────
        if request_path == "/api/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            q = _monitor.subscribe()
            h2 = _pipeline_stats["hops"]["2_sse_handler"]
            _pl_update("2_sse_handler",
                       active_conn=h2["active_conn"]+1,
                       total_conn=h2["total_conn"]+1)
            bytes_sent = 0
            # Seed with current snapshot so tab is populated immediately
            snap = _monitor.snapshot()
            if snap:
                seed = json.dumps({"event":"proc_table","ts":"now","net_in_rate":0,
                                   "net_out_rate":0,"procs":snap})
                seed_msg = f"event: proc_table\ndata: {seed}\n\n".encode()
                try:
                    self.wfile.write(seed_msg)
                    self.wfile.flush()
                    bytes_sent += len(seed_msg)
                except Exception:
                    _monitor.unsubscribe(q)
                    _pl_update("2_sse_handler",
                               active_conn=max(0,_pipeline_stats["hops"]["2_sse_handler"]["active_conn"]-1),
                               disconnect_count=_pipeline_stats["hops"]["2_sse_handler"]["disconnect_count"]+1)
                    return
            for event in reversed(_monitor.events(50)):
                seed = f"event: io_event\ndata: {json.dumps(event)}\n\n".encode()
                try:
                    self.wfile.write(seed)
                    bytes_sent += len(seed)
                except Exception:
                    _monitor.unsubscribe(q)
                    return
            if bytes_sent:
                self.wfile.flush()
            try:
                while True:
                    drained = False
                    while q:
                        msg = q.popleft()
                        raw = msg.encode()
                        self.wfile.write(raw)
                        bytes_sent += len(raw)
                        drained = True
                    if drained:
                        self.wfile.flush()
                        _pl_update("2_sse_handler",
                                   total_bytes_sent=h2["total_bytes_sent"]+bytes_sent,
                                   last_send_ts=datetime.now().isoformat(timespec="milliseconds"))
                        bytes_sent = 0
                    else:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                    time.sleep(0.5)
            except Exception:
                _pl_update("2_sse_handler",
                           disconnect_count=_pipeline_stats["hops"]["2_sse_handler"]["disconnect_count"]+1)
            finally:
                _monitor.unsubscribe(q)
                _pl_update("2_sse_handler",
                           active_conn=max(0,_pipeline_stats["hops"]["2_sse_handler"]["active_conn"]-1))
            return

        if request_path == "/api/pipeline-log":
            with _pipeline_lock:
                payload = json.loads(json.dumps(_pipeline_stats, default=str))
            self.send_json(payload)

        elif request_path == "/api/status":
            try:
                with open(REPORT, encoding="utf-8") as f:
                    self.send_json(json.load(f))
            except Exception:
                self.send_json({"score": 0, "status": "no scan yet"})

        elif request_path == "/api/alerts":
            try:
                with open(ALERT_LOG, encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                self.send_json({"lines": [l.rstrip() for l in lines[-150:]]})
            except Exception:
                self.send_json({"lines": []})

        elif request_path == "/api/stasis":
            with _stasis_lock:
                self.send_json(_stasis)

        elif request_path == "/api/graph-hypotheses":
            try:
                self.send_json(_graph_hypotheses_cached())
            except Exception as e:
                self.send_json({"metrics": {}, "hypotheses": [], "error": str(e)})

        elif request_path == "/api/procs":
            self.send_json(_monitor.snapshot())

        elif request_path == "/api/events":
            self.send_json(_monitor.events())

        elif request_path.startswith("/api/iodata"):
            # ?window=300 (5min), 3600 (1h), 86400 (24h)
            qs = parse_qs(urlparse(self.path).query)
            w  = int(qs.get("window",["3600"])[0])
            self.send_json(_db_query(w))

        elif request_path == "/api/throttle-state":
            state_path = os.path.join(BASE, "throttle-state.json")
            try:
                self.send_json(json.loads(open(state_path).read()))
            except:
                self.send_json({"ts":"--","active":[],"throttle_count":0,"baseline":50})

        elif request_path == "/api/allow-list":
            allow_path = os.path.join(BASE, "allow_list.json")
            try:
                self.send_json(json.loads(open(allow_path).read()))
            except:
                self.send_json({"allowed":[]})

        elif request_path == "/api/all-procs":
            # All non-vital running process names for the allow-list dropdown
            VITAL = {"system","idle","registry","smss","csrss","wininit","winlogon",
                     "services","lsass","svchost","dwm","sihost","fontdrvhost",
                     "spoolsv","taskhostw","msmpeng","securityhealthsvc",
                     "securityhealthhost","audiodg","runtimebroker",
                     "shellexperiencehost","startmenuexperiencehost",
                     "textinputhost","ctfmon","searchhost","searchindexer",
                     "wudfhost","ntoskrnl","conhost","dllhost","msiexec",
                     "trustedinstaller","wmiprvse","wermgr","logonui","userinit",
                     "explorer","python","security","jarvis","quantum","graphify"}
            seen, procs = set(), []
            for p in psutil.process_iter(["name","exe"], ad_value=None):
                try:
                    n = (p.info["name"] or "").lower().replace(".exe","")
                    if n and n not in VITAL and n not in seen and len(n) > 1:
                        seen.add(n)
                        procs.append({"name": p.info["name"], "exe": p.info["exe"] or ""})
                except: pass
            procs.sort(key=lambda x: x["name"].lower())
            self.send_json({"procs": procs})

        elif request_path.startswith("/api/memory"):
            qs = parse_qs(urlparse(self.path).query)
            window_h = int(qs.get("h", ["24"])[0])
            limit    = int(qs.get("limit", ["200"])[0])
            self.send_json(mem_query(window_s=window_h*3600, limit=limit))

        elif request_path == "/api/research-tsv":
            tsv_path = os.path.join(BASE, "AndroidStudioProjects", "autoresearch", "security_results.tsv")
            try:
                lines = open(tsv_path, encoding="utf-8").read().splitlines()
                header = lines[0].split("\t") if lines else []
                rows   = [l.split("\t") for l in lines[1:] if l.strip()]
                self.send_json({"header": header, "rows": rows})
            except:
                self.send_json({"header": [], "rows": []})

        elif request_path == "/api/secmetrics":
            try:
                import sys as _sys
                _sys.path.insert(0, os.path.join(BASE, "AndroidStudioProjects", "autoresearch"))
                from violation_tracker import compute_metrics, security_score
                from perf_researcher import snapshot as _snap, perf_score as _ps, analyze as _an
                m = compute_metrics()
                sc = security_score(m)
                s = _snap()
                ps = _ps(s)
                findings = _an(s)
                self.send_json({
                    "security_score": sc,
                    "perf_score": ps,
                    "metrics": m,
                    "findings_count": len(findings),
                    "auto_findings": [f["reason"][:60] for f in findings if f["tier"] == "AUTO"],
                    "prompt_findings": [f["reason"][:60] for f in findings if f["tier"] == "PROMPT"],
                })
            except Exception as e:
                self.send_json({"error": str(e)})

        elif request_path == "/api/firewall":
            try:
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Get-NetFirewallRule -DisplayName 'WF-*' -ErrorAction SilentlyContinue | "
                     "Select-Object DisplayName,Action,Enabled | ConvertTo-Json"],
                    capture_output=True, text=True, timeout=10)
                raw = json.loads(r.stdout or "[]")
                if isinstance(raw, dict): raw = [raw]
                rules = [{"name": x.get("DisplayName",""), "action": str(x.get("Action","")),
                          "enabled": x.get("Enabled", False)} for x in raw]
                self.send_json({"rules": rules})
            except Exception as ex:
                self.send_json({"rules": [], "error": str(ex)})

        elif request_path == "/api/listeners":
            try:
                self.send_json({"listeners": listener_inventory(), "ts": datetime.now().isoformat(timespec="seconds")})
            except Exception as ex:
                self.send_json({"listeners": [], "error": str(ex)})

        elif request_path.startswith("/api/job/"):
            name = self.path.split("/api/job/")[1]
            with _jobs_lock:
                job = _jobs.get(name, {"output": "", "done": False})
            self.send_json(job)

        else:
            self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        if not self.require_auth():
            return
        request_path = urlparse(self.path).path
        if request_path.startswith("/api/run/"):
            name = request_path.split("/api/run/", 1)[1]
            if name not in SCRIPTS:
                self.send_json({"error": "unknown tool"}, 400); return
            threading.Thread(target=run_job, args=(name, SCRIPTS[name]), daemon=True).start()
            self.send_json({"message": f"Started {name}"})
        elif request_path == "/api/allow-list":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body   = self.rfile.read(length)
                data   = json.loads(body)
                allow_path = os.path.join(BASE, "allow_list.json")
                open(allow_path, "w").write(json.dumps({"allowed": data.get("allowed", [])}, indent=2))
                self.send_json({"ok": True})
            except Exception as e:
                self.send_json({"error": str(e)}, 400)
        elif request_path == "/api/port-control":
            try:
                length = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(length))
                port = int(data.get("port", 0))
                pid = int(data.get("pid", 0))
                action = str(data.get("action", ""))
                if port < 1 or port > 65535 or action not in {"block", "block-stop", "unblock"}:
                    self.send_json({"error": "Invalid port or action"}, 400)
                    return

                rule_name = f"WF-Dashboard-Port-{port}"
                if action == "unblock":
                    command = f"Remove-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue"
                    message = f"Port {port} firewall block removed"
                else:
                    command = (
                        f"$rule = Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue; "
                        f"if (-not $rule) {{ New-NetFirewallRule -DisplayName '{rule_name}' "
                        f"-Direction Inbound -Protocol TCP -LocalPort {port} -Action Block "
                        f"-Profile Any -ErrorAction Stop | Out-Null }}"
                    )
                    message = f"Inbound traffic blocked on port {port}"

                result = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                    capture_output=True, text=True, timeout=15)
                if result.returncode != 0:
                    self.send_json({"error": (result.stderr or result.stdout or "Firewall command failed").strip()}, 400)
                    return

                stopped = False
                if action == "block-stop" and pid:
                    owned_port = False
                    for conn in psutil.net_connections(kind="inet"):
                        if conn.pid == pid and conn.status == psutil.CONN_LISTEN and conn.laddr:
                            if getattr(conn.laddr, "port", None) == port:
                                owned_port = True
                                break
                    if owned_port:
                        try:
                            psutil.Process(pid).terminate()
                            stopped = True
                            message += f"; stopped PID {pid}"
                        except (psutil.NoSuchProcess, psutil.AccessDenied) as ex:
                            message += f"; process stop denied: {ex}"

                mode_path = os.path.join(BASE, "jarvis-port-modes.json")
                try:
                    mode_data = json.loads(open(mode_path, encoding="utf-8").read())
                except Exception:
                    mode_data = {}
                if action == "unblock":
                    mode_data.pop(str(port), None)
                else:
                    mode_data[str(port)] = {
                        "mode": "STOPPED" if stopped else "BLOCKED",
                        "pid": pid,
                        "action": action,
                        "updated": datetime.now().isoformat(timespec="seconds"),
                    }
                open(mode_path, "w", encoding="utf-8").write(json.dumps(mode_data, indent=2))

                mem_log_event("PORT_CONTROL", "CRITICAL" if action != "unblock" else "INFO",
                              "FIREWALL", message,
                              f"port={port} pid={pid} action={action}")
                self.send_json({"ok": True, "message": message, "stopped": stopped})
            except (json.JSONDecodeError, ValueError) as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
        else:
            self.send_json({"error": "not found"}, 404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    url    = f"http://localhost:{PORT}"
    print(f"[JARVIS PRIME Dashboard] {url}")
    print(f"[Dashboard token] {_DASHBOARD_TOKEN}")
    print(f"[Kernel Monitor] polling every {KernelMonitor.INTERVAL}s via psutil")
    print("Press Ctrl+C to stop.")
    threading.Thread(target=_research_loop, daemon=True).start()
    threading.Thread(target=_stasis_loop, daemon=True).start()
    print("[Stasis] aggregating every script -> stasis.json @ 1 Hz")
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Dashboard] Stopped.")
