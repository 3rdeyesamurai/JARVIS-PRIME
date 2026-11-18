"""Runtime paths and safety configuration for the bundled JARVIS suite."""

import json
import sys
import os
import secrets
from pathlib import Path

BASE_DIR = (
    Path(sys.executable).resolve().parent
    if getattr(sys, "frozen", False)
    else Path(__file__).resolve().parent
)
STATE_DIR = BASE_DIR / "runtime"
STATE_DIR.mkdir(exist_ok=True)

ALERT_LOG = BASE_DIR / "intruder-alerts.log"
REPORT_OUT = BASE_DIR / "quantum-report.json"
JARVIS_LOG = BASE_DIR / "jarvis-prime.log"
PIPELINE_LOG = BASE_DIR / "jarvis-pipeline-log.json"
MEMORY_DB = BASE_DIR / "jarvis-memory.db"
IO_DB = BASE_DIR / "jarvis-io-analytics.db"
STATE_FILE = BASE_DIR / "jarvis-state.json"
RESPONSE_DIR = BASE_DIR / "jarvis-responses"
VECTOR_DB_DIR = BASE_DIR / "vector-db" / "cybersec_protective_scripts_db"
VECTOR_DB_PY = BASE_DIR / "vector-db" / "cybersec_protective_scripts_vector_db.py"
TOKEN_FILE = STATE_DIR / "dashboard-token"
EXECUTION_POLICY_FILE = STATE_DIR / "execution-policy.json"

RESPONSE_DIR.mkdir(exist_ok=True)


def dashboard_token() -> str:
    """Return a persistent local bearer token, creating it on first use."""
    if TOKEN_FILE.exists():
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
        if token:
            return token
    token = secrets.token_urlsafe(32)
    TOKEN_FILE.write_text(token + "\n", encoding="utf-8")
    return token


def execution_policy() -> dict:
    """Load the safe default policy, tolerating only a missing policy file."""
    if not EXECUTION_POLICY_FILE.exists():
        return {"mode": "review_dry_run", "allow_live": False}
    try:
        policy = json.loads(EXECUTION_POLICY_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Invalid execution policy: {EXECUTION_POLICY_FILE}: {exc}") from exc
    mode = policy.get("mode")
    if mode not in {"review_dry_run", "approved_live"}:
        raise RuntimeError(f"Unsupported execution policy mode: {mode!r}")
    return {"mode": mode, "allow_live": bool(policy.get("allow_live", False))}


def bundled_path(path: str | Path) -> Path:
    """Resolve a path relative to the bundle unless it is already absolute."""
    candidate = Path(path)
    return candidate if candidate.is_absolute() else BASE_DIR / candidate
