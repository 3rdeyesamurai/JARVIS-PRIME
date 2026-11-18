"""
search_guardian.py — Auto-restart Windows Search (WSearch) when a user triggers it,
then stop it again after 90s of idle.

Detection signals:
  - SearchApp.exe or SearchUI.exe appears in running processes (Start menu search)
  - explorer.exe opens a new window with a search query (File Explorer search)

Run as daemon: python search_guardian.py
"""

import time, subprocess, sys
from pathlib import Path
from datetime import datetime

LOG = Path.home() / "search-guardian.log"
POLL = 3          # seconds between checks
IDLE_TIMEOUT = 90 # seconds of no search activity before stopping WSearch

def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}][SEARCH-GUARDIAN] {msg}"
    print(line, flush=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def service_status() -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-Service WSearch -ErrorAction SilentlyContinue).Status"],
            capture_output=True, text=True, timeout=5)
        return r.stdout.strip()
    except:
        return "Unknown"

def set_wsearch(running: bool):
    action = "Start-Service WSearch" if running else "Stop-Service WSearch -Force"
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", action],
            capture_output=True, timeout=10)
        log(f"WSearch {'STARTED' if running else 'STOPPED'}")
    except Exception as e:
        log(f"WSearch toggle error: {e}")

def search_procs_running() -> bool:
    import psutil
    SEARCH_NAMES = {"searchapp", "searchui", "searchhost"}
    for p in psutil.process_iter(["name"], ad_value=None):
        try:
            if p.info["name"] and p.info["name"].lower().replace(".exe", "") in SEARCH_NAMES:
                return True
        except:
            pass
    return False

def main():
    log("Search Guardian started — polling every 3s for search activity")

    wsearch_on = service_status() == "Running"
    last_active = 0.0

    while True:
        try:
            active = search_procs_running()

            if active:
                last_active = time.time()
                if not wsearch_on:
                    log("Search activity detected — starting WSearch")
                    set_wsearch(True)
                    wsearch_on = True

            elif wsearch_on:
                idle_s = time.time() - last_active
                if last_active > 0 and idle_s > IDLE_TIMEOUT:
                    log(f"Search idle {idle_s:.0f}s — stopping WSearch")
                    set_wsearch(False)
                    wsearch_on = False
                    last_active = 0.0

        except Exception as e:
            log(f"poll error: {e}")

        time.sleep(POLL)

if __name__ == "__main__":
    main()
