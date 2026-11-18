#!/usr/bin/env python3
"""JARVIS PRIME desktop controller.

The controller intentionally starts in review/dry-run mode and never elevates
itself. Live actions remain protected by the existing execution policy gate.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from tkinter import Button, Label, StringVar, Tk, messagebox

APP_NAME = "JARVIS PRIME"
HOST = "127.0.0.1"
PORT = 8765


def app_dir() -> Path:
    return Path(__file__).resolve().parent


def resource_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return app_dir()


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class JarvisPrimeApp:
    def __init__(self) -> None:
        self.root = Tk()
        self.root.title(APP_NAME)
        self.root.geometry("430x220")
        self.root.minsize(360, 180)
        self.root.configure(bg="#111812")
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.status = StringVar(value="Starting review/dry-run services...")
        self.children: list[subprocess.Popen] = []
        self.stop_event = threading.Event()
        self._build_ui()
        self.root.after(500, self.start_services)

    def _build_ui(self) -> None:
        Label(
            self.root,
            text=APP_NAME,
            fg="#ff8c00",
            bg="#111812",
            font=("Segoe UI", 20, "bold"),
        ).pack(pady=(18, 2))
        Label(
            self.root,
            text="Defensive monitoring • least privilege • review mode",
            fg="#9cff57",
            bg="#111812",
            font=("Segoe UI", 10),
        ).pack()
        Label(
            self.root,
            textvariable=self.status,
            fg="#e8f5e9",
            bg="#111812",
            wraplength=390,
            justify="center",
        ).pack(pady=18)
        Button(
            self.root,
            text="Open local dashboard",
            command=lambda: webbrowser.open(f"http://{HOST}:{PORT}/"),
            bg="#ff8c00",
            fg="#111812",
            activebackground="#9cff57",
        ).pack(side="left", padx=35)
        Button(
            self.root,
            text="Stop services",
            command=self.close,
            bg="#243226",
            fg="#9cff57",
            activebackground="#ff8c00",
        ).pack(side="right", padx=35)

    def _start_dashboard(self) -> None:
        dashboard_path = resource_dir() / "security-dashboard.py"
        if not dashboard_path.exists():
            raise FileNotFoundError(dashboard_path)
        dashboard = _load_module("jarvis_prime_dashboard", dashboard_path)
        server = dashboard.http.server.ThreadingHTTPServer(
            (HOST, PORT), dashboard.Handler
        )
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self._dashboard = server

    def _start_jarvis_loop(self) -> None:
        prime = _load_module("jarvis_prime_runtime", resource_dir() / "jarvis_prime.py")
        threading.Thread(
            target=prime.watch_log,
            kwargs={"dry_run": True},
            daemon=True,
        ).start()

    def _start_search_guardian(self) -> None:
        guardian = _load_module(
            "jarvis_prime_search_guardian", resource_dir() / "search_guardian.py"
        )
        threading.Thread(target=guardian.main, daemon=True).start()

    def _start_quantum_analyzer(self) -> None:
        analyzer = _load_module(
            "jarvis_prime_quantum_analyzer", resource_dir() / "quantum-analyzer.py"
        )
        threading.Thread(
            target=analyzer.run_analysis,
            args=(None, None, None),
            daemon=True,
        ).start()

    def _start_powershell(self, filename: str) -> None:
        path = resource_dir() / filename
        if not path.exists():
            return
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.children.append(
            subprocess.Popen(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(path),
                    "-Silent",
                ],
                cwd=str(app_dir()),
                creationflags=creationflags,
            )
        )

    def start_services(self) -> None:
        try:
            self._start_dashboard()
            self._start_jarvis_loop()
            self._start_search_guardian()
            self._start_quantum_analyzer()
            self._start_powershell("web-fortress.ps1")
            self._start_powershell("intruder-protocol.ps1")
            self.status.set("Protected locally on 127.0.0.1:8765 • review/dry-run")
        except Exception as exc:
            self.status.set(f"Startup failed: {exc}")
            messagebox.showerror(APP_NAME, str(exc))

    def close(self) -> None:
        self.stop_event.set()
        for child in self.children:
            if child.poll() is None:
                child.terminate()
        server = getattr(self, "_dashboard", None)
        if server is not None:
            server.shutdown()
            server.server_close()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def startup_task_name() -> str:
    return "JARVIS PRIME (per-user, review mode)"


def startup_script_path() -> Path:
    return (
        Path(os.environ["APPDATA"])
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
        / "JarvisPrime.cmd"
    )


def startup_command() -> str:
    if getattr(sys, "frozen", False):
        executable = Path(sys.executable).resolve()
        return f'@"{executable}"'
    executable = Path(sys.executable).resolve()
    script = Path(__file__).resolve()
    return f'@"{executable}" "{script}"'


def install_startup() -> None:
    path = startup_script_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "@echo off\r\n"
        "rem JARVIS PRIME starts as the signed-in user; no elevation is requested.\r\n"
        f"{startup_command()}\r\n",
        encoding="ascii",
    )
    print(f"Installed per-user startup entry: {path}")


def uninstall_startup() -> None:
    path = startup_script_path()
    if path.exists():
        path.unlink()
    print(f"Removed per-user startup entry: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--install-startup", action="store_true")
    parser.add_argument("--uninstall-startup", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.install_startup:
        install_startup()
        return 0
    if args.uninstall_startup:
        uninstall_startup()
        return 0
    if args.self_test:
        _load_module("jarvis_prime_dashboard_test", resource_dir() / "security-dashboard.py")
        _load_module("jarvis_prime_runtime_test", resource_dir() / "jarvis_prime.py")
        _load_module("jarvis_prime_search_test", resource_dir() / "search_guardian.py")
        _load_module("jarvis_prime_quantum_test", resource_dir() / "quantum-analyzer.py")
        print("JARVIS PRIME self-test passed: dashboard and response runtime imported")
        return 0
    JarvisPrimeApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
