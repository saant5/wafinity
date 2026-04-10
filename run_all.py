from __future__ import annotations
import subprocess
import sys
import os
import json
import time
import signal
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PID_FILE = BASE_DIR / "logs" / "launcher_pids.json"
PID_FILE.parent.mkdir(exist_ok=True)

SERVICES = {
    "dashboard": {
        "cmd": [sys.executable, str(BASE_DIR / "dashboard" / "app.py")],
        "port": 5000,
    },
    "backend": {
        "cmd": [sys.executable, str(BASE_DIR / "api_backend.py")],
        "port": 5002,
    },
    "proxy": {
        "cmd": [sys.executable, "-m", "proxy.reverse_proxy"],
        "port": 8080,
    },
}


# =========================
# UTIL FUNCTIONS
# =========================

def is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def start_services():
    pids = {}

    print("🚀 Starting WAFinity Enterprise Stack...\n")

    for name, cfg in SERVICES.items():
        print(f"▶ Starting {name}...")
        if os.name == "nt":
            p = subprocess.Popen(cfg["cmd"], creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        else:
            p = subprocess.Popen(cfg["cmd"], preexec_fn=os.setsid)

        pids[name] = p.pid
        time.sleep(1.5)

    with open(PID_FILE, "w") as f:
        json.dump(pids, f)

    print("\n✅ All services started!")
    print("🌐 Dashboard  : http://127.0.0.1:5000")
    print("🔐 API Gateway: http://127.0.0.1:8080")
    print("📦 Backend    : http://127.0.0.1:5002")


def stop_services():
    if not PID_FILE.exists():
        print("⚠ No running services found.")
        return

    with open(PID_FILE) as f:
        pids = json.load(f)

    print("🛑 Stopping services...\n")

    for name, pid in pids.items():
        print(f"⏹ Stopping {name} (PID {pid})...")
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            else:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
        except Exception:
            pass

    PID_FILE.unlink(missing_ok=True)
    print("\n✅ All services stopped.")


def status_services():
    if not PID_FILE.exists():
        print("❌ No services running.")
        return

    with open(PID_FILE) as f:
        pids = json.load(f)

    print("\n📊 Service Status:\n")

    for name, pid in pids.items():
        running = is_running(pid)
        print(f"{name:10} → {'RUNNING ✅' if running else 'STOPPED ❌'} (PID {pid})")


def restart_services():
    stop_services()
    time.sleep(2)
    start_services()


# =========================
# MAIN CLI
# =========================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python run_all.py start")
        print("  python run_all.py stop")
        print("  python run_all.py status")
        print("  python run_all.py restart")
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "start":
        start_services()
    elif cmd == "stop":
        stop_services()
    elif cmd == "status":
        status_services()
    elif cmd == "restart":
        restart_services()
    else:
        print("Unknown command.")