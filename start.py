"""
Sentinela - Startup Script
Launches all Sentinela components in the correct order.

WHY THIS EXISTS:
    Sentinela has three components that need to start in a specific order
    with dependencies between them. This script handles that automatically
    so you don't need four terminal windows and a mental checklist.

    Dependency chain:
    Docker → Elasticsearch → Flask server → Collector + Monitor

USAGE:
    Double-click start.py, or run:
    python start.py

    The collector will trigger a UAC prompt for admin privileges.
    Click Yes to allow it — the Security Event Log requires admin access.
"""

import os
import sys
import time
import subprocess
import webbrowser
import ctypes
import requests

# ─── Config ───────────────────────────────────────────────────────────────────

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
ES_URL        = "http://localhost:9200"
DASHBOARD_URL = "http://localhost:8080"
ES_TIMEOUT    = 60   # seconds to wait for Elasticsearch
ES_POLL       = 3    # seconds between health checks

# ANSI colors for console output
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def log(msg, color=RESET):
    print(f"{color}{msg}{RESET}")

def log_step(step, msg):
    print(f"{CYAN}{BOLD}[{step}]{RESET} {msg}")

# ─── Step 1: Docker ───────────────────────────────────────────────────────────

def ensure_docker():
    log_step("1/5", "Checking Docker...")

    # Check if Docker is responding
    result = subprocess.run(
        ["docker", "info"],
        capture_output=True, text=True
    )

    if result.returncode != 0:
        log("  Docker is not running. Starting Docker Desktop...", YELLOW)
        # Start Docker Desktop
        docker_paths = [
            r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
            r"C:\Program Files (x86)\Docker\Docker\Docker Desktop.exe",
        ]
        started = False
        for path in docker_paths:
            if os.path.exists(path):
                subprocess.Popen([path])
                started = True
                break

        if not started:
            log("  Could not find Docker Desktop. Please start it manually.", RED)
            input("  Press Enter once Docker is running...")
            return

        log("  Waiting for Docker to start (this may take 30-60 seconds)...", YELLOW)
        for i in range(30):
            time.sleep(3)
            result = subprocess.run(["docker", "info"], capture_output=True)
            if result.returncode == 0:
                log("  Docker is ready.", GREEN)
                return
            print(f"  Still waiting... ({(i+1)*3}s)", end="\r")

        log("  Docker took too long. Please start it manually.", RED)
        input("  Press Enter once Docker is running...")
    else:
        log("  Docker is already running.", GREEN)

# ─── Step 2: Elasticsearch ────────────────────────────────────────────────────

def ensure_elasticsearch():
    log_step("2/5", "Starting Elasticsearch...")

    # Start docker-compose
    compose_file = os.path.join(BASE_DIR, "docker-compose.yml")
    subprocess.run(
        ["docker-compose", "-f", compose_file, "up", "-d"],
        capture_output=True
    )

    # Wait for ES to be healthy
    log(f"  Waiting for Elasticsearch at {ES_URL}...", YELLOW)
    for i in range(ES_TIMEOUT // ES_POLL):
        try:
            r = requests.get(f"{ES_URL}/_cluster/health", timeout=3)
            if r.status_code == 200:
                health = r.json().get("status", "unknown")
                log(f"  Elasticsearch is ready (cluster status: {health})", GREEN)
                return True
        except Exception:
            pass
        print(f"  Still waiting... ({(i+1)*ES_POLL}s / {ES_TIMEOUT}s max)", end="\r")
        time.sleep(ES_POLL)

    log(f"\n  Elasticsearch did not start within {ES_TIMEOUT}s.", RED)
    log("  Check Docker Desktop to see if the container is running.", RED)
    return False

# ─── Step 3: Flask server ─────────────────────────────────────────────────────

def start_flask():
    log_step("3/5", "Starting Flask dashboard server...")

    script = os.path.join(BASE_DIR, "dashboard", "server.py")
    proc = subprocess.Popen(
        [sys.executable, script],
        cwd=BASE_DIR,
        creationflags=subprocess.CREATE_NEW_CONSOLE  # own window
    )

    # Give Flask a moment to bind to port
    time.sleep(3)

    # Verify it started
    try:
        r = requests.get(f"{DASHBOARD_URL}/api/health", timeout=5)
        if r.status_code == 200:
            log(f"  Dashboard running at {DASHBOARD_URL}", GREEN)
            return proc
    except Exception:
        pass

    log("  Flask started (window opened)", GREEN)
    return proc

# ─── Step 4: Windows collector (admin) ───────────────────────────────────────

def start_collector():
    log_step("4/5", "Starting Windows Event Log collector (requires admin)...")
    log("  A UAC prompt will appear — click Yes to allow admin access.", YELLOW)
    log("  This is required to read the Windows Security Event Log.", YELLOW)

    script = os.path.join(BASE_DIR, "collector", "windows_collector.py")

    # Use ShellExecute with 'runas' verb to trigger UAC elevation
    # This is the standard Windows way to request admin for a specific process
    ctypes.windll.shell32.ShellExecuteW(
        None,           # parent window
        "runas",        # verb — triggers UAC
        sys.executable, # program
        f'"{script}" --historical',  # arguments
        BASE_DIR,       # working directory
        1               # show window (SW_SHOWNORMAL)
    )

    log("  Collector started in elevated window.", GREEN)

# ─── Step 5: Monitor daemon ───────────────────────────────────────────────────

def start_monitor():
    log_step("5/5", "Starting continuous monitor daemon...")

    script = os.path.join(BASE_DIR, "monitor", "daemon.py")
    subprocess.Popen(
        [sys.executable, script],
        cwd=BASE_DIR,
        creationflags=subprocess.CREATE_NEW_CONSOLE
    )

    log("  Monitor daemon started.", GREEN)

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{CYAN}{BOLD}{'='*56}{RESET}")
    print(f"{CYAN}{BOLD}  SENTINELA — Starting up{RESET}")
    print(f"{CYAN}{BOLD}{'='*56}{RESET}\n")

    # Step 1 — Docker
    ensure_docker()

    # Step 2 — Elasticsearch
    es_ready = ensure_elasticsearch()
    if not es_ready:
        log("\nCannot start without Elasticsearch. Exiting.", RED)
        input("Press Enter to exit...")
        sys.exit(1)

    # Step 3 — Flask
    start_flask()

    # Step 4 — Collector (admin)
    start_collector()

    # Step 5 — Monitor
    start_monitor()

    # Open browser
    print()
    log("All components started. Opening dashboard...", GREEN)
    time.sleep(2)
    webbrowser.open(DASHBOARD_URL)

    print(f"\n{GREEN}{BOLD}{'='*56}{RESET}")
    print(f"{GREEN}{BOLD}  SENTINELA is running{RESET}")
    print(f"{GREEN}{BOLD}{'='*56}{RESET}")
    print(f"\n  Dashboard:  {DASHBOARD_URL}")
    print(f"  To stop:    Close the individual component windows")
    print(f"\n  This window can be closed.\n")

if __name__ == "__main__":
    # Check we're on Windows
    if sys.platform != "win32":
        print("Sentinela currently supports Windows only.")
        sys.exit(1)

    main()