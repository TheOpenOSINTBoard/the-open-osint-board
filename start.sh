#!/usr/bin/env bash

# ================================================================
# The Open OSINT Board — Linux/macOS Startup Script
# Compatible: Ubuntu 20.04+, Debian 11+, macOS 12+
# Requires: Python 3.8 or higher
# ================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$SCRIPT_DIR/backend"
FRONTEND="$SCRIPT_DIR/frontend/index.html"

# ── Colours ─────────────────────────────────────────────────────
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
RESET='\033[0m'

echo ""
echo "  +==================================================+"
echo "  |        The Open OSINT Board — OSINT Dashboard    |"
echo "  +==================================================+"
echo ""

# ── Check frontend exists ────────────────────────────────────────
if [ ! -f "$FRONTEND" ]; then
    echo -e "${RED}[!] ERROR: frontend/index.html not found.${RESET}"
    echo "    Make sure your folder structure is:"
    echo "      toob/"
    echo "        start.sh"
    echo "        backend/server.py"
    echo "        frontend/index.html"
    echo ""
    exit 1
fi

# ── Check backend exists ─────────────────────────────────────────
if [ ! -f "$BACKEND/server.py" ]; then
    echo -e "${RED}[!] ERROR: backend/server.py not found.${RESET}"
    exit 1
fi

# ── Find Python 3.8+ ─────────────────────────────────────────────
echo -e "${CYAN}[*] Checking for Python 3.8+...${RESET}"
PYTHON=""

for candidate in python3 python python3.12 python3.11 python3.10 python3.9 python3.8; do
    if command -v "$candidate" &>/dev/null; then
        version=$("$candidate" --version 2>&1 | awk '{print $2}')
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 8 ]; then
            PYTHON="$candidate"
            echo -e "    ${GREEN}Found: Python $version using '$PYTHON'${RESET}"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo -e "${RED}[!] Python 3.8+ not found. Please install it:${RESET}"
    echo ""
    echo "    Ubuntu/Debian:  sudo apt install python3 python3-pip"
    echo "    Fedora/RHEL:    sudo dnf install python3 python3-pip"
    echo "    macOS:          brew install python3"
    echo "    Or download from: https://www.python.org/downloads/"
    echo ""
    exit 1
fi
echo ""

# ── Install/verify dependencies ──────────────────────────────────
echo -e "${CYAN}[*] Installing/checking dependencies...${RESET}"
"$PYTHON" -m pip install --upgrade pip --quiet 2>/dev/null || true

if ! "$PYTHON" -m pip install -r "$BACKEND/requirements.txt" --quiet 2>/dev/null; then
    echo "    [!] pip install failed. Trying with --user flag..."
    "$PYTHON" -m pip install -r "$BACKEND/requirements.txt" --quiet --user 2>/dev/null || {
        echo -e "${RED}    [!] Dependency install failed. Try running manually:${RESET}"
        echo "        $PYTHON -m pip install -r $BACKEND/requirements.txt"
        exit 1
    }
fi
echo -e "    ${GREEN}[OK] Dependencies ready${RESET}"
echo ""

# ── Free up port 5000 if occupied ────────────────────────────────
echo -e "${CYAN}[*] Checking port 5000...${RESET}"
if command -v lsof &>/dev/null; then
    PIDS=$(lsof -ti tcp:5000 2>/dev/null || true)
elif command -v fuser &>/dev/null; then
    PIDS=$(fuser 5000/tcp 2>/dev/null | tr -s ' ' '\n' | grep -v '^$' || true)
else
    PIDS=""
fi

if [ -n "$PIDS" ]; then
    for pid in $PIDS; do
        echo "    Freeing port 5000 (PID $pid)..."
        kill -9 "$pid" 2>/dev/null || true
    done
fi
echo -e "    ${GREEN}[OK] Port 5000 ready${RESET}"
echo ""

# ── Start backend ────────────────────────────────────────────────
echo -e "${CYAN}[*] Starting The Open OSINT Board backend...${RESET}"
cd "$BACKEND"
"$PYTHON" server.py > /tmp/toob-backend.log 2>&1 &
BACKEND_PID=$!
echo -e "    ${GREEN}[OK] Backend process launched (PID $BACKEND_PID)${RESET}"
echo ""

# ── Cleanup trap — kill backend when script exits ─────────────────
cleanup() {
    echo ""
    echo -e "${CYAN}[*] Stopping backend...${RESET}"
    kill "$BACKEND_PID" 2>/dev/null || true
    # Belt-and-suspenders: also free the port
    if command -v lsof &>/dev/null; then
        lsof -ti tcp:5000 2>/dev/null | xargs kill -9 2>/dev/null || true
    fi
    echo -e "    ${GREEN}[OK] Stopped. Goodbye.${RESET}"
    exit 0
}
trap cleanup INT TERM

# ── Wait for backend to respond ──────────────────────────────────
echo -e "${CYAN}[*] Waiting for backend to initialize...${RESET}"
TRIES=0
printf "    "

while true; do
    TRIES=$((TRIES + 1))

    if [ "$TRIES" -gt 30 ]; then
        echo ""
        echo -e "${YELLOW}    [!] Backend slow to start. Opening dashboard anyway.${RESET}"
        echo "        If feeds show errors, wait 30s and refresh the page."
        break
    fi

    if curl -s --max-time 1 http://localhost:5000/api/status > /dev/null 2>&1; then
        echo ""
        echo -e "    ${GREEN}[OK] Backend responding (${TRIES}s)${RESET}"
        break
    fi

    printf "."
    sleep 1
done
echo ""

# ── Open dashboard ───────────────────────────────────────────────
echo "  +==================================================+"
echo "  |  The Open OSINT Board is running!                |"
echo "  |                                                  |"
echo "  |  Backend:   http://localhost:5000                |"
echo "  |  Status:    http://localhost:5000/api/status     |"
echo "  |                                                  |"
echo "  |  Opening dashboard in your browser...            |"
echo "  +==================================================+"
echo ""

# Detect OS and open browser appropriately
if command -v xdg-open &>/dev/null; then
    xdg-open "$FRONTEND" 2>/dev/null &   # Linux
elif command -v open &>/dev/null; then
    open "$FRONTEND" 2>/dev/null &        # macOS
else
    echo -e "${YELLOW}  Could not auto-open browser. Open this file manually:${RESET}"
    echo "  $FRONTEND"
fi

echo "  Feeds will populate within 15-30 seconds."
echo "  Keep this window open — closing it stops the backend."
echo "  Backend log: /tmp/toob-backend.log"
echo ""
echo "  Press Ctrl+C to STOP and exit."
echo ""

# ── Keep alive until Ctrl+C ──────────────────────────────────────
wait "$BACKEND_PID"
