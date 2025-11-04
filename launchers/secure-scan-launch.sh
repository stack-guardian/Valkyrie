#!/usr/bin/env bash
set -e

PROJECT_DIR="/home/vibhor/projects/secure-scan"
VENV_DIR="$PROJECT_DIR/venv"
WATCHER="$PROJECT_DIR/watcher/watcher.py"
DASHBOARD="$PROJECT_DIR/gui/backend/app.py"
URL="http://127.0.0.1:5000"

# Activate venv
source "$VENV_DIR/bin/activate"

# Start watcher if not running
if ! pgrep -f "$WATCHER" >/dev/null 2>&1; then
  nohup python "$WATCHER" >/dev/null 2>&1 &
fi

# Start dashboard if not running
if ! pgrep -f "$DASHBOARD" >/dev/null 2>&1; then
  nohup python "$DASHBOARD" >/dev/null 2>&1 &
fi

# Give the server a moment to start
sleep 1

# Open the dashboard
xdg-open "$URL" >/dev/null 2>&1 || true
notify-send "Valkyrie" "Starting Valkyrie dashboard..."
