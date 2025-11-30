#!/bin/bash
# Valkyrie Startup Script
# Starts the watcher and dashboard with proper environment setup

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# PID file locations
WATCHER_PID_FILE="/tmp/valkyrie_watcher.pid"
DASHBOARD_PID_FILE="/tmp/valkyrie_dashboard.pid"
LOG_DIR="$SCRIPT_DIR/logs"

# Create logs directory
mkdir -p "$LOG_DIR"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                                      ║${NC}"
echo -e "${BLUE}║                    🛡️  VALKYRIE FILE SCANNER 🛡️                     ║${NC}"
echo -e "${BLUE}║                                                                      ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo

# Function to check if process is running
is_running() {
    local pid_file=$1
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ps -p "$pid" > /dev/null 2>&1; then
            return 0  # Running
        fi
    fi
    return 1  # Not running
}

# Function to stop services
stop_services() {
    echo -e "${YELLOW}Stopping Valkyrie services...${NC}"
    
    # Stop watcher
    if [ -f "$WATCHER_PID_FILE" ]; then
        local watcher_pid=$(cat "$WATCHER_PID_FILE")
        if ps -p "$watcher_pid" > /dev/null 2>&1; then
            echo -e "  ${YELLOW}→${NC} Stopping watcher (PID: $watcher_pid)..."
            kill "$watcher_pid" 2>/dev/null || true
            sleep 1
            # Force kill if still running
            if ps -p "$watcher_pid" > /dev/null 2>&1; then
                kill -9 "$watcher_pid" 2>/dev/null || true
            fi
        fi
        rm -f "$WATCHER_PID_FILE"
    fi
    
    # Stop dashboard
    if [ -f "$DASHBOARD_PID_FILE" ]; then
        local dashboard_pid=$(cat "$DASHBOARD_PID_FILE")
        if ps -p "$dashboard_pid" > /dev/null 2>&1; then
            echo -e "  ${YELLOW}→${NC} Stopping dashboard (PID: $dashboard_pid)..."
            kill "$dashboard_pid" 2>/dev/null || true
            sleep 1
            # Force kill if still running
            if ps -p "$dashboard_pid" > /dev/null 2>&1; then
                kill -9 "$dashboard_pid" 2>/dev/null || true
            fi
        fi
        rm -f "$DASHBOARD_PID_FILE"
    fi
    
    echo -e "${GREEN}✓ Services stopped${NC}"
    echo
}

# Function to show status
show_status() {
    echo -e "${BLUE}Service Status:${NC}"
    echo
    
    if is_running "$WATCHER_PID_FILE"; then
        local watcher_pid=$(cat "$WATCHER_PID_FILE")
        echo -e "  ${GREEN}✓${NC} Watcher:   ${GREEN}RUNNING${NC} (PID: $watcher_pid)"
    else
        echo -e "  ${RED}✗${NC} Watcher:   ${RED}STOPPED${NC}"
    fi
    
    if is_running "$DASHBOARD_PID_FILE"; then
        local dashboard_pid=$(cat "$DASHBOARD_PID_FILE")
        echo -e "  ${GREEN}✓${NC} Dashboard: ${GREEN}RUNNING${NC} (PID: $dashboard_pid)"
        echo -e "  ${BLUE}→${NC} URL:       ${BLUE}http://127.0.0.1:5000${NC}"
    else
        echo -e "  ${RED}✗${NC} Dashboard: ${RED}STOPPED${NC}"
    fi
    echo
}

# Handle command line arguments
case "${1:-start}" in
    stop)
        stop_services
        exit 0
        ;;
    restart)
        stop_services
        sleep 2
        # Continue to start
        ;;
    status)
        show_status
        exit 0
        ;;
    start)
        # Continue to start
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac

# Check if already running
if is_running "$WATCHER_PID_FILE" || is_running "$DASHBOARD_PID_FILE"; then
    echo -e "${YELLOW}⚠ Valkyrie is already running!${NC}"
    show_status
    echo -e "Use ${YELLOW}$0 restart${NC} to restart services"
    exit 1
fi

echo -e "${BLUE}[1/5] Checking dependencies...${NC}"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python 3 not found${NC}"
    echo "  Install: sudo pacman -S python3"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Python 3: $(python3 --version)"

# Check ClamAV
if ! command -v clamscan &> /dev/null; then
    echo -e "${YELLOW}⚠ ClamAV not found (signatures will be skipped)${NC}"
    echo "  Install: sudo pacman -S clamav && sudo freshclam"
else
    echo -e "  ${GREEN}✓${NC} ClamAV: $(clamscan --version | head -1)"
fi

# Check YARA
if ! command -v yara &> /dev/null; then
    echo -e "${YELLOW}⚠ YARA not found (rules will be skipped)${NC}"
    echo "  Install: sudo pacman -S yara"
else
    echo -e "  ${GREEN}✓${NC} YARA: $(yara --version)"
fi

# Check bubblewrap (sandboxing)
if ! command -v bwrap &> /dev/null; then
    echo -e "${RED}⚠ Bubblewrap not found - RUNNING WITHOUT ISOLATION!${NC}"
    echo -e "${RED}  This is UNSAFE for untrusted files!${NC}"
    echo "  Install: sudo pacman -S bubblewrap"
    SANDBOXED=false
else
    echo -e "  ${GREEN}✓${NC} Bubblewrap: $(bwrap --version | head -1)"
    SANDBOXED=true
fi

echo

# Check Python dependencies
echo -e "${BLUE}[2/5] Checking Python packages...${NC}"

check_python_package() {
    python3 -c "import $1" 2>/dev/null
}

MISSING_PACKAGES=()

if ! check_python_package "watchdog"; then
    MISSING_PACKAGES+=("watchdog")
fi

if ! check_python_package "flask"; then
    MISSING_PACKAGES+=("Flask")
fi

if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
    echo -e "${YELLOW}⚠ Missing Python packages: ${MISSING_PACKAGES[*]}${NC}"
    echo -e "  Installing..."
    pip install --user "${MISSING_PACKAGES[@]}" || {
        echo -e "${RED}✗ Failed to install packages${NC}"
        echo "  Try manually: pip install ${MISSING_PACKAGES[*]}"
        exit 1
    }
    echo -e "  ${GREEN}✓${NC} Packages installed"
else
    echo -e "  ${GREEN}✓${NC} All required packages found"
fi

echo

# Check if watcher uses sandboxed analysis
echo -e "${BLUE}[3/5] Checking configuration...${NC}"

if grep -q "from analysis_sandboxed import analyze" watcher/watcher.py; then
    echo -e "  ${GREEN}✓${NC} Watcher configured for sandboxed analysis"
elif [ "$SANDBOXED" = true ]; then
    echo -e "${YELLOW}⚠ Watcher not using sandboxed analysis${NC}"
    echo -e "  ${BLUE}→${NC} Updating watcher.py to use sandboxing..."
    sed -i.bak 's/from analysis import analyze/from analysis_sandboxed import analyze/' watcher/watcher.py
    echo -e "  ${GREEN}✓${NC} Watcher updated (backup: watcher/watcher.py.bak)"
else
    echo -e "  ${YELLOW}⚠${NC} Watcher using non-sandboxed analysis (bubblewrap not available)"
fi

# Create necessary directories
mkdir -p reports quarantine processed

echo -e "  ${GREEN}✓${NC} Directories ready (reports, quarantine, processed)"
echo

# Start services
echo -e "${BLUE}[4/5] Starting services...${NC}"

# Start watcher in background
echo -e "  ${BLUE}→${NC} Starting file watcher..."
nohup python3 watcher/watcher.py > "$LOG_DIR/watcher.log" 2>&1 &
WATCHER_PID=$!
echo $WATCHER_PID > "$WATCHER_PID_FILE"

# Wait a moment to check if it started successfully
sleep 2
if ! ps -p $WATCHER_PID > /dev/null 2>&1; then
    echo -e "  ${RED}✗ Watcher failed to start${NC}"
    echo "  Check logs: tail -f $LOG_DIR/watcher.log"
    rm -f "$WATCHER_PID_FILE"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Watcher started (PID: $WATCHER_PID)"

# Start dashboard in background
echo -e "  ${BLUE}→${NC} Starting web dashboard..."
nohup python3 gui/backend/app.py > "$LOG_DIR/dashboard.log" 2>&1 &
DASHBOARD_PID=$!
echo $DASHBOARD_PID > "$DASHBOARD_PID_FILE"

# Wait a moment to check if it started successfully
sleep 2
if ! ps -p $DASHBOARD_PID > /dev/null 2>&1; then
    echo -e "  ${RED}✗ Dashboard failed to start${NC}"
    echo "  Check logs: tail -f $LOG_DIR/dashboard.log"
    rm -f "$DASHBOARD_PID_FILE"
    # Stop watcher too
    kill $WATCHER_PID 2>/dev/null || true
    rm -f "$WATCHER_PID_FILE"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Dashboard started (PID: $DASHBOARD_PID)"

echo

# Show status
echo -e "${BLUE}[5/5] Valkyrie is ready!${NC}"
echo
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                          ✓ ALL SYSTEMS READY                         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${BLUE}Services:${NC}"
echo -e "  ${GREEN}✓${NC} File Watcher:  Monitoring ~/Downloads/"
echo -e "  ${GREEN}✓${NC} Web Dashboard: ${BLUE}http://127.0.0.1:5000${NC}"
echo
echo -e "${BLUE}Logs:${NC}"
echo -e "  → Watcher:   ${LOG_DIR}/watcher.log"
echo -e "  → Dashboard: ${LOG_DIR}/dashboard.log"
echo
echo -e "${BLUE}Commands:${NC}"
echo -e "  → View logs:     tail -f $LOG_DIR/watcher.log"
echo -e "  → Stop services: $0 stop"
echo -e "  → Restart:       $0 restart"
echo -e "  → Check status:  $0 status"
echo

if [ "$SANDBOXED" = true ]; then
    echo -e "${GREEN}🛡️  Security: All scans running in isolated sandbox${NC}"
else
    echo -e "${RED}⚠️  Security: Running WITHOUT sandbox isolation (UNSAFE!)${NC}"
    echo -e "${YELLOW}   Install bubblewrap for safe operation: sudo pacman -S bubblewrap${NC}"
fi

echo
echo -e "${BLUE}Test it:${NC}"
echo -e "  echo 'test' > ~/Downloads/test.txt"
echo -e "  # Check dashboard at http://127.0.0.1:5000"
echo

# Try to open browser (optional)
if command -v xdg-open &> /dev/null; then
    echo -e "${YELLOW}Opening dashboard in browser...${NC}"
    sleep 1
    xdg-open "http://127.0.0.1:5000" 2>/dev/null &
fi

echo -e "${GREEN}Valkyrie is running in the background. Logs are being written to $LOG_DIR/${NC}"
echo
