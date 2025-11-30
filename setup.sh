#!/bin/bash
#
# Valkyrie File Security Scanner - Setup Script
#
# This script automates the installation and setup process for Valkyrie.
#

set -e  # Exit on error

echo "=========================================="
echo "  Valkyrie File Security Scanner"
echo "  Setup & Installation"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_warning "Running as root. This is not recommended."
   read -p "Continue anyway? (y/N): " -n 1 -r
   echo
   if [[ ! $REPLY =~ ^[Yy]$ ]]; then
       print_error "Setup cancelled."
       exit 1
   fi
fi

# Detect Linux distribution (for default choice)
DETECTED_FAMILY="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if echo "$ID_LIKE $ID" | grep -qi "debian\|ubuntu"; then
        DETECTED_FAMILY="debian"
    elif echo "$ID_LIKE $ID" | grep -qi "rhel\|fedora\|centos\|rocky\|alma"; then
        DETECTED_FAMILY="fedora"
    elif echo "$ID_LIKE $ID" | grep -qi "arch"; then
        DETECTED_FAMILY="arch"
    fi
    print_info "Detected OS family: $DETECTED_FAMILY (from /etc/os-release)"
else
    print_warning "Cannot detect operating system automatically."
fi

echo "Select Linux family for package installation:"
echo "  1) Debian / Ubuntu"
echo "  2) Fedora / RHEL / Rocky"
echo "  3) Arch / Manjaro"
echo "  4) Skip system package install (already installed)"
read -p "Choice [auto:${DETECTED_FAMILY}]: " CHOICE

case "$CHOICE" in
  1) OS_FAMILY="debian" ;;
  2) OS_FAMILY="fedora" ;;
  3) OS_FAMILY="arch" ;;
  4) OS_FAMILY="skip" ;;
  "") OS_FAMILY="$DETECTED_FAMILY" ;;
  *) OS_FAMILY="$DETECTED_FAMILY" ;;
esac

if [[ "$OS_FAMILY" == "unknown" ]]; then
  print_error "Could not determine OS family. Re-run and choose 1/2/3/4."
  exit 1
fi

# Check for required tools
check_command() {
    if command -v $1 &> /dev/null; then
        return 0
    else
        return 1
    fi
}

print_info "Checking prerequisites..."

# Check Python 3.10+
if ! check_command python3; then
    print_error "Python 3 is not installed"
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    print_error "Python 3.10+ is required. Found: $PYTHON_VERSION"
    exit 1
fi

print_success "Python $PYTHON_VERSION detected"

# Install system dependencies based on OS
print_info "Installing system dependencies..."

if [[ "$OS_FAMILY" == "debian" ]]; then
    sudo apt update
    sudo apt install -y \
        python3 python3-pip python3-venv python3-dev build-essential \
        clamav clamav-daemon yara file bubblewrap
    print_success "System dependencies installed (apt)"
    print_info "Updating ClamAV signatures..."; sudo freshclam || true
elif [[ "$OS_FAMILY" == "fedora" ]]; then
    sudo dnf install -y \
        python3 python3-pip python3-venv python3-devel gcc \
        clamav clamav-update yara file bubblewrap
    print_success "System dependencies installed (dnf)"
    print_info "Updating ClamAV signatures..."; sudo freshclam || true
elif [[ "$OS_FAMILY" == "arch" ]]; then
    sudo pacman -Sy --noconfirm \
        python python-pip python-virtualenv base-devel \
        clamav yara file bubblewrap
    print_success "System dependencies installed (pacman)"
    print_info "Updating ClamAV signatures..."; sudo freshclam || true
elif [[ "$OS_FAMILY" == "skip" ]]; then
    print_warning "Skipping system package install per user choice. Make sure clamav, yara, bubblewrap are installed."
else
    print_error "Unsupported or unknown OS family: $OS_FAMILY"
    exit 1
fi

# Create virtual environment
print_info "Creating Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    print_success "Virtual environment created"
else
    print_warning "Virtual environment already exists"
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source .venv/bin/activate
print_success "Virtual environment activated"

# Upgrade pip
print_info "Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
print_info "Installing Python dependencies..."
pip install -r requirements.txt
print_success "Python dependencies installed"

# Create necessary directories
print_info "Creating directories..."
mkdir -p reports quarantine processed logs
print_success "Directories created"

# Validate configuration
print_info "Validating configuration..."
python -m valkyrie.cli config validate
print_success "Configuration is valid"

# Offer to run tests
print_info "Running test suite..."
read -p "Would you like to run the test suite? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if command -v pytest &> /dev/null; then
        pytest tests/ -v
        print_success "Test suite completed"
    else
        print_warning "pytest not installed, skipping tests"
    fi
fi

# Create systemd service files (optional)
read -p "Would you like to create systemd service files? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cat > valkyrie-watcher.service <<EOF
[Unit]
Description=Valkyrie File Security Scanner - Watcher
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/.venv/bin/python watcher/watcher.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    cat > valkyrie-dashboard.service <<EOF
[Unit]
Description=Valkyrie File Security Scanner - Dashboard
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/.venv/bin/python gui/backend/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    print_success "Systemd service files created"
    print_info "To install services, run:"
    print_info "  sudo cp valkyrie-*.service /etc/systemd/system/"
    print_info "  sudo systemctl enable valkyrie-watcher valkyrie-dashboard"
    print_info "  sudo systemctl start valkyrie-watcher valkyrie-dashboard"
fi

echo ""
echo "=========================================="
echo -e "${GREEN}✓ Setup Complete!${NC}"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Edit configuration (optional):"
echo "   nano config/valkyrie.yaml"
echo ""
echo "2. Start the file watcher:"
echo "   python watcher/watcher.py"
echo ""
echo "3. In another terminal, start the dashboard:"
echo "   python gui/backend/app.py"
echo ""
echo "4. Open the dashboard:"
echo "   http://127.0.0.1:5000"
echo ""
echo "5. Drop files into ~/Downloads to see real-time scanning"
echo ""
echo "CLI Commands:"
echo "  Scan a file:       python -m valkyrie.cli scan /path/to/file"
echo "  Check status:      python -m valkyrie.cli status"
echo "  List quarantine:   python -m valkyrie.cli quarantine list"
echo ""
echo "For more information, see README.md"
echo ""
