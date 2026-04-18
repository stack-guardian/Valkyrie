# Valkyrie — Linux Security Monitoring Utility

Valkyrie is a production-ready, local-first malware detection and automated triage system for Linux environments. It combines multi-engine static analysis with real-time file-system monitoring and intelligent risk scoring.

## Features

- Multi-engine detection using ClamAV, YARA, and custom heuristics  
- Real-time file-system monitoring with automatic quarantine  
- Multi-factor risk scoring and configurable thresholds  
- JSON reporting and structured logging  
- Web-based dashboard for scan visualization  
- YAML-based configuration and Docker support  

## Quick Start

### Prerequisites
```bash
sudo apt update
sudo apt install -y clamav clamav-daemon yara python3 python3-pip python3-venv
sudo freshclam
```

### Installation
```bash
git clone https://github.com/stack-guardian/Valkyrie.git
cd Valkyrie
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Start the watcher:
```bash
python watcher/watcher.py
```

Start the dashboard (in a separate terminal):
```bash
python gui/backend/app.py
```

Access the dashboard at http://127.0.0.1:5000.

## Usage

Full CLI documentation is available in the `valkyrie/cli.py` module. Run `python -m valkyrie.cli --help` for command reference.

## Architecture

The system consists of a file-system watcher, analysis pipeline (ClamAV + YARA + heuristics), decision engine, and Flask-based dashboard. All components run locally with no external dependencies beyond the listed prerequisites.

## License

MIT License — see LICENSE file.
