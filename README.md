# Valkyrie - File Security Scanner

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](#testing)

**Valkyrie** is a production-ready, local-first malware detection and automated triage system for Linux environments. It combines multi-layered static analysis with intelligent threat scoring and real-time monitoring to keep your system secure.

## ✨ Features

### 🔍 Multi-Engine Detection
- **ClamAV**: Industry-standard signature-based antivirus scanning
- **YARA**: Advanced rule-based malware detection with custom rules
- **Heuristic Analysis**: Entropy analysis, packer detection, and archive inspection
- **File Type Validation**: Detects extension spoofing and malicious file types

### 🎯 Intelligent Scoring
- Multi-factor risk scoring (0-100 scale)
- Configurable thresholds for quarantine/review/allow
- Weighted detection engine results
- Comprehensive scoring breakdown

### 📊 Real-Time Monitoring
- Continuous file system monitoring
- Automatic file categorization (quarantine/processed)
- Desktop notifications on threat detection
- JSON report generation

### 🎨 Web Dashboard
- Real-time scan results visualization
- Color-coded verdict system
- Search and filter capabilities
- JSON export for external analysis

### ⚙️ Enterprise Features
- YAML configuration file support
- Structured logging with rotation
- CLI management tools
- Comprehensive test suite
- Docker containerization support

## 🚀 Quick Start

### Prerequisites

```bash
# Install system dependencies
sudo apt update
sudo apt install -y clamav clamav-daemon yara python3 python3-pip python3-venv

# Update ClamAV signatures
sudo freshclam
```

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/vibhxr69/valkyrie.git
   cd valkyrie
   ```

2. **Create virtual environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Valkyrie**
   ```bash
   # Edit configuration (optional)
   nano config/valkyrie.yaml

   # Validate configuration
   python -m valkyrie.cli config validate
   ```

5. **Run the scanner**
   ```bash
   # Start file watcher
   python watcher/watcher.py

   # In another terminal, start dashboard
   python gui/backend/app.py
   ```

6. **Access the dashboard**
   - Open http://127.0.0.1:5000 in your browser
   - Drop files into `~/Downloads` to see real-time scanning

### One-Line Setup

```bash
# Use the setup script
chmod +x setup.sh
./setup.sh
```

## 📖 Usage

### Command-Line Interface

**Scan a file:**
```bash
python -m valkyrie.cli scan /path/to/file.pdf
```

**Scan a directory:**
```bash
python -m valkyrie.cli scan /path/to/directory
```

**Dry-run mode (analyze without moving files):**
```bash
python -m valkyrie.cli scan --dry-run /path/to/file
```

**Check system status:**
```bash
python -m valkyrie.cli status
```

**List quarantined files:**
```bash
python -m valkyrie.cli quarantine list
```

**Clean old reports:**
```bash
python -m valkyrie.cli clean --reports-days 30 --dry-run
```

**Validate configuration:**
```bash
python -m valkyrie.cli config validate
```

### Configuration

Edit `config/valkyrie.yaml` to customize:

```yaml
# Watcher Configuration
watcher:
  watch_path: ~/Downloads
  max_file_size_mb: 500

# Analysis Engines
analysis:
  engines:
    clamav:
      enabled: true
    yara:
      enabled: true
      rules_directory: yara_rules

# Scoring Configuration
scoring:
  thresholds:
    quarantine: 80
    review: 40
  weights:
    clamav_signature: 100
    yara_critical: 90

# Heuristics
analysis:
  heuristics:
    entropy:
      enabled: true
      suspicious_threshold: 7.2
    packer_detection:
      enabled: true
    archive_inspection:
      enabled: true
      max_depth: 3
```

### Programmatic Usage

```python
from valkyrie.analysis import analyze_file
from valkyrie.config import get_config

# Analyze a file
report = analyze_file("/path/to/file.pdf")

# Check verdict
if report["scoring"]["verdict"] == "quarantine":
    print(f"Threat detected: {report['scoring']['total_score']}")
    print(f"Detections: {report['scoring']['factors']}")
```

## 🏗️ Architecture

```
┌─────────────────┐
│  File System    │  ~/Downloads (configurable)
│  Event Source   │
└────────┬────────┘
         │ watchdog
         ▼
┌─────────────────┐
│  Analysis       │  Hash, MIME, ClamAV, YARA
│  Pipeline       │  Heuristics, Scoring
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Decision       │  Allow / Review / Quarantine
│  Engine         │  Threshold-based scoring
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌──────────┐
│Reports │ │File Move │  processed/ or quarantine/
│(JSON)  │ │+ Notify  │
└────────┘ └──────────┘
    │
    ▼
┌─────────────────┐
│  Dashboard      │  Flask web UI
│  (Web UI)       │  View reports, search, filter
└─────────────────┘
```

## 📊 Scanning Flow

1. **File Detection**: Watcher monitors configured directory
2. **Basic Analysis**: SHA256 hashing + MIME type detection
3. **Signature Scan**: ClamAV antivirus scan
4. **Rule Matching**: YARA ruleset scanning
5. **Heuristic Analysis**:
   - Entropy analysis (packed/encrypted detection)
   - Packer identification
   - Archive inspection
   - File type validation
6. **Risk Scoring**: Multi-factor scoring algorithm
7. **Decision**: Quarantine, Review, or Allow
8. **Reporting**: JSON report + dashboard update

## 🔬 Detection Capabilities

### Signature-Based Detection
- **ClamAV**: 8M+ malware signatures
- **YARA Rules**: Custom malware family signatures

### Heuristic Detection
- **High Entropy**: Detects packed/encrypted content (>7.2)
- **Packer Detection**: UPX, ASPack, PECompact, Themida
- **Archive Bombs**: Detects zip bombs (100:1 expansion ratio)
- **File Type Spoofing**: Identifies mismatched extensions

### Scoring Algorithm

```
Risk Score = (ClamAV × 1.0) + (YARA × Severity) + (Heuristics)

Verdict Thresholds:
- Quarantine: Score ≥ 80 (High confidence threat)
- Review: Score 40-79 (Suspicious, manual review)
- Allow: Score < 40 (Likely benign)
```

## 📁 Project Structure

```
valkyrie/
├── config/                    # Configuration files
│   └── valkyrie.yaml         # Main configuration
├── valkyrie/                  # Core library
│   ├── __init__.py
│   ├── config.py             # Configuration management
│   ├── logger.py             # Logging infrastructure
│   ├── heuristics.py         # Heuristic analysis
│   ├── scoring.py            # Risk scoring engine
│   ├── analysis.py           # Enhanced analysis engine
│   └── cli.py                # Command-line interface
├── watcher/                   # Real-time monitoring
│   ├── watcher.py            # File system watcher
│   ├── analysis.py           # Legacy analysis (compat)
│   └── analysis.bak          # Backup
├── gui/
│   └── backend/
│       ├── app.py            # Flask dashboard
│       ├── requirements.txt
├── yara_rules/               # Detection rules
│   ├── demo_rules.yar        # Demo rules
│   ├── malware.yar           # Malware signatures
│   └── suspicious.yar        # Suspicious behaviors
├── tests/                     # Test suite
│   ├── __init__.py
│   ├── test_config.py
│   ├── test_heuristics.py
│   ├── test_scoring.py
│   └── test_analysis.py
├── reports/                   # Scan reports
├── quarantine/               # Quarantined threats
├── processed/                # Clean files
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=valkyrie --cov-report=html

# Run specific test file
pytest tests/test_analysis.py -v

# Run with verbose output
pytest tests/ -vv
```

## 🐳 Docker Deployment

```bash
# Build container
docker build -t valkyrie-scanner .

# Run container
docker run -d \
  -p 5000:5000 \
  -v ~/Downloads:/watch \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/quarantine:/app/quarantine \
  valkyrie-scanner
```

## 📈 Roadmap

See [ROADMAP.md](ROADMAP.md) for detailed development plan.

### ✅ Completed (v0.2.0)
- [x] Configuration file system
- [x] Structured logging
- [x] Enhanced analysis engine
- [x] Heuristic analysis (entropy, packer, archive)
- [x] Intelligent scoring
- [x] CLI tool
- [x] Test suite
- [x] Documentation

### 🔄 In Progress
- [ ] Error handling and resilience
- [ ] Report rotation
- [ ] Dashboard enhancements
- [ ] Performance optimization

### 📋 Planned (v1.0.0)
- [ ] Machine learning detection
- [ ] Threat intelligence feeds
- [ ] Sandbox integration
- [ ] Multi-tenant support
- [ ] Distributed deployment

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Make changes with tests
4. Run test suite: `pytest tests/`
5. Check code quality: `black . && flake8`
6. Commit: `git commit -m "feat: add amazing feature"`
7. Push and create Pull Request

### Code Style

- Python 3.10+
- PEP 8 compliant
- Type hints
- Google-style docstrings
- 4-space indentation

## 📚 Documentation

- [ROADMAP.md](ROADMAP.md) - Detailed development roadmap
- [INSTALL.md](INSTALL.md) - Installation guide
- [CONFIGURATION.md](CONFIGURATION.md) - Configuration reference
- [RULES.md](RULES.md) - YARA rule development guide

## 🛡️ Security

- **Privacy-First**: All analysis happens locally
- **No Telemetry**: Zero data sent to external servers
- **Open Source**: Auditable codebase
- **Report Issues**: security@valkyrie-project.org

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- ClamAV Team - Antivirus engine
- VirusTotal - YARA rule inspiration
- Security community - Malware samples for testing

## 📞 Support

- 📖 Documentation: https://docs.valkyrie-project.org
- 🐛 Issues: https://github.com/yourusername/valkyrie/issues
- 💬 Discussions: https://github.com/yourusername/valkyrie/discussions
- 📧 Email: support@valkyrie-project.org

---

**Built with ❤️ by the Valkyrie Team**
