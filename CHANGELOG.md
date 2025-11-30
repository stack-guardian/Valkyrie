# Changelog

All notable changes to the Valkyrie File Security Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-11-30

### Added
- **Configuration Management**
  - YAML configuration file support (`config/valkyrie.yaml`)
  - Environment variable overrides
  - Configuration validation
  - Dot notation access to config values

- **Structured Logging**
  - Component-based logging infrastructure
  - Log rotation with configurable size and backup count
  - Multiple log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  - Structured log formatting

- **Heuristic Analysis Engine**
  - Shannon entropy analysis (packed/encrypted detection)
  - Packer detection (UPX, ASPack, PECompact, Themida)
  - Archive inspection (ZIP, TAR, GZ, RAR, 7Z)
  - Archive bomb detection (100:1 expansion ratio)
  - File type validation (extension spoofing detection)
  - Double extension detection
  - Hidden extension detection

- **Intelligent Scoring System**
  - Multi-factor risk scoring algorithm
  - Configurable scoring weights
  - YARA severity-based scoring
  - Comprehensive scoring breakdown
  - Verdict determination (quarantine/review/allow)

- **Enhanced Analysis Engine**
  - Multi-engine detection pipeline
  - Timeout protection for all operations
  - File size limit enforcement
  - ClamAV and YARA integration
  - Comprehensive error handling

- **Command-Line Interface**
  - `scan` command (single file or directory)
  - `config validate` command
  - `rules list` command
  - `quarantine list` command
  - `status` command
  - `clean` command
  - Dry-run mode support
  - JSON and human-readable output formats

- **Comprehensive Test Suite**
  - Configuration tests
  - Heuristic analysis tests
  - Risk scoring tests
  - Analysis engine tests
  - Pytest integration
  - Mock support for external dependencies

- **Enhanced YARA Rules**
  - Malware detection rules (backdoors, ransomware, stealers)
  - Suspicious behavior rules (anti-analysis, obfuscation)
  - Organized by category
  - Metadata for severity and author

- **Documentation**
  - Comprehensive README with examples
  - Installation and setup guide
  - Usage documentation
  - Architecture overview
  - Roadmap and future features

- **Docker Support**
  - Dockerfile for containerized deployment
  - Docker Compose configuration
  - Health checks
  - Volume mounts for persistent storage
  - Non-root user for security

- **Setup Automation**
  - Automated installation script (`setup.sh`)
  - Dependency detection and installation
  - Systemd service file generation
  - Virtual environment setup

### Changed
- Improved error handling throughout the application
- Enhanced logging with component names
- Better file path handling and validation
- Optimized analysis pipeline for performance

### Deprecated
- Legacy `analysis.py` in watcher directory (maintained for compatibility)

### Security
- Quarantine directory permissions (700)
- Path validation to prevent directory traversal
- Safe filename sanitization
- Non-root container user
- No external network dependencies

## [0.1.0] - 2025-11-29

### Added
- Initial MVP implementation
- Basic file monitoring with watchdog
- ClamAV antivirus integration
- YARA rule scanning
- Flask dashboard
- SHA256 hashing
- MIME type detection
- Basic risk scoring
- Automatic file quarantine
- Desktop notifications
- JSON report generation
