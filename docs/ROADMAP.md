# Valkyrie File Security Scanner — Product Roadmap & Technical Plan

> **Mission**: Deliver a production-ready, local-first malware detection and automated triage system for Linux environments that combines multi-layered static analysis with intelligent threat scoring and real-time monitoring.

---

## Executive Summary

**Valkyrie** is an open-source file security scanner designed for Linux systems that provides automated malware detection, risk scoring, and quarantine capabilities. The system monitors incoming files in real-time, analyzes them through multiple detection engines (ClamAV, YARA, heuristics), and provides actionable intelligence through a web-based dashboard.

**Current Status**: MVP functional with basic monitoring, ClamAV + YARA integration, and Flask dashboard  
**Target**: Production-ready system with enterprise-grade reliability, comprehensive detection coverage, and operational tooling

---

## 🎯 Project Vision & Goals

### Primary Objectives
1. **Zero-Day Protection**: Detect unknown threats through multi-layered heuristic analysis and behavioral indicators
2. **Operational Excellence**: Provide reliable, maintainable security automation with minimal false positives
3. **Privacy-First**: All analysis happens locally—no cloud dependencies, no data exfiltration
4. **Developer-Friendly**: Simple setup, clear documentation, extensible architecture

### Target Use Cases
- **Personal Security**: Monitor downloads folder for malicious files on personal Linux systems
- **Development Environments**: Scan incoming dependencies, packages, and artifacts
- **Small Team Operations**: Provide basic endpoint protection for small organizations
- **Security Research**: Platform for testing YARA rules and malware samples safely

---

## 📊 Current Architecture

### System Components

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

### Technology Stack
- **Language**: Python 3.10+
- **File Monitoring**: watchdog library
- **Signature Detection**: ClamAV (system)
- **Rule Engine**: YARA (system)
- **Web Framework**: Flask 3.0.0
- **Data Format**: JSON reports
- **Notifications**: notify-send (Linux desktop)

### Current Capabilities
✅ Real-time file monitoring on specified directory  
✅ SHA-256 hashing and MIME type detection  
✅ ClamAV signature-based detection  
✅ YARA rule matching  
✅ Simple risk scoring (0-100 scale)  
✅ Automatic file quarantine/processing  
✅ JSON report generation  
✅ Basic web dashboard with verdict display  
✅ Desktop notifications for detections  

### Known Limitations
❌ Hardcoded paths in launch scripts  
❌ No configuration file support  
❌ Limited heuristic analysis (no entropy, packer detection, archive inspection)  
❌ Basic scoring algorithm (binary thresholds)  
❌ No log rotation or report cleanup  
❌ Dashboard lacks filtering, search, pagination  
❌ No error handling for large files or scan timeouts  
❌ Missing unit tests and integration tests  
❌ No performance metrics or health monitoring  
❌ YARA rule collection is minimal (demo only)  

---

## 🚀 Development Roadmap

### Phase 1: Foundation & Hardening (Weeks 1-2)
**Goal**: Make the system configurable, reliable, and production-ready

#### 1.1 Configuration Management
- [ ] **Configuration File System**
  - Implement YAML/TOML config file (`config/valkyrie.yml`)
  - Support for watch paths, output directories, thresholds
  - Environment variable overrides
  - Config validation on startup
  
- [ ] **Logging Infrastructure**
  - Structured logging with Python `logging` module
  - Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
  - Separate logs: `watcher.log`, `analysis.log`, `api.log`
  - Log rotation (size-based, max 10 files, 10MB each)
  - Log format: timestamp, level, component, message, context

#### 1.2 Operational Reliability
- [ ] **Report Management**
  - Automatic report rotation (keep last N days, configurable)
  - Report archival to compressed format (JSON → .json.gz)
  - Cleanup job for old quarantine/processed files
  - Report database index for faster dashboard queries
  
- [ ] **Error Handling & Resilience**
  - Graceful handling of missing dependencies (ClamAV, YARA)
  - Timeout protection for long-running scans (configurable limits)
  - File size limits (skip files > configurable threshold, log skip)
  - Permission error handling (readonly files, access denied)
  - Crash recovery (resume monitoring after failure)
  - Health check endpoint (`/health`) for monitoring

#### 1.3 Security Hardening
- [ ] **Safe File Handling**
  - Validate file paths (prevent directory traversal)
  - Safe filename sanitization for reports
  - Quarantine directory permissions (700, owner-only)
  - Secure temp file handling during analysis
  
- [ ] **Process Isolation**
  - Run analysis in separate process/thread pool
  - Resource limits for scan processes (CPU, memory)
  - Sandbox consideration for future dynamic analysis

### Phase 2: Enhanced Detection (Weeks 3-4)
**Goal**: Improve detection accuracy and reduce false positives/negatives

#### 2.1 Advanced Heuristic Analysis
- [ ] **Entropy Analysis**
  - Calculate Shannon entropy for file sections
  - Flag high-entropy files (possible encryption/packing)
  - Entropy threshold: >7.2 = suspicious, >7.8 = high risk
  - Per-section entropy for PE/ELF files
  
- [ ] **Packer Detection**
  - Detect common packers: UPX, ASPack, PECompact, Themida
  - Check for suspicious section names (.packed, .upx, .themida)
  - Identify abnormal entry points in PE files
  - Flag files with low import count relative to size
  
- [ ] **Archive Inspection**
  - Recursive extraction support (ZIP, TAR, GZ, RAR, 7Z)
  - Scan archive contents (depth limit: 3 levels)
  - Detect archive bombs (expansion ratio > 100:1)
  - Flag password-protected archives
  - Support for nested archives
  
- [ ] **File Type Anomalies**
  - Mismatch detection (extension vs. actual MIME type)
  - Double extension detection (.pdf.exe)
  - Hidden extensions (trailing spaces, unicode tricks)
  - Executable files masquerading as documents

#### 2.2 YARA Rule Enhancement
- [ ] **Curated Rule Collection**
  - Import quality rulesets:
    - YARA-Forge community rules
    - Elastic Security YARA rules
    - Custom rules for common malware families
  - Organize by category: malware/, exploits/, suspicious/, pua/
  
- [ ] **Rule Management**
  - Rule metadata standardization (author, date, severity, reference)
  - Severity levels: critical, high, medium, low, info
  - Rule testing framework (benign corpus, malware samples)
  - Performance profiling for slow rules
  - Rule update mechanism (git submodule or download script)
  
- [ ] **Advanced YARA Features**
  - Module usage: PE, ELF, magic, hash, math
  - Import hash (imphash) detection
  - Section hash matching
  - String entropy conditions
  - File size and format constraints

#### 2.3 Intelligent Scoring System
- [ ] **Multi-Factor Risk Scoring**
  ```
  Risk Score = (Detection Weight × Confidence) + Heuristic Factors
  
  Detection Weights:
  - ClamAV signature hit: 100 points (definitive)
  - YARA critical rule: 90 points
  - YARA high severity: 70 points
  - YARA medium severity: 40 points
  - High entropy (>7.8): 30 points
  - Packer detected: 25 points
  - File type mismatch: 20 points
  - Archive bomb indicators: 50 points
  - Suspicious imports/exports: 15 points
  
  Verdict Thresholds:
  - Score >= 80: QUARANTINE (immediate threat)
  - Score 40-79: REVIEW (suspicious, manual check)
  - Score < 40: ALLOW (likely benign)
  ```
  
- [ ] **Configurable Thresholds**
  - Per-rule severity override (config file)
  - Custom scoring weights for each heuristic
  - Whitelist/blacklist by hash or file pattern
  - Exemption rules (trusted paths, known good files)

#### 2.4 ClamAV Integration Improvements
- [ ] **Signature Management**
  - Automated freshclam updates (systemd timer)
  - Custom signature loading (local .ndb, .hdb files)
  - Alert on outdated signatures (> 7 days old)
  
- [ ] **Performance Optimization**
  - Pre-load ClamAV database to memory (clamd daemon)
  - Socket communication instead of CLI calls
  - Batch scanning for multiple files
  - Cache results for unchanged files (hash-based)

### Phase 3: User Experience & Operations (Weeks 5-6)
**Goal**: Make the system easy to use, monitor, and maintain

#### 3.1 Dashboard Enhancements
- [ ] **UI/UX Improvements**
  - Responsive design (mobile-friendly)
  - Real-time updates (WebSocket or SSE)
  - Color-coded verdict badges with icons
  - Severity indicators for YARA hits
  - File preview for safe file types (text, images)
  - Timeline view of detections
  
- [ ] **Search & Filtering**
  - Full-text search across filename, hash, YARA rules
  - Filter by: verdict, date range, MIME type, file size
  - Sort by: timestamp, risk score, file name
  - Saved filter presets
  - Export filtered results to CSV/JSON
  
- [ ] **Pagination & Performance**
  - Server-side pagination (50 reports per page)
  - Lazy loading for large datasets
  - Report caching (in-memory or Redis)
  - Database backend option (SQLite for >10k reports)
  
- [ ] **Detailed Report View**
  - Expandable sections: hashes, YARA hits, heuristics
  - Visual risk score gauge
  - Related files (same family, similar hash)
  - VirusTotal integration (optional, API key)
  - Action buttons: re-scan, restore from quarantine, delete

#### 3.2 CLI Enhancements
- [ ] **Analysis CLI**
  - `--dry-run` mode (analyze without moving files)
  - `--verbose` detailed output
  - `--output` specify custom report path
  - `--format` JSON, CSV, or human-readable
  - Batch analysis: `valkyrie scan /path/to/directory`
  
- [ ] **Management CLI**
  - `valkyrie config validate` - check config syntax
  - `valkyrie rules update` - fetch latest YARA rules
  - `valkyrie rules list` - show loaded rules
  - `valkyrie quarantine list` - show quarantined files
  - `valkyrie quarantine restore <hash>` - restore file
  - `valkyrie clean --reports --older-than 30d`
  - `valkyrie status` - show service health

#### 3.3 Monitoring & Observability
- [ ] **Metrics Collection**
  - Files scanned (total, per verdict)
  - Scan duration (avg, p95, p99)
  - Detection rates (by engine: ClamAV, YARA, heuristics)
  - Error counts (by type)
  - Queue depth (pending scans)
  - System resource usage (CPU, memory, disk I/O)
  
- [ ] **Prometheus Integration**
  - `/metrics` endpoint for Prometheus scraping
  - Custom metrics: `valkyrie_scans_total`, `valkyrie_detections`, etc.
  - Grafana dashboard template
  
- [ ] **Alerting System**
  - Webhook support (POST JSON to URL on detection)
  - Email notifications (SMTP configuration)
  - Slack/Discord integration
  - Alert rules: threshold-based (X detections in Y minutes)
  - Alert deduplication (don't spam on repeated detections)

#### 3.4 Deployment & Installation
- [ ] **Packaging**
  - PyPI package: `pip install valkyrie-scanner`
  - Debian package (.deb) for Ubuntu/Debian
  - RPM package for Fedora/RHEL
  - Docker container with all dependencies
  - Docker Compose setup (watcher + dashboard + database)
  
- [ ] **Installation Script**
  - One-line installer: `curl -sSL install.sh | bash`
  - Dependency checking (ClamAV, YARA)
  - Automatic config generation
  - Systemd service files
  - Uninstaller script
  
- [ ] **Documentation**
  - README: Quick start, features, screenshots
  - INSTALL.md: Detailed installation for each platform
  - CONFIGURATION.md: All config options explained
  - RULES.md: YARA rule development guide
  - ARCHITECTURE.md: System design documentation
  - API.md: REST API documentation
  - TROUBLESHOOTING.md: Common issues and solutions

### Phase 4: Testing & Quality (Week 7)
**Goal**: Ensure reliability through comprehensive testing

#### 4.1 Unit Testing
- [ ] **Core Functions**
  - `test_sha256()` - hash calculation correctness
  - `test_mime_type()` - MIME detection accuracy
  - `test_entropy_calculation()` - entropy algorithm
  - `test_risk_scoring()` - scoring logic validation
  - `test_config_parsing()` - config file validation
  - Target: >80% code coverage
  
- [ ] **Test Framework**
  - pytest with fixtures
  - Mock external dependencies (ClamAV, YARA)
  - Parametrized tests for edge cases
  - Test data: benign samples, EICAR test file

#### 4.2 Integration Testing
- [ ] **End-to-End Scenarios**
  - Benign file flow (download → scan → allow → processed/)
  - EICAR detection (download → scan → quarantine)
  - YARA rule hit (custom rule → detection → quarantine)
  - Archive scanning (ZIP with nested malware)
  - Large file handling (>100MB, skip logic)
  - Concurrent scans (multiple files at once)
  
- [ ] **Dashboard Testing**
  - API endpoint tests (GET /api/reports, etc.)
  - UI tests (Selenium or Playwright)
  - Load testing (1000+ reports)

#### 4.3 Performance Testing
- [ ] **Benchmarking**
  - Scan throughput (files per second)
  - Memory usage under load
  - Disk I/O patterns
  - Startup time
  - Dashboard response time (with 10k reports)
  
- [ ] **Optimization**
  - Profile slow paths (cProfile)
  - Optimize hot loops
  - Reduce memory allocations
  - Parallelize independent tasks

#### 4.4 Security Testing
- [ ] **Vulnerability Assessment**
  - Path traversal testing (malicious filenames)
  - Command injection testing (file processing)
  - XSS testing in dashboard (filename display)
  - CSRF protection for API endpoints
  - Dependency vulnerability scanning (pip-audit, Safety)
  
- [ ] **Malware Testing**
  - Test against known malware samples (with safety precautions)
  - False positive testing (benign file corpus)
  - Evasion technique testing (obfuscation, polymorphism)

### Phase 5: Advanced Features (Weeks 8+)
**Goal**: Differentiate with advanced capabilities

#### 5.1 Machine Learning Integration
- [ ] **ML-Based Detection**
  - Feature extraction (PE headers, strings, opcodes)
  - Pre-trained models (MalConv, Ember)
  - Local inference (no cloud dependencies)
  - Model versioning and updates
  - Explainability (SHAP values for predictions)

#### 5.2 Threat Intelligence
- [ ] **Hash Reputation**
  - Local hash database (known good/bad)
  - Optional VirusTotal API integration
  - MISP integration (Malware Information Sharing Platform)
  - Threat feed ingestion (STIX/TAXII)

#### 5.3 Dynamic Analysis
- [ ] **Sandbox Integration**
  - Cuckoo Sandbox connector (optional)
  - Behavior monitoring (process, network, file I/O)
  - VM snapshot and restoration
  - Automated report generation

#### 5.4 Enterprise Features
- [ ] **Multi-Tenant Support**
  - User authentication (LDAP, OAuth)
  - Role-based access control (admin, analyst, viewer)
  - Per-user/group policies
  - Audit logging
  
- [ ] **Distributed Deployment**
  - Agent-server architecture
  - Central management console
  - Multi-node scanning (load balancing)
  - Centralized reporting and dashboards

---

## 📋 Implementation Priorities

### Must-Have (MVP+)
1. Configuration file support
2. Logging infrastructure
3. Error handling & timeouts
4. Report rotation
5. Entropy analysis
6. Archive inspection
7. Dashboard search/filtering
8. CLI improvements (`--dry-run`, batch scanning)
9. Basic test suite (unit + E2E)
10. Documentation (README, INSTALL, CONFIGURATION)

### Should-Have (Version 1.0)
1. Packer detection
2. Enhanced YARA ruleset (>50 quality rules)
3. Intelligent scoring system
4. Dashboard real-time updates
5. Metrics & monitoring
6. Systemd service integration
7. Docker container
8. API documentation
9. Performance optimization
10. Security hardening

### Nice-to-Have (Version 2.0+)
1. Machine learning detection
2. Threat intelligence feeds
3. Sandbox integration
4. Multi-tenant support
5. Distributed deployment
6. Advanced visualization (graphs, heatmaps)
7. Plugin system for extensibility
8. REST API for integrations
9. Mobile app (monitor on the go)
10. Cloud backup of reports (optional)

---

## 🎬 Getting Started (Current Setup)

### Prerequisites
```bash
# System packages
sudo apt install clamav clamav-daemon yara python3 python3-venv

# Update ClamAV signatures
sudo freshclam
```

### Installation
```bash
# Clone repository
git clone https://github.com/yourusername/valkyrie.git
cd valkyrie

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r gui/backend/requirements.txt watchdog

# Configure watch path (edit watcher/watcher.py)
# INCOMING = os.path.expanduser("~/Downloads")

# Run components
python watcher/watcher.py          # Terminal 1: File watcher
python gui/backend/app.py          # Terminal 2: Dashboard
```

### Usage
1. Open dashboard: http://127.0.0.1:5000
2. Drop files into `~/Downloads`
3. View scan results in dashboard
4. Check `quarantine/` for threats, `processed/` for clean files

---

## 🔧 Technical Debt & Refactoring

### Code Quality
- [ ] Type hints for all functions (Python 3.10+ syntax)
- [ ] Docstrings for all public functions (Google style)
- [ ] PEP 8 compliance (use Black formatter)
- [ ] Remove hardcoded paths and magic numbers
- [ ] Extract configuration to constants file
- [ ] Reduce cyclomatic complexity (max 10 per function)

### Architecture Improvements
- [ ] Separate concerns: analysis logic vs. I/O operations
- [ ] Plugin architecture for detection engines
- [ ] Abstract storage layer (filesystem, database, S3)
- [ ] Event-driven architecture (message queue for scans)
- [ ] API-first design (dashboard as API consumer)

### Performance
- [ ] Profile and optimize hot paths
- [ ] Implement caching (LRU cache for repeated scans)
- [ ] Parallel scanning (thread pool or multiprocessing)
- [ ] Async I/O for dashboard (FastAPI or aiohttp)
- [ ] Database indexing (if using SQL backend)

---

## 📊 Success Metrics

### Detection Efficacy
- **Detection Rate**: >95% on known malware corpus (e.g., Malpedia samples)
- **False Positive Rate**: <2% on benign file corpus (e.g., Windows system files, popular software)
- **Time to Detect**: <5 seconds for 95th percentile file size (<10MB)

### Performance
- **Throughput**: >50 files/minute on modest hardware (4 core, 8GB RAM)
- **Memory Usage**: <500MB under normal load (<100 files in queue)
- **Startup Time**: <3 seconds for watcher and dashboard

### Reliability
- **Uptime**: >99.5% (measured over 30 days)
- **Error Rate**: <0.1% of scans result in unhandled errors
- **Recovery Time**: <10 seconds to resume after crash

### User Experience
- **Setup Time**: <10 minutes from clone to running (for technical users)
- **Dashboard Load Time**: <1 second for <1000 reports
- **Documentation Quality**: >90% of issues resolved without external support

---

## 🤝 Contributing

### Development Workflow
1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Make changes with tests
4. Run test suite: `pytest tests/`
5. Check code quality: `black . && flake8`
6. Commit: `git commit -m "feat: add amazing feature"`
7. Push and create Pull Request

### Code Review Checklist
- [ ] Tests pass (`pytest`)
- [ ] Code coverage maintained or improved
- [ ] Documentation updated
- [ ] CHANGELOG.md entry added
- [ ] No new security vulnerabilities (`pip-audit`)
- [ ] Performance impact assessed

---

## 📚 Resources & References

### Security Standards
- **MITRE ATT&CK**: Defense Evasion, Initial Access techniques
- **OWASP Top 10**: Input validation, secure file handling
- **CWE Top 25**: Common weakness enumeration

### Technical Resources
- **YARA Documentation**: https://yara.readthedocs.io/
- **ClamAV Manual**: https://docs.clamav.net/
- **Python watchdog**: https://python-watchdog.readthedocs.io/
- **Flask Documentation**: https://flask.palletsprojects.com/

### Malware Analysis
- **Practical Malware Analysis** (book)
- **Malware Data Science** (book)
- **Awesome Malware Analysis**: GitHub resource list
- **YARA-Forge**: Community rule repository

### Similar Projects
- **Cuckoo Sandbox**: Automated malware analysis
- **CAPE Sandbox**: Config And Payload Extraction
- **DRAKVUF Sandbox**: VMI-based sandboxing
- **Joe Sandbox**: Commercial malware analysis platform

---

## 📅 Release Schedule

### Version 0.2.0 (Target: Week 2)
- Configuration file support
- Logging infrastructure
- Error handling improvements
- Report rotation

### Version 0.3.0 (Target: Week 4)
- Entropy analysis
- Archive inspection
- Enhanced YARA rules
- Improved scoring

### Version 0.4.0 (Target: Week 6)
- Dashboard enhancements (search, filter, real-time)
- CLI improvements
- Metrics & monitoring
- Docker container

### Version 1.0.0 (Target: Week 8)
- Complete test suite (>80% coverage)
- Full documentation
- Production-ready hardening
- PyPI package release
- Public announcement

---

## 🛡️ Security & Privacy

### Privacy Commitments
- **No telemetry**: No data sent to external servers by default
- **Local analysis**: All scanning happens on your machine
- **No cloud dependencies**: Works completely offline
- **Transparent code**: Open source, auditable

### Optional Integrations
- VirusTotal API (requires API key, explicit opt-in)
- MISP threat feeds (requires endpoint configuration)
- Webhook notifications (user-controlled endpoints)

### Security Disclosures
- Report vulnerabilities to: security@valkyrie-project.org
- PGP key: [to be added]
- Response time: <48 hours for critical issues
- Coordinated disclosure timeline: 90 days

---

## 📞 Support & Community

- **Documentation**: https://docs.valkyrie-project.org
- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: Q&A and general discussion
- **Discord**: Real-time community chat (invite link)
- **Security**: security@valkyrie-project.org

---

## 📄 License

This project is licensed under the MIT License - see LICENSE file for details.

---

**Last Updated**: 2025-01-XX  
**Document Version**: 2.0  
**Status**: Active Development
