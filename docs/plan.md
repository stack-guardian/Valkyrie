Valkyrie File Security — Execution Plan

Objective
- Deliver a reliable, local-first malware triage loop for Linux: monitor inbound files, score with ClamAV + YARA + heuristics, quarantine on risk, and present clear reports via CLI and dashboard.

Inventory (today)
- Core engine in `valkyrie/`: enhanced analysis (hash, MIME, ClamAV, YARA, heuristics), risk scoring, config loader, rotating logger, and CLI (`python -m valkyrie.cli ...`).
- Watcher in `watcher/`: legacy pipeline using its own `analysis.py`, hardcoded `~/Downloads`, minimal logging/notifications, writes JSON to `reports/` and moves files to `processed/` or `quarantine/`.
- Dashboard in `gui/backend/app.py`: lists reports, no pagination/search, reads straight from `reports/`.
- Config in `config/valkyrie.yaml`: full defaults for paths, thresholds, timeouts, logging; not yet consumed by the watcher or dashboard.
- Rules in `yara_rules/`: demo/malware/suspicious sample rule sets.
- Tests in `tests/`: unit coverage for config, heuristics, scoring, analysis; one assertion conflict in `test_scoring.py::test_custom_thresholds` needs fixing (quarantine vs review expectation).
- Ops scripts: `setup.sh` (installs deps, creates venv, optional systemd units) and `launchers/secure-scan-launch.sh` (hardcoded project paths).

Key Gaps to Close
- Duplicate analysis paths: watcher uses legacy `watcher/analysis.py` instead of the enhanced engine and config-driven settings.
- Configuration plumbing: watcher and dashboard ignore `config/valkyrie.yaml`; launch script and systemd examples hardcode paths/ports.
- Observability/retention: mixed `print`/notify-send, no log rotation in watcher, no report retention/compression despite config fields.
- UX: dashboard lacks filters/search/pagination and safe links to quarantined files; API lacks health endpoint.
- Tests: no integration/E2E coverage for watcher→report→dashboard flow; known failing assertion in scoring test.
- Packaging/devex: no pinned dev toolchain, no docker or make targets, no one-command smoke test.

Work Plan & Milestones
- Phase 0 (Day 0-1) Baseline correctness
  - Fix `test_scoring.py::test_custom_thresholds` expectation; ensure `pytest -v` passes locally.
  - Align report schema (include scoring block) between watcher and `valkyrie.analysis`.
- Phase 1 (Week 1) Config + watcher unification
  - Refactor `watcher/watcher.py` to load `ValkyrieConfig` and call `EnhancedAnalysisEngine`; drop duplicate `watcher/analysis.py`.
  - Make watch path, size limits, and thresholds come from config; sanitize filenames and apply quarantine permissions.
  - Wire `valkyrie.logger` into watcher; honor log file/rotation settings.
- Phase 2 (Week 2) Reliability & retention
  - Implement report retention/compression per `output.retention`; CLI `clean` to reuse; add health endpoint `/health` in dashboard.
  - Harden timeouts/size caps; skip oversized or unsupported files with reason in report; ensure graceful error handling.
- Phase 3 (Week 3) Detection & rules quality
  - Curate YARA packs (at least one per severity tier) and add a lightweight rule benchmark; schedule `freshclam` guidance.
  - Extend heuristics scoring weights from config; add archive expansion ratio and entropy thresholds to reports.
- Phase 4 (Week 4) UX & Ops polish
  - Dashboard: pagination/search/filter by verdict/date, badge colors, link to JSON, and safe metadata view for quarantine entries.
  - Ship `make` targets or a `tasks.sh` for common flows (setup, scan, test, clean, serve).
  - Provide docker image and updated `systemd` units that read env/config instead of hardcoded paths; refresh README snippets.

Acceptance Checks
- Unit: `pytest -v` green (analysis, config, heuristics, scoring); add watcher adapter tests once refactored.
- Integration: scripted smoke (`scripts/smoke.sh`): drop benign .txt → ALLOW; drop EICAR → QUARANTINE; verify reports created, files moved, dashboard lists entries.
- Ops: log files rotate at configured size; retention job deletes/compresses old reports; health endpoint returns 200 with component statuses.

Dependencies & Commands
- System: `clamav`, `clamav-daemon` (freshclam), `yara`, `file`.
- Python: `pip install -r requirements.txt` (includes Flask, watchdog, pytest, bandit, safety).
- Run: `python -m valkyrie.cli scan /path/to/file`, `python watcher/watcher.py`, `python gui/backend/app.py`, `python -m valkyrie.cli status`.
- Tests: `pytest -v` (unit), `pytest tests/test_analysis.py::TestEnhancedAnalysisEngine::test_analyze_benign_file -v` for quick smoke.

Risks & Mitigations
- False positives: calibrate YARA severities and scoring weights; keep REVIEW tier default; allow hash/path allowlist in config.
- Performance spikes: enforce timeouts and size caps; avoid scanning already-processed hashes; batch ClamAV when possible.
- Path/permission errors: validate directories on startup; ensure quarantine perms 700; sanitize filenames before moving.
