# Repository Guidelines

## Project Structure & Module Organization
- `watcher/` runs the real-time scanner: `watcher.py` monitors `~/Downloads` (edit `INCOMING` to change), calls `analysis.py` for hashing, MIME detection, ClamAV, and YARA scoring, then writes JSON to `reports/` and moves samples into `processed/` or `quarantine/`.
- `gui/backend/app.py` is a minimal Flask dashboard that renders the contents of `reports/`; dependencies live in `gui/backend/requirements.txt`.
- `yara_rules/*.yar` contains detection rules; `launchers/secure-scan-launch.sh` is a convenience starter (update hardcoded paths before using).
- `reports/`, `quarantine/`, and `processed/` are runtime artifacts—do not commit them unless intentionally sharing sanitized samples.

## Build, Test, and Development Commands
- Create a virtual env: `python3 -m venv .venv && source .venv/bin/activate`
- Install Python deps: `pip install -r gui/backend/requirements.txt watchdog`
- System tools required for full scanning: `sudo apt install clamav yara`
- One-off scan of a file: `python watcher/analysis.py /path/to/file`
- Run the file watcher: `python watcher/watcher.py`
- Start the dashboard: `python gui/backend/app.py` then open http://127.0.0.1:5000 (or use `launchers/secure-scan-launch.sh` after fixing its paths).

## Coding Style & Naming Conventions
- Python 3 with PEP 8, 4-space indents, and `snake_case` for modules, functions, and variables.
- Keep helpers in `analysis.py` side-effect free; perform I/O in the caller. Add short docstrings for non-obvious logic.
- Avoid hardcoded usernames/paths; prefer `os.path` helpers and environment variables when extending.
- YARA: one family per file, kebab-case filenames (e.g., `office-macros.yar`), include concise `meta` entries describing intent.

## Testing Guidelines
- No automated suite yet; validate locally with `python watcher/analysis.py sample.bin` and confirm the JSON includes `sha256`, `verdict`, `clamav`, and `yara` keys.
- Integration check before PRs: run watcher + dashboard, drop a benign file to ensure it moves to `processed/` and appears as ALLOW; use a known test signature (e.g., EICAR) or a YARA test rule to confirm QUARANTINE flow.

## Commit & Pull Request Guidelines
- Current history uses short, imperative subjects (e.g., "Initial commit - Valkyrie"); keep titles ≤72 chars, present tense, and call out scope (`watcher`, `gui`, `rules`).
- PRs should include: purpose summary, manual test notes (commands and results), screenshots when UI changes, and links to related issues. Keep diffs focused and note any path/port/config changes.
