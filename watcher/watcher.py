import os, json, time, shutil, subprocess, sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from analysis_sandboxed import analyze
from scanning_modes import get_mode_config
from archive_tools import get_archive_info

# Add parent directory to path to import valkyrie modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from valkyrie.logger import setup_logging, get_logger

# Folders
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORTS = os.path.join(ROOT, "reports")
QUARANTINE = os.path.join(ROOT, "quarantine")
PROCESSED = os.path.join(ROOT, "processed")
LOGS_DIR = os.path.join(ROOT, "logs")
CONFIG_DIR = os.path.join(ROOT, "config")
SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings.json")

for d in (REPORTS, QUARANTINE, PROCESSED, LOGS_DIR, CONFIG_DIR):
    os.makedirs(d, exist_ok=True)

# Set up logging
LOG_FILE = os.path.join(LOGS_DIR, "watcher.log")
setup_logging(log_level="INFO", log_file=LOG_FILE, max_size_mb=10, backup_count=5)
logger = get_logger("watcher")

# Load settings
def load_settings():
    """Load settings from JSON file"""
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load settings: {e}")
    
    # Default settings
    return {
        "scanning_mode": "medium",
        "recursive_monitoring": False,
        "watch_path": "~/Downloads",
        "max_file_size_mb": 500,
        "auto_quarantine": True,
        "desktop_notifications": True,
        "archive_inspection": True
    }

settings = load_settings()
INCOMING = os.path.expanduser(settings.get("watch_path", "~/Downloads"))
RECURSIVE = settings.get("recursive_monitoring", False)
MODE = settings.get("scanning_mode", "medium")
mode_config = get_mode_config(MODE)

def notify(title, message, critical=False):
    """
    Try notify-send (no Python dbus needed). If that fails, just print.
    """
    try:
        # -u critical|normal controls urgency in many desktops
        urgency = "critical" if critical else "normal"
        subprocess.run(
            ["notify-send", "-u", urgency, title, message],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
        )
    except Exception:
        # Fallback: console only
        print(f"[NOTIFY] {title}: {message}")

def save_report(report):
    fname = f"{report['sha256']}_{report['name']}.json"
    path = os.path.join(REPORTS, fname)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    return path

def calculate_archive_score(archive_info, mode_config):
    """Calculate additional score based on archive analysis"""
    score = 0
    scoring = mode_config.get("scoring", {})
    
    if archive_info.get("suspicious", False):
        score += 30
    
    if archive_info.get("encrypted", False):
        score += scoring.get("archive_encrypted", 10)
    
    if archive_info.get("compression_ratio", 0) > 100:
        score += scoring.get("archive_bomb", 50)
    
    # Check for executables
    exe_count = sum(1 for f in archive_info.get("files", [])
                   if f.get("name", "").lower().endswith((".exe", ".dll", ".so", ".sh", ".bat")))
    if exe_count > 0:
        score += min(scoring.get("archive_executables", 15) * exe_count, 40)
    
    return score

def recalculate_score_with_mode(report, mode_config):
    """Recalculate score based on scanning mode"""
    score = 0
    scoring = mode_config.get("scoring", {})
    
    # ClamAV score
    if report.get("clamav", {}).get("found", False):
        score += scoring.get("clamav_signature", 100)
    
    # YARA score
    yara_hits = report.get("yara", {}).get("hits", [])
    if yara_hits:
        # Count hits by severity (parse from rule names)
        for hit in yara_hits:
            if "critical" in hit.lower() or "backdoor" in hit.lower() or "trojan" in hit.lower():
                score += scoring.get("yara_critical", 90)
            elif "high" in hit.lower() or "ransomware" in hit.lower() or "stealer" in hit.lower():
                score += scoring.get("yara_high", 70)
            elif "medium" in hit.lower() or "suspicious" in hit.lower():
                score += scoring.get("yara_medium", 40)
            else:
                score += scoring.get("yara_low", 20)
    
    # Archive score
    if "archive_score" in report:
        score += report["archive_score"]
    
    return min(score, 200)  # Cap at 200

class Handler(FileSystemEventHandler):
    def on_created(self, event):
        global settings, mode_config, MODE, RECURSIVE
        
        if event.is_directory:
            return
        path = event.src_path
        base = os.path.basename(path)
        
        # Reload settings to pick up changes
        settings = load_settings()
        MODE = settings.get("scanning_mode", "medium")
        mode_config = get_mode_config(MODE)
        
        logger.info(f"New file detected: {base} (Mode: {MODE.upper()})")
        
        # Check if scanning is disabled
        if MODE == "disabled":
            logger.info(f"Scanning disabled - skipping {base}")
            print(f"[DISABLED] {base} (scanning disabled)")
            return
        
        # wait a moment for writes to finish
        time.sleep(0.5)
        
        try:
            logger.debug(f"Starting analysis of {base}")
            report = analyze(path)
            
            # Add archive inspection if enabled
            if mode_config.get("archive_inspection", False):
                logger.debug(f"Running archive inspection on {base}")
                archive_info = get_archive_info(path)
                if archive_info["is_archive"]:
                    report["archive_analysis"] = archive_info
                    logger.info(f"Archive detected: {archive_info['file_count']} files, " +
                              f"encrypted={archive_info['encrypted']}, " +
                              f"suspicious={archive_info['suspicious']}")
                    
                    # Add archive scoring
                    archive_score = calculate_archive_score(archive_info, mode_config)
                    report["archive_score"] = archive_score
                    logger.debug(f"Archive score: {archive_score}")
            
            # Apply mode-specific scoring adjustments
            adjusted_score = recalculate_score_with_mode(report, mode_config)
            report["adjusted_score"] = adjusted_score
            report["scanning_mode"] = MODE

            # Determine final verdict based on mode thresholds
            thresholds = mode_config.get("thresholds", {"quarantine": 80, "review": 40})
            if adjusted_score >= thresholds["quarantine"]:
                verdict = "quarantine"
            elif adjusted_score >= thresholds["review"]:
                verdict = "review"
            else:
                verdict = "allow"

            report["final_verdict"] = verdict
            # Normalize scoring block for UI/API
            report["scoring"] = {
                "total_score": adjusted_score,
                "verdict": verdict,
                "breakdown": {
                    "clamav": 100 if report.get("clamav", {}).get("found") else 0,
                    "yara": (min(80, len(report.get("yara", {}).get("hits", [])) * 40)
                              if report.get("yara", {}).get("hits") else 0),
                    "archive": report.get("archive_score", 0)
                }
            }
            report.setdefault("actions", {})

            save_report(report)
            logger.info(f"Analysis complete for {base}: verdict={verdict}, score={adjusted_score}, sha256={report.get('sha256', 'N/A')}")

            if verdict == "quarantine" and settings.get("auto_quarantine", True):
                dst = os.path.join(QUARANTINE, base)
                shutil.move(path, dst)
                report["actions"] = {
                    "action": "quarantine_move",
                    "destination": dst,
                    "kept_original": False
                }
                save_report(report)
                logger.warning(f"THREAT DETECTED: {base} moved to quarantine (score: {adjusted_score})")
                if settings.get("desktop_notifications", True):
                    notify("Valkyrie", f"Threat detected in {base}. Moved to quarantine.", critical=True)
                print(f"[QUARANTINE] {base} (score: {adjusted_score})")
            else:
                # Keep the original in Downloads; archive a copy into processed/
                dst = os.path.join(PROCESSED, base)
                shutil.copy2(path, dst)
                report["actions"] = {
                    "action": "allow_copy",
                    "destination": dst,
                    "kept_original": True
                }
                save_report(report)
                logger.info(f"File {base} marked as {verdict}, archived to processed/")
                if settings.get("desktop_notifications", True):
                    notify("Valkyrie", f"{base} scanned: {verdict.upper()} (score: {adjusted_score})")
                print(f"[{verdict.upper()}] {base} (score: {adjusted_score}, copied to processed)")
        except Exception as e:
            logger.error(f"Error processing {base}: {str(e)}", exc_info=True)
            print("Error:", e)

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("Valkyrie File Watcher starting...")
    logger.info(f"Scanning Mode: {MODE.upper()} ({mode_config['name']})")
    logger.info(f"Monitoring directory: {INCOMING}")
    logger.info(f"Recursive monitoring: {RECURSIVE}")
    logger.info(f"Reports directory: {REPORTS}")
    logger.info(f"Quarantine directory: {QUARANTINE}")
    logger.info(f"Processed directory: {PROCESSED}")
    logger.info(f"Log file: {LOG_FILE}")
    logger.info(f"Settings file: {SETTINGS_FILE}")
    logger.info("=" * 60)
    
    print("╔" + "═" * 58 + "╗")
    print("║" + " " * 15 + "VALKYRIE FILE WATCHER" + " " * 22 + "║")
    print("╠" + "═" * 58 + "╣")
    print(f"║ Mode:       {MODE.upper():44} ║")
    print(f"║ Watching:   {INCOMING:44} ║")
    print(f"║ Recursive:  {'Yes' if RECURSIVE else 'No':44} ║")
    print(f"║ ClamAV:     {'Enabled' if mode_config.get('clamav') else 'Disabled':44} ║")
    print(f"║ YARA:       {'Enabled' if mode_config.get('yara') else 'Disabled':44} ║")
    print(f"║ Archives:   {'Enabled' if mode_config.get('archive_inspection') else 'Disabled':44} ║")
    print("╚" + "═" * 58 + "╝")
    print(f"\nLogs: {LOG_FILE}")
    print(f"Settings can be changed via web UI: http://127.0.0.1:5000\n")
    
    observer = Observer()
    observer.schedule(Handler(), INCOMING, recursive=RECURSIVE)
    observer.start()
    logger.info(f"File watcher observer started successfully (recursive={RECURSIVE})")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Received shutdown signal (Ctrl+C)")
        print("\n\nShutting down...")
        observer.stop()
    observer.join()
    logger.info("Valkyrie File Watcher stopped")
