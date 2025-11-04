import os, json, time, shutil, subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from analysis import analyze

# Folders
INCOMING = os.path.expanduser("~/Downloads")   # watched folder (change if you want)
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORTS = os.path.join(ROOT, "reports")
QUARANTINE = os.path.join(ROOT, "quarantine")
PROCESSED = os.path.join(ROOT, "processed")

for d in (REPORTS, QUARANTINE, PROCESSED):
    os.makedirs(d, exist_ok=True)

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

class Handler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        # wait a moment for writes to finish
        time.sleep(0.5)
        try:
            report = analyze(path)
            save_report(report)
            base = os.path.basename(path)
            if report["verdict"] == "quarantine":
                dst = os.path.join(QUARANTINE, base)
                shutil.move(path, dst)
                notify("SecureScan", f"Threat detected in {base}. Moved to quarantine.", critical=True)
                print(f"[QUARANTINE] {base}")
            else:
                dst = os.path.join(PROCESSED, base)
                shutil.move(path, dst)
                notify("SecureScan", f"{base} is secure.")
                print(f"[ALLOW] {base}")
        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    print("Watcher running. Monitoring:", INCOMING)
    print("Reports:", REPORTS)
    observer = Observer()
    observer.schedule(Handler(), INCOMING, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

