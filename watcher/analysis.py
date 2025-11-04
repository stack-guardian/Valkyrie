import hashlib, subprocess, json, os, time, sys
from glob import glob

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1<<20), b""):
            h.update(chunk)
    return h.hexdigest()

def mime_type(path):
    try:
        p = subprocess.run(["file", "-b", "--mime-type", path],
                           capture_output=True, text=True, timeout=5)
        if p.returncode == 0:
            return p.stdout.strip()
    except Exception:
        pass
    return "unknown"

def clamscan(path):
    try:
        p = subprocess.run(["clamscan", "--no-summary", path],
                           capture_output=True, text=True, timeout=30)
        out = (p.stdout + p.stderr).strip()
        found = ("FOUND" in out) or (p.returncode == 1)
        return {"found": found, "output": out}
    except Exception as e:
        return {"found": False, "error": str(e)}

def yara_scan(path, rules_dir=None):
    if rules_dir is None:
        rules_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "yara_rules"))
    rule_files = sorted([p for p in glob(os.path.join(rules_dir, "*.yar")) if os.path.isfile(p)])
    if not rule_files:
        return {"hits": [], "note": "no .yar files found"}
    try:
        cmd = ["yara"] + rule_files + [path]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        hits = [line.strip() for line in p.stdout.splitlines() if line.strip()]
        return {"hits": hits, "cmd": " ".join(cmd)}
    except Exception as e:
        return {"hits": [], "error": str(e)}

def analyze(path):
    t0 = time.time()
    report = {
        "name": os.path.basename(path),
        "path": os.path.abspath(path),
        "sha256": sha256(path),
        "mime": mime_type(path),
        "timestamp": t0,
        "clamav": clamscan(path),
        "yara": yara_scan(path),
    }
    score = 0
    if report["clamav"].get("found"): score += 100
    if report["yara"].get("hits"): score += 80
    if score >= 80:
        report["verdict"] = "quarantine"
    elif score >= 40:
        report["verdict"] = "review"
    else:
        report["verdict"] = "allow"
    return report

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analysis.py /path/to/file")
        sys.exit(1)
    target = sys.argv[1]
    if not os.path.isfile(target):
        print("File not found:", target)
        sys.exit(2)
    rep = analyze(target)
    print(json.dumps(rep, indent=2))

