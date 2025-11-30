"""
Sandboxed version of analysis.py

This is a drop-in replacement for analysis.py that uses the sandbox module
for all external command execution. Provides the same interface but with
enhanced security.

Usage:
    python analysis_sandboxed.py /path/to/file
"""

import hashlib
import json
import os
import time
import sys
from glob import glob

# Try to import sandbox, fall back to non-sandboxed if unavailable
try:
    from sandbox import (
        sandboxed_clamscan, 
        sandboxed_file_type, 
        sandboxed_yara,
        is_sandbox_available,
        Sandbox,
        SandboxError
    )
    SANDBOX_AVAILABLE = is_sandbox_available()
except ImportError:
    SANDBOX_AVAILABLE = False
    print("[WARNING] Sandbox module not available, running WITHOUT isolation!")
    print("[WARNING] This is UNSAFE for analyzing untrusted files.")
    # Fall back to original implementation
    from analysis import clamscan, mime_type, yara_scan


def sha256(path):
    """
    Calculate SHA-256 hash of file.
    This doesn't need sandboxing as it only reads the file.
    """
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"error:{e}"


def mime_type(path):
    """
    Detect MIME type using sandboxed file command.
    
    Args:
        path: Path to file
        
    Returns:
        MIME type string or "unknown" on error
    """
    if not SANDBOX_AVAILABLE:
        # Fallback to original implementation
        import subprocess
        try:
            p = subprocess.run(
                ["file", "-b", "--mime-type", path],
                capture_output=True, 
                text=True, 
                timeout=5
            )
            if p.returncode == 0:
                return p.stdout.strip()
        except Exception:
            pass
        return "unknown"
    
    # Use sandboxed version
    try:
        result = sandboxed_file_type(path)
        if result['success']:
            return result['stdout'].strip()
        else:
            print(f"[MIME] Error: {result['stderr']}")
            return "unknown"
    except Exception as e:
        print(f"[MIME] Exception: {e}")
        return "unknown"


def clamscan(path):
    """
    Run ClamAV scan in sandbox.
    
    Args:
        path: Path to file
        
    Returns:
        Dict with 'found' (bool) and 'output' or 'error' keys
    """
    if not SANDBOX_AVAILABLE:
        # Fallback to original implementation
        import subprocess
        try:
            p = subprocess.run(
                ["clamscan", "--no-summary", path],
                capture_output=True, 
                text=True, 
                timeout=30
            )
            out = (p.stdout + p.stderr).strip()
            found = ("FOUND" in out) or (p.returncode == 1)
            return {"found": found, "output": out}
        except Exception as e:
            return {"found": False, "error": str(e)}
    
    # Use sandboxed version
    try:
        result = sandboxed_clamscan(path, timeout=30)
        
        if result['timeout']:
            return {"found": False, "error": "Scan timeout (30s)"}
        
        if result['error']:
            return {"found": False, "error": result['error']}
        
        # Check for malware detection
        output = result['stdout'] + result['stderr']
        found = ("FOUND" in output) or (result['returncode'] == 1)
        
        return {
            "found": found,
            "output": output.strip(),
            "sandboxed": True
        }
        
    except SandboxError as e:
        return {"found": False, "error": f"Sandbox error: {e}"}
    except Exception as e:
        return {"found": False, "error": f"Unexpected error: {e}"}


def yara_scan(path, rules_dir=None):
    """
    Run YARA scan in sandbox.
    
    Args:
        path: Path to file
        rules_dir: Directory containing .yar files (default: ../yara_rules)
        
    Returns:
        Dict with 'hits' (list) and optional 'error' or 'note' keys
    """
    if rules_dir is None:
        rules_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "yara_rules")
        )
    
    if not SANDBOX_AVAILABLE:
        # Fallback to original implementation
        import subprocess
        rule_files = sorted([
            p for p in glob(os.path.join(rules_dir, "*.yar")) 
            if os.path.isfile(p)
        ])
        
        if not rule_files:
            return {"hits": [], "note": "no .yar files found"}
        
        try:
            cmd = ["yara"] + rule_files + [path]
            p = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=15
            )
            hits = [
                line.strip() 
                for line in p.stdout.splitlines() 
                if line.strip()
            ]
            return {"hits": hits, "cmd": " ".join(cmd)}
        except Exception as e:
            return {"hits": [], "error": str(e)}
    
    # Use sandboxed version
    try:
        result = sandboxed_yara(path, rules_dir, timeout=15)
        
        if result['timeout']:
            return {"hits": [], "error": "YARA scan timeout (15s)"}
        
        if result['error']:
            # Check if it's a "no rules" error
            if result['error'] in ['rules_not_found', 'no_rules']:
                return {"hits": [], "note": result['stderr']}
            return {"hits": [], "error": result['error']}
        
        # Parse YARA output (format: "rule_name file_path")
        hits = [
            line.strip() 
            for line in result['stdout'].splitlines() 
            if line.strip()
        ]
        
        return {
            "hits": hits,
            "sandboxed": True
        }
        
    except SandboxError as e:
        return {"hits": [], "error": f"Sandbox error: {e}"}
    except Exception as e:
        return {"hits": [], "error": f"Unexpected error: {e}"}


def analyze(path):
    """
    Perform complete security analysis of file.
    
    All external tools are executed in isolated sandbox environment.
    
    Args:
        path: Path to file to analyze
        
    Returns:
        Dict containing analysis results and verdict
    """
    t0 = time.time()
    errors = []

    size_bytes = None
    try:
        size_bytes = os.path.getsize(path)
    except Exception as e:
        errors.append(f"size_error:{e}")
    
    report = {
        "name": os.path.basename(path),
        "path": os.path.abspath(path),
        "sha256": sha256(path),
        "mime": mime_type(path),
        "size_bytes": size_bytes,
        "timestamp": t0,
        "sandboxed": SANDBOX_AVAILABLE,
        "clamav": clamscan(path),
        "yara": yara_scan(path),
    }
    
    # Calculate risk score
    score = 0
    
    breakdown = {}

    # ClamAV detection is definitive (signature match)
    if report["clamav"].get("found"):
        breakdown["clamav_signature"] = 100
    if report["clamav"].get("error"):
        errors.append(f"clamav:{report['clamav'].get('error')}")
    
    # YARA hits are high confidence (rule match)
    yara_hits = report["yara"].get("hits", [])
    if yara_hits:
        breakdown["yara_hits"] = min(80, len(yara_hits) * 40)
    if report["yara"].get("error"):
        errors.append(f"yara:{report['yara'].get('error')}")
    
    score = sum(breakdown.values())

    # Determine verdict based on score
    if score >= 80:
        verdict = "quarantine"
    elif score >= 40:
        verdict = "review"
    else:
        verdict = "allow"

    report["verdict"] = verdict
    report["score"] = score
    report["scan_time"] = time.time() - t0
    report["scoring"] = {
        "total_score": score,
        "verdict": verdict,
        "breakdown": breakdown,
        "factors": [
            {"engine": "ClamAV", "description": "Signature detected", "score": breakdown["clamav_signature"]}
            for k in breakdown if k == "clamav_signature"
        ] + [
            {"engine": "YARA", "description": f"{len(yara_hits)} rule match(es)", "score": breakdown.get("yara_hits", 0)}
            for _ in ([1] if "yara_hits" in breakdown else [])
        ]
    }

    if errors:
        report["errors"] = errors

    return report


if __name__ == "__main__":
    # Check if sandbox is available
    if not SANDBOX_AVAILABLE:
        print("=" * 70)
        print("WARNING: SANDBOX NOT AVAILABLE - RUNNING WITHOUT ISOLATION")
        print("=" * 70)
        print()
        print("To enable sandboxing, install bubblewrap:")
        print("  sudo pacman -S bubblewrap")
        print()
        print("Running without sandboxing is UNSAFE for untrusted files!")
        print("=" * 70)
        print()
    else:
        print("[OK] Sandbox available - all scans will run isolated")
        print()
    
    if len(sys.argv) != 2:
        print("Usage: python analysis_sandboxed.py /path/to/file")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if not os.path.isfile(target):
        print(f"File not found: {target}")
        sys.exit(2)
    
    print(f"Analyzing: {target}")
    print()
    
    try:
        report = analyze(target)
        print(json.dumps(report, indent=2))
    except Exception as e:
        print(f"Error during analysis: {e}")
        sys.exit(3)
