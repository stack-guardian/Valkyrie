# 🚀 Valkyrie Quick Start Guide

## Before You Begin

**IMPORTANT**: The current code is NOT SAFE without sandboxing!
Follow this guide to set it up securely.

---

## Option 1: Run WITHOUT Sandboxing (UNSAFE - Testing Only!)

⚠️ **WARNING**: Only use this for trusted files or testing!

### Step 1: Install Dependencies

```bash
# System packages
sudo pacman -S clamav clamav-daemon yara python3 python3-pip

# Update ClamAV signatures
sudo freshclam

# Python packages
pip install watchdog Flask
```

### Step 2: Test Analysis on a Single File

```bash
# Analyze a single file
python watcher/analysis.py /bin/ls

# You should see JSON output with:
# - sha256 hash
# - MIME type
# - ClamAV results
# - YARA results
# - verdict (allow/review/quarantine)
```

### Step 3: Run the File Watcher

```bash
# Start the watcher (monitors ~/Downloads by default)
python watcher/watcher.py

# In another terminal, test by creating a file:
echo "hello world" > ~/Downloads/test.txt

# Check the watcher output - should show "[ALLOW] test.txt"
# File will be moved to processed/
ls processed/

# Check the report
ls reports/
cat reports/*.json | jq '.'  # Use jq for pretty output (optional)
```

### Step 4: Run the Dashboard

```bash
# In a new terminal, start the web UI
python gui/backend/app.py

# Open browser to: http://127.0.0.1:5000
# You should see the dashboard with your scanned files
```

---

## Option 2: Run WITH Sandboxing (SECURE - Recommended!)

✅ **This is the SAFE way to run Valkyrie**

### Step 1: Install All Dependencies

```bash
# System packages (including bubblewrap for sandboxing)
sudo pacman -S clamav clamav-daemon yara python3 python3-pip bubblewrap

# Update ClamAV signatures
sudo freshclam

# Python packages
pip install watchdog Flask pytest
```

### Step 2: Test the Sandbox

```bash
# Test that bubblewrap works
bwrap --version

# Test the sandbox module
python watcher/sandbox.py /bin/ls

# Expected output:
# [Sandbox] Using bubblewrap 0.8.0
# Testing sandbox with: /bin/ls
# 1. Testing basic command execution...
#    Result: application/x-sharedlib; charset=binary
#    Success: True
```

### Step 3: Update Watcher to Use Sandboxing

```bash
# Edit watcher/watcher.py
# Change line 3 from:
#   from analysis import analyze
# To:
#   from analysis_sandboxed import analyze

# Quick way to do it:
sed -i 's/from analysis import analyze/from analysis_sandboxed import analyze/' watcher/watcher.py

# Verify the change:
grep "from analysis" watcher/watcher.py
# Should show: from analysis_sandboxed import analyze
```

### Step 4: Validate Security Setup

```bash
# Run the security validation script
chmod +x test_security.sh
./test_security.sh

# Expected output: 7/7 tests passing ✅
```

### Step 5: Test with EICAR (Safe Malware Test)

```bash
# Create EICAR test file (safe malware signature)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt

# Analyze it with sandboxing
python watcher/analysis_sandboxed.py /tmp/eicar.txt

# Expected output includes:
# [OK] Sandbox available - all scans will run isolated
# "verdict": "quarantine"
# "score": 100
# "sandboxed": true
# ClamAV should detect: Eicar-Signature FOUND
```

### Step 6: Run Everything Securely

```bash
# Terminal 1: Start the watcher (with sandboxing!)
python watcher/watcher.py

# Terminal 2: Start the dashboard
python gui/backend/app.py

# Terminal 3: Test by dropping files
cp /tmp/eicar.txt ~/Downloads/

# Check watcher output - should show:
# [QUARANTINE] eicar.txt
# Threat detected in eicar.txt. Moved to quarantine.

# Verify the file is quarantined
ls quarantine/

# Check the report
cat reports/*eicar*.json | grep -E '(verdict|sandboxed|score)'
# Should show:
#   "verdict": "quarantine",
#   "score": 100,
#   "sandboxed": true
```

### Step 7: Open Dashboard

```bash
# Open browser to: http://127.0.0.1:5000
# You should see:
# - eicar.txt with QUARANTINE verdict (red)
# - JSON link to view full report
```

---

## Common Issues & Solutions

### Issue: "ModuleNotFoundError: No module named 'watchdog'"

**Solution**:
```bash
pip install watchdog Flask
```

### Issue: "clamscan: command not found"

**Solution**:
```bash
sudo pacman -S clamav
sudo freshclam  # Update virus signatures
```

### Issue: "yara: command not found"

**Solution**:
```bash
sudo pacman -S yara
```

### Issue: "[WARNING] Sandbox module not available"

**Solution**:
```bash
# Install bubblewrap
sudo pacman -S bubblewrap

# Verify installation
bwrap --version

# Test sandbox module
python watcher/sandbox.py /bin/ls
```

### Issue: "Operation not permitted" with bubblewrap

**Solution**:
```bash
# Enable user namespaces (Arch Linux)
sudo sysctl -w kernel.unprivileged_userns_clone=1

# Make it permanent
echo "kernel.unprivileged_userns_clone=1" | sudo tee /etc/sysctl.d/99-userns.conf
```

### Issue: EICAR not detected by ClamAV

**Solution**:
```bash
# Update ClamAV signatures
sudo freshclam

# Verify detection
clamscan /tmp/eicar.txt
# Should show: Eicar-Signature FOUND
```

---

## Architecture Overview

```
Terminal 1: Watcher               Terminal 2: Dashboard
┌─────────────────────┐          ┌─────────────────────┐
│ python watcher/     │          │ python gui/backend/ │
│   watcher.py        │          │   app.py            │
│                     │          │                     │
│ Monitors:           │          │ Serves:             │
│ ~/Downloads/        │────────▶ │ http://127.0.0.1:   │
│                     │          │ 5000                │
│ On new file:        │          │                     │
│ 1. Scan (sandboxed) │          │ Shows:              │
│ 2. Score            │          │ - All reports       │
│ 3. Verdict          │          │ - Verdicts          │
│ 4. Move file        │          │ - JSON downloads    │
│ 5. Write report     │          │                     │
│ 6. Notify           │          │                     │
└─────────────────────┘          └─────────────────────┘
        │                                  │
        ▼                                  ▼
   File Moved                         Reports Read
        │                                  │
    ┌───┴─────────┐                  ┌────┴────┐
    │             │                  │         │
    ▼             ▼                  ▼         │
processed/   quarantine/        reports/   ◄───┘
(safe)       (threats)          (JSON)
```

---

## What Happens When You Drop a File?

### Benign File Flow:
```
1. File created in ~/Downloads/test.txt
2. Watcher detects it
3. Analysis runs (in sandbox if enabled):
   - Calculate SHA-256 hash
   - Detect MIME type
   - Run ClamAV scan
   - Run YARA rules
   - Calculate risk score
4. Score < 40 → verdict = "allow"
5. File moved to processed/test.txt
6. Report saved to reports/[hash]_test.txt.json
7. Desktop notification: "test.txt is secure"
8. Dashboard shows green "ALLOW" badge
```

### Malicious File Flow (e.g., EICAR):
```
1. File created in ~/Downloads/eicar.txt
2. Watcher detects it
3. Analysis runs (in sandbox if enabled):
   - Calculate SHA-256 hash
   - Detect MIME type
   - Run ClamAV scan → FOUND!
   - Run YARA rules
   - Calculate risk score
4. Score = 100 → verdict = "quarantine"
5. File moved to quarantine/eicar.txt
6. Report saved to reports/[hash]_eicar.txt.json
7. Desktop notification: "Threat detected in eicar.txt"
8. Dashboard shows red "QUARANTINE" badge
```

---

## Directory Structure After Running

```
Valkyrie/
├── watcher/
│   ├── watcher.py          # Running in terminal 1
│   ├── analysis_sandboxed.py
│   └── sandbox.py
│
├── gui/backend/
│   └── app.py              # Running in terminal 2
│
├── processed/              # Clean files end up here
│   └── test.txt
│
├── quarantine/             # Threats end up here
│   └── eicar.txt
│
├── reports/                # JSON reports
│   ├── a1b2c3...test.txt.json
│   └── d4e5f6...eicar.txt.json
│
└── yara_rules/
    └── demo_rules.yar      # Your YARA detection rules
```

---

## Configuration (Optional)

### Change Watch Directory

Edit `watcher/watcher.py` line 6:
```python
INCOMING = os.path.expanduser("~/Downloads")  # Change this
```

Example:
```python
INCOMING = "/mnt/incoming"  # Watch this directory instead
```

### Change Dashboard Port

Edit `gui/backend/app.py` line 108:
```python
app.run(host="127.0.0.1", port=5000, debug=False)  # Change port
```

---

## Testing Checklist

- [ ] `python watcher/analysis_sandboxed.py /bin/ls` works
- [ ] `bwrap --version` shows bubblewrap is installed
- [ ] `./test_security.sh` shows 7/7 tests passing
- [ ] EICAR file gets quarantined
- [ ] Benign file gets allowed
- [ ] Dashboard shows reports at http://127.0.0.1:5000
- [ ] Desktop notifications appear
- [ ] Reports show `"sandboxed": true`

---

## Quick Commands Reference

```bash
# Install everything
sudo pacman -S clamav yara bubblewrap python3 python3-pip
sudo freshclam
pip install watchdog Flask pytest

# Update watcher to use sandboxing
sed -i 's/from analysis import/from analysis_sandboxed import/' watcher/watcher.py

# Validate setup
./test_security.sh

# Run watcher
python watcher/watcher.py

# Run dashboard (separate terminal)
python gui/backend/app.py

# Test with EICAR
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > ~/Downloads/eicar.txt

# View results
ls quarantine/
ls reports/
cat reports/*.json | jq '.'
```

---

## Next Steps

Once everything is running:

1. **Add More YARA Rules**: Put `.yar` files in `yara_rules/`
2. **Customize Scoring**: Edit `analysis_sandboxed.py` scoring logic
3. **Monitor**: Keep an eye on the watcher output
4. **Review**: Check quarantine folder regularly
5. **Improve**: Follow the ROADMAP.md for enhancements

---

## Need Help?

- **Setup Issues**: See `docs/SANDBOX_SETUP.md`
- **Security Questions**: See `docs/ISOLATION_ARCHITECTURE.md`
- **Full Documentation**: See `ISOLATION_PROJECT_COMPLETE.md`

---

**Ready to run Valkyrie safely? Start with Option 2!** ✅
