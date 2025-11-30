# Valkyrie Detection Approach & File Support

## Overview
Valkyrie uses a **multi-layered defense approach** combining signature-based detection, behavior analysis, and heuristics to identify threats. It's designed to work with **any file type** but provides deeper analysis for specific formats.

---

## 🛡️ Detection Methods

### 1. **Signature-Based Detection (ClamAV)**
**What it does:** Matches files against a database of known malware signatures.

- **Database Size:** 8.7+ million signatures (daily updates)
  - Main database: 6,647,427 signatures
  - Daily database: 2,077,252 signatures
  - Bytecode signatures: 80 patterns

- **How it works:**
  - Scans file content for byte patterns matching known malware
  - Detects viruses, trojans, worms, ransomware, backdoors
  - Updates daily with latest threat intelligence

- **Strengths:**
  - ✅ Very fast (sub-second scans)
  - ✅ High accuracy for known threats
  - ✅ Zero false positives on clean files

- **Limitations:**
  - ❌ Cannot detect brand new malware (zero-day)
  - ❌ Misses polymorphic/obfuscated variants

**Score Impact:** ClamAV detection = **+100 points** (instant quarantine)

---

### 2. **Behavioral Pattern Matching (YARA)**
**What it does:** Matches files against custom rules detecting suspicious behaviors and patterns.

- **Rule Count:** 361 lines across 3 files
  - `malware.yar`: 178 lines - 9 critical malware families
  - `suspicious.yar`: 177 lines - 11 behavioral patterns
  - `demo_rules.yar`: 6 lines - test rules

- **Detection Categories:**

#### Critical Threats (malware.yar)
1. **Backdoor_Trojan** - Remote access trojans, reverse shells
2. **Ransomware_Locker** - File encryption, ransom demands
3. **InfoStealer_Password** - Credential theft, keyloggers
4. **Cryptocurrency_Miner** - CPU mining, cryptojacking
5. **Exploit_Kit** - Heap sprays, ROP chains, shellcode
6. **PUP_Adware** - Potentially unwanted programs
7. **Suspicious_NetworkActivity** - C2 communication, beaconing
8. **Packed_Executable** - UPX, ASPack, Themida packers
9. **Suspicious_Strings** - Registry manipulation, DLL injection

#### Behavioral Indicators (suspicious.yar)
1. **Suspicious_File_Hidden** - Hidden executables
2. **Suspicious_Base64** - Large base64 encoded data
3. **Suspicious_Registry_Access** - Autorun keys
4. **Suspicious_Persistence** - Task scheduler, WMI
5. **Suspicious_Process_Injection** - WriteProcessMemory, remote threads
6. **Suspicious_Mutex** - Malware synchronization
7. **Suspicious_Crypto** - Encryption operations
8. **Suspicious_Sleep** - Evasion delays
9. **Suspicious_Obfuscation** - Code obfuscation
10. **Suspicious_AntiAnalysis** - VM detection, anti-debug
11. **Suspicious_Mutex** - Inter-process communication

- **How it works:**
  - Scans for string patterns (ASCII/Unicode)
  - Matches byte sequences (hex patterns)
  - Combines conditions (e.g., "2 of 5 patterns")
  - Low false-positive rules (require multiple indicators)

- **Strengths:**
  - ✅ Detects unknown variants
  - ✅ Catches behavior-based threats
  - ✅ Customizable and extensible

- **Limitations:**
  - ❌ Higher false positive rate
  - ❌ Slower than signature matching

**Score Impact:** 
- Each YARA hit = **+40 points** (capped at 80)
- 1 hit = 40 (review)
- 2+ hits = 80+ (quarantine)

---

### 3. **Heuristic Analysis** (Available but not active in watcher)
**What it does:** Analyzes file characteristics for suspicious indicators.

The `valkyrie/heuristics.py` module provides advanced detection:

#### Entropy Analysis
- Measures randomness in file content
- High entropy (>7.8) suggests encryption/packing
- Identifies compressed malware and obfuscated code

#### Packer Detection
- Identifies UPX, ASPack, PECompact, Themida
- Detects unusual section names (.upx0, .aspack)
- Flags compressed executables

#### Archive Inspection
- Recursively extracts ZIP, TAR, GZIP
- Detects archive bombs (expansion ratio >100:1)
- Scans nested archives (max depth: 3)
- Flags password-protected archives

#### File Type Validation
- Compares MIME type vs file extension
- Detects double extensions (e.g., `.pdf.exe`)
- Identifies hidden extensions
- Flags type mismatches

**Note:** These heuristics are available in the `valkyrie/heuristics.py` module but **not currently integrated** into the watcher. They can be enabled for deeper analysis.

---

## 📊 Scoring System

Valkyrie uses a **0-100+ point risk score** to determine verdicts:

```python
Score Calculation:
- ClamAV detection:    +100 points (definitive threat)
- YARA hits:          +40 per hit (capped at 80)
- Entropy (high):     +30 points (if enabled)
- Packer detected:    +25 points (if enabled)
- Archive bomb:       +50 points (if enabled)
- Type mismatch:      +20 points (if enabled)

Verdict Thresholds:
- 0-39:   ALLOW      (safe, moves to processed/)
- 40-79:  REVIEW     (suspicious, manual check)
- 80+:    QUARANTINE (malicious, isolated)
```

**Current Active Scoring:**
```python
if clamav_found:
    score += 100  # Instant quarantine
    
if yara_hits:
    score += min(80, len(yara_hits) * 40)  # 40 per hit, max 80

if score >= 80:
    verdict = "quarantine"
elif score >= 40:
    verdict = "review"
else:
    verdict = "allow"
```

---

## 📁 File Type Support

### Universal Support
Valkyrie can analyze **ANY file type** because it:
- Reads files as binary data (no parsing required)
- Uses `file` command for MIME type detection
- Scans byte patterns (not file format specific)

### What Gets Scanned:
```bash
✅ Executables:     .exe, .dll, .so, .elf, ELF binaries
✅ Scripts:         .sh, .py, .js, .ps1, .bat, .vbs
✅ Archives:        .zip, .tar, .gz, .rar, .7z
✅ Documents:       .pdf, .doc, .docx, .xls, .xlsx, .ppt
✅ Images:          .jpg, .png, .gif, .svg, .ico
✅ Web files:       .html, .php, .asp, .jsp
✅ Office macros:   Embedded VBA, PowerShell
✅ Mobile apps:     .apk, .ipa
✅ Firmware:        Embedded binaries, bootloaders
✅ Email:           .eml, .msg with attachments
✅ Unknown types:   ANY file with suspicious content
```

### MIME Types Detected:
The `file` command can identify 500+ file types:
```
application/x-executable
application/pdf
application/zip
text/plain
text/html
image/jpeg
application/javascript
application/x-dosexec (Windows PE)
application/x-elf (Linux binaries)
application/x-mach-binary (macOS)
... and hundreds more
```

### File Size Limits:
- **Default max:** 500 MB (configurable in `config/valkyrie.yaml`)
- **ClamAV timeout:** 30 seconds
- **YARA timeout:** 15 seconds
- Files larger than limits are skipped

---

## 🔬 Analysis Workflow

```
File Created in ~/Downloads
         ↓
    [SHA-256 Hash]
         ↓
    [MIME Detection] ← file command in sandbox
         ↓
    [ClamAV Scan] ← 8.7M signatures
         ↓
    [YARA Scan] ← 20+ behavioral rules
         ↓
    [Risk Scoring] ← Combined analysis
         ↓
    [Verdict Decision]
         ↓
    ├─ QUARANTINE (80+) → quarantine/
    ├─ REVIEW (40-79)   → processed/ + flag
    └─ ALLOW (0-39)     → processed/
         ↓
    [JSON Report] → reports/
    [Desktop Notification]
    [Log Entry] → logs/watcher.log
```

---

## 🔒 Security Features

### Sandboxed Execution
- All scans run in **bubblewrap sandbox** (if available)
- Isolated from host system
- Limited filesystem access
- No network access for malware
- Prevents malicious file execution

### Safe File Handling
- Files opened read-only
- SHA-256 for integrity verification
- Path validation (prevents directory traversal)
- Filename sanitization

---

## 📈 Real-World Examples

### Example 1: Clean PDF
```json
{
  "verdict": "allow",
  "score": 0,
  "clamav": {"found": false},
  "yara": {"hits": []},
  "mime": "application/pdf"
}
```
**Result:** ✅ Moved to processed/

### Example 2: EICAR Test File
```json
{
  "verdict": "quarantine",
  "score": 100,
  "clamav": {"found": true, "output": "EICAR.Test.File FOUND"},
  "yara": {"hits": []},
  "mime": "text/plain"
}
```
**Result:** ⚠️ Quarantined immediately

### Example 3: Suspicious Script
```json
{
  "verdict": "quarantine",
  "score": 80,
  "clamav": {"found": false},
  "yara": {"hits": [
    "Backdoor_Trojan /path/to/script.sh",
    "Suspicious_Process_Injection /path/to/script.sh"
  ]},
  "mime": "text/x-shellscript"
}
```
**Result:** ⚠️ Quarantined (2 YARA hits = 80 points)

### Example 4: Borderline File
```json
{
  "verdict": "review",
  "score": 40,
  "clamav": {"found": false},
  "yara": {"hits": ["Suspicious_Registry_Access /path/to/file"]},
  "mime": "application/x-executable"
}
```
**Result:** ⚡ Flagged for manual review

---

## 🎯 Detection Effectiveness

### Strong Detection:
- ✅ Known malware (ClamAV signatures)
- ✅ Common malware families (YARA rules)
- ✅ Backdoors, ransomware, infostealers
- ✅ Packed executables
- ✅ Suspicious scripts
- ✅ Exploits kits

### Limited Detection:
- ⚠️ Zero-day exploits (no signatures yet)
- ⚠️ Heavily obfuscated code
- ⚠️ Fileless malware (registry-only)
- ⚠️ Targeted attacks (custom malware)

### False Positives:
- Low rate due to conservative scoring
- YARA rules require multiple indicators
- Manual review threshold (40 points) catches edge cases

---

## 🚀 Extending Detection

### Add More YARA Rules
```bash
# Create new rule file
nano yara_rules/custom.yar

rule MyCustomRule {
    meta:
        description = "Detects specific threat"
        severity = "high"
    strings:
        $string1 = "malicious_pattern" ascii
        $hex1 = { 4D 5A 90 00 }
    condition:
        $string1 or $hex1
}
```

### Enable Heuristics
Modify `watcher/watcher.py` to use `valkyrie/heuristics.py`:
```python
from valkyrie.heuristics import HeuristicAnalyzer

analyzer = HeuristicAnalyzer()
heuristics = analyzer.analyze_file(path)
score += heuristics.get("entropy_score", 0)
```

### Update ClamAV
```bash
sudo freshclam  # Updates daily
```

---

## 📝 Summary

| Feature | Status | Scope |
|---------|--------|-------|
| **File Types** | ✅ Universal | All file types supported |
| **ClamAV Signatures** | ✅ Active | 8.7M+ patterns |
| **YARA Rules** | ✅ Active | 20+ behavioral rules |
| **Heuristics** | 🟡 Available | Not integrated in watcher |
| **Sandboxing** | ✅ Active | Bubblewrap isolation |
| **Real-time** | ✅ Active | Monitors ~/Downloads |
| **Logging** | ✅ Active | Full audit trail |
| **Dashboard** | ✅ Active | Web UI on :5000 |

**Bottom Line:** Valkyrie provides **layered defense** using industry-standard tools (ClamAV, YARA) with custom behavioral rules, suitable for detecting both known and suspicious threats across **all file types**.
