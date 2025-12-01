# ⚔️ Valkyrie — Automatic File Security Scanner for Linux

**Valkyrie** is a real-time file monitoring and malware detection tool for Linux systems.  
It automatically scans new files entering your system (like the Android Play Store’s “Secure” scanner), classifies them as *Safe* or *Threat*, and quarantines malicious files.  

---

## 🚀 Features
- 🔍 **Automatic file scanning** (via `watchdog`)
- 🧠 **Static + heuristic checks**
  - ClamAV antivirus
  - YARA rule engine
  - MIME-type mismatch detection
- 💾 **SHA256 hashing** for file integrity
- 📂 **Auto quarantine** for suspicious files
- 🌐 **Flask dashboard**
  - View reports and scan history
  - Color-coded verdicts (Allow / Review / Quarantine)
- 🔔 **Desktop notifications**
- 🧰 **Lightweight Python backend**

---

## 🧪 Demonstration

| Event | Action | Result |
|-------|---------|--------|
| A new file enters `~/Downloads` | Valkyrie scans it | `ok.txt` → Secure |
| A malicious YARA match | Valkyrie quarantines it | `bad.txt` → Threat detected |
| EICAR test file | Detected via ClamAV | `eicar.com` quarantined |

---

## 🧰 Installation

```bash
git clone https://github.com/vibhxr69/Valkyrie.git
cd Valkyrie
python3 -m venv venv
source venv/bin/activate
pip install -r gui/backend/requirements.txt watchdog python-magic
sudo apt install -y clamav yara file jq zenity
