# 🚀 Valkyrie Startup Scripts - Quick Reference

## Three Ways to Run Valkyrie

### 1. **Full Startup Script** (Recommended)
```bash
./start_valkyrie.sh
```

**Features:**
- ✅ Checks all dependencies
- ✅ Auto-installs missing Python packages
- ✅ Auto-enables sandboxing if available
- ✅ Starts both watcher and dashboard
- ✅ Runs in background with logs
- ✅ Opens browser automatically
- ✅ Pretty colored output

**Commands:**
```bash
./start_valkyrie.sh start    # Start services
./start_valkyrie.sh stop     # Stop services
./start_valkyrie.sh restart  # Restart services
./start_valkyrie.sh status   # Check status
```

---

### 2. **Simple CLI** (Easy to remember)
```bash
./valkyrie_cli start
```

**All Commands:**
```bash
./valkyrie_cli start         # Start everything
./valkyrie_cli stop          # Stop everything
./valkyrie_cli restart       # Restart
./valkyrie_cli status        # Check status
./valkyrie_cli logs          # Show recent logs
./valkyrie_cli tail          # Follow logs (Ctrl+C to stop)
./valkyrie_cli scan <file>   # Scan a specific file
./valkyrie_cli dashboard     # Open browser
./valkyrie_cli test          # Run security tests
./valkyrie_cli quarantine    # List threats
./valkyrie_cli reports       # List reports
./valkyrie_cli clean         # Clean old files
./valkyrie_cli help          # Show help
```

---

### 3. **Quick Stop**
```bash
./stop_valkyrie.sh
```

Simple shortcut to stop all services.

---

## 📝 Quick Start Example

```bash
# 1. Start Valkyrie
./start_valkyrie.sh

# Output will show:
# ╔══════════════════════════════════════╗
# ║    🛡️  VALKYRIE FILE SCANNER 🛡️     ║
# ╚══════════════════════════════════════╝
#
# [1/5] Checking dependencies...
#   ✓ Python 3: Python 3.11.0
#   ✓ ClamAV: ClamAV 1.0.0
#   ✓ YARA: yara 4.3.0
#   ✓ Bubblewrap: bubblewrap 0.8.0
#
# [2/5] Checking Python packages...
#   ✓ All required packages found
#
# [3/5] Checking configuration...
#   ✓ Watcher configured for sandboxed analysis
#   ✓ Directories ready
#
# [4/5] Starting services...
#   ✓ Watcher started (PID: 12345)
#   ✓ Dashboard started (PID: 12346)
#
# [5/5] Valkyrie is ready!
#
# ╔══════════════════════════════════════╗
# ║      ✓ ALL SYSTEMS READY             ║
# ╚══════════════════════════════════════╝
#
# Services:
#   ✓ File Watcher:  Monitoring ~/Downloads/
#   ✓ Web Dashboard: http://127.0.0.1:5000
#
# 🛡️ Security: All scans running in isolated sandbox

# 2. Browser opens automatically to http://127.0.0.1:5000

# 3. Test it
echo "test" > ~/Downloads/test.txt

# 4. Check logs
./valkyrie_cli logs

# 5. Check status
./valkyrie_cli status

# 6. Stop when done
./stop_valkyrie.sh
```

---

## 📂 Where Things Are

After starting:

```
Valkyrie/
├── start_valkyrie.sh     ← Main startup script
├── stop_valkyrie.sh      ← Quick stop
├── valkyrie_cli          ← Command interface
│
├── logs/                 ← Created on first run
│   ├── watcher.log       ← File watcher logs
│   └── dashboard.log     ← Web UI logs
│
├── reports/              ← Scan reports (JSON)
├── quarantine/           ← Quarantined threats
└── processed/            ← Clean files
```

---

## 🔍 Monitoring Valkyrie

### Watch Logs in Real-Time
```bash
./valkyrie_cli tail
```

Output:
```
Following logs (Ctrl+C to stop)...

==> logs/watcher.log <==
Watcher running. Monitoring: /home/user/Downloads
Reports: /home/user/Valkyrie/reports

==> logs/dashboard.log <==
SecureScan dashboard starting on http://127.0.0.1:5000 ...
```

### Check Status
```bash
./valkyrie_cli status
```

Output:
```
Service Status:

  ✓ Watcher:   RUNNING (PID: 12345)
  ✓ Dashboard: RUNNING (PID: 12346)
  → URL:       http://127.0.0.1:5000
```

### View Recent Logs
```bash
./valkyrie_cli logs
```

---

## 🧪 Testing

### Run Security Tests
```bash
./valkyrie_cli test
```

This runs the full `test_security.sh` suite:
- [1/7] Checking bubblewrap...
- [2/7] Testing sandbox module...
- [3/7] Checking watcher integration...
- [4/7] Testing EICAR detection...
- [5/7] Testing benign file handling...
- [6/7] Verifying sandbox flag...
- [7/7] Testing network isolation...

### Scan a Specific File
```bash
./valkyrie_cli scan /path/to/file.exe
```

### Create EICAR Test
```bash
# Create test malware
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > ~/Downloads/eicar.txt

# Watch the watcher log
./valkyrie_cli tail

# Check quarantine
./valkyrie_cli quarantine
```

---

## ⚙️ What the Startup Script Does

### Checks (Automatic)
1. ✅ Python 3 installed
2. ✅ ClamAV installed (warns if missing)
3. ✅ YARA installed (warns if missing)
4. ✅ Bubblewrap installed (warns if missing, disables sandboxing)
5. ✅ Python packages (auto-installs if missing)
6. ✅ Watcher configuration (auto-updates for sandboxing)
7. ✅ Directories created (reports, quarantine, processed)

### Actions (Automatic)
1. 🔧 Installs missing Python packages
2. 🔧 Updates watcher to use sandboxing
3. 🔧 Creates logs directory
4. 🚀 Starts watcher in background
5. 🚀 Starts dashboard in background
6. 📝 Saves PID files for management
7. 🌐 Opens browser to dashboard
8. 📊 Shows status and helpful info

### Safety Features
- ⚠️ Prevents starting if already running
- ⚠️ Checks if services started successfully
- ⚠️ Warns if running without sandboxing
- ⚠️ Creates backups when modifying files
- ⚠️ Graceful shutdown (tries TERM, then KILL)

---

## 🛠️ Troubleshooting

### Services Won't Start

**Check logs:**
```bash
./valkyrie_cli logs
```

**Common issues:**

1. **Port 5000 already in use**
   ```bash
   # Find what's using port 5000
   sudo lsof -i :5000
   
   # Kill it or change dashboard port in gui/backend/app.py
   ```

2. **Missing dependencies**
   ```bash
   # Install everything
   sudo pacman -S clamav yara bubblewrap python3 python3-pip
   sudo freshclam
   pip install watchdog Flask
   ```

3. **Permission errors**
   ```bash
   # Make scripts executable
   chmod +x start_valkyrie.sh stop_valkyrie.sh valkyrie_cli
   ```

### Services Running But Not Working

**Restart:**
```bash
./start_valkyrie.sh restart
```

**Check if processes are alive:**
```bash
./valkyrie_cli status
```

**Follow logs for errors:**
```bash
./valkyrie_cli tail
```

### Can't Stop Services

**Force stop:**
```bash
# Find PIDs
ps aux | grep -E "(watcher|app\.py)"

# Kill them
kill -9 <PID>

# Clean PID files
rm -f /tmp/valkyrie_*.pid
```

---

## 💡 Pro Tips

### Run on System Startup (systemd)

Create `/etc/systemd/system/valkyrie.service`:
```ini
[Unit]
Description=Valkyrie File Scanner
After=network.target

[Service]
Type=forking
User=your-username
WorkingDirectory=/path/to/Valkyrie
ExecStart=/path/to/Valkyrie/start_valkyrie.sh start
ExecStop=/path/to/Valkyrie/start_valkyrie.sh stop
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable:
```bash
sudo systemctl daemon-reload
sudo systemctl enable valkyrie
sudo systemctl start valkyrie
```

### Add to PATH

```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$PATH:/path/to/Valkyrie"

# Now you can run from anywhere:
valkyrie_cli start
```

### Create Desktop Launcher

Create `~/.local/share/applications/valkyrie.desktop`:
```ini
[Desktop Entry]
Name=Valkyrie Scanner
Comment=Start Valkyrie File Scanner
Exec=/path/to/Valkyrie/start_valkyrie.sh start
Icon=security-high
Terminal=true
Type=Application
Categories=Security;Utility;
```

### Monitor Performance

```bash
# Watch resource usage
watch -n 1 'ps aux | grep -E "(watcher|app\.py)" | grep -v grep'

# Check scan stats
cat reports/*.json | jq -r '.scan_time' | awk '{sum+=$1; count++} END {print "Avg scan time:", sum/count, "seconds"}'
```

---

## 📊 Output Examples

### Successful Start
```
╔══════════════════════════════════════════════════════════════════════╗
║                    🛡️  VALKYRIE FILE SCANNER 🛡️                     ║
╚══════════════════════════════════════════════════════════════════════╝

[1/5] Checking dependencies...
  ✓ Python 3: Python 3.11.0
  ✓ ClamAV: ClamAV 1.0.0
  ✓ YARA: yara 4.3.0
  ✓ Bubblewrap: bubblewrap 0.8.0

[2/5] Checking Python packages...
  ✓ All required packages found

[3/5] Checking configuration...
  ✓ Watcher configured for sandboxed analysis
  ✓ Directories ready (reports, quarantine, processed)

[4/5] Starting services...
  ✓ Watcher started (PID: 12345)
  ✓ Dashboard started (PID: 12346)

[5/5] Valkyrie is ready!

╔══════════════════════════════════════════════════════════════════════╗
║                          ✓ ALL SYSTEMS READY                         ║
╚══════════════════════════════════════════════════════════════════════╝

Services:
  ✓ File Watcher:  Monitoring ~/Downloads/
  ✓ Web Dashboard: http://127.0.0.1:5000

Logs:
  → Watcher:   logs/watcher.log
  → Dashboard: logs/dashboard.log

Commands:
  → View logs:     tail -f logs/watcher.log
  → Stop services: ./start_valkyrie.sh stop
  → Restart:       ./start_valkyrie.sh restart
  → Check status:  ./start_valkyrie.sh status

🛡️  Security: All scans running in isolated sandbox

Test it:
  echo 'test' > ~/Downloads/test.txt
  # Check dashboard at http://127.0.0.1:5000

Opening dashboard in browser...
```

### Status Check
```
Service Status:

  ✓ Watcher:   RUNNING (PID: 12345)
  ✓ Dashboard: RUNNING (PID: 12346)
  → URL:       http://127.0.0.1:5000
```

### Graceful Stop
```
Stopping Valkyrie services...
  → Stopping watcher (PID: 12345)...
  → Stopping dashboard (PID: 12346)...
✓ Services stopped
```

---

## 🎯 Summary

**To run Valkyrie:**
```bash
./start_valkyrie.sh
```

**To stop:**
```bash
./stop_valkyrie.sh
```

**To manage:**
```bash
./valkyrie_cli <command>
```

**That's it!** 🎉

Everything else is automatic:
- Dependency checking
- Package installation
- Configuration
- Service management
- Log management
- Browser opening

Just run the script and start dropping files into Downloads!

---

**Need more help?** See:
- `QUICKSTART.md` - How to run manually
- `SECURITY_UPGRADE_CHECKLIST.md` - Full deployment guide
- `docs/SANDBOX_SETUP.md` - Troubleshooting
