# Valkyrie Sandbox Setup Guide

This guide will help you set up the isolated sandbox environment for Valkyrie.

## Why Sandboxing?

**CRITICAL**: Without sandboxing, analyzing malicious files can compromise your system. The sandbox provides:
- ✅ Isolated filesystem (malware can't access your files)
- ✅ No network access (prevents data exfiltration)
- ✅ Resource limits (prevents system exhaustion)
- ✅ Process isolation (can't spawn backdoors)

---

## Quick Setup (Arch Linux)

### 1. Install Bubblewrap

```bash
sudo pacman -S bubblewrap
```

### 2. Verify Installation

```bash
bwrap --version
```

You should see output like: `bubblewrap 0.8.0`

### 3. Test the Sandbox

```bash
cd /path/to/valkyrie
python watcher/sandbox.py /bin/ls
```

Expected output:
```
Testing sandbox with: /bin/ls
1. Testing basic command execution...
   Result: application/x-sharedlib; charset=binary
   Success: True
```

---

## Using the Sandboxed Analysis

### Option A: Use the Sandboxed Script Directly

```bash
# Analyze a file with sandboxing
python watcher/analysis_sandboxed.py /path/to/suspicious/file.exe

# If sandbox is available, you'll see:
# [OK] Sandbox available - all scans will run isolated
```

### Option B: Update Watcher to Use Sandbox

Replace the import in `watcher/watcher.py`:

```python
# OLD (line 3):
from analysis import analyze

# NEW:
from analysis_sandboxed import analyze
```

---

## Troubleshooting

### "bubblewrap not found"

**Problem**: Sandbox module can't find bwrap command

**Solution**:
```bash
# Install bubblewrap
sudo pacman -S bubblewrap

# Verify it's in PATH
which bwrap
```

### "Permission denied" or "Operation not permitted"

**Problem**: User namespaces might be disabled

**Solution**:
```bash
# Check if user namespaces are enabled
cat /proc/sys/kernel/unprivileged_userns_clone

# If it shows 0, enable it:
sudo sysctl -w kernel.unprivileged_userns_clone=1

# Make it permanent:
echo "kernel.unprivileged_userns_clone=1" | sudo tee /etc/sysctl.d/99-userns.conf
```

### Sandbox Warnings in Analysis

If you see:
```
[WARNING] Sandbox module not available, running WITHOUT isolation!
```

This means bubblewrap isn't installed or there's an error. The analysis will still run but **WITHOUT SECURITY ISOLATION** - only use this for trusted files!

---

## Advanced Configuration

### Custom Timeout

```python
from sandbox import Sandbox

# 60 second timeout
sandbox = Sandbox(max_time=60)
result = sandbox.run_command(['clamscan', '/scan/target'], '/path/to/file')
```

### Enable Network (NOT RECOMMENDED)

```python
# Only enable if you REALLY need it
sandbox = Sandbox(network_enabled=True)
```

### Extra Mounts

```python
sandbox = Sandbox()
result = sandbox.run_command(
    ['tool', '--config', '/config/file.conf'],
    '/path/to/target',
    extra_mounts={
        '/host/path/config.conf': '/config/file.conf'
    }
)
```

---

## Testing Your Setup

### Create Test Files

```bash
# Create benign test file
echo "This is safe" > /tmp/safe.txt

# Create EICAR test signature (safe malware test file)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
```

### Test Sandboxed Analysis

```bash
# Test with safe file
python watcher/analysis_sandboxed.py /tmp/safe.txt

# Test with EICAR (should detect as malware)
python watcher/analysis_sandboxed.py /tmp/eicar.txt
```

Expected for EICAR:
```json
{
  "verdict": "quarantine",
  "score": 100,
  "clamav": {
    "found": true,
    "output": "... Eicar-Signature FOUND"
  }
}
```

---

## Security Checklist

Before running Valkyrie in production:

- [ ] Bubblewrap installed and tested
- [ ] `analysis_sandboxed.py` shows "[OK] Sandbox available"
- [ ] Tested with EICAR file (should quarantine)
- [ ] Tested with benign file (should allow)
- [ ] Network isolation verified (no outbound connections during scan)
- [ ] Watcher updated to use `from analysis_sandboxed import analyze`

---

## Performance Impact

Sandboxing adds minimal overhead:
- **Startup**: ~50-100ms per scan
- **CPU**: ~5-10% additional
- **Memory**: ~50MB for sandbox namespace

This is **negligible** compared to the security benefits!

---

## Need Help?

- Check logs: Look for sandbox-related errors in console output
- Test manually: Run `python watcher/sandbox.py /bin/ls` to isolate issues
- Verify permissions: Ensure you can run `bwrap --ro-bind / /test echo test`
- Check kernel: `uname -r` - older kernels (<4.8) may have limited namespace support

---

## Next Steps

After setting up the sandbox:
1. Update `watcher.py` to use `analysis_sandboxed`
2. Run the watcher: `python watcher/watcher.py`
3. Test by dropping files into Downloads
4. Monitor quarantine folder for threats
5. Check reports for sandboxing indicator: `"sandboxed": true`
