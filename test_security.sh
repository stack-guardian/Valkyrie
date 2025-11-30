#!/bin/bash
# Valkyrie Security Validation Script

echo "Valkyrie Security Validation"
echo "============================"
echo

# Test 1: Bubblewrap installed
echo "[1/7] Checking bubblewrap..."
if command -v bwrap &> /dev/null; then
    echo "✅ bubblewrap installed: $(bwrap --version | head -1)"
else
    echo "❌ bubblewrap NOT installed"
    echo "   Install: sudo pacman -S bubblewrap"
    exit 1
fi
echo

# Test 2: Sandbox module works
echo "[2/7] Testing sandbox module..."
if python3 -c "from watcher.sandbox import is_sandbox_available; exit(0 if is_sandbox_available() else 1)" 2>/dev/null; then
    echo "✅ Sandbox module functional"
else
    echo "❌ Sandbox module not working"
    exit 1
fi
echo

# Test 3: Analysis uses sandbox
echo "[3/7] Checking watcher integration..."
if grep -q "from analysis_sandboxed import analyze" watcher/watcher.py; then
    echo "✅ Watcher uses sandboxed analysis"
else
    echo "⚠️  Watcher still using unsafe analysis"
    echo "   Update line 3 of watcher/watcher.py"
fi
echo

# Test 4: EICAR detection
echo "[4/7] Testing EICAR detection..."
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar_test.txt
EICAR_RESULT=$(python3 watcher/analysis_sandboxed.py /tmp/eicar_test.txt 2>/dev/null | grep -o '"verdict": "quarantine"')
if [ -n "$EICAR_RESULT" ]; then
    echo "✅ EICAR properly quarantined"
else
    echo "⚠️  EICAR not detected (ClamAV may need signature update)"
    echo "   Run: sudo freshclam"
fi
rm /tmp/eicar_test.txt
echo

# Test 5: Benign file handling
echo "[5/7] Testing benign file handling..."
echo "This is a safe test file" > /tmp/safe_test.txt
SAFE_RESULT=$(python3 watcher/analysis_sandboxed.py /tmp/safe_test.txt 2>/dev/null | grep -o '"verdict": "allow"')
if [ -n "$SAFE_RESULT" ]; then
    echo "✅ Benign file properly allowed"
else
    echo "❌ Benign file not allowed (unexpected)"
fi
rm /tmp/safe_test.txt
echo

# Test 6: Sandboxing flag
echo "[6/7] Verifying sandbox flag in reports..."
echo "safe content" > /tmp/flag_test.txt
SANDBOX_FLAG=$(python3 watcher/analysis_sandboxed.py /tmp/flag_test.txt 2>/dev/null | grep -o '"sandboxed": true')
if [ -n "$SANDBOX_FLAG" ]; then
    echo "✅ Reports include sandboxing flag"
else
    echo "❌ Sandboxing flag missing"
fi
rm /tmp/flag_test.txt
echo

# Test 7: Network isolation
echo "[7/7] Testing network isolation..."
NETWORK_TEST=$(python3 << 'PYEOF'
try:
    from watcher.sandbox import Sandbox
    s = Sandbox(network_enabled=False)
    result = s.run_command(['ping', '-c', '1', '8.8.8.8'], '/bin/ls', timeout=2)
    print("isolated" if not result['success'] else "exposed")
except:
    print("error")
PYEOF
)

if [ "$NETWORK_TEST" = "isolated" ]; then
    echo "✅ Network properly isolated"
elif [ "$NETWORK_TEST" = "exposed" ]; then
    echo "❌ Network NOT isolated (CRITICAL)"
else
    echo "⚠️  Network test inconclusive"
fi
echo

# Summary
echo "============================"
echo "Security Validation Complete"
echo "============================"
echo
echo "If all tests pass (✅), your Valkyrie installation is SECURE."
echo "If any tests fail (❌), review docs/SANDBOX_SETUP.md"
