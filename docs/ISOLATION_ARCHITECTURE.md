# Valkyrie Isolation & Sandboxing Architecture

> **Security Principle**: Never trust the files you're analyzing. All scanning operations must occur in isolated environments with minimal privileges and restricted system access.

---

## 🚨 Current State: CRITICAL SECURITY GAPS

### ❌ Existing Vulnerabilities

**Current implementation has NO isolation:**
```python
# watcher/analysis.py - UNSAFE
subprocess.run(["clamscan", path], ...)     # Direct access to file
subprocess.run(["yara"] + rules + [path])   # Direct access to file
subprocess.run(["file", "-b", path])        # Direct access to file
```

**Attack Vectors:**
1. **Malicious Filenames**: Path traversal (`../../etc/passwd`), command injection
2. **Exploit Bugs in Scanners**: ClamAV/YARA vulnerabilities could be exploited
3. **Resource Exhaustion**: Zip bombs, decompression attacks, infinite loops
4. **File System Access**: Analyzed files have full read access to user's home directory
5. **Network Access**: No restrictions on outbound connections
6. **Process Spawning**: Malware could spawn child processes

### 🎯 Required Isolation Levels

| Component | Current | Required | Priority |
|-----------|---------|----------|----------|
| File Access | Full read/write | Read-only single file | **CRITICAL** |
| Network | Full access | Completely blocked | **CRITICAL** |
| Process Spawning | Allowed | Restricted/blocked | **HIGH** |
| System Calls | Unrestricted | Seccomp filtered | **HIGH** |
| Resource Limits | None | CPU/Memory/Time limits | **HIGH** |
| Filesystem Visibility | Full home dir | Minimal (only scan target) | **MEDIUM** |

---

## 🏗️ Proposed Multi-Layer Isolation Architecture

### Strategy: Defense in Depth
```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: Process Isolation (Namespaces)                        │
│  - PID namespace (can't see host processes)                     │
│  - Network namespace (no network access)                        │
│  - Mount namespace (custom filesystem view)                     │
│  - IPC namespace (isolated IPC)                                 │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 2: System Call Filtering (Seccomp-BPF)                   │
│  - Whitelist only required syscalls                             │
│  - Block: execve, fork, socket, connect, bind, etc.            │
│  - Allow: read, write, open, close, stat, mmap                 │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 3: Resource Limits (cgroups/rlimit)                      │
│  - CPU: max 80% single core                                     │
│  - Memory: max 512MB                                            │
│  - Processes: max 5                                             │
│  - Time: max 30 seconds per scan                                │
│  - File size: max 100MB read                                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 4: Filesystem Restrictions                                │
│  - Read-only mount of scan target (single file)                 │
│  - No access to home directory                                  │
│  - Temporary writable tmpfs (limited size)                      │
│  - No device access                                             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 5: Unprivileged Execution                                 │
│  - Drop all capabilities                                        │
│  - Run as dedicated low-privilege user                          │
│  - No setuid/setgid                                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Implementation Options

### Option 1: **Bubblewrap** (RECOMMENDED for Arch Linux)
**Pros:**
- ✅ Lightweight and fast (minimal overhead)
- ✅ Available in Arch repos: `pacman -S bubblewrap`
- ✅ User namespaces (no root/SUID required in many configs)
- ✅ Fine-grained filesystem control
- ✅ Simple CLI interface
- ✅ Used by Flatpak (battle-tested)

**Cons:**
- ⚠️ Manual configuration (no profiles out-of-box)
- ⚠️ Requires wrapper scripts

**Installation:**
```bash
sudo pacman -S bubblewrap
```

**Example Usage:**
```bash
bwrap \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind /bin /bin \
  --ro-bind /sbin /sbin \
  --ro-bind-try /etc/alternatives /etc/alternatives \
  --ro-bind-try /etc/ld.so.cache /etc/ld.so.cache \
  --tmpfs /tmp \
  --proc /proc \
  --dev /dev \
  --ro-bind /path/to/file.bin /scan/target.bin \
  --unshare-all \
  --die-with-parent \
  --new-session \
  /usr/bin/clamscan /scan/target.bin
```

---

### Option 2: **Firejail**
**Pros:**
- ✅ Easy to use (pre-made profiles)
- ✅ Available in AUR: `yay -S firejail`
- ✅ Built-in profiles for common apps
- ✅ Seccomp-BPF built-in

**Cons:**
- ⚠️ SUID binary (larger attack surface)
- ⚠️ More complex codebase
- ⚠️ Some security concerns raised in past

**Installation:**
```bash
yay -S firejail  # AUR package
```

**Example Usage:**
```bash
firejail \
  --noprofile \
  --private \
  --net=none \
  --seccomp \
  --caps.drop=all \
  --nonewprivs \
  --rlimit-cpu=30 \
  --rlimit-as=512M \
  /usr/bin/clamscan /path/to/file.bin
```

---

### Option 3: **Docker Containers**
**Pros:**
- ✅ Complete isolation
- ✅ Reproducible environments
- ✅ Easy to distribute
- ✅ Network isolation by default
- ✅ Resource limits via cgroups

**Cons:**
- ⚠️ Heavier weight (daemon required)
- ⚠️ More complex setup
- ⚠️ Requires Docker installation and privileges

**Installation:**
```bash
sudo pacman -S docker
sudo systemctl start docker
sudo usermod -aG docker $USER  # Optional: allow non-root
```

**Dockerfile Example:**
```dockerfile
FROM archlinux:latest
RUN pacman -Syu --noconfirm clamav yara
RUN useradd -m -s /bin/false scanner
WORKDIR /scan
USER scanner
ENTRYPOINT ["/usr/bin/clamscan"]
```

**Usage:**
```bash
docker run --rm \
  --read-only \
  --network=none \
  --memory=512m \
  --cpus=0.8 \
  --pids-limit=5 \
  -v /path/to/file.bin:/scan/target.bin:ro \
  valkyrie-scanner /scan/target.bin
```

---

### Option 4: **Native Python Sandboxing (seccomp + namespaces)**
**Pros:**
- ✅ No external dependencies
- ✅ Direct integration with Python code
- ✅ Fine-grained control

**Cons:**
- ⚠️ Complex implementation
- ⚠️ Requires root for some namespaces (or user namespaces)
- ⚠️ More code to maintain

**Libraries:**
- `python-prctl` - Control process capabilities
- `python-seccomp` - Seccomp filter management
- Built-in: `resource`, `os.setns()`, `unshare()`

---

## 📋 Recommended Implementation Plan

### Phase 1: Immediate (Week 1-2) - **Bubblewrap Integration**

#### 1. Install Bubblewrap
```bash
sudo pacman -S bubblewrap
```

#### 2. Create Sandbox Wrapper Module
**File: `watcher/sandbox.py`**

```python
import subprocess
import os
import tempfile
from typing import List, Dict, Optional

class SandboxError(Exception):
    """Raised when sandbox execution fails"""
    pass

class Sandbox:
    """
    Bubblewrap-based sandbox for safe command execution.
    Provides isolated environment for scanning untrusted files.
    """
    
    def __init__(self, 
                 max_time: int = 30,
                 max_memory_mb: int = 512,
                 network_enabled: bool = False):
        self.max_time = max_time
        self.max_memory_mb = max_memory_mb
        self.network_enabled = network_enabled
        self._check_bwrap()
    
    def _check_bwrap(self):
        """Verify bubblewrap is installed"""
        try:
            subprocess.run(['bwrap', '--version'], 
                         capture_output=True, check=True, timeout=5)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise SandboxError("bubblewrap not found. Install: pacman -S bubblewrap")
    
    def _build_bwrap_args(self, target_file: str, work_dir: str) -> List[str]:
        """Build bubblewrap arguments for maximum isolation"""
        
        # Create minimal read-only filesystem
        args = [
            'bwrap',
            # Essential system directories (read-only)
            '--ro-bind', '/usr', '/usr',
            '--ro-bind', '/lib', '/lib',
            '--ro-bind', '/lib64', '/lib64',
            '--ro-bind', '/bin', '/bin',
            '--ro-bind', '/sbin', '/sbin',
            
            # System configs needed by tools
            '--ro-bind-try', '/etc/ld.so.cache', '/etc/ld.so.cache',
            '--ro-bind-try', '/etc/alternatives', '/etc/alternatives',
            '--ro-bind-try', '/etc/clamav', '/etc/clamav',
            
            # Writable temp directory (limited)
            '--tmpfs', '/tmp',
            '--size', '50M', '/tmp',  # Limit tmpfs size
            
            # Working directory for output
            '--bind', work_dir, '/work',
            '--chdir', '/work',
            
            # Target file (read-only)
            '--ro-bind', target_file, '/scan/target',
            
            # Proc filesystem (needed by some scanners)
            '--proc', '/proc',
            
            # Minimal /dev
            '--dev', '/dev',
            
            # Isolation options
            '--unshare-all',      # Unshare all namespaces
            '--die-with-parent',  # Kill if parent dies
            '--new-session',      # New session ID
            '--clearenv',         # Clear environment variables
            
            # Set safe environment
            '--setenv', 'PATH', '/usr/bin:/bin',
            '--setenv', 'HOME', '/tmp',
            
            # Security options
            '--cap-drop', 'ALL',  # Drop all capabilities
        ]
        
        # Network isolation (default: disabled)
        if not self.network_enabled:
            args.extend(['--unshare-net'])
        
        return args
    
    def run_command(self, 
                    command: List[str], 
                    target_file: str,
                    timeout: Optional[int] = None) -> Dict[str, any]:
        """
        Execute command in sandbox with target file.
        
        Args:
            command: Command and args to run (e.g., ['clamscan', '/scan/target'])
            target_file: Absolute path to file to analyze
            timeout: Override default timeout
            
        Returns:
            Dict with stdout, stderr, returncode, success
        """
        if not os.path.isfile(target_file):
            raise SandboxError(f"Target file not found: {target_file}")
        
        timeout = timeout or self.max_time
        
        # Create temporary work directory for outputs
        with tempfile.TemporaryDirectory() as work_dir:
            try:
                # Build sandbox arguments
                bwrap_args = self._build_bwrap_args(target_file, work_dir)
                
                # Add the actual command
                full_cmd = bwrap_args + command
                
                # Execute with resource limits
                result = subprocess.run(
                    full_cmd,
                    capture_output=True,
                    timeout=timeout,
                    text=True
                )
                
                return {
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'returncode': result.returncode,
                    'success': result.returncode == 0,
                    'timeout': False
                }
                
            except subprocess.TimeoutExpired:
                return {
                    'stdout': '',
                    'stderr': f'Scan timeout after {timeout}s',
                    'returncode': -1,
                    'success': False,
                    'timeout': True
                }
            except Exception as e:
                raise SandboxError(f"Sandbox execution failed: {e}")

# Convenience functions
def sandboxed_clamscan(file_path: str, timeout: int = 30) -> Dict:
    """Run ClamAV scan in sandbox"""
    sandbox = Sandbox(max_time=timeout)
    return sandbox.run_command(
        ['clamscan', '--no-summary', '/scan/target'],
        file_path,
        timeout
    )

def sandboxed_yara(file_path: str, rule_files: List[str], timeout: int = 15) -> Dict:
    """Run YARA scan in sandbox"""
    sandbox = Sandbox(max_time=timeout)
    
    # Copy rule files to work dir (they need to be accessible in sandbox)
    # This is more complex - for now, rules should be in /usr/share/yara/
    # TODO: Implement rule file mounting
    
    return sandbox.run_command(
        ['yara'] + ['/scan/target'],  # Simplified
        file_path,
        timeout
    )

def sandboxed_file_type(file_path: str) -> Dict:
    """Get MIME type in sandbox"""
    sandbox = Sandbox(max_time=5)
    return sandbox.run_command(
        ['file', '-b', '--mime-type', '/scan/target'],
        file_path,
        5
    )
```

#### 3. Update `analysis.py` to Use Sandbox

```python
# Add to imports
from sandbox import sandboxed_clamscan, sandboxed_file_type, Sandbox

def clamscan(path):
    """ClamAV scan with sandboxing"""
    try:
        result = sandboxed_clamscan(path, timeout=30)
        if result['timeout']:
            return {"found": False, "error": "Scan timeout"}
        
        found = "FOUND" in result['stdout'] or result['returncode'] == 1
        return {"found": found, "output": result['stdout']}
    except Exception as e:
        return {"found": False, "error": str(e)}

def mime_type(path):
    """MIME detection with sandboxing"""
    try:
        result = sandboxed_file_type(path)
        if result['success']:
            return result['stdout'].strip()
    except Exception:
        pass
    return "unknown"
```

---

### Phase 2: Enhanced (Week 3-4) - **Resource Limits & Monitoring**

#### 1. Add Python Resource Limits
```python
import resource

def set_resource_limits():
    """Apply resource limits to current process"""
    # CPU time limit (30 seconds)
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    
    # Memory limit (512MB)
    max_mem = 512 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (max_mem, max_mem))
    
    # Process limit
    resource.setrlimit(resource.RLIMIT_NPROC, (5, 5))
    
    # File size limit (100MB)
    max_file = 100 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_FSIZE, (max_file, max_file))
```

#### 2. Add Seccomp Filtering (Optional)
```bash
# Install python-seccomp
yay -S python-seccomp
```

```python
import seccomp

def apply_seccomp_filter():
    """Apply syscall whitelist"""
    f = seccomp.SyscallFilter(defaction=seccomp.KILL)
    
    # Allow essential syscalls only
    allowed = [
        'read', 'write', 'open', 'close', 'stat', 'fstat',
        'lstat', 'lseek', 'mmap', 'mprotect', 'munmap',
        'brk', 'rt_sigaction', 'rt_sigprocmask', 'ioctl',
        'access', 'exit', 'exit_group', 'getpid', 'getcwd',
        'readlink', 'getdents', 'getdents64'
    ]
    
    for syscall in allowed:
        f.add_rule(seccomp.ALLOW, syscall)
    
    f.load()
```

---

### Phase 3: Docker Option (Week 5-6) - **Containerized Scanning**

#### 1. Create Scanner Container
**File: `docker/Dockerfile.scanner`**

```dockerfile
FROM archlinux:latest

# Install scanning tools
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm clamav yara file && \
    pacman -Scc --noconfirm

# Update ClamAV signatures
RUN freshclam || true

# Create non-root user
RUN useradd -m -u 1000 -s /bin/false scanner && \
    mkdir -p /scan /work && \
    chown scanner:scanner /scan /work

# Copy YARA rules
COPY yara_rules /usr/share/yara/

USER scanner
WORKDIR /work

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
  CMD clamscan --version || exit 1

# No default command (run as needed)
```

#### 2. Create Docker Wrapper
**File: `watcher/docker_sandbox.py`**

```python
import subprocess
import os

class DockerSandbox:
    IMAGE_NAME = "valkyrie-scanner:latest"
    
    def __init__(self):
        self._check_docker()
        self._ensure_image()
    
    def _check_docker(self):
        try:
            subprocess.run(['docker', 'version'], 
                         capture_output=True, check=True)
        except:
            raise Exception("Docker not available")
    
    def _ensure_image(self):
        """Build image if not exists"""
        result = subprocess.run(
            ['docker', 'images', '-q', self.IMAGE_NAME],
            capture_output=True, text=True
        )
        if not result.stdout.strip():
            self._build_image()
    
    def _build_image(self):
        """Build scanner container"""
        dockerfile_dir = os.path.join(
            os.path.dirname(__file__), '..', 'docker'
        )
        subprocess.run(
            ['docker', 'build', '-t', self.IMAGE_NAME, '-f', 
             'Dockerfile.scanner', '.'],
            cwd=dockerfile_dir,
            check=True
        )
    
    def scan(self, file_path: str, command: list) -> dict:
        """Run scan in Docker container"""
        abs_path = os.path.abspath(file_path)
        
        result = subprocess.run([
            'docker', 'run',
            '--rm',
            '--read-only',
            '--network=none',
            '--memory=512m',
            '--cpus=0.8',
            '--pids-limit=5',
            '--security-opt=no-new-privileges',
            '-v', f'{abs_path}:/scan/target:ro',
            self.IMAGE_NAME
        ] + command + ['/scan/target'],
        capture_output=True,
        text=True,
        timeout=30
        )
        
        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
```

---

## 🔒 Security Best Practices

### File Handling
```python
def safe_file_access(file_path: str) -> bool:
    """Validate file before analysis"""
    
    # 1. Resolve path (prevent symlink tricks)
    try:
        real_path = os.path.realpath(file_path)
    except:
        return False
    
    # 2. Check path traversal
    allowed_dirs = ['/home/user/Downloads', '/tmp/valkyrie']
    if not any(real_path.startswith(d) for d in allowed_dirs):
        return False
    
    # 3. Check file size
    max_size = 100 * 1024 * 1024  # 100MB
    if os.path.getsize(real_path) > max_size:
        return False
    
    # 4. Check it's a regular file
    if not os.path.isfile(real_path):
        return False
    
    return True
```

### Filename Sanitization
```python
import re

def sanitize_filename(filename: str) -> str:
    """Remove dangerous characters from filename"""
    # Remove path components
    filename = os.path.basename(filename)
    
    # Remove special chars (keep alphanumeric, dash, underscore, dot)
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    
    # Limit length
    if len(filename) > 200:
        filename = filename[:200]
    
    return filename
```

---

## 📊 Performance Impact

| Method | Overhead | Startup Time | Isolation Level |
|--------|----------|--------------|-----------------|
| **None (current)** | 0% | 0ms | ❌ None |
| **Bubblewrap** | ~5-10% | 50-100ms | ✅ High |
| **Firejail** | ~10-15% | 100-150ms | ✅ High |
| **Docker** | ~15-20% | 200-500ms | ✅ Very High |
| **Native Python** | ~5% | 20-50ms | ⚠️ Medium |

**Recommendation**: Start with Bubblewrap for best balance of security and performance.

---

## 🧪 Testing Isolation

### Test Suite: `tests/test_sandbox.py`

```python
import pytest
from watcher.sandbox import Sandbox, SandboxError

def test_sandbox_basic():
    """Test basic command execution"""
    sandbox = Sandbox()
    result = sandbox.run_command(['echo', 'test'], '/bin/ls')
    assert result['success']

def test_sandbox_network_blocked():
    """Verify network is blocked"""
    sandbox = Sandbox(network_enabled=False)
    result = sandbox.run_command(['ping', '-c', '1', '8.8.8.8'], '/bin/ls')
    assert not result['success']  # Should fail

def test_sandbox_timeout():
    """Test timeout enforcement"""
    sandbox = Sandbox(max_time=2)
    result = sandbox.run_command(['sleep', '10'], '/bin/ls', timeout=2)
    assert result['timeout']

def test_sandbox_file_isolation():
    """Test filesystem isolation"""
    sandbox = Sandbox()
    # Try to read file outside sandbox - should fail
    result = sandbox.run_command(['cat', '/etc/passwd'], '/bin/ls')
    # In sandbox, /etc/passwd shouldn't exist or be accessible
```

---

## 📚 References

- **Bubblewrap**: https://github.com/containers/bubblewrap
- **Firejail**: https://firejail.wordpress.com/
- **Linux Namespaces**: https://man7.org/linux/man-pages/man7/namespaces.7.html
- **Seccomp-BPF**: https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
- **Docker Security**: https://docs.docker.com/engine/security/
- **OWASP Secure Coding**: https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/

---

## 🎯 Summary & Next Steps

### Immediate Actions (This Week)
1. ✅ **Install Bubblewrap**: `sudo pacman -S bubblewrap`
2. ✅ **Create `sandbox.py` module** with Sandbox class
3. ✅ **Update `analysis.py`** to use sandboxed functions
4. ✅ **Test with EICAR file** and benign samples
5. ✅ **Document in README.md** that isolation is implemented

### Short-term (Next 2 Weeks)
- Add resource limits (CPU, memory, processes)
- Implement YARA rule mounting in sandbox
- Add sandbox metrics (overhead, success rate)
- Create configuration options for sandbox behavior

### Long-term (Future)
- Investigate Docker-based isolation for distribution
- Consider gVisor for stronger isolation
- Explore VM-based sandboxing (Firecracker) for dynamic analysis
- Build web UI to show isolation status

---

**Status**: Proposal - Pending Implementation  
**Priority**: **CRITICAL** - Security vulnerability in current design  
**Estimated Effort**: 3-5 days for Phase 1 (Bubblewrap)

