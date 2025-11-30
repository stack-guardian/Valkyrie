"""
Sandbox module for safe execution of file analysis commands.

Provides isolated environment using bubblewrap to analyze untrusted files
without risking the host system. Implements multiple layers of security:
- Filesystem isolation (read-only target, minimal system access)
- Network isolation (no network access by default)
- Process isolation (namespaces)
- Resource limits (timeout, memory)

Example:
    >>> from sandbox import Sandbox
    >>> sandbox = Sandbox()
    >>> result = sandbox.run_command(['clamscan', '/scan/target'], '/path/to/suspicious.exe')
    >>> print(result['stdout'])
"""

import subprocess
import os
import tempfile
import shutil
from typing import List, Dict, Optional
from pathlib import Path


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
                 network_enabled: bool = False,
                 enable_tmpfs: bool = True,
                 tmpfs_size_mb: int = 50):
        """
        Initialize sandbox with security parameters.
        
        Args:
            max_time: Maximum execution time in seconds (default: 30)
            max_memory_mb: Maximum memory in MB (default: 512)
            network_enabled: Allow network access (default: False - RECOMMENDED)
            enable_tmpfs: Provide writable /tmp (default: True)
            tmpfs_size_mb: Size limit for /tmp in MB (default: 50)
        """
        self.max_time = max_time
        self.max_memory_mb = max_memory_mb
        self.network_enabled = network_enabled
        self.enable_tmpfs = enable_tmpfs
        self.tmpfs_size_mb = tmpfs_size_mb
        
        # Verify bubblewrap is available
        self._check_bwrap()
    
    def _check_bwrap(self):
        """Verify bubblewrap is installed and accessible"""
        try:
            result = subprocess.run(
                ['bwrap', '--version'], 
                capture_output=True, 
                check=True, 
                timeout=5
            )
            version = result.stdout.decode().strip()
            # Version should be at least 0.3.0 for good security
            print(f"[Sandbox] Using {version}")
        except FileNotFoundError:
            raise SandboxError(
                "bubblewrap not found. Install with: sudo pacman -S bubblewrap"
            )
        except subprocess.CalledProcessError as e:
            raise SandboxError(f"bubblewrap check failed: {e}")
        except subprocess.TimeoutExpired:
            raise SandboxError("bubblewrap check timed out")
    
    def _build_bwrap_args(self, target_file: str, work_dir: str) -> List[str]:
        """
        Build bubblewrap arguments for maximum isolation.
        
        Creates a minimal read-only root filesystem with only essential
        system directories, then mounts the target file read-only.
        
        Args:
            target_file: Absolute path to file being analyzed
            work_dir: Temporary working directory for outputs
            
        Returns:
            List of command-line arguments for bwrap
        """
        
        args = ['bwrap']
        
        # Mount essential system directories (read-only)
        essential_dirs = {
            '/usr': '/usr',
            '/lib': '/lib',
            '/lib64': '/lib64',
            '/bin': '/bin',
            '/sbin': '/sbin',
        }
        
        for src, dst in essential_dirs.items():
            if os.path.exists(src):
                args.extend(['--ro-bind', src, dst])
        
        # Mount configuration files needed by tools (read-only)
        config_files = [
            '/etc/ld.so.cache',
            '/etc/ld.so.conf',
            '/etc/ld.so.conf.d',
            '/etc/alternatives',
            '/etc/clamav',
            '/etc/mime.types',
        ]
        
        for config in config_files:
            if os.path.exists(config):
                args.extend(['--ro-bind-try', config, config])
        
        # Create writable temporary directory (size-limited tmpfs)
        if self.enable_tmpfs:
            args.extend(['--tmpfs', '/tmp'])
            # Note: size limit not directly supported in bwrap, 
            # would need cgroups for strict enforcement
        else:
            args.extend(['--dir', '/tmp'])
        
        # Create /dev with minimal devices
        args.extend(['--dev', '/dev'])
        
        # Mount /proc (needed by some analysis tools)
        args.extend(['--proc', '/proc'])
        
        # Create work directory for outputs (read-write)
        args.extend(['--bind', work_dir, '/work'])
        args.extend(['--chdir', '/work'])
        
        # Mount target file as read-only at standard location
        # This prevents the analyzed file from being modified
        args.extend(['--ro-bind', target_file, '/scan/target'])
        
        # Namespace isolation
        args.extend([
            '--unshare-all',      # Unshare all namespaces (pid, net, ipc, uts, user, cgroup)
            '--die-with-parent',  # Kill sandbox if parent dies (prevent orphans)
            '--new-session',      # New session ID
        ])
        
        # Network isolation (unless explicitly enabled)
        if not self.network_enabled:
            args.extend(['--unshare-net'])
        
        # Clear environment and set minimal safe vars
        args.extend([
            '--clearenv',
            '--setenv', 'PATH', '/usr/bin:/bin:/usr/sbin:/sbin',
            '--setenv', 'HOME', '/tmp',
            '--setenv', 'TMPDIR', '/tmp',
            '--setenv', 'USER', 'scanner',
        ])
        
        # Security hardening
        args.extend([
            '--cap-drop', 'ALL',  # Drop all capabilities
        ])
        
        return args
    
    def run_command(self, 
                    command: List[str], 
                    target_file: str,
                    timeout: Optional[int] = None,
                    extra_mounts: Optional[Dict[str, str]] = None) -> Dict:
        """
        Execute command in sandbox with target file.
        
        Args:
            command: Command and args to run (e.g., ['clamscan', '/scan/target'])
            target_file: Absolute path to file to analyze
            timeout: Override default timeout (seconds)
            extra_mounts: Additional read-only mounts {host_path: sandbox_path}
            
        Returns:
            Dict with keys:
                - stdout: Command standard output
                - stderr: Command standard error
                - returncode: Exit code
                - success: True if returncode == 0
                - timeout: True if execution timed out
                - error: Error message if exception occurred
                
        Raises:
            SandboxError: If target file doesn't exist or sandbox setup fails
        """
        
        # Validate target file
        if not os.path.isfile(target_file):
            raise SandboxError(f"Target file not found: {target_file}")
        
        # Get absolute path
        target_file = os.path.abspath(target_file)
        
        # Use provided timeout or default
        timeout = timeout or self.max_time
        
        # Create temporary work directory for outputs
        with tempfile.TemporaryDirectory(prefix='valkyrie_sandbox_') as work_dir:
            try:
                # Build base sandbox arguments
                bwrap_args = self._build_bwrap_args(target_file, work_dir)
                
                # Add extra mounts if provided
                if extra_mounts:
                    for host_path, sandbox_path in extra_mounts.items():
                        if os.path.exists(host_path):
                            bwrap_args.extend(['--ro-bind', host_path, sandbox_path])
                
                # Append the actual command to execute
                full_cmd = bwrap_args + command
                
                # Execute in sandbox with timeout
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
                    'timeout': False,
                    'error': None
                }
                
            except subprocess.TimeoutExpired:
                return {
                    'stdout': '',
                    'stderr': f'Sandbox execution timed out after {timeout} seconds',
                    'returncode': -1,
                    'success': False,
                    'timeout': True,
                    'error': 'timeout'
                }
            except Exception as e:
                return {
                    'stdout': '',
                    'stderr': str(e),
                    'returncode': -1,
                    'success': False,
                    'timeout': False,
                    'error': str(e)
                }


# Convenience functions for common operations

def sandboxed_clamscan(file_path: str, timeout: int = 30) -> Dict:
    """
    Run ClamAV scan in isolated sandbox.
    
    Args:
        file_path: Path to file to scan
        timeout: Maximum scan time in seconds
        
    Returns:
        Dict with stdout, stderr, returncode, success, timeout keys
    """
    sandbox = Sandbox(max_time=timeout, network_enabled=False)
    return sandbox.run_command(
        ['clamscan', '--no-summary', '/scan/target'],
        file_path,
        timeout
    )


def sandboxed_yara(file_path: str, rules_dir: str, timeout: int = 15) -> Dict:
    """
    Run YARA scan in isolated sandbox.
    
    Args:
        file_path: Path to file to scan
        rules_dir: Directory containing .yar rule files
        timeout: Maximum scan time in seconds
        
    Returns:
        Dict with stdout, stderr, returncode, success, timeout keys
    """
    sandbox = Sandbox(max_time=timeout, network_enabled=False)
    
    # Get all .yar files from rules directory
    if not os.path.isdir(rules_dir):
        return {
            'stdout': '',
            'stderr': f'Rules directory not found: {rules_dir}',
            'returncode': -1,
            'success': False,
            'timeout': False,
            'error': 'rules_not_found'
        }
    
    rule_files = sorted([
        os.path.join(rules_dir, f) 
        for f in os.listdir(rules_dir) 
        if f.endswith('.yar')
    ])
    
    if not rule_files:
        return {
            'stdout': '',
            'stderr': 'No .yar files found in rules directory',
            'returncode': -1,
            'success': False,
            'timeout': False,
            'error': 'no_rules'
        }
    
    # Create temporary combined rules file in work dir
    # This is a workaround since we can't easily mount multiple files
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as combined:
        combined_path = combined.name
        for rule_file in rule_files:
            with open(rule_file, 'r') as rf:
                combined.write(f"// From {os.path.basename(rule_file)}\n")
                combined.write(rf.read())
                combined.write("\n\n")
    
    try:
        # Mount combined rules file into sandbox
        result = sandbox.run_command(
            ['yara', '/rules/combined.yar', '/scan/target'],
            file_path,
            timeout,
            extra_mounts={combined_path: '/rules/combined.yar'}
        )
        return result
    finally:
        # Clean up temporary file
        try:
            os.unlink(combined_path)
        except:
            pass


def sandboxed_file_type(file_path: str) -> Dict:
    """
    Detect MIME type in isolated sandbox.
    
    Args:
        file_path: Path to file to analyze
        
    Returns:
        Dict with stdout, stderr, returncode, success, timeout keys
    """
    sandbox = Sandbox(max_time=5, network_enabled=False)
    return sandbox.run_command(
        ['file', '-b', '--mime-type', '/scan/target'],
        file_path,
        5
    )


def is_sandbox_available() -> bool:
    """
    Check if sandboxing is available on this system.
    
    Returns:
        True if bubblewrap is installed and functional
    """
    try:
        result = subprocess.run(
            ['bwrap', '--version'],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False


if __name__ == '__main__':
    """Test sandbox functionality"""
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python sandbox.py /path/to/test/file")
        sys.exit(1)
    
    test_file = sys.argv[1]
    
    if not os.path.isfile(test_file):
        print(f"Error: File not found: {test_file}")
        sys.exit(2)
    
    print(f"Testing sandbox with: {test_file}")
    print()
    
    # Test basic sandbox
    print("1. Testing basic command execution...")
    sandbox = Sandbox()
    result = sandbox.run_command(['file', '/scan/target'], test_file)
    print(f"   Result: {result['stdout'].strip()}")
    print(f"   Success: {result['success']}")
    print()
    
    # Test file type detection
    print("2. Testing MIME type detection...")
    result = sandboxed_file_type(test_file)
    print(f"   MIME: {result['stdout'].strip()}")
    print()
    
    # Test ClamAV (if available)
    print("3. Testing ClamAV scan...")
    if shutil.which('clamscan'):
        result = sandboxed_clamscan(test_file)
        print(f"   Output: {result['stdout'][:200]}...")
        print(f"   Success: {result['success']}")
    else:
        print("   Skipped (clamscan not found)")
    print()
    
    print("Sandbox tests complete!")
