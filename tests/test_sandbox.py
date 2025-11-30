"""
Unit tests for sandbox module.

Run with: pytest tests/test_sandbox.py -v
"""

import pytest
import os
import tempfile
from pathlib import Path

# Import sandbox module
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'watcher'))

from sandbox import Sandbox, SandboxError, is_sandbox_available


@pytest.fixture
def test_file():
    """Create a temporary test file"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("This is a test file\n")
        f.write("It contains benign content\n")
        path = f.name
    yield path
    # Cleanup
    try:
        os.unlink(path)
    except:
        pass


@pytest.mark.skipif(not is_sandbox_available(), reason="bubblewrap not installed")
class TestSandbox:
    """Test sandbox functionality"""
    
    def test_sandbox_initialization(self):
        """Test sandbox can be initialized"""
        sandbox = Sandbox()
        assert sandbox.max_time == 30
        assert sandbox.max_memory_mb == 512
        assert not sandbox.network_enabled
    
    def test_basic_command_execution(self, test_file):
        """Test running a simple command in sandbox"""
        sandbox = Sandbox()
        result = sandbox.run_command(['echo', 'hello'], test_file)
        
        assert result['success']
        assert 'hello' in result['stdout']
        assert not result['timeout']
        assert result['error'] is None
    
    def test_file_access(self, test_file):
        """Test accessing target file in sandbox"""
        sandbox = Sandbox()
        result = sandbox.run_command(['cat', '/scan/target'], test_file)
        
        assert result['success']
        assert 'benign content' in result['stdout']
    
    def test_timeout_enforcement(self, test_file):
        """Test that timeout is enforced"""
        sandbox = Sandbox(max_time=2)
        result = sandbox.run_command(['sleep', '10'], test_file, timeout=2)
        
        assert result['timeout']
        assert not result['success']
        assert result['returncode'] == -1
    
    def test_nonexistent_file(self):
        """Test error handling for missing files"""
        sandbox = Sandbox()
        with pytest.raises(SandboxError):
            sandbox.run_command(['cat', '/scan/target'], '/nonexistent/file.txt')


def test_sandbox_availability():
    """Test sandbox availability check"""
    available = is_sandbox_available()
    assert isinstance(available, bool)
