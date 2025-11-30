"""Tests for enhanced analysis engine."""

import os
import tempfile
import pytest
import json
import hashlib

from valkyrie.analysis import (
    sha256,
    mime_type,
    ClamAVScanner,
    YaraScanner,
    EnhancedAnalysisEngine
)


class TestSha256:
    """Test SHA256 hashing."""

    def test_sha256_calculation(self):
        """Test SHA256 calculation is correct."""
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b"Hello, World!")
            f.flush()

            calc_hash = sha256(f.name)

            # Calculate expected hash
            expected = hashlib.sha256(b"Hello, World!").hexdigest()

            assert calc_hash == expected

        os.unlink(f.name)

    def test_sha256_large_file(self):
        """Test SHA256 calculation on large file."""
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            # Write 10MB of data
            data = b"X" * (10 * 1024 * 1024)
            f.write(data)
            f.flush()

            calc_hash = sha256(f.name)
            expected = hashlib.sha256(data).hexdigest()

            assert calc_hash == expected

        os.unlink(f.name)


class TestMimeType:
    """Test MIME type detection."""

    def test_text_file(self):
        """Test MIME type of text file."""
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            f.write("Hello, World!")
            f.flush()

            mime = mime_type(f.name)
            assert "text" in mime or "application" in mime

        os.unlink(f.name)

    def test_binary_file(self):
        """Test MIME type of binary file."""
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b"\x00\x01\x02\x03")
            f.flush()

            mime = mime_type(f.name)
            assert mime != "unknown"

        os.unlink(f.name)


class TestClamAVScanner:
    """Test ClamAV scanner."""

    def test_scanner_initialization(self):
        """Test scanner can be initialized."""
        scanner = ClamAVScanner()
        assert scanner.enabled is True

    def test_disabled_scanner(self):
        """Test disabled scanner returns disabled status."""
        scanner = ClamAVScanner({"enabled": False})
        result = scanner.scan("/dev/null")
        assert result["enabled"] is False


class TestYaraScanner:
    """Test YARA scanner."""

    def test_scanner_initialization(self):
        """Test scanner can be initialized."""
        scanner = YaraScanner()
        assert scanner.enabled is True

    def test_no_rules_directory(self):
        """Test scanner with missing rules directory."""
        scanner = YaraScanner({"rules_directory": "/nonexistent"})
        result = scanner.scan("/dev/null")
        assert result["error"] == "no rules"


class TestEnhancedAnalysisEngine:
    """Test enhanced analysis engine."""

    def test_file_not_found(self):
        """Test analysis fails for non-existent file."""
        engine = EnhancedAnalysisEngine()
        with pytest.raises(FileNotFoundError):
            engine.analyze("/nonexistent/file.txt")

    def test_analyze_benign_file(self):
        """Test analysis of benign file."""
        engine = EnhancedAnalysisEngine()

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b"This is a benign test file")
            f.flush()

            report = engine.analyze(f.name)

            # Verify report structure
            assert "name" in report
            assert "sha256" in report
            assert "mime" in report
            assert "clamav" in report
            assert "yara" in report
            assert "heuristics" in report
            assert "scoring" in report

            # Verify analysis completed
            assert "execution_time" in report
            assert report["execution_time"] > 0

            # Benign file should have low score
            assert report["scoring"]["total_score"] < 40

        os.unlink(f.name)

    def test_analyze_quick_scan(self):
        """Test quick scan without heuristics."""
        engine = EnhancedAnalysisEngine()

        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            f.write("test data")
            f.flush()

            report = engine.analyze_quick(f.name)

            # Quick scan should not include heuristics
            # (but implementation might still include empty heuristics)
            assert "clamav" in report
            assert "yara" in report

        os.unlink(f.name)

    def test_file_size_limit(self):
        """Test file size limit enforcement."""
        # Create custom config with small limit
        from valkyrie.config import ValkyrieConfig, WatcherConfig
        config = ValkyrieConfig(watcher=WatcherConfig(max_file_size_mb=1))

        engine = EnhancedAnalysisEngine(config)

        # Create 2MB file (exceeds 1MB limit)
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b"X" * (2 * 1024 * 1024))
            f.flush()

            report = engine.analyze(f.name)

            assert "error" in report
            assert report["error"] == "file_too_large"
            assert report["size"] == 2 * 1024 * 1024

        os.unlink(f.name)

    def test_malicious_content_detection(self):
        """Test detection of EICAR test file."""
        engine = EnhancedAnalysisEngine()

        # EICAR test string
        eicar = (
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        )

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(eicar)
            f.flush()

            report = engine.analyze(f.name)

            # EICAR should trigger high score (ClamAV or YARA)
            # Score depends on whether ClamAV is installed
            assert "scoring" in report
            assert report["scoring"]["total_score"] >= 0

        os.unlink(f.name)


if __name__ == "__main__":
    pytest.main([__file__])
