"""Tests for heuristic analysis."""

import os
import tempfile
import math
import pytest

from valkyrie.heuristics import (
    EntropyAnalyzer,
    PackerDetector,
    ArchiveInspector,
    FileTypeValidator,
    HeuristicAnalyzer
)


class TestEntropyAnalyzer:
    """Test entropy analysis."""

    def test_shannon_entropy_zero(self):
        """Test entropy of repetitive data is low."""
        data = b"AAAAAAAABBBBBBBB"  # Repeating pattern
        entropy = EntropyAnalyzer.calculate_shannon_entropy(data)
        assert entropy < 1.0  # Should be low for repetitive data

    def test_shannon_entropy_high(self):
        """Test entropy of random data is high."""
        import random
        random.seed(42)
        data = bytes(random.getrandbits(8) for _ in range(1000))
        entropy = EntropyAnalyzer.calculate_shannon_entropy(data)
        assert entropy > 7.0  # Should be high for random data

    def test_shannon_entropy_max(self):
        """Test maximum entropy."""
        # All byte values equally distributed
        data = bytes(range(256) * 4)
        entropy = EntropyAnalyzer.calculate_shannon_entropy(data)
        assert abs(entropy - 8.0) < 0.1  # Should approach 8.0

    def test_file_entropy_analysis(self):
        """Test entropy analysis of file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"AAAA" * 1000)  # Low entropy data
            f.flush()

            entropy_data = EntropyAnalyzer.analyze_file_entropy(f.name)
            assert entropy_data["overall"] < 2.0
            assert entropy_data["overall"] > 0

        os.unlink(f.name)

    def test_entropy_verdict(self):
        """Test entropy verdict scoring."""
        # High entropy
        verdict, score = EntropyAnalyzer.get_entropy_verdict(8.0)
        assert verdict == "high_risk"
        assert score == 30

        # Suspicious entropy
        verdict, score = EntropyAnalyzer.get_entropy_verdict(7.5)
        assert verdict == "suspicious"
        assert score == 15

        # Normal entropy
        verdict, score = EntropyAnalyzer.get_entropy_verdict(5.0)
        assert verdict == "normal"
        assert score == 0


class TestPackerDetector:
    """Test packer detection."""

    def test_packer_detection(self):
        """Test packer detection in file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"This file contains UPX packed executable")
            f.flush()

            result = PackerDetector.detect_packer(f.name)
            assert result["detected"] is True
            assert result["packer"] == "UPX"

        os.unlink(f.name)

    def test_no_packer(self):
        """Test file without packer."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Regular text file without packer")
            f.flush()

            result = PackerDetector.detect_packer(f.name)
            assert result["detected"] is False

        os.unlink(f.name)


class TestArchiveInspector:
    """Test archive inspection."""

    def test_zip_detection(self):
        """Test ZIP file detection."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            # Create minimal ZIP file
            f.write(b"PK\x03\x04")
            f.flush()

            archive_type = ArchiveInspector.detect_archive_type(f.name)
            assert archive_type == "zip"

        os.unlink(f.name)

    def test_gzip_detection(self):
        """Test GZIP file detection."""
        with tempfile.NamedTemporaryFile(suffix=".gz", delete=False) as f:
            # GZIP magic number
            f.write(b"\x1f\x8b\x08")
            f.flush()

            archive_type = ArchiveInspector.detect_archive_type(f.name)
            assert archive_type == "gzip"

        os.unlink(f.name)

    def test_non_archive(self):
        """Test non-archive file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Regular file content")
            f.flush()

            archive_type = ArchiveInspector.detect_archive_type(f.name)
            assert archive_type is None

        os.unlink(f.name)

    def test_archive_inspection(self):
        """Test archive inspection."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            # Minimal ZIP file
            f.write(b"PK\x03\x04")
            f.flush()

            result = ArchiveInspector.inspect_archive(f.name)
            assert result["is_archive"] is True
            assert result["archive_type"] == "zip"

        os.unlink(f.name)


class TestFileTypeValidator:
    """Test file type validation."""

    def test_double_extension(self):
        """Test double extension detection."""
        # Normal extension
        assert FileTypeValidator.check_double_extension("file.pdf") is False

        # Double extension (suspicious)
        assert FileTypeValidator.check_double_extension("file.pdf.exe") is True

        # Legitimate .tar.gz
        assert FileTypeValidator.check_double_extension("archive.tar.gz") is False

    def test_hidden_extension(self):
        """Test hidden extension detection."""
        # Normal file
        assert FileTypeValidator.check_hidden_extension("file.pdf") is False

        # Trailing spaces (suspicious)
        assert FileTypeValidator.check_hidden_extension("file.pdf ") is True

    def test_file_type_validation(self):
        """Test file type validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "file.pdf.exe")

            with open(file_path, "wb") as f:
                f.write(b"test")

            result = FileTypeValidator.validate_file_type(file_path, "application/pdf")
            assert result["double_extension"] is True
            assert result["score"] >= 10


class TestHeuristicAnalyzer:
    """Test heuristic analyzer orchestrator."""

    def test_analyze_with_config(self):
        """Test full heuristic analysis."""
        config = {
            "entropy": {"enabled": True},
            "packer_detection": {"enabled": True},
            "archive_inspection": {"enabled": True},
            "file_type_validation": {"enabled": True}
        }

        analyzer = HeuristicAnalyzer(config)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"AAAA" * 1000)  # Low entropy file
            f.flush()

            result = analyzer.analyze(f.name)
            assert "entropy" in result
            assert "packer" in result
            assert "archive" in result
            assert "file_type" in result
            assert "total_score" in result

        os.unlink(f.name)

    def test_analyze_disabled_heuristics(self):
        """Test analysis with disabled heuristics."""
        config = {
            "entropy": {"enabled": False},
            "packer_detection": {"enabled": False},
            "archive_inspection": {"enabled": False},
            "file_type_validation": {"enabled": False}
        }

        analyzer = HeuristicAnalyzer(config)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test data")
            f.flush()

            result = analyzer.analyze(f.name)
            # All heuristics should return default/zero values
            assert result["entropy"]["verdict"] == "normal"
            assert result["packer"]["detected"] is False

        os.unlink(f.name)


if __name__ == "__main__":
    pytest.main([__file__])
