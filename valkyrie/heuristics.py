"""
Heuristic analysis module for detecting suspicious file characteristics.

This module implements entropy analysis, packer detection, archive inspection,
and file type validation for enhanced malware detection.
"""

import math
import os
import shutil
import subprocess
import zipfile
import tarfile
import gzip
import hashlib
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import logging

from .logger import get_logger

logger = get_logger("heuristics")


class EntropyAnalyzer:
    """Analyzes file entropy to detect packed/encrypted content."""

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of byte data.

        Args:
            data: Byte data to analyze

        Returns:
            Entropy value (0-8, where higher values indicate more randomness)
        """
        if not data:
            return 0.0

        # Count frequency of each byte value
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def analyze_file_entropy(file_path: str, chunk_size: int = 1024*1024) -> Dict[str, float]:
        """
        Analyze entropy of a file.

        Args:
            file_path: Path to file
            chunk_size: Size of chunks to read

        Returns:
            Dictionary with overall and per-section entropy scores
        """
        entropies = []
        file_size = os.path.getsize(file_path)

        if file_size == 0:
            return {"overall": 0.0, "max": 0.0, "avg": 0.0, "sections": []}

        try:
            with open(file_path, "rb") as f:
                # Calculate entropy for first few chunks
                for i in range(min(10, (file_size + chunk_size - 1) // chunk_size)):
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    entropy = EntropyAnalyzer.calculate_shannon_entropy(chunk)
                    entropies.append(entropy)
        except Exception as e:
            logger.error(f"Error analyzing entropy for {file_path}: {e}")
            return {"overall": 0.0, "max": 0.0, "avg": 0.0, "sections": []}

        return {
            "overall": EntropyAnalyzer.calculate_shannon_entropy(
                Path(file_path).read_bytes()
            ),
            "max": max(entropies) if entropies else 0.0,
            "avg": sum(entropies) / len(entropies) if entropies else 0.0,
            "sections": entropies
        }

    @staticmethod
    def get_entropy_verdict(entropy: float, suspicious_threshold: float = 7.2,
                           high_risk_threshold: float = 7.8) -> Tuple[str, int]:
        """
        Get verdict based on entropy score.

        Args:
            entropy: Calculated entropy score
            suspicious_threshold: Threshold for suspicious (default 7.2)
            high_risk_threshold: Threshold for high risk (default 7.8)

        Returns:
            Tuple of (verdict, score)
        """
        if entropy >= high_risk_threshold:
            return "high_risk", 30
        elif entropy >= suspicious_threshold:
            return "suspicious", 15
        else:
            return "normal", 0


class PackerDetector:
    """Detects common file packers and obfuscation."""

    COMMON_PACKERS = [
        "UPX", "ASPack", "PECompact", "Themida", "WinRAR", "7-Zip",
        "MPRESS", "FSG", "PE_PATCH", "PACKMA", "RCryptor", "Enigma"
    ]

    SUSPICIOUS_SECTION_NAMES = [
        ".upx", ".packed", ".aspack", ".petite", ".fsg", ".mpress",
        ".pack", ".enigma", ".themida", ".vmprotect"
    ]

    @staticmethod
    def detect_packer(file_path: str) -> Dict[str, Any]:
        """
        Detect if file is packed using common packers.

        Args:
            file_path: Path to file

        Returns:
            Dictionary with detection results
        """
        result = {
            "detected": False,
            "packer": None,
            "suspicious_sections": [],
            "score": 0
        }

        try:
            # Use 'strings' command to extract readable strings
            p = subprocess.run(
                ["strings", file_path],
                capture_output=True,
                text=True,
                timeout=5
            )

            if p.returncode == 0:
                strings_output = p.stdout.lower()

                # Check for common packer signatures
                for packer in PackerDetector.COMMON_PACKERS:
                    if packer.lower() in strings_output:
                        result["detected"] = True
                        result["packer"] = packer
                        result["score"] = 25
                        logger.info(f"Detected packer {packer} in {file_path}")
                        break
        except Exception as e:
            logger.warning(f"Error detecting packer in {file_path}: {e}")

        return result


class ArchiveInspector:
    """Inspects archive files (ZIP, TAR, etc.) for threats."""

    MAX_DEPTH = 3
    MAX_EXPANSION_RATIO = 100

    @staticmethod
    def detect_archive_type(file_path: str) -> Optional[str]:
        """
        Detect archive type.

        Args:
            file_path: Path to file

        Returns:
            Archive type or None if not an archive
        """
        try:
            # Check ZIP
            if zipfile.is_zipfile(file_path):
                return "zip"

            # Check TAR
            with open(file_path, "rb") as f:
                header = f.read(6)
                if header.startswith(b"\x1f\x8b\x08"):
                    return "gzip"
                elif header.startswith(b"ustar"):
                    return "tar"

            # Check 7z, RAR (basic check)
            with open(file_path, "rb") as f:
                header = f.read(6)
                if header.startswith(b"Rar!"):
                    return "rar"
                elif header.startswith(b"7z\xbc\xaf\x27\x1c"):
                    return "7z"
        except Exception as e:
            logger.error(f"Error detecting archive type: {e}")

        return None

    @staticmethod
    def inspect_archive(file_path: str, max_depth: int = 3,
                       max_expansion_ratio: int = 100) -> Dict[str, Any]:
        """
        Inspect archive contents.

        Args:
            file_path: Path to archive file
            max_depth: Maximum recursion depth
            max_expansion_ratio: Maximum expansion ratio to detect bombs

        Returns:
            Dictionary with inspection results
        """
        archive_type = ArchiveInspector.detect_archive_type(file_path)

        if not archive_type:
            return {"is_archive": False}

        result = {
            "is_archive": True,
            "archive_type": archive_type,
            "files": [],
            "directories": [],
            "total_size": 0,
            "compressed_size": os.path.getsize(file_path),
            "expansion_ratio": 0,
            "password_protected": False,
            "depth": 0,
            "score": 0
        }

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract archive
                if archive_type == "zip":
                    try:
                        with zipfile.ZipFile(file_path, 'r') as zf:
                            # Check if password protected
                            for info in zf.infolist():
                                if info.flag_bits & 0x1:
                                    result["password_protected"] = True
                                    result["score"] += 5
                                    break

                            # Calculate total size
                            result["total_size"] = sum(
                                info.file_size for info in zf.infolist()
                            )

                            # Extract files (limited)
                            extracted_files = zf.namelist()[:100]  # Limit to prevent abuse
                            for fname in extracted_files:
                                result["files"].append(fname)
                                if fname.endswith('/'):
                                    result["directories"].append(fname)

                    except zipfile.BadZipFile:
                        logger.warning(f"Invalid ZIP file: {file_path}")

                elif archive_type == "gzip":
                    with gzip.open(file_path, 'rb') as f:
                        data = f.read()
                        result["total_size"] = len(data)
                        result["files"].append(os.path.basename(file_path))

                # Calculate expansion ratio
                if result["compressed_size"] > 0:
                    result["expansion_ratio"] = result["total_size"] / result["compressed_size"]

                    # Flag archive bombs
                    if result["expansion_ratio"] > max_expansion_ratio:
                        result["score"] += 50
                        logger.warning(
                            f"Archive bomb detected: {result['expansion_ratio']:.1f}:1 ratio"
                        )

                    # Flag password-protected archives
                    if result["password_protected"]:
                        result["score"] += 5

        except Exception as e:
            logger.error(f"Error inspecting archive {file_path}: {e}")

        return result


class FileTypeValidator:
    """Validates file types and detects anomalies."""

    @staticmethod
    def check_double_extension(file_path: str) -> bool:
        """
        Check for double extensions (e.g., .pdf.exe).

        Args:
            file_path: Path to file

        Returns:
            True if suspicious double extension detected
        """
        basename = os.path.basename(file_path).lower()
        extensions = basename.split('.')

        # Check for pattern like .pdf.exe, .doc.js, etc.
        if len(extensions) >= 3:
            # More than 2 extensions is suspicious
            # But allow some legitimate patterns (e.g., .tar.gz, .min.js)
            legitimate_multi = [
                ('tar', 'gz'), ('tar', 'bz2'), ('tar', 'xz'),
                ('min', 'js'), ('min', 'css')
            ]

            last_two = tuple(extensions[-2:])
            if last_two not in legitimate_multi:
                return True

        return False

    @staticmethod
    def check_hidden_extensions(file_path: str) -> bool:
        """
        Check for hidden extensions (trailing spaces, Unicode tricks).

        Args:
            file_path: Path to file

        Returns:
            True if hidden extension detected
        """
        basename = os.path.basename(file_path)

        # Check for trailing spaces or non-printable characters
        if basename.rstrip() != basename:
            return True

        # Check for Unicode homoglyphs in extension
        # This is a basic check - production systems should use more sophisticated detection
        return False

    @staticmethod
    def validate_file_type(file_path: str, expected_mime: str) -> Dict[str, Any]:
        """
        Validate that file extension matches MIME type.

        Args:
            file_path: Path to file
            expected_mime: Expected MIME type

        Returns:
            Validation results
        """
        result = {
            "valid": True,
            "extension_mismatch": False,
            "double_extension": False,
            "hidden_extension": False,
            "score": 0
        }

        basename = os.path.basename(file_path).lower()

        # Check for double extension
        if FileTypeValidator.check_double_extension(file_path):
            result["double_extension"] = True
            result["score"] += 10
            logger.warning(f"Double extension detected: {file_path}")

        # Check for hidden extension
        if FileTypeValidator.check_hidden_extensions(file_path):
            result["hidden_extension"] = True
            result["score"] += 10
            logger.warning(f"Hidden extension detected: {file_path}")

        # Basic extension-to-MIME validation (simplified)
        suspicious_mime_mismatches = {
            "application/x-executable": [".pdf", ".doc", ".txt", ".jpg", ".png"],
            "text/html": [".exe", ".dll", ".bin"],
        }

        for mime, extensions in suspicious_mime_mismatches.items():
            if expected_mime == mime:
                for ext in extensions:
                    if basename.endswith(ext):
                        result["extension_mismatch"] = True
                        result["valid"] = False
                        result["score"] += 20
                        logger.warning(
                            f"Extension/MIME mismatch: {ext} detected as {mime} in {file_path}"
                        )
                        break

        return result


class HeuristicAnalyzer:
    """Main heuristic analysis orchestrator."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize analyzer with configuration.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.entropy_threshold = self.config.get("entropy", {}).get(
            "suspicious_threshold", 7.2
        )
        self.high_risk_threshold = self.config.get("entropy", {}).get(
            "high_risk_threshold", 7.8
        )
        self.max_depth = self.config.get("archive_inspection", {}).get("max_depth", 3)
        self.max_expansion = self.config.get("archive_inspection", {}).get(
            "max_expansion_ratio", 100
        )

    def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive heuristic analysis.

        Args:
            file_path: Path to file

        Returns:
            Combined analysis results
        """
        results = {
            "entropy": {"overall": 0.0, "verdict": "normal", "score": 0},
            "packer": {"detected": False, "packer": None, "score": 0},
            "archive": {"is_archive": False, "score": 0},
            "file_type": {"valid": True, "score": 0},
            "total_score": 0,
            "findings": []
        }

        # Entropy analysis
        if self.config.get("entropy", {}).get("enabled", True):
            logger.debug(f"Analyzing entropy for {file_path}")
            entropy_data = EntropyAnalyzer.analyze_file_entropy(file_path)
            verdict, score = EntropyAnalyzer.get_entropy_verdict(
                entropy_data["overall"],
                self.entropy_threshold,
                self.high_risk_threshold
            )
            results["entropy"] = {
                "overall": entropy_data["overall"],
                "max": entropy_data["max"],
                "avg": entropy_data["avg"],
                "verdict": verdict,
                "score": score
            }
            if score > 0:
                results["findings"].append(f"High entropy ({entropy_data['overall']:.2f})")

        # Packer detection
        if self.config.get("packer_detection", {}).get("enabled", True):
            logger.debug(f"Detecting packers in {file_path}")
            packer_data = PackerDetector.detect_packer(file_path)
            results["packer"] = packer_data
            if packer_data["detected"]:
                results["findings"].append(f"Packer detected: {packer_data['packer']}")

        # Archive inspection
        if self.config.get("archive_inspection", {}).get("enabled", True):
            logger.debug(f"Inspecting archive: {file_path}")
            archive_data = ArchiveInspector.inspect_archive(
                file_path,
                self.max_depth,
                self.max_expansion
            )
            results["archive"] = archive_data
            if archive_data.get("is_archive"):
                results["findings"].append(f"Archive type: {archive_data.get('archive_type')}")

        # File type validation
        if self.config.get("file_type_validation", {}).get("enabled", True):
            logger.debug(f"Validating file type: {file_path}")
            # This would be called with actual MIME type from analysis
            file_type_data = {"valid": True, "score": 0, "findings": []}
            results["file_type"] = file_type_data

        # Calculate total score
        results["total_score"] = (
            results["entropy"]["score"] +
            results["packer"]["score"] +
            results["archive"].get("score", 0) +
            results["file_type"]["score"]
        )

        return results
