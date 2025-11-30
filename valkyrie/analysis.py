"""
Enhanced analysis engine for Valkyrie file security scanner.

This module provides comprehensive file analysis with multi-engine detection,
heuristic analysis, and intelligent risk scoring.
"""

import hashlib
import json
import os
import subprocess
import sys
import time
import signal
from pathlib import Path
from typing import Dict, Any, Optional
from contextlib import contextmanager

from .config import get_config
from .logger import get_logger, LoggingContext
from .heuristics import HeuristicAnalyzer
from .scoring import RiskScorer

logger = get_logger("analysis")


class TimeoutException(Exception):
    """Raised when operation times out."""
    pass


def timeout_handler(signum, frame):
    """Signal handler for timeout."""
    raise TimeoutException("Operation timed out")


def sha256(path: str) -> str:
    """
    Calculate SHA256 hash of a file.

    Args:
        path: Path to file

    Returns:
        SHA256 hash as hex string
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1<<20), b""):
            h.update(chunk)
    return h.hexdigest()


def mime_type(path: str) -> str:
    """
    Detect MIME type of a file.

    Args:
        path: Path to file

    Returns:
        MIME type string
    """
    try:
        p = subprocess.run(
            ["file", "-b", "--mime-type", path],
            capture_output=True,
            text=True,
            timeout=5
        )
        if p.returncode == 0:
            return p.stdout.strip()
    except Exception as e:
        logger.warning(f"Error detecting MIME type: {e}")
    return "unknown"


@contextmanager
def timeout(seconds: int):
    """Context manager for timeout operations."""
    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


class ClamAVScanner:
    """ClamAV signature scanner."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize scanner.

        Args:
            config: Configuration for ClamAV
        """
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.use_daemon = self.config.get("use_daemon", False)
        self.socket_path = self.config.get("socket_path", "/var/run/clamav/clamd.ctl")
        self.timeout = self.config.get("timeout", 30)

    def scan(self, path: str) -> Dict[str, Any]:
        """
        Scan file with ClamAV.

        Args:
            path: Path to file

        Returns:
            Scan results
        """
        if not self.enabled:
            logger.info("ClamAV disabled in configuration")
            return {"enabled": False, "found": False}

        try:
            with timeout(self.timeout):
                if self.use_daemon and os.path.exists(self.socket_path):
                    # TODO: Implement socket-based scanning
                    logger.warning("Daemon mode not yet implemented, falling back to CLI")
                    return self._scan_cli(path)
                else:
                    return self._scan_cli(path)
        except TimeoutException:
            logger.error(f"ClamAV scan timed out after {self.timeout}s: {path}")
            return {"found": False, "error": "timeout"}
        except Exception as e:
            logger.error(f"ClamAV scan error: {e}")
            return {"found": False, "error": str(e)}

    def _scan_cli(self, path: str) -> Dict[str, Any]:
        """Scan using clamscan CLI."""
        try:
            p = subprocess.run(
                ["clamscan", "--no-summary", path],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            output = (p.stdout + p.stderr).strip()
            found = ("FOUND" in output) or (p.returncode == 1)

            if found:
                logger.warning(f"ClamAV detection: {output}")

            return {"found": found, "output": output, "returncode": p.returncode}
        except Exception as e:
            return {"found": False, "error": str(e)}


class YaraScanner:
    """YARA rule-based scanner."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize scanner.

        Args:
            config: Configuration for YARA
        """
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.rules_dir = self.config.get("rules_directory", "yara_rules")
        self.timeout = self.config.get("timeout", 15)

    def scan(self, path: str) -> Dict[str, Any]:
        """
        Scan file with YARA rules.

        Args:
            path: Path to file

        Returns:
            Scan results
        """
        if not self.enabled:
            logger.info("YARA disabled in configuration")
            return {"enabled": False, "hits": []}

        # Find rule files
        if not os.path.isabs(self.rules_dir):
            self.rules_dir = os.path.join(
                os.path.dirname(__file__), "..", "..", self.rules_dir
            )

        rule_files = sorted([
            p for p in Path(self.rules_dir).glob("*.yar")
            if p.is_file()
        ])

        if not rule_files:
            logger.warning(f"No YARA rule files found in {self.rules_dir}")
            return {"hits": [], "error": "no rules"}

        try:
            with timeout(self.timeout):
                cmd = ["yara"] + [str(f) for f in rule_files] + [path]
                p = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )

                hits = [line.strip() for line in p.stdout.splitlines() if line.strip()]

                if hits:
                    logger.info(f"YARA matches: {hits}")

                return {"hits": hits, "cmd": " ".join(cmd)}
        except TimeoutException:
            logger.error(f"YARA scan timed out after {self.timeout}s: {path}")
            return {"hits": [], "error": "timeout"}
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
            return {"hits": [], "error": str(e)}


class EnhancedAnalysisEngine:
    """
    Enhanced analysis engine with multi-engine detection and scoring.
    """

    def __init__(self, config: Optional[Any] = None):
        """
        Initialize analysis engine.

        Args:
            config: Valkyrie configuration object
        """
        self.config = config or get_config()
        self.logger = get_logger("analysis")

        # Initialize scanners
        self.clamav = ClamAVScanner(
            self.config.analysis.get("engines", {}).get("clamav", {})
        )
        self.yara = YaraScanner(
            self.config.analysis.get("engines", {}).get("yara", {})
        )
        self.heuristics = HeuristicAnalyzer(
            self.config.analysis.get("heuristics", {})
        )
        self.scorer = RiskScorer(self.config)

    def analyze(self, path: str, include_heuristics: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive file analysis.

        Args:
            path: Path to file to analyze
            include_heuristics: Whether to include heuristic analysis

        Returns:
            Complete analysis report
        """
        with LoggingContext(self.logger, file_path=path):
            self.logger.info(f"Starting analysis: {path}")

            # Verify file exists
            if not os.path.isfile(path):
                self.logger.error(f"File not found: {path}")
                raise FileNotFoundError(f"File not found: {path}")

            # Get file info
            file_size = os.path.getsize(path)
            self.logger.debug(f"File size: {file_size} bytes")

            # Check file size limit
            max_size = self.config.watcher.max_file_size_mb * 1024 * 1024
            if file_size > max_size:
                self.logger.warning(
                    f"File too large ({file_size} > {max_size} bytes), skipping"
                )
                return {
                    "error": "file_too_large",
                    "size": file_size,
                    "max_size": max_size
                }

            # Start analysis
            t0 = time.time()

            # Collect analysis results
            results = {
                "name": os.path.basename(path),
                "path": os.path.abspath(path),
                "size": file_size,
                "sha256": sha256(path),
                "mime": mime_type(path),
                "timestamp": t0,
            }

            # Run detection engines
            self.logger.info("Running ClamAV scan...")
            results["clamav"] = self.clamav.scan(path)

            self.logger.info("Running YARA scan...")
            results["yara"] = self.yara.scan(path)

            # Run heuristic analysis
            if include_heuristics:
                self.logger.info("Running heuristic analysis...")
                results["heuristics"] = self.heuristics.analyze(path)
            else:
                results["heuristics"] = {}

            # Calculate risk score
            self.logger.info("Calculating risk score...")
            scoring_result = self.scorer.calculate_score(results)
            results["scoring"] = {
                "total_score": scoring_result.total_score,
                "verdict": scoring_result.verdict,
                "breakdown": scoring_result.breakdown,
                "factors": scoring_result.factors,
            }

            # Add execution time
            execution_time = time.time() - t0
            results["execution_time"] = execution_time

            self.logger.info(
                f"Analysis complete: {scoring_result.verdict} "
                f"(score: {scoring_result.total_score}, time: {execution_time:.2f}s)"
            )

            return results

    def analyze_quick(self, path: str) -> Dict[str, Any]:
        """
        Perform quick analysis without heuristics.

        Args:
            path: Path to file

        Returns:
            Analysis report (quick version)
        """
        return self.analyze(path, include_heuristics=False)


def analyze_file(path: str, config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to analyze a file.

    Args:
        path: Path to file
        config_path: Optional config file path

    Returns:
        Analysis report
    """
    engine = EnhancedAnalysisEngine()
    return engine.analyze(path)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analysis.py /path/to/file")
        sys.exit(1)

    target = sys.argv[1]
    if not os.path.isfile(target):
        print(f"File not found: {target}")
        sys.exit(2)

    # Run analysis
    engine = EnhancedAnalysisEngine()
    report = engine.analyze(target)

    # Print results
    print(json.dumps(report, indent=2, default=str))
