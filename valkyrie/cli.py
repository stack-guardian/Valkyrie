"""
Command-line interface for Valkyrie file security scanner.

Provides CLI commands for scanning, configuration, and management.
"""

import argparse
import sys
import os
import json
import time
from pathlib import Path
from typing import Optional

from .config import ConfigManager, get_config, reload_config
from .logger import setup_logging, get_logger
from .analysis import analyze_file, EnhancedAnalysisEngine
from .scoring import RiskScorer

logger = get_logger("cli")


def cmd_scan(args):
    """Scan a file or directory."""
    config = get_config()

    # Set up logging
    setup_logging(
        log_level=config.logging.level,
        log_file=config.logging.file,
        max_size_mb=config.logging.max_size_mb,
        backup_count=config.logging.backup_count,
        format_string=config.logging.format
    )

    if args.verbose:
        print(f"Scanning: {args.path}")

    # Check if path is a file or directory
    if os.path.isfile(args.path):
        # Single file
        if args.dry_run:
            print("[DRY RUN] Would scan file (not moving or modifying)")
            return

        engine = EnhancedAnalysisEngine()
        report = engine.analyze(args.path)

        if args.format == "json":
            print(json.dumps(report, indent=2, default=str))
        else:
            # Human-readable format
            print(f"\n{'='*60}")
            print(f"File: {report['name']}")
            print(f"SHA256: {report['sha256']}")
            print(f"MIME: {report['mime']}")
            print(f"Size: {report['size']} bytes")
            print(f"\nScoring:")
            print(f"  Total Score: {report['scoring']['total_score']}")
            print(f"  Verdict: {report['scoring']['verdict'].upper()}")
            print(f"\nBreakdown:")
            for factor, score in report['scoring']['breakdown'].items():
                print(f"  {factor:20s} +{score:3d}")
            print(f"\nExecution time: {report['execution_time']:.2f}s")
            print(f"{'='*60}\n")

    elif os.path.isdir(args.path):
        # Directory
        files = list(Path(args.path).rglob("*"))
        files = [f for f in files if f.is_file()]

        print(f"Found {len(files)} files to scan\n")

        if args.dry_run:
            print("[DRY RUN] Would scan files (not moving or modifying)")
            for f in files[:10]:
                print(f"  - {f.name}")
            if len(files) > 10:
                print(f"  ... and {len(files) - 10} more")
            return

        total = len(files)
        results = []
        start_time = time.time()

        for i, file_path in enumerate(files, 1):
            if args.verbose:
                print(f"[{i}/{total}] Scanning: {file_path.name}")

            try:
                engine = EnhancedAnalysisEngine()
                report = engine.analyze(str(file_path))
                results.append(report)

                # Print quick summary
                verdict = report.get("scoring", {}).get("verdict", "unknown")
                score = report.get("scoring", {}).get("total_score", 0)
                print(f"  {verdict.upper():12s} ({score:3d}) - {file_path.name}")
            except Exception as e:
                print(f"  ERROR - {file_path.name}: {e}")

        elapsed = time.time() - start_time
        print(f"\n{'-'*60}")
        print(f"Scanned {total} files in {elapsed:.2f}s")
        print(f"Average: {total/elapsed:.2f} files/sec")
        print(f"{'-'*60}\n")

    else:
        print(f"Error: Path not found: {args.path}")
        return 1

    return 0


def cmd_config_validate(args):
    """Validate configuration file."""
    config_manager = ConfigManager(args.config)

    print(f"Loading configuration from: {config_manager.config_path}")

    try:
        config = config_manager.load()
        if config_manager.validate():
            print("✓ Configuration is valid")
            return 0
        else:
            print("✗ Configuration validation failed")
            return 1
    except Exception as e:
        print(f"✗ Error: {e}")
        return 1


def cmd_rules_list(args):
    """List loaded YARA rules."""
    config = get_config()
    rules_dir = config.analysis.get("engines", {}).get("yara", {}).get("rules_directory", "yara_rules")

    if not os.path.isabs(rules_dir):
        rules_dir = os.path.join(os.path.dirname(__file__), "..", "..", rules_dir)

    if not os.path.exists(rules_dir):
        print(f"Rules directory not found: {rules_dir}")
        return 1

    rule_files = sorted(Path(rules_dir).glob("*.yar"))

    if not rule_files:
        print(f"No YARA rule files found in {rules_dir}")
        return 0

    print(f"YARA Rules in {rules_dir}:")
    print(f"  {len(rule_files)} rule files\n")

    for rule_file in rule_files:
        print(f"  {rule_file.name}")
        # Read file and count rules
        try:
            content = rule_file.read_text()
            rule_count = content.count("rule ")
            print(f"    - {rule_count} rule(s)")
        except Exception as e:
            print(f"    - Error reading: {e}")

    return 0


def cmd_quarantine_list(args):
    """List quarantined files."""
    config = get_config()
    quarantine_dir = config.output.directories.get("quarantine", "quarantine")

    if not os.path.isabs(quarantine_dir):
        quarantine_dir = os.path.join(os.path.dirname(__file__), "..", "..", quarantine_dir)

    if not os.path.exists(quarantine_dir):
        print("No quarantine directory found")
        return 0

    files = list(Path(quarantine_dir).glob("*"))
    files = [f for f in files if f.is_file()]

    if not files:
        print("No quarantined files")
        return 0

    print(f"Quarantined files ({len(files)}):\n")

    for file_path in files:
        stat = file_path.stat()
        size = stat.st_size
        mtime = time.ctime(stat.st_mtime)
        print(f"  {file_path.name}")
        print(f"    Size: {size} bytes")
        print(f"    Quarantined: {mtime}")

        # Check if report exists
        report_file = Path("reports") / f"{file_path.name}.json"
        if report_file.exists():
            print(f"    Report: {report_file}")
        print()

    return 0


def cmd_status(args):
    """Show service status."""
    config = get_config()

    print("Valkyrie Status")
    print("="*60)

    # Configuration
    print(f"\nConfiguration:")
    print(f"  Watch path: {config.watcher.watch_path}")
    print(f"  Max file size: {config.watcher.max_file_size_mb} MB")

    # Engines
    print(f"\nEngines:")
    print(f"  ClamAV: {'Enabled' if config.analysis.get('engines', {}).get('clamav', {}).get('enabled') else 'Disabled'}")
    print(f"  YARA: {'Enabled' if config.analysis.get('engines', {}).get('yara', {}).get('enabled') else 'Disabled'}")

    # Heuristics
    print(f"\nHeuristics:")
    heuristics = config.analysis.get("heuristics", {})
    print(f"  Entropy: {'Enabled' if heuristics.get('entropy', {}).get('enabled') else 'Disabled'}")
    print(f"  Packer: {'Enabled' if heuristics.get('packer_detection', {}).get('enabled') else 'Disabled'}")
    print(f"  Archive: {'Enabled' if heuristics.get('archive_inspection', {}).get('enabled') else 'Disabled'}")

    # Scoring
    print(f"\nScoring:")
    print(f"  Quarantine threshold: {config.scoring.thresholds.get('quarantine', 80)}")
    print(f"  Review threshold: {config.scoring.thresholds.get('review', 40)}")

    # Directories
    print(f"\nDirectories:")
    print(f"  Reports: {config.output.directories.get('reports', 'reports')}")
    print(f"  Quarantine: {config.output.directories.get('quarantine', 'quarantine')}")
    print(f"  Processed: {config.output.directories.get('processed', 'processed')}")

    # Stats
    reports_dir = config.output.directories.get("reports", "reports")
    if os.path.exists(reports_dir):
        reports = list(Path(reports_dir).glob("*.json"))
        print(f"\nStatistics:")
        print(f"  Total reports: {len(reports)}")

    print("="*60)

    return 0


def cmd_clean(args):
    """Clean old reports and files."""
    config = get_config()

    if not args.force and not args.dry_run:
        response = input("This will delete old files. Continue? (y/N): ")
        if response.lower() != 'y':
            print("Cancelled")
            return 0

    retention_days = args.reports_days
    quarantine_days = args.quarantine_days

    print(f"Cleaning old files...")
    print(f"  Reports older than {retention_days} days")
    print(f"  Quarantine files older than {quarantine_days} days")

    if args.dry_run:
        print("\n[DRY RUN] Would clean:")

    # Clean reports
    reports_dir = config.output.directories.get("reports", "reports")
    if os.path.exists(reports_dir):
        cutoff = time.time() - (retention_days * 86400)
        files = list(Path(reports_dir).glob("*.json"))

        deleted = 0
        for file_path in files:
            if file_path.stat().st_mtime < cutoff:
                if args.dry_run:
                    print(f"  Would delete report: {file_path.name}")
                else:
                    file_path.unlink()
                    deleted += 1

        if not args.dry_run:
            print(f"  Deleted {deleted} old reports")

    # Clean quarantine
    quarantine_dir = config.output.directories.get("quarantine", "quarantine")
    if os.path.exists(quarantine_dir):
        cutoff = time.time() - (quarantine_days * 86400)
        files = list(Path(quarantine_dir).glob("*"))

        deleted = 0
        for file_path in files:
            if file_path.stat().st_mtime < cutoff:
                if args.dry_run:
                    print(f"  Would delete from quarantine: {file_path.name}")
                else:
                    file_path.unlink()
                    deleted += 1

        if not args.dry_run:
            print(f"  Deleted {deleted} old quarantine files")

    if args.dry_run:
        print("\n[DRY RUN] - No files were deleted")
    else:
        print("\n✓ Clean complete")

    return 0


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Valkyrie File Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Global options
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--config",
        help="Path to configuration file"
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a file or directory")
    scan_parser.add_argument("path", help="Path to scan")
    scan_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Analyze without moving files"
    )
    scan_parser.add_argument(
        "--format",
        choices=["json", "human"],
        default="human",
        help="Output format"
    )
    scan_parser.set_defaults(func=cmd_scan)

    # Config validate command
    config_parser = subparsers.add_parser("config", help="Configuration management")
    config_subparsers = config_parser.add_subparsers(dest="config_command")
    validate_parser = config_subparsers.add_parser("validate", help="Validate configuration")
    validate_parser.set_defaults(func=cmd_config_validate)

    # Rules command
    rules_parser = subparsers.add_parser("rules", help="YARA rules management")
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command")
    rules_list_parser = rules_subparsers.add_parser("list", help="List YARA rules")
    rules_list_parser.set_defaults(func=cmd_rules_list)

    # Quarantine command
    quarantine_parser = subparsers.add_parser("quarantine", help="Quarantine management")
    quarantine_subparsers = quarantine_parser.add_subparsers(dest="quarantine_command")
    quarantine_list_parser = quarantine_subparsers.add_parser("list", help="List quarantined files")
    quarantine_list_parser.set_defaults(func=cmd_quarantine_list)

    # Status command
    status_parser = subparsers.add_parser("status", help="Show system status")
    status_parser.set_defaults(func=cmd_status)

    # Clean command
    clean_parser = subparsers.add_parser("clean", help="Clean old files")
    clean_parser.add_argument(
        "--reports-days",
        type=int,
        default=30,
        help="Keep reports for N days (default: 30)"
    )
    clean_parser.add_argument(
        "--quarantine-days",
        type=int,
        default=90,
        help="Keep quarantine files for N days (default: 90)"
    )
    clean_parser.add_argument(
        "--force",
        action="store_true",
        help="Skip confirmation prompt"
    )
    clean_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be cleaned without deleting"
    )
    clean_parser.set_defaults(func=cmd_clean)

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Load configuration
    try:
        if args.config:
            config_manager = ConfigManager(args.config)
            config_manager.load()
    except Exception as e:
        print(f"Configuration error: {e}")
        return 1

    # Execute command
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nCancelled")
        return 1
    except Exception as e:
        logger.error(f"Command failed: {e}", exc_info=args.verbose)
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
