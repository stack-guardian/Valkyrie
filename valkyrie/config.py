"""
Configuration management for Valkyrie file security scanner.

This module handles loading, validating, and providing access to configuration
settings from YAML files and environment variables.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


logger = logging.getLogger(__name__)


@dataclass
class EngineConfig:
    """Configuration for scan engines."""
    enabled: bool = True
    timeout: int = 30
    # ClamAV specific
    use_daemon: bool = False
    socket_path: str = "/var/run/clamav/clamd.ctl"
    # YARA specific
    rules_directory: str = "yara_rules"


@dataclass
class HeuristicConfig:
    """Configuration for heuristic analysis."""
    entropy: Dict[str, float] = field(default_factory=lambda: {
        "enabled": True,
        "suspicious_threshold": 7.2,
        "high_risk_threshold": 7.8
    })
    packer_detection: Dict[str, bool] = field(default_factory=lambda: {
        "enabled": True
    })
    archive_inspection: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": True,
        "max_depth": 3,
        "max_expansion_ratio": 100,
        "password_protected_flag": True
    })
    file_type_validation: Dict[str, bool] = field(default_factory=lambda: {
        "enabled": True,
        "check_double_extensions": True,
        "check_hidden_extensions": True
    })


@dataclass
class ScoringConfig:
    """Configuration for risk scoring."""
    weights: Dict[str, int] = field(default_factory=lambda: {
        "clamav_signature": 100,
        "yara_critical": 90,
        "yara_high": 70,
        "yara_medium": 40,
        "yara_low": 20,
        "entropy_high": 30,
        "entropy_suspicious": 15,
        "packer_detected": 25,
        "file_type_mismatch": 20,
        "archive_bomb": 50,
        "suspicious_imports": 15
    })
    thresholds: Dict[str, int] = field(default_factory=lambda: {
        "quarantine": 80,
        "review": 40
    })


@dataclass
class OutputConfig:
    """Configuration for output directories."""
    directories: Dict[str, str] = field(default_factory=lambda: {
        "reports": "reports",
        "quarantine": "quarantine",
        "processed": "processed",
        "logs": "logs"
    })
    retention: Dict[str, Any] = field(default_factory=lambda: {
        "reports_days": 30,
        "compress_days": 7,
        "quarantine_days": 90,
        "max_reports": 0
    })


@dataclass
class DashboardConfig:
    """Configuration for web dashboard."""
    host: str = "127.0.0.1"
    port: int = 5000
    debug: bool = False
    reports_per_page: int = 50


@dataclass
class LoggingConfig:
    """Configuration for logging."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file: str = "logs/valkyrie.log"
    max_size_mb: int = 10
    backup_count: int = 10


@dataclass
class NotificationConfig:
    """Configuration for notifications."""
    desktop: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": True,
        "urgency": "normal"
    })
    webhook: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": False,
        "url": "",
        "on_detection_only": True
    })


@dataclass
class SecurityConfig:
    """Configuration for security settings."""
    quarantine_permissions: int = 0o700
    validate_paths: bool = True
    sanitize_filenames: bool = True


@dataclass
class PerformanceConfig:
    """Configuration for performance settings."""
    max_workers: int = 4
    enable_cache: bool = True
    cache_ttl: int = 3600


@dataclass
class WatcherConfig:
    """Configuration for file watcher."""
    watch_path: str = "~/Downloads"
    recursive: bool = False
    max_file_size_mb: int = 500
    write_delay: float = 0.5


@dataclass
class ValkyrieConfig:
    """Main configuration class."""
    watcher: WatcherConfig = field(default_factory=WatcherConfig)
    analysis: Dict[str, Any] = field(default_factory=dict)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)


class ConfigManager:
    """Manages configuration loading and validation."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager.

        Args:
            config_path: Path to config file. If None, auto-detects.
        """
        self.config_path = config_path or self._find_config_file()
        self._config: Optional[ValkyrieConfig] = None

    def _find_config_file(self) -> str:
        """Find configuration file in standard locations."""
        # Check environment variable
        if os.getenv("VALKYRIE_CONFIG"):
            return os.getenv("VALKYRIE_CONFIG")

        # Check standard locations
        search_paths = [
            "config/valkyrie.yaml",
            "config/valkyrie.yml",
            "valkyrie.yaml",
            "valkyrie.yml",
            ".valkyrie.yaml",
            os.path.expanduser("~/.valkyrie.yaml"),
        ]

        for path in search_paths:
            if os.path.isfile(path):
                logger.info(f"Found config file: {path}")
                return path

        # Default location
        return "config/valkyrie.yaml"

    def load(self) -> ValkyrieConfig:
        """
        Load configuration from file.

        Returns:
            Loaded and validated configuration.
        """
        config_data = self._load_yaml()
        self._config = self._parse_config(config_data)
        return self._config

    def _load_yaml(self) -> Dict[str, Any]:
        """Load YAML configuration file."""
        try:
            with open(self.config_path, "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config file not found: {self.config_path}, using defaults")
            return self._get_default_config()
        except yaml.YAMLError as e:
            logger.error(f"Error parsing config file: {e}")
            raise

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "watcher": {},
            "analysis": {},
            "scoring": {},
            "output": {},
            "dashboard": {},
            "logging": {},
            "notifications": {},
            "security": {},
            "performance": {}
        }

    def _parse_config(self, data: Dict[str, Any]) -> ValkyrieConfig:
        """
        Parse configuration data into dataclasses.

        Args:
            data: Raw configuration dictionary.

        Returns:
            Parsed configuration object.
        """
        # Extract nested configurations
        watcher_data = data.get("watcher", {})
        analysis_data = data.get("analysis", {})
        scoring_data = data.get("scoring", {})
        output_data = data.get("output", {})
        dashboard_data = data.get("dashboard", {})
        logging_data = data.get("logging", {})
        notifications_data = data.get("notifications", {})
        security_data = data.get("security", {})
        performance_data = data.get("performance", {})

        # Parse nested configs
        engines = analysis_data.get("engines", {})
        heuristics = analysis_data.get("heuristics", {})

        config = ValkyrieConfig(
            watcher=WatcherConfig(**watcher_data),
            analysis={
                "engines": {
                    "clamav": EngineConfig(**engines.get("clamav", {})),
                    "yara": EngineConfig(**engines.get("yara", {}))
                },
                "heuristics": HeuristicConfig(**heuristics) if heuristics else HeuristicConfig()
            },
            scoring=ScoringConfig(**scoring_data),
            output=OutputConfig(**output_data),
            dashboard=DashboardConfig(**dashboard_data),
            logging=LoggingConfig(**logging_data),
            notifications=NotificationConfig(**notifications_data),
            security=SecurityConfig(**security_data),
            performance=PerformanceConfig(**performance_data)
        )

        return config

    def get_config(self) -> ValkyrieConfig:
        """
        Get loaded configuration.

        Returns:
            Current configuration, or default if not loaded.
        """
        if self._config is None:
            self._config = self.load()
        return self._config

    def validate(self) -> bool:
        """
        Validate configuration settings.

        Returns:
            True if valid, False otherwise.
        """
        try:
            config = self.get_config()

            # Validate thresholds
            if config.scoring.thresholds.get("quarantine", 0) < 0 or \
               config.scoring.thresholds.get("review", 0) < 0:
                logger.error("Invalid threshold values")
                return False

            if config.scoring.thresholds.get("quarantine", 0) < \
               config.scoring.thresholds.get("review", 0):
                logger.error("Quarantine threshold must be >= review threshold")
                return False

            # Validate paths
            if not os.path.isabs(config.watcher.watch_path):
                logger.warning("Watch path is relative, expanding to absolute path")
                config.watcher.watch_path = os.path.abspath(
                    os.path.expanduser(config.watcher.watch_path)
                )

            logger.info("Configuration validation successful")
            return True

        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.

        Args:
            key: Configuration key (e.g., 'watcher.watch_path')
            default: Default value if key not found.

        Returns:
            Configuration value.
        """
        config = self.get_config()

        # Navigate through nested structure
        keys = key.split(".")
        value = config

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            elif hasattr(value, k):
                value = getattr(value, k)
            else:
                return default

        return value if value is not None else default


# Global configuration instance
_config_manager: Optional[ConfigManager] = None


def get_config() -> ValkyrieConfig:
    """
    Get global configuration instance.

    Returns:
        Loaded configuration.
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager.get_config()


def get_config_value(key: str, default: Any = None) -> Any:
    """
    Get configuration value using dot notation.

    Args:
        key: Configuration key (e.g., 'watcher.watch_path')
        default: Default value if key not found.

    Returns:
        Configuration value.
    """
    return get_config().get(key, default) if hasattr(get_config(), 'get') \
        else _config_manager.get(key, default)


def reload_config() -> ValkyrieConfig:
    """
    Reload configuration from file.

    Returns:
        Reloaded configuration.
    """
    global _config_manager
    _config_manager = ConfigManager()
    return _config_manager.get_config()
