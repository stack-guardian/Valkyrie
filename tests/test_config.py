"""Tests for configuration management."""

import os
import tempfile
import pytest
from pathlib import Path

from valkyrie.config import (
    ConfigManager,
    ValkyrieConfig,
    WatcherConfig,
    ScoringConfig
)


class TestConfigManager:
    """Test configuration loading and validation."""

    def test_default_config(self):
        """Test default configuration is valid."""
        manager = ConfigManager()
        config = manager.load()
        assert isinstance(config, ValkyrieConfig)
        assert config.watcher.watch_path == "~/Downloads"
        assert config.scoring.thresholds.get("quarantine") == 80

    def test_config_validation_valid(self):
        """Test valid configuration passes validation."""
        manager = ConfigManager()
        manager.load()
        assert manager.validate() is True

    def test_config_validation_invalid_thresholds(self):
        """Test invalid thresholds fail validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "test.yaml")
            with open(config_file, "w") as f:
                f.write("""
                    scoring:
                      thresholds:
                        quarantine: 50
                        review: 60
                """)

            manager = ConfigManager(config_file)
            manager.load()
            # Quarantine threshold should be >= review threshold
            assert manager.validate() is False

    def test_expand_user_path(self):
        """Test relative paths are expanded to absolute."""
        manager = ConfigManager()
        manager.load()
        config = manager.get_config()
        # Watch path should be absolute after validation
        assert os.path.isabs(config.watcher.watch_path)

    def test_get_nested_value(self):
        """Test getting nested configuration values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "test.yaml")
            with open(config_file, "w") as f:
                f.write("""
                    watcher:
                      watch_path: /test/path
                    analysis:
                      engines:
                        clamav:
                          timeout: 30
                """)

            manager = ConfigManager(config_file)
            manager.load()

            # Test dot notation access
            assert manager.get("watcher.watch_path") == "/test/path"
            assert manager.get("analysis.engines.clamav.timeout") == 30
            assert manager.get("nonexistent.key", "default") == "default"


class TestValkyrieConfig:
    """Test configuration structure."""

    def test_watcher_config(self):
        """Test watcher configuration."""
        config = WatcherConfig(
            watch_path="/custom/path",
            max_file_size_mb=100
        )
        assert config.watch_path == "/custom/path"
        assert config.max_file_size_mb == 100

    def test_scoring_config(self):
        """Test scoring configuration."""
        config = ScoringConfig(
            weights={"clamav_signature": 100},
            thresholds={"quarantine": 80}
        )
        assert config.weights["clamav_signature"] == 100
        assert config.thresholds["quarantine"] == 80


class TestConfigFile:
    """Test YAML configuration file."""

    def test_yaml_parsing(self):
        """Test YAML file is correctly parsed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "valkyrie.yaml")
            with open(config_file, "w") as f:
                f.write("""
                    watcher:
                      watch_path: /test/dir
                      recursive: true
                    scoring:
                      thresholds:
                        quarantine: 90
                        review: 50
                """)

            manager = ConfigManager(config_file)
            config = manager.load()

            assert config.watcher.watch_path == "/test/dir"
            assert config.watcher.recursive is True
            assert config.scoring.thresholds["quarantine"] == 90
            assert config.scoring.thresholds["review"] == 50


if __name__ == "__main__":
    pytest.main([__file__])
