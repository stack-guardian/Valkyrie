"""
Logging infrastructure for Valkyrie file security scanner.

This module provides structured logging with rotation, multiple log levels,
and component-based logging.
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional


class ValkyrieLogger:
    """
    Centralized logging configuration for Valkyrie.

    Provides component-based logging with rotation and structured formatting.
    """

    def __init__(self, name: str = "valkyrie"):
        """
        Initialize logger.

        Args:
            name: Base logger name.
        """
        self.name = name
        self.loggers: dict[str, logging.Logger] = {}

    def setup_logging(
        self,
        log_level: str = "INFO",
        log_file: Optional[str] = None,
        max_size_mb: int = 10,
        backup_count: int = 10,
        format_string: Optional[str] = None
    ) -> None:
        """
        Configure logging for all components.

        Args:
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Path to log file (optional, logs to console if None)
            max_size_mb: Maximum log file size before rotation
            backup_count: Number of backup log files to keep
            format_string: Custom log format string
        """
        # Create logs directory if needed
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

        # Set up root logger
        root_logger = logging.getLogger(self.name)
        root_logger.setLevel(getattr(logging, log_level.upper()))

        # Clear existing handlers
        root_logger.handlers.clear()

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, log_level.upper()))
        console_handler.setFormatter(
            logging.Formatter(format_string or "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        root_logger.addHandler(console_handler)

        # File handler with rotation
        if log_file:
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_size_mb * 1024 * 1024,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(getattr(logging, log_level.upper()))
            file_handler.setFormatter(
                logging.Formatter(
                    format_string or "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                )
            )
            root_logger.addHandler(file_handler)

    def get_logger(self, component: str) -> logging.Logger:
        """
        Get a logger for a specific component.

        Args:
            component: Component name (e.g., 'watcher', 'analysis', 'dashboard')

        Returns:
            Configured logger instance.
        """
        logger_name = f"{self.name}.{component}"
        return logging.getLogger(logger_name)


# Global logging instance
_logging_manager: Optional[ValkyrieLogger] = None


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    max_size_mb: int = 10,
    backup_count: int = 10,
    format_string: Optional[str] = None
) -> None:
    """
    Set up global logging configuration.

    Args:
        log_level: Logging level
        log_file: Path to log file
        max_size_mb: Maximum size per log file
        backup_count: Number of backup files
        format_string: Custom format string
    """
    global _logging_manager
    if _logging_manager is None:
        _logging_manager = ValkyrieLogger()

    _logging_manager.setup_logging(log_level, log_file, max_size_mb, backup_count, format_string)


def get_logger(component: str) -> logging.Logger:
    """
    Get a logger for a specific component.

    Args:
        component: Component name

    Returns:
        Logger instance.
    """
    global _logging_manager
    if _logging_manager is None:
        _logging_manager = ValkyrieLogger()
        _logging_manager.setup_logging()

    return _logging_manager.get_logger(component)


class LoggingContext:
    """
    Context manager for adding contextual information to log messages.
    """

    def __init__(self, logger: logging.Logger, **context):
        """
        Initialize context manager.

        Args:
            logger: Logger instance
            context: Context key-value pairs
        """
        self.logger = logger
        self.context = context
        self.old_factory = None

    def __enter__(self):
        """Enter context and set custom formatter."""
        self.old_factory = logging.getLogRecordFactory()

        def record_factory(*args, **kwargs):
            record = self.old_factory(*args, **kwargs)
            for key, value in self.context.items():
                setattr(record, key, value)
            return record

        logging.setLogRecordFactory(record_factory)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context and restore original factory."""
        logging.setLogRecordFactory(self.old_factory)


def log_function_call(func):
    """
    Decorator to log function entry and exit.

    Args:
        func: Function to decorate

    Returns:
        Decorated function.
    """
    import functools
    import traceback

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        logger.debug(f"Entering {func.__name__}")
        try:
            result = func(*args, **kwargs)
            logger.debug(f"Exiting {func.__name__}")
            return result
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {e}")
            logger.debug(traceback.format_exc())
            raise

    return wrapper
