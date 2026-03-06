"""Shared logging configuration utilities.

Provides a unified, project-wide logging setup to avoid duplicated boilerplate.

Usage:
    from src.utils.logger import setup_logger

    logger = setup_logger(__name__)
    logger.info("Info message")
    logger.warning("Warning message")
    logger.error("Error message")
    logger.debug("Debug message")
"""
import logging
import sys
from pathlib import Path
from typing import Optional


# Default log format.
DEFAULT_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Global log level (may be overridden by CLI arguments).
_GLOBAL_LOG_LEVEL = logging.INFO


def setup_logger(
    name: str,
    level: int = logging.INFO,
    log_format: Optional[str] = None,
    log_file: Optional[str] = None,
    file_level: Optional[int] = None
) -> logging.Logger:
    """
    Configure and return a logger.

    Args:
        name: Logger name, typically use __name__.
        level: Console log level (default: INFO).
        log_format: Log format (default: DEFAULT_FORMAT).
        log_file: Optional log file path.
        file_level: File log level (defaults to the same as level).

    Returns:
        A configured logging.Logger instance.

    Example:
        >>> logger = setup_logger(__name__)
        >>> logger.info("This is an info message")
        >>> 
        >>> # Also write to a file
        >>> logger = setup_logger(__name__, log_file="app.log", file_level=logging.DEBUG)
    """
    logger = logging.getLogger(name)
    
    # If handlers are already configured, return directly (avoid duplicate setup).
    if logger.handlers:
        return logger
    
    logger.setLevel(logging.DEBUG)  # Keep logger at lowest level; handlers control actual output.
    
    # Use provided format or fall back to default.
    formatter = logging.Formatter(
        log_format or DEFAULT_FORMAT,
        datefmt=DATE_FORMAT
    )
    
    # Console handler.
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (optional).
    if log_file:
        # Ensure the log directory exists.
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(file_level or level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Prevent log propagation to the root logger (avoid duplicate output).
    logger.propagate = False
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get an existing logger; create one with default configuration if missing.

    Args:
        name: Logger name.

    Returns:
        A logging.Logger instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        return setup_logger(name, level=_GLOBAL_LOG_LEVEL)
    return logger


def set_log_level(logger: logging.Logger, level: int):
    """
    Set a logger's log level (also updates all handlers).

    Args:
        logger: Logger instance.
        level: Log level (logging.DEBUG/INFO/WARNING/ERROR/CRITICAL).
    """
    logger.setLevel(level)
    for handler in logger.handlers:
        handler.setLevel(level)


def set_global_log_level(level: int):
    """
    Set the global log level; affects loggers created afterwards.

    Args:
        level: Log level (logging.DEBUG/INFO/WARNING/ERROR/CRITICAL).
    """
    global _GLOBAL_LOG_LEVEL
    _GLOBAL_LOG_LEVEL = level
    
    # Also update all existing loggers.
    for name in logging.Logger.manager.loggerDict:
        logger = logging.getLogger(name)
        if logger.handlers:  # Only update configured loggers.
            set_log_level(logger, level)
