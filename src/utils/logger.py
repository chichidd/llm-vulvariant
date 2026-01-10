"""
统一的日志配置工具

提供项目范围内的统一日志配置，避免重复代码。
使用方式:
    from src.utils.logger import setup_logger
    
    logger = setup_logger(__name__)
    logger.info("信息日志")
    logger.warning("警告日志")
    logger.error("错误日志")
    logger.debug("调试日志")
"""
import logging
import sys
from pathlib import Path
from typing import Optional


# 默认日志格式
DEFAULT_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


def setup_logger(
    name: str,
    level: int = logging.INFO,
    log_format: Optional[str] = None,
    log_file: Optional[str] = None,
    file_level: Optional[int] = None
) -> logging.Logger:
    """
    设置并返回一个配置好的 logger
    
    Args:
        name: logger 名称，通常使用 __name__
        level: 控制台日志级别（默认 INFO）
        log_format: 日志格式（默认使用 DEFAULT_FORMAT）
        log_file: 可选的日志文件路径
        file_level: 文件日志级别（默认与 level 相同）
    
    Returns:
        配置好的 logging.Logger 对象
    
    Example:
        >>> logger = setup_logger(__name__)
        >>> logger.info("This is an info message")
        >>> 
        >>> # 同时输出到文件
        >>> logger = setup_logger(__name__, log_file="app.log", file_level=logging.DEBUG)
    """
    logger = logging.getLogger(name)
    
    # 如果已经配置过处理器，直接返回（避免重复配置）
    if logger.handlers:
        return logger
    
    logger.setLevel(logging.DEBUG)  # Logger 自身设置为最低级别，由 Handler 控制
    
    # 使用指定格式或默认格式
    formatter = logging.Formatter(
        log_format or DEFAULT_FORMAT,
        datefmt=DATE_FORMAT
    )
    
    # 控制台处理器
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 文件处理器（如果指定）
    if log_file:
        # 确保日志目录存在
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(file_level or level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # 防止日志传播到根 logger（避免重复输出）
    logger.propagate = False
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    获取已存在的 logger，如果不存在则创建默认配置的 logger
    
    Args:
        name: logger 名称
    
    Returns:
        logging.Logger 对象
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        return setup_logger(name)
    return logger


def set_log_level(logger: logging.Logger, level: int):
    """
    设置 logger 的日志级别（同时设置所有处理器）
    
    Args:
        logger: Logger 对象
        level: 日志级别（logging.DEBUG/INFO/WARNING/ERROR/CRITICAL）
    """
    logger.setLevel(level)
    for handler in logger.handlers:
        handler.setLevel(level)


# 为方便使用，提供一个默认的 logger
default_logger = setup_logger('vulvariant')
