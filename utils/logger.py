# ============================================================
# 模块: 日志工具 (logger.py)
# 功能: 统一的日志配置
# ============================================================

import logging
import sys
from pathlib import Path


def setup_logger(name: str = 'NADS',
                 level: str = 'INFO',
                 log_dir: str = './logs',
                 log_file: str = 'ids.log') -> logging.Logger:
    """配置并返回日志器"""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # 格式化器
    formatter = logging.Formatter(
        fmt='%(asctime)s [%(levelname)-7s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # 控制台输出
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 文件输出
    log_path = Path(log_dir) / log_file
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_path), encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        logger.warning(f"无法创建日志文件 {log_path}: {e}")

    return logger
