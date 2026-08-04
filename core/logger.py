"""
CyberMint Logging System
"""
import logging
import os
from pathlib import Path
from datetime import datetime

LOG_DIR = Path("database/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / f"cybermint_{datetime.now().strftime('%Y%m%d')}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
    ]
)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"CyberMint.{name}")
