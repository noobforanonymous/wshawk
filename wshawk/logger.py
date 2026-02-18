#!/usr/bin/env python3
"""
WSHawk Logging Configuration
Centralized logging with colors and vulnerability reporting

Author: Regaan (@noobforanonymous)
"""

import logging
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

# Custom log levels
VULN_LEVEL = 35
SUCCESS_LEVEL = 25
logging.addLevelName(VULN_LEVEL, "VULN")
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")

class WSHawkFormatter(logging.Formatter):
    """Custom formatter with WSHawk-style symbols and colors."""
    
    FORMATS = {
        logging.DEBUG: f"{Colors.CYAN}[DEBUG]{Colors.END} %(message)s",
        logging.INFO: f"{Colors.BLUE}[*]{Colors.END} %(message)s",
        SUCCESS_LEVEL: f"{Colors.GREEN}[+]{Colors.END} %(message)s",
        logging.WARNING: f"{Colors.YELLOW}[!]{Colors.END} %(message)s",
        logging.ERROR: f"{Colors.RED}[-]{Colors.END} %(message)s",
        logging.CRITICAL: f"{Colors.RED}{Colors.BOLD}[CRITICAL]{Colors.END} %(message)s",
        VULN_LEVEL: f"{Colors.RED}{Colors.BOLD}[VULN]{Colors.END} %(message)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, "%(message)s")
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

def setup_logging(verbose: bool = False, log_file: Optional[str] = None):
    """
    Setup logging configuration
    
    Args:
        verbose: Enable debug logging
        log_file: Optional file path for logging
    """
    level = logging.DEBUG if verbose else logging.INFO
    
    # Root logger
    root_logger = logging.getLogger('wshawk')
    root_logger.setLevel(logging.DEBUG) # Allow handlers to filter
    
    # Clear existing handlers
    if root_logger.handlers:
        root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(WSHawkFormatter())
    root_logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        root_logger.addHandler(file_handler)
    else:
        # Default log file in ~/.wshawk/logs/
        try:
            default_log_dir = Path.home() / ".wshawk" / "logs"
            default_log_dir.mkdir(parents=True, exist_ok=True)
            default_log_file = default_log_dir / f"wshawk_{datetime.now().strftime('%Y%m%d')}.log"
            
            file_handler = logging.FileHandler(str(default_log_file))
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(
                logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            )
            root_logger.addHandler(file_handler)
        except Exception:
            pass # Silently fail if we can't write to home dir
    
    return root_logger

def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a logger for a specific module"""
    if name:
        return logging.getLogger(f'wshawk.{name}')
    return logging.getLogger('wshawk')

def log_vuln(msg: str):
    """Global helper to log vulnerabilities."""
    get_logger().log(VULN_LEVEL, msg)
