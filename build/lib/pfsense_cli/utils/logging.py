"""
Structured logging configuration for pfSense CLI tool.
"""

import logging
import logging.handlers
import json
import sys
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime


class StructuredFormatter(logging.Formatter):
    """Custom formatter that outputs structured JSON logs."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add extra fields if present
        if hasattr(record, 'client_name'):
            log_entry['client_name'] = record.client_name
        
        if hasattr(record, 'operation'):
            log_entry['operation'] = record.operation
        
        if hasattr(record, 'duration'):
            log_entry['duration_ms'] = record.duration
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry, default=str)


class ColoredFormatter(logging.Formatter):
    """Colored console formatter for better readability."""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'ENDC': '\033[0m'       # End color
    }
    
    def format(self, record: logging.LogRecord) -> str:
        level_color = self.COLORS.get(record.levelname, '')
        end_color = self.COLORS['ENDC']
        
        # Format timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        
        # Format the message with colors
        formatted = f"{level_color}[{timestamp}] {record.levelname:8}{end_color} "
        formatted += f"{record.name}: {record.getMessage()}"
        
        # Add client context if available
        if hasattr(record, 'client_name'):
            formatted += f" (client: {record.client_name})"
        
        # Add exception info if present
        if record.exc_info:
            formatted += "\n" + self.formatException(record.exc_info)
        
        return formatted


def setup_logging(
    level: str = 'INFO',
    log_file: Optional[str] = None,
    console_output: bool = True,
    structured_logs: bool = False
) -> logging.Logger:
    """
    Setup comprehensive logging for the pfSense CLI tool.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (optional)
        console_output: Whether to output to console
        structured_logs: Whether to use structured JSON logs in file
    
    Returns:
        Configured logger instance
    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create root logger
    logger = logging.getLogger('pfsense_cli')
    logger.setLevel(numeric_level)
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)
        
        if sys.stdout.isatty():  # Use colors if terminal supports it
            console_formatter = ColoredFormatter()
        else:
            console_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Rotating file handler to prevent huge log files
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(numeric_level)
        
        if structured_logs:
            file_formatter = StructuredFormatter()
        else:
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
        
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    # Set levels for noisy libraries
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('aiohttp').setLevel(logging.WARNING)
    
    return logger


class LogContext:
    """Context manager for adding contextual information to log records."""
    
    def __init__(self, logger: logging.Logger, **context):
        self.logger = logger
        self.context = context
        self.old_factory = logging.getLogRecordFactory()
    
    def __enter__(self):
        def record_factory(*args, **kwargs):
            record = self.old_factory(*args, **kwargs)
            for key, value in self.context.items():
                setattr(record, key, value)
            return record
        
        logging.setLogRecordFactory(record_factory)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        logging.setLogRecordFactory(self.old_factory)


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the given name under the pfsense_cli namespace."""
    return logging.getLogger(f'pfsense_cli.{name}')


# Performance logging decorator
import functools
import time

def log_performance(logger: logging.Logger = None, operation: str = None):
    """
    Decorator to log function execution time.
    
    Args:
        logger: Logger instance to use
        operation: Operation name for logging context
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal logger, operation
            
            if logger is None:
                logger = get_logger(func.__module__)
            
            if operation is None:
                operation = func.__name__
            
            start_time = time.time()
            
            try:
                with LogContext(logger, operation=operation):
                    result = func(*args, **kwargs)
                    duration_ms = (time.time() - start_time) * 1000
                    
                    logger.info(f"Operation '{operation}' completed successfully", 
                               extra={'duration': duration_ms})
                    return result
                    
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                logger.error(f"Operation '{operation}' failed: {e}", 
                           extra={'duration': duration_ms})
                raise
        
        return wrapper
    return decorator


# Async version of performance logging decorator
import asyncio

def log_async_performance(logger: logging.Logger = None, operation: str = None):
    """
    Decorator to log async function execution time.
    
    Args:
        logger: Logger instance to use
        operation: Operation name for logging context
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            nonlocal logger, operation
            
            if logger is None:
                logger = get_logger(func.__module__)
            
            if operation is None:
                operation = func.__name__
            
            start_time = time.time()
            
            try:
                with LogContext(logger, operation=operation):
                    result = await func(*args, **kwargs)
                    duration_ms = (time.time() - start_time) * 1000
                    
                    logger.info(f"Async operation '{operation}' completed successfully", 
                               extra={'duration': duration_ms})
                    return result
                    
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                logger.error(f"Async operation '{operation}' failed: {e}", 
                           extra={'duration': duration_ms})
                raise
        
        return wrapper
    return decorator