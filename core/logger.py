#!/usr/bin/env python3
"""
REVUEX - Logger Module
======================

Professional logging system for bug bounty automation.

Features:
- Colored terminal output with severity levels
- File logging with rotation
- Structured JSON logging for analysis
- Scan activity tracking and audit trails
- Request/Response logging for evidence
- Performance metrics logging
- Integration with report generator

Author: REVUEX Team
License: MIT
"""

import os
import sys
import json
import logging
import traceback
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from functools import wraps
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from contextlib import contextmanager
import threading

# Optional imports
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False


# =============================================================================
# CONSTANTS
# =============================================================================

# Default log format
DEFAULT_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# JSON log format fields
JSON_FIELDS = [
    "timestamp", "level", "logger", "message",
    "scanner", "target", "finding", "request", "response"
]

# Log file settings
DEFAULT_LOG_DIR = "logs"
DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_BACKUP_COUNT = 5

# ANSI color codes (fallback if colorama not available)
COLORS = {
    "DEBUG": "\033[36m",      # Cyan
    "INFO": "\033[32m",       # Green
    "WARNING": "\033[33m",    # Yellow
    "ERROR": "\033[31m",      # Red
    "CRITICAL": "\033[35m",   # Magenta
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
}

# Severity icons for terminal
SEVERITY_ICONS = {
    "DEBUG": "[D]",
    "INFO": "[*]",
    "WARNING": "[!]",
    "ERROR": "[-]",
    "CRITICAL": "[X]",
    "SUCCESS": "[+]",
    "FINDING": "[ð¯]",
    "REQUEST": "[â]",
    "RESPONSE": "[â]",
}


# =============================================================================
# LOG LEVEL EXTENSIONS
# =============================================================================

# Custom log levels for security scanning
SUCCESS = 25  # Between INFO and WARNING
FINDING = 26  # For vulnerability findings
REQUEST = 15  # For HTTP request logging
RESPONSE = 16  # For HTTP response logging

# Register custom levels
logging.addLevelName(SUCCESS, "SUCCESS")
logging.addLevelName(FINDING, "FINDING")
logging.addLevelName(REQUEST, "REQUEST")
logging.addLevelName(RESPONSE, "RESPONSE")


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class LogEntry:
    """Structured log entry for analysis and reporting"""
    timestamp: str
    level: str
    logger: str
    message: str
    scanner: str = ""
    target: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


@dataclass
class RequestLog:
    """HTTP request log entry"""
    timestamp: str
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ResponseLog:
    """HTTP response log entry"""
    timestamp: str
    status_code: int
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0
    size_bytes: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanActivityLog:
    """Complete scan activity log for audit trails"""
    scan_id: str
    scanner_name: str
    target: str
    start_time: str
    end_time: str = ""
    status: str = "running"
    total_requests: int = 0
    findings_count: int = 0
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================================
# CUSTOM FORMATTERS
# =============================================================================

class ColoredFormatter(logging.Formatter):
    """
    Colored log formatter for terminal output.
    
    Applies colors based on log level and formats
    messages for easy scanning during bug bounty work.
    """
    
    def __init__(
        self,
        fmt: str = DEFAULT_FORMAT,
        datefmt: str = DEFAULT_DATE_FORMAT,
        use_colors: bool = True
    ):
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors and sys.stdout.isatty()
    
    def format(self, record: logging.LogRecord) -> str:
        # Save original level name
        original_levelname = record.levelname
        
        if self.use_colors:
            # Get color for level
            color = COLORS.get(record.levelname, "")
            reset = COLORS["RESET"]
            
            # Get icon
            icon = SEVERITY_ICONS.get(record.levelname, "[?]")
            
            # Apply color to level name
            record.levelname = f"{color}{icon}{reset}"
            
            # Color the message based on level
            if original_levelname == "ERROR":
                record.msg = f"{COLORS['ERROR']}{record.msg}{reset}"
            elif original_levelname == "CRITICAL":
                record.msg = f"{COLORS['BOLD']}{COLORS['CRITICAL']}{record.msg}{reset}"
            elif original_levelname == "WARNING":
                record.msg = f"{COLORS['WARNING']}{record.msg}{reset}"
            elif original_levelname == "SUCCESS":
                record.msg = f"{COLORS['INFO']}{record.msg}{reset}"
            elif original_levelname == "FINDING":
                record.msg = f"{COLORS['BOLD']}{COLORS['CRITICAL']}{record.msg}{reset}"
        else:
            icon = SEVERITY_ICONS.get(record.levelname, "[?]")
            record.levelname = f"{icon}"
        
        # Format the record
        result = super().format(record)
        
        # Restore original level name
        record.levelname = original_levelname
        
        return result


class JSONFormatter(logging.Formatter):
    """
    JSON log formatter for structured logging.
    
    Outputs logs in JSON format for easy parsing,
    analysis, and integration with log management systems.
    """
    
    def __init__(self, scanner_name: str = "", target: str = ""):
        super().__init__()
        self.scanner_name = scanner_name
        self.target = target
    
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "scanner": self.scanner_name,
            "target": self.target,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, "extra_data"):
            log_entry["extra"] = record.extra_data
        
        # Add request/response data if present
        if hasattr(record, "request_data"):
            log_entry["request"] = record.request_data
        if hasattr(record, "response_data"):
            log_entry["response"] = record.response_data
        if hasattr(record, "finding_data"):
            log_entry["finding"] = record.finding_data
        
        return json.dumps(log_entry, default=str)


class BriefFormatter(logging.Formatter):
    """
    Brief formatter for minimal output.
    
    Used for quiet mode or when minimal logging is needed.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        icon = SEVERITY_ICONS.get(record.levelname, "[?]")
        return f"{icon} {record.getMessage()}"


# =============================================================================
# CUSTOM HANDLERS
# =============================================================================

class FindingHandler(logging.Handler):
    """
    Handler that collects vulnerability findings.
    
    Stores findings in memory for later report generation.
    """
    
    def __init__(self):
        super().__init__(level=FINDING)
        self.findings: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
    
    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno == FINDING:
            with self._lock:
                finding_data = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "message": record.getMessage(),
                }
                if hasattr(record, "finding_data"):
                    finding_data.update(record.finding_data)
                self.findings.append(finding_data)
    
    def get_findings(self) -> List[Dict[str, Any]]:
        with self._lock:
            return self.findings.copy()
    
    def clear(self) -> None:
        with self._lock:
            self.findings.clear()


class RequestResponseHandler(logging.Handler):
    """
    Handler for HTTP request/response logging.
    
    Stores request/response pairs for evidence collection.
    """
    
    def __init__(self, max_entries: int = 1000):
        super().__init__()
        self.max_entries = max_entries
        self.entries: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
    
    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno in (REQUEST, RESPONSE):
            with self._lock:
                entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "request" if record.levelno == REQUEST else "response",
                    "message": record.getMessage(),
                }
                
                if hasattr(record, "request_data"):
                    entry["request"] = record.request_data
                if hasattr(record, "response_data"):
                    entry["response"] = record.response_data
                
                self.entries.append(entry)
                
                # Limit entries
                if len(self.entries) > self.max_entries:
                    self.entries = self.entries[-self.max_entries:]
    
    def get_entries(self) -> List[Dict[str, Any]]:
        with self._lock:
            return self.entries.copy()
    
    def clear(self) -> None:
        with self._lock:
            self.entries.clear()


# =============================================================================
# MAIN LOGGER CLASS
# =============================================================================

class RevuexLogger:
    """
    Main logger class for REVUEX scanners.
    
    Provides unified logging with:
    - Colored terminal output
    - File logging with rotation
    - JSON structured logging
    - Finding collection
    - Request/Response tracking
    - Scan activity audit trails
    
    Usage:
        logger = RevuexLogger(
            name="SSRFScanner",
            target="https://example.com",
            log_dir="./logs",
            verbose=True
        )
        
        logger.info("Starting scan")
        logger.finding("SSRF Detected", finding_data={...})
        logger.request("GET", url, headers={...})
        logger.success("Scan completed")
    """
    
    def __init__(
        self,
        name: str = "revuex",
        target: str = "",
        log_dir: Optional[str] = None,
        log_file: Optional[str] = None,
        level: int = logging.INFO,
        verbose: bool = False,
        quiet: bool = False,
        json_logging: bool = False,
        console_output: bool = True,
        file_output: bool = True,
        color: bool = True,
        max_bytes: int = DEFAULT_MAX_BYTES,
        backup_count: int = DEFAULT_BACKUP_COUNT,
    ):
        """
        Initialize the REVUEX logger.
        
        Args:
            name: Logger name (typically scanner name)
            target: Target being scanned
            log_dir: Directory for log files
            log_file: Specific log file name
            level: Logging level
            verbose: Enable debug output
            quiet: Suppress non-essential output
            json_logging: Use JSON format for file logs
            console_output: Enable console output
            file_output: Enable file output
            color: Enable colored output
            max_bytes: Max log file size before rotation
            backup_count: Number of backup files to keep
        """
        self.name = name
        self.target = target
        self.verbose = verbose
        self.quiet = quiet
        self.color = color and sys.stdout.isatty()
        
        # Set up log directory
        if log_dir:
            self.log_dir = Path(log_dir)
        else:
            self.log_dir = Path(DEFAULT_LOG_DIR)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create the base logger
        self.logger = logging.getLogger(f"revuex.{name}")
        self.logger.setLevel(logging.DEBUG if verbose else level)
        self.logger.handlers = []  # Clear existing handlers
        
        # Track scan activity
        self._scan_activity: Optional[ScanActivityLog] = None
        self._request_count = 0
        self._finding_count = 0
        
        # Custom handlers
        self._finding_handler = FindingHandler()
        self._request_handler = RequestResponseHandler()
        
        # Set up handlers
        if console_output and not quiet:
            self._setup_console_handler(verbose)
        
        if file_output:
            self._setup_file_handler(
                log_file, json_logging, max_bytes, backup_count
            )
        
        # Add custom handlers
        self.logger.addHandler(self._finding_handler)
        self.logger.addHandler(self._request_handler)
    
    def _setup_console_handler(self, verbose: bool) -> None:
        """Set up console output handler"""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        
        if self.quiet:
            formatter = BriefFormatter()
        else:
            formatter = ColoredFormatter(use_colors=self.color)
        
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
    
    def _setup_file_handler(
        self,
        log_file: Optional[str],
        json_logging: bool,
        max_bytes: int,
        backup_count: int
    ) -> None:
        """Set up file output handler"""
        if log_file:
            file_path = self.log_dir / log_file
        else:
            timestamp = datetime.now().strftime("%Y%m%d")
            extension = "json" if json_logging else "log"
            file_path = self.log_dir / f"{self.name}_{timestamp}.{extension}"
        
        file_handler = RotatingFileHandler(
            file_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        
        if json_logging:
            formatter = JSONFormatter(self.name, self.target)
        else:
            formatter = logging.Formatter(DEFAULT_FORMAT, DEFAULT_DATE_FORMAT)
        
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
    
    # =========================================================================
    # STANDARD LOGGING METHODS
    # =========================================================================
    
    def debug(self, message: str, **kwargs) -> None:
        """Log debug message"""
        self._log(logging.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs) -> None:
        """Log info message"""
        self._log(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        """Log warning message"""
        self._log(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        """Log error message"""
        self._log(logging.ERROR, message, **kwargs)
        if self._scan_activity:
            self._scan_activity.errors.append(message)
    
    def critical(self, message: str, **kwargs) -> None:
        """Log critical message"""
        self._log(logging.CRITICAL, message, **kwargs)
        if self._scan_activity:
            self._scan_activity.errors.append(f"CRITICAL: {message}")
    
    def exception(self, message: str, **kwargs) -> None:
        """Log exception with traceback"""
        self.logger.exception(message, **kwargs)
    
    # =========================================================================
    # CUSTOM LOGGING METHODS (BUG BOUNTY SPECIFIC)
    # =========================================================================
    
    def success(self, message: str, **kwargs) -> None:
        """Log success message"""
        self._log(SUCCESS, message, **kwargs)
    
    def finding(
        self,
        message: str,
        severity: str = "info",
        url: str = "",
        parameter: str = "",
        payload: str = "",
        evidence: str = "",
        **kwargs
    ) -> None:
        """
        Log a vulnerability finding.
        
        Args:
            message: Finding description
            severity: Severity level (critical, high, medium, low, info)
            url: Affected URL
            parameter: Vulnerable parameter
            payload: Payload that triggered the finding
            evidence: Evidence/proof
        """
        finding_data = {
            "severity": severity,
            "url": url,
            "parameter": parameter,
            "payload": payload,
            "evidence": evidence[:500] if evidence else "",
            **kwargs
        }
        
        # Format message with severity
        formatted_msg = f"[{severity.upper()}] {message}"
        if url:
            formatted_msg += f" @ {url}"
        
        record = self.logger.makeRecord(
            self.logger.name,
            FINDING,
            "(finding)",
            0,
            formatted_msg,
            (),
            None
        )
        record.finding_data = finding_data
        self.logger.handle(record)
        
        self._finding_count += 1
        if self._scan_activity:
            self._scan_activity.findings_count = self._finding_count
    
    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        params: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log an HTTP request.
        
        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            body: Request body
            params: Query parameters
        """
        request_data = RequestLog(
            timestamp=datetime.now(timezone.utc).isoformat(),
            method=method,
            url=url,
            headers=headers or {},
            body=body[:1000] if body else "",
            params=params or {}
        ).to_dict()
        
        message = f"{method} {url}"
        
        record = self.logger.makeRecord(
            self.logger.name,
            REQUEST,
            "(request)",
            0,
            message,
            (),
            None
        )
        record.request_data = request_data
        self.logger.handle(record)
        
        self._request_count += 1
        if self._scan_activity:
            self._scan_activity.total_requests = self._request_count
    
    def response(
        self,
        status_code: int,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        elapsed_ms: float = 0.0,
        size_bytes: int = 0
    ) -> None:
        """
        Log an HTTP response.
        
        Args:
            status_code: HTTP status code
            url: Response URL
            headers: Response headers
            body: Response body (truncated)
            elapsed_ms: Request duration in milliseconds
            size_bytes: Response size
        """
        response_data = ResponseLog(
            timestamp=datetime.now(timezone.utc).isoformat(),
            status_code=status_code,
            url=url,
            headers=headers or {},
            body=body[:1000] if body else "",
            elapsed_ms=elapsed_ms,
            size_bytes=size_bytes
        ).to_dict()
        
        message = f"{status_code} {url} ({elapsed_ms:.0f}ms, {size_bytes} bytes)"
        
        record = self.logger.makeRecord(
            self.logger.name,
            RESPONSE,
            "(response)",
            0,
            message,
            (),
            None
        )
        record.response_data = response_data
        self.logger.handle(record)
    
    def banner(self, text: str) -> None:
        """Log a banner/header message"""
        if not self.quiet:
            border = "=" * 60
            self.info(border)
            self.info(text.center(60))
            self.info(border)
    
    def section(self, title: str) -> None:
        """Log a section header"""
        if not self.quiet:
            self.info(f"\n{'â' * 40}")
            self.info(f"  {title}")
            self.info(f"{'â' * 40}")
    
    def progress(self, current: int, total: int, message: str = "") -> None:
        """Log progress update"""
        percentage = (current / total * 100) if total > 0 else 0
        bar_length = 30
        filled = int(bar_length * current / total) if total > 0 else 0
        bar = "â" * filled + "â" * (bar_length - filled)
        
        msg = f"[{bar}] {percentage:.1f}% ({current}/{total})"
        if message:
            msg += f" - {message}"
        
        # Use carriage return for in-place update
        if sys.stdout.isatty():
            print(f"\r{msg}", end="", flush=True)
            if current >= total:
                print()  # New line when complete
        else:
            self.info(msg)
    
    def table(self, headers: List[str], rows: List[List[Any]]) -> None:
        """Log data as a formatted table"""
        if self.quiet:
            return
        
        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Format header
        header_line = " | ".join(
            h.ljust(col_widths[i]) for i, h in enumerate(headers)
        )
        separator = "-+-".join("-" * w for w in col_widths)
        
        self.info(header_line)
        self.info(separator)
        
        # Format rows
        for row in rows:
            row_line = " | ".join(
                str(cell).ljust(col_widths[i]) for i, cell in enumerate(row)
            )
            self.info(row_line)
    
    # =========================================================================
    # SCAN ACTIVITY TRACKING
    # =========================================================================
    
    def start_scan(self, scan_id: str, target: str) -> None:
        """Start tracking a scan activity"""
        self._scan_activity = ScanActivityLog(
            scan_id=scan_id,
            scanner_name=self.name,
            target=target,
            start_time=datetime.now(timezone.utc).isoformat(),
            status="running"
        )
        self._request_count = 0
        self._finding_count = 0
        
        self.banner(f"{self.name} - Scan Started")
        self.info(f"Scan ID: {scan_id}")
        self.info(f"Target: {target}")
    
    def end_scan(self, status: str = "completed") -> Optional[ScanActivityLog]:
        """End scan tracking and return activity log"""
        if self._scan_activity:
            self._scan_activity.end_time = datetime.now(timezone.utc).isoformat()
            self._scan_activity.status = status
            self._scan_activity.total_requests = self._request_count
            self._scan_activity.findings_count = self._finding_count
            
            self.section("Scan Summary")
            self.info(f"Status: {status}")
            self.info(f"Total Requests: {self._request_count}")
            self.info(f"Findings: {self._finding_count}")
            if self._scan_activity.errors:
                self.warning(f"Errors: {len(self._scan_activity.errors)}")
            
            return self._scan_activity
        return None
    
    def get_scan_activity(self) -> Optional[ScanActivityLog]:
        """Get current scan activity"""
        return self._scan_activity
    
    # =========================================================================
    # DATA RETRIEVAL
    # =========================================================================
    
    def get_findings(self) -> List[Dict[str, Any]]:
        """Get all logged findings"""
        return self._finding_handler.get_findings()
    
    def get_requests(self) -> List[Dict[str, Any]]:
        """Get all logged requests/responses"""
        return self._request_handler.get_entries()
    
    def clear_findings(self) -> None:
        """Clear logged findings"""
        self._finding_handler.clear()
        self._finding_count = 0
    
    def clear_requests(self) -> None:
        """Clear logged requests"""
        self._request_handler.clear()
        self._request_count = 0
    
    # =========================================================================
    # EXPORT METHODS
    # =========================================================================
    
    def export_findings_json(self, filepath: str) -> None:
        """Export findings to JSON file"""
        findings = self.get_findings()
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2, default=str)
        self.info(f"Findings exported to {filepath}")
    
    def export_activity_json(self, filepath: str) -> None:
        """Export scan activity to JSON file"""
        if self._scan_activity:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self._scan_activity.to_dict(), f, indent=2, default=str)
            self.info(f"Activity log exported to {filepath}")
    
    def export_requests_json(self, filepath: str) -> None:
        """Export requests/responses to JSON file"""
        entries = self.get_requests()
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2, default=str)
        self.info(f"Request log exported to {filepath}")
    
    # =========================================================================
    # INTERNAL METHODS
    # =========================================================================
    
    def _log(self, level: int, message: str, **kwargs) -> None:
        """Internal log method"""
        extra_data = kwargs.pop("extra", None)
        
        if extra_data:
            record = self.logger.makeRecord(
                self.logger.name,
                level,
                "(log)",
                0,
                message,
                (),
                None
            )
            record.extra_data = extra_data
            self.logger.handle(record)
        else:
            self.logger.log(level, message, **kwargs)
    
    # =========================================================================
    # CONTEXT MANAGERS
    # =========================================================================
    
    @contextmanager
    def scan_context(self, scan_id: str, target: str):
        """
        Context manager for scan lifecycle.
        
        Usage:
            with logger.scan_context("scan123", "https://example.com") as log:
                log.info("Scanning...")
                # ... scan logic ...
        """
        self.start_scan(scan_id, target)
        try:
            yield self
            self.end_scan("completed")
        except KeyboardInterrupt:
            self.end_scan("cancelled")
            raise
        except Exception as e:
            self.error(f"Scan failed: {str(e)}")
            self.end_scan("failed")
            raise
    
    @contextmanager
    def timed_operation(self, operation_name: str):
        """
        Context manager for timing operations.
        
        Usage:
            with logger.timed_operation("URL enumeration"):
                # ... operation ...
        """
        start_time = datetime.now()
        self.debug(f"Starting: {operation_name}")
        
        try:
            yield
        finally:
            elapsed = (datetime.now() - start_time).total_seconds()
            self.debug(f"Completed: {operation_name} ({elapsed:.2f}s)")


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def get_logger(
    name: str = "revuex",
    target: str = "",
    verbose: bool = False,
    quiet: bool = False,
    **kwargs
) -> RevuexLogger:
    """
    Get or create a REVUEX logger.
    
    Args:
        name: Logger name
        target: Target being scanned
        verbose: Enable debug output
        quiet: Suppress non-essential output
        **kwargs: Additional arguments for RevuexLogger
    
    Returns:
        RevuexLogger instance
    """
    return RevuexLogger(
        name=name,
        target=target,
        verbose=verbose,
        quiet=quiet,
        **kwargs
    )


def configure_logging(
    level: int = logging.INFO,
    log_dir: str = DEFAULT_LOG_DIR,
    json_logging: bool = False
) -> None:
    """
    Configure global logging settings.
    
    Args:
        level: Global logging level
        log_dir: Directory for log files
        json_logging: Enable JSON format
    """
    # Create log directory
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger("revuex")
    root_logger.setLevel(level)
    
    # Add console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(ColoredFormatter())
    root_logger.addHandler(console)


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Main class
    "RevuexLogger",
    
    # Data classes
    "LogEntry",
    "RequestLog",
    "ResponseLog",
    "ScanActivityLog",
    
    # Formatters
    "ColoredFormatter",
    "JSONFormatter",
    "BriefFormatter",
    
    # Handlers
    "FindingHandler",
    "RequestResponseHandler",
    
    # Functions
    "get_logger",
    "configure_logging",
    
    # Constants
    "SUCCESS",
    "FINDING",
    "REQUEST",
    "RESPONSE",
    "SEVERITY_ICONS",
    "DEFAULT_LOG_DIR",
]
