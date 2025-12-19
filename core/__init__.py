#!/usr/bin/env python3
"""
REVUEX Core Module
==================

Shared infrastructure for all REVUEX security scanners.

This module provides:
- BaseScanner: Abstract base class for all scanners
- Finding: Data class for vulnerability findings
- ScanResult: Container for scan results and statistics
- RateLimiter: Token bucket rate limiter
- Logging and reporting utilities
- Safety validation helpers

Usage:
    from revuex.core import BaseScanner, Finding, Severity
    
    class MyScanner(BaseScanner):
        def scan(self):
            # Implementation
            pass
        
        def _validate_target(self):
            return True

Author: REVUEX Team
License: MIT
"""

from .base_scanner import (
    # Core classes
    BaseScanner,
    Finding,
    ScanResult,
    RateLimiter,
    
    # Enums
    Severity,
    ScanStatus,
    RequestMethod,
    
    # Constants
    REVUEX_VERSION,
    REVUEX_BANNER,
    DEFAULT_CONFIG,
    USER_AGENTS,
    
    # Utility functions
    get_scanner_info,
    print_disclaimer,
)

from .safety_checks import (
    # Main classes
    SafetyManager,
    ScopeValidator,
    PayloadValidator,
    RequestValidator,
    DNSRebindingProtector,
    
    # Data classes
    ScopeDefinition,
    SafetyCheckResult,
    
    # Enums
    SafetyLevel,
    ValidationResult,
    
    # Utility functions
    is_private_ip,
    is_cloud_metadata,
    extract_base_domain,
    create_default_scope,
    
    # Constants
    PRIVATE_IP_RANGES,
    CLOUD_METADATA_ENDPOINTS,
    DANGEROUS_PORTS,
    SENSITIVE_PATHS,
)

from .utils import (
    # URL utilities
    normalize_url,
    parse_url,
    build_url,
    extract_domain,
    extract_base_url,
    extract_parameters,
    inject_parameter,
    is_same_origin,
    
    # Encoding utilities
    url_encode,
    url_decode,
    base64_encode,
    base64_decode,
    html_encode,
    html_decode,
    to_json,
    from_json,
    
    # Hashing utilities
    md5,
    sha1,
    sha256,
    generate_hash_id,
    
    # String utilities
    random_string,
    random_hex,
    truncate,
    clean_string,
    extract_between,
    similarity_ratio,
    
    # Data extraction
    extract_emails,
    extract_urls,
    extract_ips,
    extract_secrets,
    PATTERNS,
    
    # File utilities
    read_file,
    write_file,
    read_json_file,
    write_json_file,
    ensure_dir,
    file_exists,
    
    # Network utilities
    is_valid_ip,
    resolve_hostname,
    is_success_status,
    is_error_status,
    
    # Time utilities
    get_timestamp,
    format_duration,
    sleep_with_jitter,
    
    # Color/formatting
    Colors,
    print_success,
    print_error,
    print_warning,
    print_info,
    
    # Decorators
    retry,
    memoize,
    timed,
)

# Will be populated as we create more core modules
# from .intelligence_hub import IntelligenceHub

from .logger import (
    RevuexLogger,
    LogEntry,
    RequestLog,
    ResponseLog,
    ScanActivityLog,
    ColoredFormatter,
    JSONFormatter,
    get_logger,
    configure_logging,
    SUCCESS,
    FINDING,
    REQUEST,
    RESPONSE,
)

from .report_generator import (
    ReportGenerator,
    ReportMetadata,
    FindingReport,
    ScanStatistics,
    create_report,
    SEVERITY_COLORS,
    OWASP_TOP_10,
    VULN_CLASSIFICATION,
)

__version__ = REVUEX_VERSION
__author__ = "REVUEX Team"

__all__ = [
    # === base_scanner.py ===
    # Core classes
    "BaseScanner",
    "Finding",
    "ScanResult",
    "RateLimiter",
    # Enums
    "Severity",
    "ScanStatus",
    "RequestMethod",
    # Constants
    "REVUEX_VERSION",
    "REVUEX_BANNER",
    "DEFAULT_CONFIG",
    "USER_AGENTS",
    # Utility functions
    "get_scanner_info",
    "print_disclaimer",
    
    # === safety_checks.py ===
    # Main classes
    "SafetyManager",
    "ScopeValidator",
    "PayloadValidator",
    "RequestValidator",
    "DNSRebindingProtector",
    # Data classes
    "ScopeDefinition",
    "SafetyCheckResult",
    # Enums
    "SafetyLevel",
    "ValidationResult",
    # Utility functions
    "is_private_ip",
    "is_cloud_metadata",
    "extract_base_domain",
    "create_default_scope",
    # Constants
    "PRIVATE_IP_RANGES",
    "CLOUD_METADATA_ENDPOINTS",
    "DANGEROUS_PORTS",
    "SENSITIVE_PATHS",
    
    # === utils.py ===
    # URL utilities
    "normalize_url",
    "parse_url",
    "build_url",
    "extract_domain",
    "extract_base_url",
    "extract_parameters",
    "inject_parameter",
    "is_same_origin",
    # Encoding utilities
    "url_encode",
    "url_decode",
    "base64_encode",
    "base64_decode",
    "html_encode",
    "html_decode",
    "to_json",
    "from_json",
    # Hashing utilities
    "md5",
    "sha1",
    "sha256",
    "generate_hash_id",
    # String utilities
    "random_string",
    "random_hex",
    "truncate",
    "clean_string",
    "extract_between",
    "similarity_ratio",
    # Data extraction
    "extract_emails",
    "extract_urls",
    "extract_ips",
    "extract_secrets",
    "PATTERNS",
    # File utilities
    "read_file",
    "write_file",
    "read_json_file",
    "write_json_file",
    "ensure_dir",
    "file_exists",
    # Network utilities
    "is_valid_ip",
    "resolve_hostname",
    "is_success_status",
    "is_error_status",
    # Time utilities
    "get_timestamp",
    "format_duration",
    "sleep_with_jitter",
    # Color/formatting
    "Colors",
    "print_success",
    "print_error",
    "print_warning",
    "print_info",
    # Decorators
    "retry",
    "memoize",
    "timed",
    
    # === logger.py ===
    "RevuexLogger",
    "LogEntry",
    "RequestLog",
    "ResponseLog",
    "ScanActivityLog",
    "ColoredFormatter",
    "JSONFormatter",
    "get_logger",
    "configure_logging",
    "SUCCESS",
    "FINDING",
    "REQUEST",
    "RESPONSE",
    
    # === report_generator.py ===
    "ReportGenerator",
    "ReportMetadata",
    "FindingReport",
    "ScanStatistics",
    "create_report",
    "SEVERITY_COLORS",
    "OWASP_TOP_10",
    "VULN_CLASSIFICATION",
]
