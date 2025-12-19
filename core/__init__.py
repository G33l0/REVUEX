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

# Will be populated as we create more core modules
# from .safety_checks import SafetyValidator
# from .logger import RevuexLogger
# from .intelligence_hub import IntelligenceHub
# from .report_generator import ReportGenerator
# from .utils import *

__version__ = REVUEX_VERSION
__author__ = "REVUEX Team"

__all__ = [
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
]
