#!/usr/bin/env python3
"""
REVUEX XSS Scanner
==================

Research-Grade XSS Detection Engine for Bug Bounty Professionals.

Usage:
    from tools.xss import XSSScanner
    
    scanner = XSSScanner(target="https://example.com/search?q=test")
    result = scanner.run()

CLI:
    python -m tools.xss -t https://example.com/search?q=test
    revuex-xss -t https://example.com/search?q=test

Author: REVUEX Team
License: MIT
"""

from .enhanced_xss_scanner import XSSScanner, main

__all__ = ["XSSScanner", "main"]
__version__ = "3.5.0"
