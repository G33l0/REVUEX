#!/usr/bin/env python3
"""
REVUEX SQLi Scanner
===================

Enhanced SQL Injection vulnerability scanner.

Usage:
    from tools.sqli import SQLiScanner
    
    scanner = SQLiScanner(target="https://example.com/search?q=test")
    result = scanner.run()

CLI:
    python -m tools.sqli -t https://example.com/search?q=test
    revuex-sqli -t https://example.com/search?q=test

Author: REVUEX Team
License: MIT
"""

from .enhanced_sqli_scanner import SQLiScanner, main

__all__ = ["SQLiScanner", "main"]
__version__ = "1.0.0"