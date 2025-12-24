#!/usr/bin/env python3
"""
REVUEX XXE Scanner GOLD
=======================

Enterprise-grade non-exploitational XXE vulnerability validator with
multi-engine correlation and zero-destructive testing.

Usage:
    from tools.xxe import XXEScanner
    
    scanner = XXEScanner(target="https://example.com/api/xml")
    result = scanner.run()

CLI:
    python -m tools.xxe -u https://example.com/api/xml

Author: REVUEX Team
License: MIT
"""

from .xxe_scanner import XXEScanner, main

__all__ = ["XXEScanner", "main"]
__version__ = "1.0.0"
