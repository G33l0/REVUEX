#!/usr/bin/env python3
"""
REVUEX SSTI Scanner GOLD
========================

High-confidence Server-Side Template Injection capability detector
with multi-engine support and zero-exploitation methodology.

Usage:
    from tools.ssti import SSTIScanner
    
    scanner = SSTIScanner(target="https://example.com")
    result = scanner.run()

CLI:
    python -m tools.ssti -t https://example.com

Author: REVUEX Team
License: MIT
"""

from .ssti_scanner import SSTIScanner, main

__all__ = ["SSTIScanner", "main"]
__version__ = "1.0.0"
