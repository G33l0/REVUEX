#!/usr/bin/env python3
"""
REVUEX CORS Scanner GOLD
========================

High-confidence CORS misconfiguration scanner for detecting
origin reflection, wildcard issues, and credential exposure.

Usage:
    from tools.cors import CORSScanner
    
    scanner = CORSScanner(target="https://example.com/api")
    result = scanner.run()

CLI:
    python -m tools.cors -t https://example.com/api

Author: REVUEX Team
License: MIT
"""

from .cors_scanner import CORSScanner, main

__all__ = ["CORSScanner", "main"]
__version__ = "1.0.0"
