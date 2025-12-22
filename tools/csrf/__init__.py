#!/usr/bin/env python3
"""
REVUEX CSRF Scanner GOLD
========================

Research-grade CSRF validation scanner for detecting
token bypass, origin enforcement, and method confusion.

Usage:
    from tools.csrf import CSRFScanner
    
    scanner = CSRFScanner(
        target="https://example.com",
        action_path="/api/transfer"
    )
    result = scanner.run()

CLI:
    python -m tools.csrf -t https://example.com -a /api/transfer

Author: REVUEX Team
License: MIT
"""

from .csrf_scanner import CSRFScanner, main

__all__ = ["CSRFScanner", "main"]
__version__ = "1.0.0"
