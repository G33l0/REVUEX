#!/usr/bin/env python3
"""
REVUEX XSS Scanner - CLI Entry Point
=====================================

Allows running the scanner as a module:
    python -m tools.xss -t https://example.com/search?q=test

Author: REVUEX Team
License: MIT
"""

from .enhanced_xss_scanner import main

if __name__ == "__main__":
    main()
