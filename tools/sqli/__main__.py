#!/usr/bin/env python3
"""
REVUEX SQLi Scanner - CLI Entry Point
======================================

Allows running the scanner as a module:
    python -m tools.sqli -t https://example.com/search?q=test

Author: REVUEX Team
License: MIT
"""

from .enhanced_sqli_scanner import main

if __name__ == "__main__":
    main()