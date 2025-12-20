#!/usr/bin/env python3
"""
REVUEX SSRF Scanner - CLI Entry Point
======================================

Allows running the scanner as a module:
    python -m tools.ssrf -t https://example.com

Author: REVUEX Team
License: MIT
"""

from .ssrf_scanner import main

if __name__ == "__main__":
    main()
