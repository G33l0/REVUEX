#!/usr/bin/env python3
"""
REVUEX XXE Scanner - CLI Entry Point
====================================

Usage:
    python -m tools.xxe -u https://example.com/api/xml

Author: REVUEX Team
License: MIT
"""

from .xxe_scanner import main

if __name__ == "__main__":
    main()
