#!/usr/bin/env python3
"""
REVUEX SSTI Scanner - CLI Entry Point
=====================================

Usage:
    python -m tools.ssti -t https://example.com

Author: REVUEX Team
License: MIT
"""

from .ssti_scanner import main

if __name__ == "__main__":
    main()
