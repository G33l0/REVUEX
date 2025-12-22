#!/usr/bin/env python3
"""
REVUEX CSRF Scanner - CLI Entry Point
=====================================

Usage:
    python -m tools.csrf -t https://example.com -a /api/transfer

Author: REVUEX Team
License: MIT
"""

from .csrf_scanner import main

if __name__ == "__main__":
    main()
