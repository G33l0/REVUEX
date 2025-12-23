#!/usr/bin/env python3
"""
REVUEX CORS Scanner - CLI Entry Point
=====================================

Usage:
    python -m tools.cors -t https://example.com/api

Author: REVUEX Team
License: MIT
"""

from .cors_scanner import main

if __name__ == "__main__":
    main()
