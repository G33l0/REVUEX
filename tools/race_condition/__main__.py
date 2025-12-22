#!/usr/bin/env python3
"""
REVUEX Race Condition Scanner - CLI Entry Point
===============================================

Usage:
    python -m tools.race_condition -u https://example.com/api/transfer -X POST

Author: REVUEX Team
License: MIT
"""

from .race_condition_scanner import main

if __name__ == "__main__":
    main()
