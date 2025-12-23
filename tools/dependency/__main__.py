#!/usr/bin/env python3
"""
REVUEX Dependency Scanner - CLI Entry Point
===========================================

Usage:
    python -m tools.dependency -t https://example.com

Author: REVUEX Team
License: MIT
"""

from .dependency_scanner import main

if __name__ == "__main__":
    main()
