#!/usr/bin/env python3
"""
REVUEX Session Scanner - CLI Entry Point
========================================

Usage:
    python -m tools.session -t https://example.com --login-path /login

Author: REVUEX Team
License: MIT
"""

from .session_scanner import main

if __name__ == "__main__":
    main()
