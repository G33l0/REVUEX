#!/usr/bin/env python3
"""
REVUEX Session Scanner GOLD
===========================

Research-grade session management scanner for detecting
session fixation, invalidation failures, and token weaknesses.

Usage:
    from tools.session import SessionScanner
    
    scanner = SessionScanner(
        target="https://example.com",
        login_path="/login",
        logout_path="/logout"
    )
    result = scanner.run()

CLI:
    python -m tools.session -t https://example.com --login-path /login

Author: REVUEX Team
License: MIT
"""

from .session_scanner import SessionScanner, main

__all__ = ["SessionScanner", "main"]
__version__ = "1.0.0"
