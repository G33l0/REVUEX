#!/usr/bin/env python3
"""
REVUEX IDOR Scanner
===================

Research-Grade IDOR Detection using Dual-Account Authorization Diffing.

Usage:
    from tools.idor import IDORScanner
    
    scanner = IDORScanner(
        target="https://example.com/api/orders/123",
        token_a="Bearer owner_token",
        token_b="Bearer attacker_token"
    )
    result = scanner.run()

CLI:
    python -m tools.idor -t https://example.com/api/orders/123 --token-a "Bearer xxx" --token-b "Bearer yyy"
    revuex-idor -t https://example.com/api/orders/123 --token-a "Bearer xxx" --token-b "Bearer yyy"

Author: REVUEX Team
License: MIT
"""

from .idor_tester import IDORScanner, main

__all__ = ["IDORScanner", "main"]
__version__ = "1.0.0"
