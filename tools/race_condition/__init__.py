#!/usr/bin/env python3
"""
REVUEX Race Condition Scanner GOLD
==================================

Research-grade race condition and concurrency scanner for detecting
atomicity violations and idempotency failures.

Usage:
    from tools.race_condition import RaceConditionScanner
    
    scanner = RaceConditionScanner(
        target="https://example.com/api/transfer",
        method="POST",
        data={"amount": "100"}
    )
    result = scanner.run()

CLI:
    python -m tools.race_condition -u https://example.com/api/transfer -X POST

Author: REVUEX Team
License: MIT
"""

from .race_condition_scanner import RaceConditionScanner, main

__all__ = ["RaceConditionScanner", "main"]
__version__ = "1.0.0"
