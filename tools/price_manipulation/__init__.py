#!/usr/bin/env python3
"""
REVUEX Price Manipulation Scanner
=================================

Unified detection of pricing, coupon, subscription, and trial abuse
via server-side trust invariant violations.

Usage:
    from tools.price_manipulation import PriceManipulationScanner
    
    scanner = PriceManipulationScanner(
        target="https://api.example.com",
        baseline={"method": "POST", "path": "/checkout", "json": {...}},
        probes=[...]
    )
    result = scanner.run()

CLI:
    python -m tools.price_manipulation -t https://api.example.com --baseline baseline.json --probes probes.json

Author: REVUEX Team
License: MIT
"""

from .price_manipulation_scanner import PriceManipulationScanner, main

__all__ = ["PriceManipulationScanner", "main"]
__version__ = "2.0.0"
