#!/usr/bin/env python3
"""
REVUEX Price Manipulation Scanner - CLI Entry Point
====================================================

Allows running the scanner as a module:
    python -m tools.price_manipulation -t https://api.example.com --baseline baseline.json --probes probes.json

Author: REVUEX Team
License: MIT
"""

from .price_manipulation_scanner import main

if __name__ == "__main__":
    main()