#!/usr/bin/env python3
"""
REVUEX IDOR Scanner - CLI Entry Point
======================================

Allows running the scanner as a module:
    python -m tools.idor -t https://example.com/api/orders/123 --token-a "Bearer xxx" --token-b "Bearer yyy"

Author: REVUEX Team
License: MIT
"""

from .idor_tester import main

if __name__ == "__main__":
    main()
