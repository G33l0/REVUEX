#!/usr/bin/env python3
"""
REVUEX Business Logic Scanner - CLI Entry Point
================================================

Allows running the scanner as a module:
    python -m tools.business_logic -t https://api.example.com --baseline baseline.json --probes probes.json

Author: REVUEX Team
License: MIT
"""

from .business_logic_scanner import main

if __name__ == "__main__":
    main()