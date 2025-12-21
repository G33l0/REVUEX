#!/usr/bin/env python3
"""
REVUEX Business Logic Scanner
=============================

Research-Grade Business Logic Vulnerability Detection without Exploitation.

Usage:
    from tools.business_logic import BusinessLogicScanner
    
    scanner = BusinessLogicScanner(
        target="https://api.example.com",
        baseline={"method": "POST", "path": "/checkout", "json": {...}},
        probes=[...]
    )
    result = scanner.run()

CLI:
    python -m tools.business_logic -t https://api.example.com --baseline baseline.json --probes probes.json

Author: REVUEX Team
License: MIT
"""

from .business_logic_scanner import BusinessLogicScanner, main

__all__ = ["BusinessLogicScanner", "main"]
__version__ = "1.0.0"
