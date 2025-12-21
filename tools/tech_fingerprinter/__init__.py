#!/usr/bin/env python3
"""
REVUEX Tech Fingerprinter
=========================

Research-Grade Technology Stack Detection via Invariants & Correlation.

Usage:
    from tools.tech_fingerprinter import TechFingerprinter
    
    scanner = TechFingerprinter(target="https://example.com")
    result = scanner.run()
    
    # Access intelligence for other tools
    intel = scanner.get_intel()

CLI:
    python -m tools.tech_fingerprinter -t https://example.com

Author: REVUEX Team
License: MIT
"""

from .tech_fingerprinter import TechFingerprinter, main

__all__ = ["TechFingerprinter", "main"]
__version__ = "1.1.0"
