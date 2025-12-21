#!/usr/bin/env python3
"""
REVUEX Tech Fingerprinter - CLI Entry Point
============================================

Allows running the scanner as a module:
    python -m tools.tech_fingerprinter -t https://example.com

Author: REVUEX Team
License: MIT
"""

from .tech_fingerprinter import main

if __name__ == "__main__":
    main()
