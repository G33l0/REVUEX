#!/usr/bin/env python3
"""
REVUEX JWT Analyzer - CLI Entry Point
=====================================

Allows running the scanner as a module:
    python -m tools.jwt -t https://api.example.com --jwt "eyJ..."

Author: REVUEX Team
License: MIT
"""

from .jwt_analyzer import main

if __name__ == "__main__":
    main()