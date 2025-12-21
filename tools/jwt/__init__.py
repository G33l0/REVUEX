#!/usr/bin/env python3
"""
REVUEX JWT Analyzer
===================

Research-Grade JWT Vulnerability Detection without Exploitation.

Usage:
    from tools.jwt import JWTAnalyzer
    
    scanner = JWTAnalyzer(
        target="https://api.example.com",
        token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
    )
    result = scanner.run()

CLI:
    python -m tools.jwt -t https://api.example.com --jwt "eyJ..."

Author: REVUEX Team
License: MIT
"""

from .jwt_analyzer import JWTAnalyzer, main

__all__ = ["JWTAnalyzer", "main"]
__version__ = "1.0.0"
