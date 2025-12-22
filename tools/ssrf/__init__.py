#!/usr/bin/env python3
"""
REVUEX SSRF Scanner GOLD v4.0
=============================

High-confidence SSRF scanner with embedded Scope Intelligence Engine (SIE)
for automatic endpoint and parameter discovery.

Usage:
    from tools.ssrf import SSRFScanner
    
    scanner = SSRFScanner(target="https://example.com")
    result = scanner.run()

CLI:
    python -m tools.ssrf -t https://example.com

Author: REVUEX Team
License: MIT
"""

from .ssrf_scanner import SSRFScanner, ScopeIntelligenceEngine, main

__all__ = ["SSRFScanner", "ScopeIntelligenceEngine", "main"]
__version__ = "4.0.0"
