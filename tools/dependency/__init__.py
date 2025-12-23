#!/usr/bin/env python3
"""
REVUEX Dependency Scanner GOLD
==============================

High-confidence dependency and component risk analyzer for detecting
vulnerable JavaScript libraries and outdated components.

Usage:
    from tools.dependency import DependencyScanner
    
    scanner = DependencyScanner(target="https://example.com")
    result = scanner.run()

CLI:
    python -m tools.dependency -t https://example.com

Author: REVUEX Team
License: MIT
"""

from .dependency_scanner import DependencyScanner, main

__all__ = ["DependencyScanner", "main"]
__version__ = "1.0.0"
