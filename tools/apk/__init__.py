#!/usr/bin/env python3
"""
REVUEX APK Analyzer GOLD
========================

Research-grade Android APK security analyzer for detecting
misconfigurations, hardcoded secrets, and security weaknesses.

Usage:
    from tools.apk_analyzer import APKAnalyzer
    
    analyzer = APKAnalyzer(apk_path="app.apk")
    result = analyzer.run()

CLI:
    python -m tools.apk_analyzer -a app.apk

Author: REVUEX Team
License: MIT
"""

from .apk_analyzer import APKAnalyzer, main

__all__ = ["APKAnalyzer", "main"]
__version__ = "1.0.0"
