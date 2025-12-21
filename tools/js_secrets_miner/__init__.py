#!/usr/bin/env python3
"""
REVUEX JS Secrets Miner
=======================

Research-Grade JavaScript Secret & Trust-Leak Discovery Engine.

Usage:
    from tools.js_secrets_miner import JSSecretsMiner
    
    scanner = JSSecretsMiner(target="https://example.com")
    result = scanner.run()

CLI:
    python -m tools.js_secrets_miner -t https://example.com

Author: REVUEX Team
License: MIT
"""

from .js_secrets_miner import JSSecretsMiner, main

__all__ = ["JSSecretsMiner", "main"]
__version__ = "1.0.0"
