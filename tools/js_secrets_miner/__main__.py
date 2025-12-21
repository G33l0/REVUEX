#!/usr/bin/env python3
"""
REVUEX JS Secrets Miner - CLI Entry Point
==========================================

Allows running the scanner as a module:
    python -m tools.js_secrets_miner -t https://example.com

Author: REVUEX Team
License: MIT
"""

from .js_secrets_miner import main

if __name__ == "__main__":
    main()
