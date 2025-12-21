#!/usr/bin/env python3
"""
REVUEX Subdomain Hunter - CLI Entry Point
==========================================

Allows running the scanner as a module:
    python -m tools.subdomain_hunter -d example.com

Author: REVUEX Team
License: MIT
"""

from .subdomain_hunter import main

if __name__ == "__main__":
    main()
