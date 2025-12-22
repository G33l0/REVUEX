#!/usr/bin/env python3
"""
REVUEX GraphQL Scanner - CLI Entry Point
========================================

Usage:
    python -m tools.graphql -e https://example.com/graphql

Author: REVUEX Team
License: MIT
"""

from .graphql_scanner import main

if __name__ == "__main__":
    main()
