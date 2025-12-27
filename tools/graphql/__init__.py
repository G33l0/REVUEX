#!/usr/bin/env python3
"""
REVUEX GraphQL Scanner GOLD
===========================

Research-grade GraphQL security scanner for detecting
introspection exposure, query depth issues, and method confusion.

Usage:
    from tools.graphql import GraphQLScanner
    
    scanner = GraphQLScanner(
        target="https://example.com/graphql"
    )
    result = scanner.run()

CLI:
    python -m tools.graphql -e https://example.com/graphql

Author: REVUEX Team
License: MIT
"""

try:
    from .graphql_scanner import GraphQLScanner, main
except ImportError:
    # Fallback for module execution
    from graphql_scanner import GraphQLScanner, main

__all__ = ["GraphQLScanner", "main"]
__version__ = "1.0.0"
