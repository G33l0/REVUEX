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
    python -m tools.graphql -t https://example.com/graphql

Author: REVUEX Team
License: MIT
"""

import sys
import importlib.util
from pathlib import Path

# Get the directory containing this __init__.py
_THIS_DIR = Path(__file__).parent.absolute()
_SCANNER_FILE = _THIS_DIR / "graphql_scanner.py"

# Load the module directly from file path
def _load_scanner_module():
    spec = importlib.util.spec_from_file_location("graphql_scanner", _SCANNER_FILE)
    module = importlib.util.module_from_spec(spec)
    sys.modules["graphql_scanner"] = module
    spec.loader.exec_module(module)
    return module

try:
    # Try relative import first
    from .graphql_scanner import GraphQLScanner, main
except ImportError:
    try:
        # Try direct import
        from graphql_scanner import GraphQLScanner, main
    except ImportError:
        # Load directly from file path as last resort
        _module = _load_scanner_module()
        GraphQLScanner = _module.GraphQLScanner
        main = _module.main

__all__ = ["GraphQLScanner", "main"]
__version__ = "1.0.0"
