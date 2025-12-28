#!/usr/bin/env python3
"""REVUEX GraphQL Scanner GOLD"""

import sys
import importlib.util
from pathlib import Path

_THIS_DIR = Path(__file__).parent.absolute()
_SCANNER_FILE = _THIS_DIR / "graphql_scanner.py"

def _load_module():
    spec = importlib.util.spec_from_file_location("graphql_scanner", _SCANNER_FILE)
    module = importlib.util.module_from_spec(spec)
    sys.modules["graphql_scanner"] = module
    spec.loader.exec_module(module)
    return module

try:
    from .graphql_scanner import GraphQLScanner, main
except ImportError:
    _mod = _load_module()
    GraphQLScanner = _mod.GraphQLScanner
    main = _mod.main

__all__ = ["GraphQLScanner", "main"]
__version__ = "1.0.0"
