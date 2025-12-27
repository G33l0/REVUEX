#!/usr/bin/env python3
"""
REVUEX GraphQL Scanner - CLI Entry Point
========================================

Usage:
    python -m tools.graphql -t https://example.com/graphql

Author: REVUEX Team
License: MIT
"""

import sys
import importlib.util
from pathlib import Path

def _run_main():
    # Get the directory containing this __main__.py
    this_dir = Path(__file__).parent.absolute()
    scanner_file = this_dir / "graphql_scanner.py"
    
    # Load the module directly from file path
    spec = importlib.util.spec_from_file_location("graphql_scanner", scanner_file)
    module = importlib.util.module_from_spec(spec)
    sys.modules["graphql_scanner"] = module
    spec.loader.exec_module(module)
    
    # Run main
    return module.main()

if __name__ == "__main__":
    try:
        # Try normal import first
        from .graphql_scanner import main
        sys.exit(main())
    except ImportError:
        try:
            from graphql_scanner import main
            sys.exit(main())
        except ImportError:
            # Direct file loading as fallback
            sys.exit(_run_main())
