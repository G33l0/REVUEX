#!/usr/bin/env python3
"""REVUEX GraphQL Scanner CLI"""

import sys
import importlib.util
from pathlib import Path

def _run():
    scanner_file = Path(__file__).parent.absolute() / "graphql_scanner.py"
    spec = importlib.util.spec_from_file_location("graphql_scanner", scanner_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.main()

if __name__ == "__main__":
    sys.exit(_run())
