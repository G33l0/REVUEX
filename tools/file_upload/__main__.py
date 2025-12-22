#!/usr/bin/env python3
"""
REVUEX File Upload Scanner - CLI Entry Point
=============================================

Usage:
    python -m tools.file_upload -t https://example.com/upload -f file

Author: REVUEX Team
License: MIT
"""

from .file_upload_scanner import main

if __name__ == "__main__":
    main()
