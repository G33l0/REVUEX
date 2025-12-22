#!/usr/bin/env python3
"""
REVUEX File Upload Scanner GOLD
===============================

Research-grade file upload validation scanner using structural
contradiction and differential analysis.

Usage:
    from tools.file_upload import FileUploadScanner
    
    scanner = FileUploadScanner(
        target="https://example.com/upload",
        upload_field="file"
    )
    result = scanner.run()

CLI:
    python -m tools.file_upload -t https://example.com/upload -f file

Author: REVUEX Team
License: MIT
"""

from .file_upload_scanner import FileUploadScanner, main

__all__ = ["FileUploadScanner", "main"]
__version__ = "1.0.0"
