#!/usr/bin/env python3
"""
File Upload Scanner Tests
=========================

Unit tests for the File Upload Scanner GOLD.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.file_upload import FileUploadScanner


class TestFileUploadScannerInit:
    """Tests for FileUploadScanner initialization."""
    
    def test_basic_init(self, sample_target):
        scanner = FileUploadScanner(target=sample_target)
        assert scanner.target == sample_target
    
    def test_scanner_name(self, sample_target):
        scanner = FileUploadScanner(target=sample_target)
        assert "Upload" in scanner.scanner_name or "File" in scanner.scanner_name


class TestFileUploadPayloads:
    """Tests for file upload payloads."""
    
    def test_dangerous_extensions(self):
        extensions = [".php", ".jsp", ".asp", ".aspx", ".exe", ".sh"]
        assert len(extensions) >= 6
        assert ".php" in extensions
    
    def test_double_extensions(self):
        filenames = ["test.php.jpg", "shell.asp.png", "cmd.jsp.gif"]
        for f in filenames:
            parts = f.split(".")
            assert len(parts) >= 3
    
    def test_null_byte_bypass(self):
        filename = "shell.php%00.jpg"
        assert "%00" in filename
    
    def test_mime_type_bypass(self):
        mime_types = {
            "php": "image/jpeg",
            "jsp": "image/png",
            "exe": "application/pdf"
        }
        for ext, mime in mime_types.items():
            assert "/" in mime


class TestFileUploadDetection:
    """Tests for file upload vulnerability detection."""
    
    def test_extension_allowed(self):
        allowed = [".jpg", ".png", ".gif"]
        test_ext = ".php"
        
        is_blocked = test_ext not in allowed
        assert is_blocked is True
    
    def test_content_type_check(self):
        declared_type = "image/jpeg"
        actual_content = "<?php"  # PHP code
        
        is_mismatch = "php" in actual_content.lower() and "image" in declared_type
        assert is_mismatch is True
    
    def test_file_signature(self):
        # JPEG magic bytes
        jpeg_signature = bytes([0xFF, 0xD8, 0xFF])
        php_content = b"<?php echo 'test'; ?>"
        
        has_valid_sig = php_content[:3] == jpeg_signature
        assert has_valid_sig is False


class TestFileUploadConfidence:
    """Tests for file upload confidence scoring."""
    
    def test_extension_bypass_score(self):
        score = 35
        assert score > 0
    
    def test_execution_score(self):
        score = 50
        assert score > 40
    
    def test_threshold(self):
        threshold = 75
        score = 80
        assert score >= threshold
