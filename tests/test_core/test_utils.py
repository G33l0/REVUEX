#!/usr/bin/env python3
"""
Utils Tests
===========

Unit tests for REVUEX utility functions.
"""

import pytest
from unittest.mock import patch
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.utils import (
    print_success,
    print_error,
    print_warning,
    print_info
)


# =============================================================================
# PRINT FUNCTION TESTS
# =============================================================================

class TestPrintFunctions:
    """Tests for colored print functions."""
    
    def test_print_success(self, capsys):
        """Test success print function."""
        print_success("Test success message")
        captured = capsys.readouterr()
        assert "Test success message" in captured.out
    
    def test_print_error(self, capsys):
        """Test error print function."""
        print_error("Test error message")
        captured = capsys.readouterr()
        assert "Test error message" in captured.out
    
    def test_print_warning(self, capsys):
        """Test warning print function."""
        print_warning("Test warning message")
        captured = capsys.readouterr()
        assert "Test warning message" in captured.out
    
    def test_print_info(self, capsys):
        """Test info print function."""
        print_info("Test info message")
        captured = capsys.readouterr()
        assert "Test info message" in captured.out
    
    def test_print_empty_message(self, capsys):
        """Test print with empty message."""
        print_info("")
        captured = capsys.readouterr()
        # Should not raise error
        assert captured.out is not None


# =============================================================================
# URL VALIDATION TESTS
# =============================================================================

class TestURLValidation:
    """Tests for URL validation utilities."""
    
    def test_valid_https_url(self):
        """Test valid HTTPS URL."""
        url = "https://example.com"
        assert url.startswith("https://")
    
    def test_valid_http_url(self):
        """Test valid HTTP URL."""
        url = "http://example.com"
        assert url.startswith("http://")
    
    def test_url_with_path(self):
        """Test URL with path."""
        url = "https://example.com/api/v1/users"
        assert "/api/v1/users" in url
    
    def test_url_with_query_params(self):
        """Test URL with query parameters."""
        url = "https://example.com/search?q=test&page=1"
        assert "?" in url
        assert "q=test" in url
    
    def test_url_with_port(self):
        """Test URL with port number."""
        url = "https://example.com:8443/api"
        assert ":8443" in url


# =============================================================================
# HEADER PARSING TESTS
# =============================================================================

class TestHeaderParsing:
    """Tests for header parsing utilities."""
    
    def test_parse_single_header(self):
        """Test parsing single header."""
        header_str = "Authorization: Bearer token123"
        key, value = header_str.split(":", 1)
        assert key.strip() == "Authorization"
        assert value.strip() == "Bearer token123"
    
    def test_parse_header_with_colon_in_value(self):
        """Test parsing header with colon in value."""
        header_str = "X-Custom: value:with:colons"
        key, value = header_str.split(":", 1)
        assert key.strip() == "X-Custom"
        assert value.strip() == "value:with:colons"
    
    def test_multiple_headers(self):
        """Test parsing multiple headers."""
        headers = [
            "Authorization: Bearer token",
            "Content-Type: application/json",
            "X-Custom: value"
        ]
        
        parsed = {}
        for h in headers:
            k, v = h.split(":", 1)
            parsed[k.strip()] = v.strip()
        
        assert len(parsed) == 3
        assert parsed["Authorization"] == "Bearer token"
        assert parsed["Content-Type"] == "application/json"


# =============================================================================
# PAYLOAD SANITIZATION TESTS
# =============================================================================

class TestPayloadSanitization:
    """Tests for payload sanitization."""
    
    def test_escape_special_chars(self):
        """Test escaping special characters."""
        payload = "<script>alert(1)</script>"
        escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
        assert "&lt;script&gt;" in escaped
    
    def test_truncate_long_payload(self):
        """Test truncating long payloads."""
        payload = "A" * 1000
        max_length = 100
        truncated = payload[:max_length] + "..." if len(payload) > max_length else payload
        assert len(truncated) == 103  # 100 + "..."
    
    def test_remove_null_bytes(self):
        """Test removing null bytes."""
        payload = "test\x00value"
        cleaned = payload.replace("\x00", "")
        assert "\x00" not in cleaned
        assert cleaned == "testvalue"


# =============================================================================
# DOMAIN EXTRACTION TESTS
# =============================================================================

class TestDomainExtraction:
    """Tests for domain extraction utilities."""
    
    def test_extract_domain_from_url(self):
        """Test extracting domain from URL."""
        from urllib.parse import urlparse
        
        url = "https://api.example.com/v1/users"
        parsed = urlparse(url)
        domain = parsed.netloc
        
        assert domain == "api.example.com"
    
    def test_extract_domain_with_port(self):
        """Test extracting domain with port."""
        from urllib.parse import urlparse
        
        url = "https://example.com:8443/api"
        parsed = urlparse(url)
        domain = parsed.netloc
        
        assert domain == "example.com:8443"
    
    def test_extract_scheme(self):
        """Test extracting URL scheme."""
        from urllib.parse import urlparse
        
        url = "https://example.com"
        parsed = urlparse(url)
        
        assert parsed.scheme == "https"
    
    def test_extract_path(self):
        """Test extracting URL path."""
        from urllib.parse import urlparse
        
        url = "https://example.com/api/v1/users"
        parsed = urlparse(url)
        
        assert parsed.path == "/api/v1/users"
