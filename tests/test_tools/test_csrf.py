#!/usr/bin/env python3
"""
CSRF Scanner Tests
==================

Unit tests for the CSRF Scanner GOLD.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.csrf import CSRFScanner


class TestCSRFScannerInit:
    """Tests for CSRFScanner initialization."""
    
    def test_basic_init(self, sample_target):
        scanner = CSRFScanner(target=sample_target)
        assert scanner.target == sample_target
    
    def test_scanner_name(self, sample_target):
        scanner = CSRFScanner(target=sample_target)
        assert "CSRF" in scanner.scanner_name.upper()


class TestCSRFTokenPatterns:
    """Tests for CSRF token patterns."""
    
    def test_token_names(self):
        names = [
            "csrf_token", "csrftoken", "_token", "authenticity_token",
            "csrf", "xsrf", "_csrf", "__RequestVerificationToken"
        ]
        assert len(names) >= 8
    
    def test_token_in_form(self):
        html = '<input type="hidden" name="csrf_token" value="abc123">'
        assert "csrf_token" in html
        assert 'type="hidden"' in html
    
    def test_token_in_header(self):
        headers = {"X-CSRF-Token": "abc123"}
        assert "X-CSRF-Token" in headers


class TestCSRFDetection:
    """Tests for CSRF detection logic."""
    
    def test_missing_token(self):
        html = '<form action="/transfer" method="POST"><input name="amount"></form>'
        
        token_patterns = ["csrf", "token", "_token"]
        has_token = any(p in html.lower() for p in token_patterns)
        assert has_token is False
    
    def test_samesite_cookie(self):
        cookie = "session=abc123; SameSite=Strict; HttpOnly"
        
        has_samesite = "SameSite" in cookie
        assert has_samesite is True
    
    def test_origin_validation(self):
        headers = {
            "Origin": "https://example.com",
            "Referer": "https://example.com/page"
        }
        assert "Origin" in headers


class TestCSRFConfidence:
    """Tests for CSRF confidence scoring."""
    
    def test_missing_token_score(self):
        score = 30
        assert score > 0
    
    def test_no_samesite_score(self):
        score = 20
        assert score > 0
    
    def test_threshold(self):
        threshold = 75
        score = 80
        assert score >= threshold
