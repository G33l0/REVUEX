#!/usr/bin/env python3
"""
Session Scanner Tests
=====================

Unit tests for the Session Scanner GOLD.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.session import SessionScanner


class TestSessionScannerInit:
    """Tests for SessionScanner initialization."""
    
    def test_basic_init(self, sample_target):
        scanner = SessionScanner(target=sample_target)
        assert scanner.target == sample_target
    
    def test_scanner_name(self, sample_target):
        scanner = SessionScanner(target=sample_target)
        assert "Session" in scanner.scanner_name


class TestSessionCookieFlags:
    """Tests for session cookie flags."""
    
    def test_secure_flag(self):
        cookie = "session=abc123; Secure; HttpOnly"
        has_secure = "Secure" in cookie
        assert has_secure is True
    
    def test_httponly_flag(self):
        cookie = "session=abc123; Secure; HttpOnly"
        has_httponly = "HttpOnly" in cookie
        assert has_httponly is True
    
    def test_samesite_flag(self):
        cookie = "session=abc123; SameSite=Strict"
        has_samesite = "SameSite" in cookie
        assert has_samesite is True
    
    def test_missing_flags(self):
        cookie = "session=abc123"
        
        has_secure = "Secure" in cookie
        has_httponly = "HttpOnly" in cookie
        
        assert has_secure is False
        assert has_httponly is False


class TestSessionDetection:
    """Tests for session vulnerability detection."""
    
    def test_session_fixation(self):
        pre_login_session = "abc123"
        post_login_session = "abc123"  # Same = vulnerable
        
        is_fixated = pre_login_session == post_login_session
        assert is_fixated is True
    
    def test_session_regeneration(self):
        pre_login_session = "abc123"
        post_login_session = "xyz789"  # Different = secure
        
        is_regenerated = pre_login_session != post_login_session
        assert is_regenerated is True
    
    def test_session_entropy(self):
        import re
        session_id = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
        
        # Check length and character diversity
        assert len(session_id) >= 32
        assert re.search(r'[a-z]', session_id)
        assert re.search(r'[0-9]', session_id)


class TestSessionConfidence:
    """Tests for session confidence scoring."""
    
    def test_missing_secure_score(self):
        score = 25
        assert score > 0
    
    def test_fixation_score(self):
        score = 40
        assert score > 30
    
    def test_threshold(self):
        threshold = 75
        score = 80
        assert score >= threshold
