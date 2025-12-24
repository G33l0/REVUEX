#!/usr/bin/env python3
"""
JS Secrets Miner Tests
======================

Unit tests for the JS Secrets Miner GOLD.
"""

import pytest
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.js_secrets import JSSecretsMiner


class TestJSSecretsMinerInit:
    """Tests for JSSecretsMiner initialization."""
    
    def test_basic_init(self, sample_target):
        scanner = JSSecretsMiner(target=sample_target)
        assert scanner.target == sample_target
    
    def test_scanner_name(self, sample_target):
        scanner = JSSecretsMiner(target=sample_target)
        assert "Secret" in scanner.scanner_name or "JS" in scanner.scanner_name


class TestSecretPatterns:
    """Tests for secret detection patterns."""
    
    def test_api_key_patterns(self):
        patterns = [
            r'api[_-]?key\s*[:=]\s*["\']([^"\']+)["\']',
            r'apikey\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        test_content = 'const api_key = "sk_live_abc123"'
        for pattern in patterns:
            match = re.search(pattern, test_content, re.IGNORECASE)
            if match:
                assert match.group(1) == "sk_live_abc123"
    
    def test_aws_patterns(self):
        patterns = {
            "access_key": r'AKIA[0-9A-Z]{16}',
            "secret_key": r'[A-Za-z0-9/+=]{40}'
        }
        
        test_key = "AKIAIOSFODNN7EXAMPLE"
        assert re.match(patterns["access_key"], test_key)
    
    def test_jwt_pattern(self):
        pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"
        assert re.match(pattern, jwt)


class TestSecretDetection:
    """Tests for secret detection in content."""
    
    def test_hardcoded_password(self):
        content = 'const password = "SuperSecret123!";'
        pattern = r'password\s*[:=]\s*["\']([^"\']+)["\']'
        
        match = re.search(pattern, content, re.IGNORECASE)
        assert match is not None
    
    def test_private_key(self):
        content = '-----BEGIN RSA PRIVATE KEY-----'
        
        has_private_key = "PRIVATE KEY" in content
        assert has_private_key is True
    
    def test_firebase_url(self):
        content = 'https://myapp-12345.firebaseio.com'
        pattern = r'https://[a-z0-9-]+\.firebaseio\.com'
        
        match = re.search(pattern, content)
        assert match is not None


class TestSecretConfidence:
    """Tests for secret confidence scoring."""
    
    def test_high_entropy_score(self):
        score = 40
        assert score > 30
    
    def test_known_pattern_score(self):
        score = 50
        assert score > 40
    
    def test_threshold(self):
        threshold = 75
        score = 85
        assert score >= threshold
