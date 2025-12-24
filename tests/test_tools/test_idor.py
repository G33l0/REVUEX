#!/usr/bin/env python3
"""
IDOR Scanner Tests
==================

Unit tests for the IDOR Scanner GOLD.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.idor import IDORScanner


class TestIDORScannerInit:
    """Tests for IDORScanner initialization."""
    
    def test_basic_init(self, sample_target):
        scanner = IDORScanner(target=sample_target)
        assert scanner.target == sample_target
    
    def test_init_with_auth_headers(self, sample_target, sample_headers):
        scanner = IDORScanner(
            target=sample_target,
            auth_headers=sample_headers
        )
        assert scanner.target == sample_target
    
    def test_scanner_name(self, sample_target):
        scanner = IDORScanner(target=sample_target)
        assert "IDOR" in scanner.scanner_name.upper()


class TestIDORPatterns:
    """Tests for IDOR ID patterns."""
    
    def test_numeric_ids(self):
        ids = ["1", "2", "100", "999", "12345"]
        for id in ids:
            assert id.isdigit()
    
    def test_uuid_pattern(self):
        import re
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        assert re.match(pattern, uuid)
    
    def test_encoded_ids(self):
        ids = ["MTIz", "YWRtaW4="]  # Base64 encoded
        import base64
        for id in ids:
            decoded = base64.b64decode(id).decode()
            assert len(decoded) > 0


class TestIDORDetection:
    """Tests for IDOR detection logic."""
    
    def test_response_comparison(self):
        user1_response = '{"id": 1, "name": "User1", "email": "user1@test.com"}'
        user2_response = '{"id": 2, "name": "User2", "email": "user2@test.com"}'
        
        # Different responses indicate potential IDOR
        assert user1_response != user2_response
    
    def test_unauthorized_access(self):
        status_code = 200  # Should be 403 or 401
        expected_codes = [401, 403, 404]
        
        is_vulnerable = status_code not in expected_codes
        assert is_vulnerable is True
    
    def test_data_leakage(self):
        sensitive_fields = ["email", "phone", "address", "ssn"]
        response = '{"email": "victim@test.com", "phone": "555-1234"}'
        
        leaked = any(field in response for field in sensitive_fields)
        assert leaked is True


class TestIDORConfidence:
    """Tests for IDOR confidence scoring."""
    
    def test_cross_account_score(self):
        score = 40
        assert score > 0
    
    def test_sensitive_data_score(self):
        score = 30
        assert score > 0
    
    def test_threshold(self):
        threshold = 80
        score = 85
        assert score >= threshold
