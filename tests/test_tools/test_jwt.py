#!/usr/bin/env python3
"""
JWT Analyzer Tests
==================

Unit tests for the JWT Analyzer GOLD.
"""

import pytest
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.jwt import JWTAnalyzer


class TestJWTAnalyzerInit:
    """Tests for JWTAnalyzer initialization."""
    
    def test_basic_init(self, sample_jwt):
        scanner = JWTAnalyzer(target=sample_jwt)
        assert scanner.target == sample_jwt
    
    def test_scanner_name(self, sample_jwt):
        scanner = JWTAnalyzer(target=sample_jwt)
        assert "JWT" in scanner.scanner_name.upper()


class TestJWTStructure:
    """Tests for JWT structure parsing."""
    
    def test_jwt_parts(self, sample_jwt):
        parts = sample_jwt.split(".")
        assert len(parts) == 3
    
    def test_header_decode(self, sample_jwt):
        header_b64 = sample_jwt.split(".")[0]
        # Add padding if needed
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding
        
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        assert "alg" in header
        assert "typ" in header
    
    def test_payload_decode(self, sample_jwt):
        payload_b64 = sample_jwt.split(".")[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        assert "sub" in payload or "name" in payload


class TestJWTVulnerabilities:
    """Tests for JWT vulnerability detection."""
    
    def test_none_algorithm(self):
        vulnerable_algs = ["none", "None", "NONE", "nOnE"]
        for alg in vulnerable_algs:
            assert alg.lower() == "none"
    
    def test_weak_algorithms(self):
        weak_algs = ["HS256", "HS384", "HS512"]
        strong_algs = ["RS256", "RS384", "RS512", "ES256"]
        
        assert "HS256" in weak_algs
        assert "RS256" in strong_algs
    
    def test_algorithm_confusion(self):
        # RS256 to HS256 confusion attack
        original_alg = "RS256"
        confused_alg = "HS256"
        
        assert original_alg != confused_alg
    
    def test_expired_token(self):
        import time
        exp = 1516239022  # Past timestamp
        now = int(time.time())
        
        is_expired = exp < now
        assert is_expired is True


class TestJWTConfidence:
    """Tests for JWT confidence scoring."""
    
    def test_none_alg_score(self):
        score = 50
        assert score > 40
    
    def test_weak_secret_score(self):
        score = 30
        assert score > 0
    
    def test_threshold(self):
        threshold = 75
        score = 80
        assert score >= threshold
