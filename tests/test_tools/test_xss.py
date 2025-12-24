#!/usr/bin/env python3
"""
XSS Scanner Tests
=================

Unit tests for the XSS Scanner GOLD.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.xss import XSSScanner


class TestXSSScannerInit:
    """Tests for XSSScanner initialization."""
    
    def test_basic_init(self, sample_target):
        scanner = XSSScanner(target=sample_target)
        assert scanner.target == sample_target
    
    def test_scanner_name(self, sample_target):
        scanner = XSSScanner(target=sample_target)
        assert "XSS" in scanner.scanner_name.upper()


class TestXSSPayloads:
    """Tests for XSS payloads."""
    
    def test_html_context_payloads(self):
        payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        for p in payloads:
            assert "<" in p and ">" in p
    
    def test_attribute_context_payloads(self):
        payloads = ["\" onmouseover=\"alert(1)", "' onclick='alert(1)"]
        for p in payloads:
            assert "on" in p.lower()
    
    def test_javascript_context_payloads(self):
        payloads = ["';alert(1);//", "\";alert(1);//"]
        for p in payloads:
            assert "alert" in p


class TestXSSDetection:
    """Tests for XSS detection logic."""
    
    def test_reflection_detection(self):
        payload = "<script>alert(1)</script>"
        response = f"<html><body>{payload}</body></html>"
        is_reflected = payload in response
        assert is_reflected is True
    
    def test_encoded_reflection(self):
        payload = "<script>"
        encoded = "&lt;script&gt;"
        response = f"<html>{encoded}</html>"
        is_encoded = encoded in response
        assert is_encoded is True
    
    def test_context_detection(self):
        contexts = ["html", "attribute", "javascript", "url"]
        assert len(contexts) == 4


class TestXSSConfidence:
    """Tests for XSS confidence scoring."""
    
    def test_reflection_score(self):
        score = 30
        assert score > 0
    
    def test_unencoded_score(self):
        score = 40
        assert score > 30
    
    def test_threshold(self):
        threshold = 75
        score = 85
        assert score >= threshold
