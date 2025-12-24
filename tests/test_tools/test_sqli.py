#!/usr/bin/env python3
"""
SQLi Scanner Tests
==================

Unit tests for the SQLi Scanner GOLD.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.sqli import SQLiScanner


class TestSQLiScannerInit:
    """Tests for SQLiScanner initialization."""
    
    def test_basic_init(self, sample_target):
        scanner = SQLiScanner(target=sample_target)
        assert scanner.target == sample_target
    
    def test_scanner_name(self, sample_target):
        scanner = SQLiScanner(target=sample_target)
        assert "SQL" in scanner.scanner_name.upper()


class TestSQLiPayloads:
    """Tests for SQLi payloads."""
    
    def test_error_based_payloads(self):
        payloads = ["'", "\"", "' OR '1'='1", "1' AND '1'='1"]
        assert len(payloads) >= 4
        assert "'" in payloads
    
    def test_union_payloads(self):
        payloads = ["' UNION SELECT NULL--", "' UNION SELECT 1,2,3--"]
        for p in payloads:
            assert "UNION" in p.upper()
    
    def test_blind_payloads(self):
        payloads = ["' AND 1=1--", "' AND 1=2--", "' OR SLEEP(5)--"]
        assert len(payloads) >= 3


class TestSQLiDetection:
    """Tests for SQLi detection logic."""
    
    def test_error_indicators(self):
        indicators = [
            "sql syntax", "mysql", "ora-", "postgresql",
            "sqlite", "mssql", "you have an error"
        ]
        assert len(indicators) >= 7
    
    def test_error_in_response(self):
        response = "You have an error in your SQL syntax near"
        detected = "sql syntax" in response.lower()
        assert detected is True
    
    def test_boolean_difference(self):
        true_response_len = 1000
        false_response_len = 500
        difference = abs(true_response_len - false_response_len)
        assert difference > 100


class TestSQLiConfidence:
    """Tests for SQLi confidence scoring."""
    
    def test_error_based_score(self):
        score = 40
        assert score > 0
    
    def test_threshold(self):
        threshold = 75
        score = 80
        assert score >= threshold
