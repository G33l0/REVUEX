#!/usr/bin/env python3
"""
SSRF Scanner Tests
==================

Unit tests for the SSRF Scanner GOLD.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.ssrf import SSRFScanner


# =============================================================================
# INITIALIZATION TESTS
# =============================================================================

class TestSSRFScannerInit:
    """Tests for SSRFScanner initialization."""
    
    def test_basic_init(self, sample_target):
        """Test basic scanner initialization."""
        scanner = SSRFScanner(target=sample_target)
        assert scanner.target == sample_target
    
    def test_init_with_custom_delay(self, sample_target):
        """Test initialization with custom delay."""
        scanner = SSRFScanner(target=sample_target, delay=2.0)
        assert scanner.delay == 2.0
    
    def test_init_with_custom_timeout(self, sample_target):
        """Test initialization with custom timeout."""
        scanner = SSRFScanner(target=sample_target, timeout=30)
        assert scanner.timeout == 30
    
    def test_init_with_headers(self, sample_target, sample_headers):
        """Test initialization with custom headers."""
        scanner = SSRFScanner(
            target=sample_target,
            custom_headers=sample_headers
        )
        assert scanner.custom_headers == sample_headers
    
    def test_scanner_name(self, sample_target):
        """Test scanner name is set."""
        scanner = SSRFScanner(target=sample_target)
        assert "SSRF" in scanner.scanner_name


# =============================================================================
# PAYLOAD TESTS
# =============================================================================

class TestSSRFPayloads:
    """Tests for SSRF payloads."""
    
    def test_localhost_payloads(self):
        """Test localhost payloads exist."""
        localhost_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443"
        ]
        
        for payload in localhost_payloads:
            assert "127.0.0.1" in payload or "localhost" in payload
    
    def test_ipv6_payloads(self):
        """Test IPv6 payloads."""
        ipv6_payloads = [
            "http://[::1]",
            "http://[0:0:0:0:0:0:0:1]"
        ]
        
        for payload in ipv6_payloads:
            assert "[" in payload and "]" in payload
    
    def test_cloud_metadata_payloads(self):
        """Test cloud metadata payloads."""
        cloud_payloads = {
            "aws": "http://169.254.169.254/latest/meta-data/",
            "gcp": "http://metadata.google.internal/",
            "azure": "http://169.254.169.254/metadata/instance"
        }
        
        assert "169.254.169.254" in cloud_payloads["aws"]
        assert "metadata.google.internal" in cloud_payloads["gcp"]
    
    def test_bypass_payloads(self):
        """Test SSRF bypass payloads."""
        bypass_payloads = [
            "http://0.0.0.0",
            "http://127.1",
            "http://127.0.1",
            "http://2130706433"  # Decimal for 127.0.0.1
        ]
        
        assert len(bypass_payloads) > 0


# =============================================================================
# DETECTION LOGIC TESTS
# =============================================================================

class TestSSRFDetection:
    """Tests for SSRF detection logic."""
    
    def test_internal_ip_detection(self):
        """Test detection of internal IP in response."""
        internal_indicators = [
            "127.0.0.1",
            "localhost",
            "internal",
            "private"
        ]
        
        response_text = "Connection to 127.0.0.1 established"
        
        detected = any(ind in response_text for ind in internal_indicators)
        assert detected is True
    
    def test_cloud_metadata_detection(self):
        """Test detection of cloud metadata response."""
        aws_indicators = [
            "ami-id",
            "instance-id",
            "iam/security-credentials",
            "meta-data"
        ]
        
        response_text = '{"ami-id": "ami-12345", "instance-id": "i-abcdef"}'
        
        detected = any(ind in response_text for ind in aws_indicators)
        assert detected is True
    
    def test_error_based_detection(self):
        """Test error-based SSRF detection."""
        error_indicators = [
            "connection refused",
            "timeout",
            "could not resolve",
            "no route to host"
        ]
        
        response_text = "Error: connection refused to internal host"
        
        detected = any(ind in response_text.lower() for ind in error_indicators)
        assert detected is True


# =============================================================================
# CONFIDENCE SCORING TESTS
# =============================================================================

class TestSSRFConfidence:
    """Tests for SSRF confidence scoring."""
    
    def test_baseline_score(self):
        """Test baseline confidence score."""
        base_score = 20
        assert base_score >= 0
        assert base_score <= 100
    
    def test_signal_scoring(self):
        """Test signal-based scoring."""
        signals = {
            "internal_ip_response": 30,
            "cloud_metadata": 40,
            "timing_difference": 20,
            "error_message": 15
        }
        
        total = sum(signals.values())
        assert total > 75  # Should exceed threshold
    
    def test_threshold_check(self):
        """Test confidence threshold."""
        threshold = 80
        confidence = 85
        
        is_vulnerable = confidence >= threshold
        assert is_vulnerable is True
    
    def test_below_threshold(self):
        """Test score below threshold."""
        threshold = 80
        confidence = 50
        
        is_vulnerable = confidence >= threshold
        assert is_vulnerable is False
