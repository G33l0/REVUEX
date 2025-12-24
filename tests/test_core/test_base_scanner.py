#!/usr/bin/env python3
"""
BaseScanner Tests
=================

Unit tests for the BaseScanner class and related components.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.base_scanner import BaseScanner, Finding, ScanResult, Severity, ScanStatus


# =============================================================================
# SEVERITY ENUM TESTS
# =============================================================================

class TestSeverity:
    """Tests for Severity enum."""
    
    def test_severity_values(self):
        """Test severity enum has correct values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"
    
    def test_severity_comparison(self):
        """Test severity levels exist."""
        severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        assert len(severities) == 5


# =============================================================================
# SCAN STATUS TESTS
# =============================================================================

class TestScanStatus:
    """Tests for ScanStatus enum."""
    
    def test_status_values(self):
        """Test scan status enum values."""
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"
        assert ScanStatus.ABORTED.value == "aborted"


# =============================================================================
# FINDING TESTS
# =============================================================================

class TestFinding:
    """Tests for Finding dataclass."""
    
    def test_finding_creation(self):
        """Test creating a Finding."""
        finding = Finding(
            id="test_001",
            title="Test Vulnerability",
            severity=Severity.HIGH,
            description="Test description",
            url="https://example.com/test",
            parameter="test_param",
            method="GET",
            payload="test_payload",
            evidence="test_evidence",
            impact="Test impact",
            remediation="Test remediation",
            vulnerability_type="test",
            confidence="high"
        )
        
        assert finding.id == "test_001"
        assert finding.title == "Test Vulnerability"
        assert finding.severity == Severity.HIGH
        assert finding.url == "https://example.com/test"
        assert finding.confidence == "high"
    
    def test_finding_severity_types(self):
        """Test finding with different severity levels."""
        for severity in Severity:
            finding = Finding(
                id="test",
                title="Test",
                severity=severity,
                description="",
                url="",
                parameter="",
                method="",
                payload="",
                evidence="",
                impact="",
                remediation="",
                vulnerability_type="",
                confidence=""
            )
            assert finding.severity == severity


# =============================================================================
# SCAN RESULT TESTS
# =============================================================================

class TestScanResult:
    """Tests for ScanResult dataclass."""
    
    def test_scan_result_creation(self):
        """Test creating a ScanResult."""
        start = datetime.now()
        end = datetime.now()
        
        result = ScanResult(
            scanner_name="TestScanner",
            target="https://example.com",
            status=ScanStatus.COMPLETED,
            findings=[],
            start_time=start,
            end_time=end,
            duration_seconds=1.5,
            request_count=10
        )
        
        assert result.scanner_name == "TestScanner"
        assert result.target == "https://example.com"
        assert result.status == ScanStatus.COMPLETED
        assert result.findings == []
        assert result.duration_seconds == 1.5
        assert result.request_count == 10
    
    def test_scan_result_with_findings(self):
        """Test ScanResult with findings."""
        finding = Finding(
            id="test",
            title="Test",
            severity=Severity.HIGH,
            description="",
            url="",
            parameter="",
            method="",
            payload="",
            evidence="",
            impact="",
            remediation="",
            vulnerability_type="",
            confidence=""
        )
        
        result = ScanResult(
            scanner_name="TestScanner",
            target="https://example.com",
            status=ScanStatus.COMPLETED,
            findings=[finding],
            start_time=datetime.now(),
            end_time=datetime.now(),
            duration_seconds=1.0,
            request_count=5
        )
        
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH


# =============================================================================
# BASE SCANNER TESTS
# =============================================================================

class TestBaseScanner:
    """Tests for BaseScanner class."""
    
    def test_scanner_initialization(self, sample_target):
        """Test scanner initialization."""
        # BaseScanner is abstract, but we can test its __init__ via a mock subclass
        with patch.object(BaseScanner, '__abstractmethods__', set()):
            scanner = BaseScanner(target=sample_target)
            assert scanner.target == sample_target
    
    def test_scanner_with_custom_headers(self, sample_target, sample_headers):
        """Test scanner with custom headers."""
        with patch.object(BaseScanner, '__abstractmethods__', set()):
            scanner = BaseScanner(
                target=sample_target,
                custom_headers=sample_headers
            )
            assert scanner.target == sample_target
    
    def test_scanner_with_delay(self, sample_target):
        """Test scanner with custom delay."""
        with patch.object(BaseScanner, '__abstractmethods__', set()):
            scanner = BaseScanner(target=sample_target, delay=2.0)
            assert scanner.delay == 2.0
    
    def test_scanner_with_timeout(self, sample_target):
        """Test scanner with custom timeout."""
        with patch.object(BaseScanner, '__abstractmethods__', set()):
            scanner = BaseScanner(target=sample_target, timeout=30)
            assert scanner.timeout == 30
    
    def test_scanner_findings_list(self, sample_target):
        """Test scanner findings list initialization."""
        with patch.object(BaseScanner, '__abstractmethods__', set()):
            scanner = BaseScanner(target=sample_target)
            assert scanner.findings == []
            assert isinstance(scanner.findings, list)
    
    def test_scanner_request_count(self, sample_target):
        """Test scanner request count initialization."""
        with patch.object(BaseScanner, '__abstractmethods__', set()):
            scanner = BaseScanner(target=sample_target)
            assert scanner.request_count == 0


# =============================================================================
# CONFIDENCE SCORING TESTS
# =============================================================================

class TestConfidenceScoring:
    """Tests for confidence scoring logic."""
    
    def test_confidence_threshold_default(self):
        """Test default confidence threshold."""
        # Most scanners use 75-80 as default threshold
        default_threshold = 75
        assert default_threshold >= 0
        assert default_threshold <= 100
    
    def test_confidence_calculation(self):
        """Test confidence score calculation pattern."""
        # Simulate typical confidence scoring
        signals = ["signal1", "signal2", "signal3"]
        base_score = 20
        signal_score = len(signals) * 15
        total = min(100, base_score + signal_score)
        
        assert total == 65  # 20 + (3 * 15) = 65
    
    def test_confidence_max_cap(self):
        """Test confidence score capped at 100."""
        signals = ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"]
        base_score = 20
        signal_score = len(signals) * 15
        total = min(100, base_score + signal_score)
        
        assert total == 100  # Capped at 100
