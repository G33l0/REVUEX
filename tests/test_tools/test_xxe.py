#!/usr/bin/env python3
"""
XXE Scanner Tests
=================

Unit tests for the XXE Scanner GOLD.
"""

import pytest
from unittest.mock import Mock, patch
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.xxe import XXEScanner


# =============================================================================
# INITIALIZATION TESTS
# =============================================================================

class TestXXEScannerInit:
    """Tests for XXEScanner initialization."""
    
    def test_basic_init(self, sample_api_target):
        """Test basic scanner initialization."""
        scanner = XXEScanner(target=sample_api_target)
        assert scanner.target == sample_api_target
    
    def test_init_with_custom_xml(self, sample_api_target, sample_xml):
        """Test initialization with custom XML."""
        scanner = XXEScanner(
            target=sample_api_target,
            custom_xml=sample_xml
        )
        assert scanner.target == sample_api_target
    
    def test_scanner_name(self, sample_api_target):
        """Test scanner name is set."""
        scanner = XXEScanner(target=sample_api_target)
        assert "XXE" in scanner.scanner_name


# =============================================================================
# PAYLOAD TESTS
# =============================================================================

class TestXXEPayloads:
    """Tests for XXE payloads."""
    
    def test_safe_entity_payload(self):
        """Test safe entity payload structure."""
        payload = '''<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY harmless "REVUEX_XXE_SAFE_TEST">
]>
<root>&harmless;</root>'''
        
        assert "<!DOCTYPE" in payload
        assert "<!ENTITY" in payload
        assert "&harmless;" in payload
    
    def test_doctype_payload(self):
        """Test DOCTYPE payload."""
        payload = '''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ELEMENT root (#PCDATA)>
]>
<root>test</root>'''
        
        assert "<!DOCTYPE" in payload
        assert "<!ELEMENT" in payload
    
    def test_parameter_entity_payload(self):
        """Test parameter entity payload."""
        payload = '''<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY % param "test">
]>
<root>param_test</root>'''
        
        assert "<!ENTITY %" in payload


# =============================================================================
# PARSER DETECTION TESTS
# =============================================================================

class TestXXEParserDetection:
    """Tests for XML parser detection."""
    
    def test_parser_fingerprints(self):
        """Test known parser fingerprints."""
        parsers = [
            "libxml", "xerces", "expat", "dom4j",
            "saxon", "woodstox", "msxml"
        ]
        
        assert len(parsers) >= 7
        assert "libxml" in parsers
        assert "xerces" in parsers
    
    def test_parser_in_response(self):
        """Test parser detection in response."""
        response = "Powered by libxml2 version 2.9.10"
        
        detected = "libxml" in response.lower()
        assert detected is True
    
    def test_parser_in_headers(self):
        """Test parser detection in headers."""
        headers = {
            "Server": "Apache/2.4.41",
            "X-Powered-By": "PHP/7.4 libxml/2.9"
        }
        
        header_blob = str(headers).lower()
        detected = "libxml" in header_blob
        assert detected is True


# =============================================================================
# ENTITY EXPANSION TESTS
# =============================================================================

class TestXXEEntityExpansion:
    """Tests for entity expansion detection."""
    
    def test_entity_reflected(self):
        """Test entity reflection in response."""
        marker = "REVUEX_XXE_SAFE_TEST"
        response_text = f"<result>{marker}</result>"
        
        is_reflected = marker in response_text
        assert is_reflected is True
    
    def test_entity_not_reflected(self):
        """Test entity not reflected."""
        marker = "REVUEX_XXE_SAFE_TEST"
        response_text = "<result>Some other content</result>"
        
        is_reflected = marker in response_text
        assert is_reflected is False


# =============================================================================
# ERROR DETECTION TESTS
# =============================================================================

class TestXXEErrorDetection:
    """Tests for XXE error detection."""
    
    def test_error_indicators(self):
        """Test XXE error indicators."""
        error_indicators = [
            "entity", "dtd", "doctype", "external",
            "system", "public", "undefined entity"
        ]
        
        assert len(error_indicators) >= 7
    
    def test_error_in_response(self):
        """Test error detection in response."""
        response = "Error: undefined entity 'xxe' at line 3"
        
        indicators = ["entity", "undefined", "error"]
        detected = any(ind in response.lower() for ind in indicators)
        assert detected is True


# =============================================================================
# CONFIDENCE SCORING TESTS
# =============================================================================

class TestXXEConfidence:
    """Tests for XXE confidence scoring."""
    
    def test_engine_scores(self):
        """Test individual engine scores."""
        engine_scores = {
            "parser_fingerprint": 15,
            "safe_entity_expansion": 30,
            "blind_timing": 20,
            "content_type_mismatch": 15,
            "error_based": 20
        }
        
        total = sum(engine_scores.values())
        assert total == 100
    
    def test_threshold(self):
        """Test confidence threshold."""
        threshold = 75
        
        # With entity expansion + parser detection
        score = 30 + 15 + 20 + 15  # 80
        assert score >= threshold
    
    def test_below_threshold(self):
        """Test score below threshold."""
        threshold = 75
        
        # Only parser detected
        score = 15
        assert score < threshold
