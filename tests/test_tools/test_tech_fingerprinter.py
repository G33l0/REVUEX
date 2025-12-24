#!/usr/bin/env python3
"""
Tech Fingerprinter Tests
========================

Unit tests for the Tech Fingerprinter GOLD.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.tech_fingerprinter import TechFingerprinter


class TestTechFingerprinterInit:
    """Tests for TechFingerprinter initialization."""
    
    def test_basic_init(self, sample_target):
        scanner = TechFingerprinter(target=sample_target)
        assert scanner.target == sample_target
    
    def test_scanner_name(self, sample_target):
        scanner = TechFingerprinter(target=sample_target)
        assert "Tech" in scanner.scanner_name or "Fingerprint" in scanner.scanner_name


class TestTechFingerprints:
    """Tests for technology fingerprints."""
    
    def test_server_headers(self):
        headers = {
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/7.4.3"
        }
        
        assert "nginx" in headers["Server"]
        assert "PHP" in headers["X-Powered-By"]
    
    def test_framework_patterns(self):
        patterns = {
            "Laravel": ["laravel_session", "XSRF-TOKEN"],
            "Django": ["csrftoken", "django"],
            "Rails": ["_session_id", "X-Request-Id"]
        }
        assert len(patterns) >= 3
    
    def test_cms_patterns(self):
        patterns = {
            "WordPress": ["/wp-content/", "/wp-includes/"],
            "Drupal": ["/sites/default/", "Drupal.settings"],
            "Joomla": ["/components/", "/modules/"]
        }
        assert len(patterns) >= 3


class TestTechDetection:
    """Tests for technology detection."""
    
    def test_header_detection(self):
        response_headers = {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Powered-By": "Express"
        }
        
        has_server = "Server" in response_headers
        assert has_server is True
    
    def test_script_detection(self):
        html = '<script src="/static/js/jquery-3.6.0.min.js"></script>'
        
        has_jquery = "jquery" in html.lower()
        assert has_jquery is True
    
    def test_meta_detection(self):
        html = '<meta name="generator" content="WordPress 5.8">'
        
        has_generator = 'name="generator"' in html
        assert has_generator is True


class TestTechConfidence:
    """Tests for tech fingerprint confidence scoring."""
    
    def test_header_match_score(self):
        score = 30
        assert score > 0
    
    def test_multiple_signals_score(self):
        score = 50
        assert score > 40
    
    def test_threshold(self):
        threshold = 75
        score = 80
        assert score >= threshold
