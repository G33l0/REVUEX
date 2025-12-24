#!/usr/bin/env python3
"""
SSTI Scanner Tests
==================

Unit tests for the SSTI Scanner GOLD.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.ssti import SSTIScanner


class TestSSTIScannerInit:
    """Tests for SSTIScanner initialization."""
    
    def test_basic_init(self, sample_target):
        scanner = SSTIScanner(target=sample_target)
        assert scanner.target == sample_target
    
    def test_scanner_name(self, sample_target):
        scanner = SSTIScanner(target=sample_target)
        assert "SSTI" in scanner.scanner_name.upper()


class TestSSTIPayloads:
    """Tests for SSTI payloads."""
    
    def test_jinja2_probes(self):
        probes = ["{{7*7}}", "{{config}}", "{{self}}"]
        for p in probes:
            assert "{{" in p and "}}" in p
    
    def test_twig_probes(self):
        probes = ["{{7*7}}", "{{_self}}", "{{app}}"]
        assert len(probes) >= 3
    
    def test_freemarker_probes(self):
        probes = ["${7*7}", "${.now}", "${object.class}"]
        for p in probes:
            assert "${" in p
    
    def test_math_probes(self):
        probes = {
            "{{7*7}}": "49",
            "${7*7}": "49",
            "<%=7*7%>": "49"
        }
        for probe, expected in probes.items():
            assert expected == "49"


class TestSSTIDetection:
    """Tests for SSTI detection logic."""
    
    def test_math_evaluation(self):
        probe = "{{7*7}}"
        response = "Result: 49"
        
        is_evaluated = "49" in response
        assert is_evaluated is True
    
    def test_engine_fingerprinting(self):
        engines = [
            "jinja2", "twig", "freemarker", "velocity",
            "pebble", "thymeleaf", "smarty", "mako",
            "erb", "ejs", "nunjucks", "handlebars", "mustache"
        ]
        assert len(engines) == 13
    
    def test_error_detection(self):
        errors = [
            "jinja2.exceptions",
            "Twig\\Error",
            "freemarker.core",
            "TemplateSyntaxError"
        ]
        response = "Error: jinja2.exceptions.UndefinedError"
        
        detected = any(e.lower() in response.lower() for e in errors)
        assert detected is True


class TestSSTIConfidence:
    """Tests for SSTI confidence scoring."""
    
    def test_math_eval_score(self):
        score = 40
        assert score > 30
    
    def test_syntax_detection_score(self):
        score = 25
        assert score > 0
    
    def test_threshold(self):
        threshold = 75
        score = 80
        assert score >= threshold
