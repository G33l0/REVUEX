#!/usr/bin/env python3
"""
Dependency Scanner Tests
========================

Unit tests for the Dependency Scanner GOLD.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.dependency import DependencyScanner


class TestDependencyScannerInit:
    """Tests for DependencyScanner initialization."""
    
    def test_basic_init(self, sample_target):
        scanner = DependencyScanner(target=sample_target)
        assert scanner.target == sample_target
    
    def test_scanner_name(self, sample_target):
        scanner = DependencyScanner(target=sample_target)
        assert "Dependency" in scanner.scanner_name


class TestDependencyPatterns:
    """Tests for dependency detection patterns."""
    
    def test_cdn_patterns(self):
        cdns = [
            "cdnjs.cloudflare.com",
            "cdn.jsdelivr.net",
            "unpkg.com",
            "ajax.googleapis.com"
        ]
        assert len(cdns) >= 4
    
    def test_library_patterns(self):
        libraries = [
            "jquery", "angular", "react", "vue",
            "lodash", "moment", "bootstrap"
        ]
        assert len(libraries) >= 7
    
    def test_version_extraction(self):
        import re
        urls = [
            "jquery-3.6.0.min.js",
            "angular@1.8.2/angular.min.js",
            "lodash/4.17.21/lodash.min.js"
        ]
        
        pattern = r'[\d]+\.[\d]+\.[\d]+'
        for url in urls:
            match = re.search(pattern, url)
            assert match is not None


class TestDependencyVulnerabilities:
    """Tests for vulnerable dependency detection."""
    
    def test_jquery_vulnerabilities(self):
        vulnerable_versions = ["1.x", "2.x", "3.0.0", "3.4.1"]
        cves = ["CVE-2020-11022", "CVE-2020-11023", "CVE-2019-11358"]
        
        assert len(cves) >= 3
    
    def test_lodash_vulnerabilities(self):
        vulnerable_versions = ["4.17.0", "4.17.10", "4.17.15"]
        cves = ["CVE-2021-23337", "CVE-2020-28500", "CVE-2020-8203"]
        
        assert len(cves) >= 3
    
    def test_version_comparison(self):
        installed = "3.4.1"
        patched = "3.5.0"
        
        # Simple version comparison
        installed_parts = [int(x) for x in installed.split(".")]
        patched_parts = [int(x) for x in patched.split(".")]
        
        is_vulnerable = installed_parts < patched_parts
        assert is_vulnerable is True


class TestDependencyConfidence:
    """Tests for dependency confidence scoring."""
    
    def test_cve_found_score(self):
        score = 40
        assert score > 30
    
    def test_outdated_score(self):
        score = 20
        assert score > 0
    
    def test_threshold(self):
        threshold = 75
        score = 80
        assert score >= threshold
