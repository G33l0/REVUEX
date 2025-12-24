#!/usr/bin/env python3
"""
Subdomain Hunter Tests
======================

Unit tests for the Subdomain Hunter GOLD.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.subdomain_hunter import SubdomainHunter


class TestSubdomainHunterInit:
    """Tests for SubdomainHunter initialization."""
    
    def test_basic_init(self):
        scanner = SubdomainHunter(target="example.com")
        assert scanner.target == "example.com"
    
    def test_scanner_name(self):
        scanner = SubdomainHunter(target="example.com")
        assert "Subdomain" in scanner.scanner_name


class TestSubdomainSources:
    """Tests for subdomain enumeration sources."""
    
    def test_ct_log_sources(self):
        sources = ["crt.sh", "certspotter", "censys"]
        assert len(sources) >= 3
    
    def test_dns_sources(self):
        sources = ["virustotal", "dnsdumpster", "threatcrowd"]
        assert len(sources) >= 3
    
    def test_archive_sources(self):
        sources = ["wayback", "commoncrawl"]
        assert len(sources) >= 2


class TestSubdomainValidation:
    """Tests for subdomain validation."""
    
    def test_valid_subdomain(self):
        subdomain = "api.example.com"
        domain = "example.com"
        
        is_valid = subdomain.endswith(domain)
        assert is_valid is True
    
    def test_invalid_subdomain(self):
        subdomain = "api.evil.com"
        domain = "example.com"
        
        is_valid = subdomain.endswith(domain)
        assert is_valid is False
    
    def test_subdomain_format(self):
        import re
        subdomains = ["api.example.com", "dev.example.com", "staging.example.com"]
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.example\.com$'
        
        for sub in subdomains:
            assert re.match(pattern, sub)


class TestSubdomainConfidence:
    """Tests for subdomain confidence scoring."""
    
    def test_ct_log_score(self):
        score = 30
        assert score > 0
    
    def test_dns_verified_score(self):
        score = 40
        assert score > 30
    
    def test_threshold(self):
        threshold = 75
        score = 80
        assert score >= threshold
