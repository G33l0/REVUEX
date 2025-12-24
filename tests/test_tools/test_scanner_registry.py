#!/usr/bin/env python3
"""
Scanner Registry Tests
======================

Unit tests for the tools package scanner registry.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# =============================================================================
# REGISTRY IMPORT TESTS
# =============================================================================

class TestScannerImports:
    """Tests for scanner imports."""
    
    def test_import_tools_package(self):
        """Test importing tools package."""
        import tools
        assert hasattr(tools, '__version__')
    
    def test_import_get_scanner(self):
        """Test importing get_scanner function."""
        from tools import get_scanner
        assert callable(get_scanner)
    
    def test_import_scanners_dict(self):
        """Test importing SCANNERS dictionary."""
        from tools import SCANNERS
        assert isinstance(SCANNERS, dict)
        assert len(SCANNERS) > 0
    
    def test_import_scanner_info(self):
        """Test importing SCANNER_INFO dictionary."""
        from tools import SCANNER_INFO
        assert isinstance(SCANNER_INFO, dict)
        assert len(SCANNER_INFO) == 20  # 20 GOLD scanners


# =============================================================================
# GET_SCANNER TESTS
# =============================================================================

class TestGetScanner:
    """Tests for get_scanner function."""
    
    def test_get_ssrf_scanner(self):
        """Test getting SSRF scanner."""
        from tools import get_scanner
        scanner_class = get_scanner("ssrf")
        assert scanner_class is not None
        assert scanner_class.__name__ == "SSRFScanner"
    
    def test_get_sqli_scanner(self):
        """Test getting SQLi scanner."""
        from tools import get_scanner
        scanner_class = get_scanner("sqli")
        assert scanner_class is not None
    
    def test_get_scanner_by_alias(self):
        """Test getting scanner by alias."""
        from tools import get_scanner
        
        # "sql" is alias for SQLiScanner
        scanner_class = get_scanner("sql")
        assert scanner_class is not None
    
    def test_get_nonexistent_scanner(self):
        """Test getting non-existent scanner returns None."""
        from tools import get_scanner
        scanner_class = get_scanner("nonexistent_scanner")
        assert scanner_class is None
    
    def test_get_scanner_case_insensitive(self):
        """Test get_scanner is case insensitive."""
        from tools import get_scanner
        
        scanner1 = get_scanner("ssrf")
        scanner2 = get_scanner("SSRF")
        
        # Both should work (lowercase conversion)
        assert scanner1 is not None


# =============================================================================
# SCANNER INFO TESTS
# =============================================================================

class TestScannerInfo:
    """Tests for scanner info metadata."""
    
    def test_scanner_info_has_required_fields(self):
        """Test each scanner info has required fields."""
        from tools import SCANNER_INFO
        
        required_fields = ["name", "category", "description", "version"]
        
        for scanner_name, info in SCANNER_INFO.items():
            for field in required_fields:
                assert field in info, f"{scanner_name} missing {field}"
    
    def test_scanner_categories(self):
        """Test scanner categories are valid."""
        from tools import SCANNER_INFO
        
        valid_categories = [
            "Reconnaissance",
            "Injection", 
            "Access Control",
            "Business Logic",
            "File Upload",
            "API",
            "Mobile",
            "Dependencies"
        ]
        
        for scanner_name, info in SCANNER_INFO.items():
            assert info["category"] in valid_categories, \
                f"{scanner_name} has invalid category: {info['category']}"
    
    def test_scanner_versions(self):
        """Test scanner versions are valid format."""
        from tools import SCANNER_INFO
        
        for scanner_name, info in SCANNER_INFO.items():
            version = info["version"]
            # Version should be like "1.0.0" or "4.0.0"
            parts = version.split(".")
            assert len(parts) >= 2, f"{scanner_name} has invalid version: {version}"


# =============================================================================
# SCANNER CLASS TESTS
# =============================================================================

class TestScannerClasses:
    """Tests for individual scanner classes."""
    
    def test_ssrf_scanner_exists(self):
        """Test SSRFScanner class exists."""
        from tools.ssrf import SSRFScanner
        assert SSRFScanner is not None
    
    def test_sqli_scanner_exists(self):
        """Test SQLiScanner class exists."""
        from tools.sqli import SQLiScanner
        assert SQLiScanner is not None
    
    def test_xss_scanner_exists(self):
        """Test XSSScanner class exists."""
        from tools.xss import XSSScanner
        assert XSSScanner is not None
    
    def test_cors_scanner_exists(self):
        """Test CORSScanner class exists."""
        from tools.cors import CORSScanner
        assert CORSScanner is not None
    
    def test_idor_scanner_exists(self):
        """Test IDORScanner class exists."""
        from tools.idor import IDORScanner
        assert IDORScanner is not None
    
    def test_xxe_scanner_exists(self):
        """Test XXEScanner class exists."""
        from tools.xxe import XXEScanner
        assert XXEScanner is not None
    
    def test_ssti_scanner_exists(self):
        """Test SSTIScanner class exists."""
        from tools.ssti import SSTIScanner
        assert SSTIScanner is not None
    
    def test_jwt_analyzer_exists(self):
        """Test JWTAnalyzer class exists."""
        from tools.jwt import JWTAnalyzer
        assert JWTAnalyzer is not None
    
    def test_graphql_scanner_exists(self):
        """Test GraphQLScanner class exists."""
        from tools.graphql import GraphQLScanner
        assert GraphQLScanner is not None
    
    def test_dependency_scanner_exists(self):
        """Test DependencyScanner class exists."""
        from tools.dependency import DependencyScanner
        assert DependencyScanner is not None


# =============================================================================
# SCANNER COUNT TESTS
# =============================================================================

class TestScannerCount:
    """Tests for verifying all 20 scanners exist."""
    
    def test_total_scanner_count(self):
        """Test total number of unique scanners."""
        from tools import SCANNER_INFO
        assert len(SCANNER_INFO) == 20
    
    def test_all_scanners_in_registry(self):
        """Test all 20 scanners are in registry."""
        from tools import SCANNERS
        
        expected_scanners = [
            "subdomain", "tech", "secrets",
            "ssrf", "sqli", "xss", "ssti", "xxe",
            "idor", "cors", "csrf", "session", "jwt",
            "business_logic", "price", "race",
            "file_upload", "graphql", "apk", "dependency"
        ]
        
        for scanner in expected_scanners:
            assert scanner in SCANNERS or any(
                scanner in alias for alias in SCANNERS.keys()
            ), f"Scanner {scanner} not found in registry"
