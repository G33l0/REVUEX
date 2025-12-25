#!/usr/bin/env python3
"""
REVUEX Tools Package
====================

Professional Bug Bounty Automation Framework
20 GOLD-Standard Security Scanners

Usage:
    # Import individual scanners
    from tools.ssrf import SSRFScanner
    from tools.sqli import SQLiScanner
    from tools.xss import XSSScanner
    
    # Import all scanners
    from tools import *
    
    # Get scanner by name
    from tools import get_scanner
    scanner_class = get_scanner("ssrf")

Author: REVUEX Team (G33L0)
License: MIT (Private Research Use)
Version: 4.0.1
"""

__version__ = "4.0.1"
__author__ = "REVUEX Team"

# =============================================================================
# SCANNER IMPORTS
# =============================================================================

# Tool 1: Subdomain Hunter
from tools.subdomain_hunter import SubdomainHunter

# Tool 2: Tech Fingerprinter
from tools.tech_fingerprinter import TechFingerprinter

# Tool 3: JS Secrets Miner
from tools.js_secrets_miner import JSSecretsMiner

# Tool 4: SSRF Scanner (v4.0 with SIE)
from tools.ssrf import SSRFScanner

# Tool 5: SQLi Scanner
from tools.sqli import SQLiScanner

# Tool 6: IDOR Scanner (v1.1)
from tools.idor import IDORScanner

# Tool 7: XSS Scanner
from tools.xss import XSSScanner

# Tool 8: Business Logic Scanner
from tools.business_logic import BusinessLogicScanner

# Tool 9: File Upload Scanner
from tools.file_upload import FileUploadScanner

# Tool 10: XXE Scanner
from tools.xxe import XXEScanner

# Tool 11: Session Scanner
from tools.session import SessionScanner

# Tool 12: CORS Scanner
from tools.cors import CORSScanner

# Tool 13: CSRF Scanner
from tools.csrf import CSRFScanner

# Tool 14: Dependency Scanner
from tools.dependency import DependencyScanner

# Tool 15: GraphQL Scanner
from tools.graphql import GraphQLScanner

# Tool 16: JWT Analyzer
from tools.jwt import JWTAnalyzer

# Tool 17: APK Analyzer
from tools.apk_analyzer import APKAnalyzer

# Tool 18: Race Condition Scanner
from tools.race_condition import RaceConditionScanner

# Tool 19: Price Manipulation Scanner (v2.0)
from tools.price_manipulation import PriceManipulationScanner

# Tool 20: SSTI Scanner
from tools.ssti import SSTIScanner


# =============================================================================
# SCANNER REGISTRY
# =============================================================================

SCANNERS = {
    # Reconnaissance
    "subdomain": SubdomainHunter,
    "subdomain_hunter": SubdomainHunter,
    "tech": TechFingerprinter,
    "tech_fingerprinter": TechFingerprinter,
    "fingerprint": TechFingerprinter,
    "js_secrets": JSSecretsMiner,
    "js_secrets_miner": JSSecretsMiner,
    "secrets": JSSecretsMiner,
    
    # Injection Vulnerabilities
    "ssrf": SSRFScanner,
    "sqli": SQLiScanner,
    "sql": SQLiScanner,
    "xss": XSSScanner,
    "ssti": SSTIScanner,
    "template": SSTIScanner,
    "xxe": XXEScanner,
    "xml": XXEScanner,
    
    # Access Control
    "idor": IDORScanner,
    "cors": CORSScanner,
    "csrf": CSRFScanner,
    "session": SessionScanner,
    "jwt": JWTAnalyzer,
    "jwt_analyzer": JWTAnalyzer,
    
    # Business Logic
    "business_logic": BusinessLogicScanner,
    "business": BusinessLogicScanner,
    "price": PriceManipulationScanner,
    "price_manipulation": PriceManipulationScanner,
    "race": RaceConditionScanner,
    "race_condition": RaceConditionScanner,
    
    # File & Upload
    "file_upload": FileUploadScanner,
    "upload": FileUploadScanner,
    
    # API & GraphQL
    "graphql": GraphQLScanner,
    "gql": GraphQLScanner,
    
    # Mobile & Dependencies
    "apk": APKAnalyzer,
    "apk_analyzer": APKAnalyzer,
    "android": APKAnalyzer,
    "dependency": DependencyScanner,
    "deps": DependencyScanner,
}

# Scanner metadata
SCANNER_INFO = {
    "subdomain_hunter": {
        "name": "Subdomain Hunter GOLD",
        "category": "Reconnaissance",
        "description": "Passive subdomain enumeration via CT logs, DNS, web archives",
        "version": "1.0.0"
    },
    "tech_fingerprinter": {
        "name": "Tech Fingerprinter GOLD v1.1",
        "category": "Reconnaissance", 
        "description": "Technology stack detection via headers, scripts, patterns",
        "version": "1.1.0"
    },
    "js_secrets": {
        "name": "JS Secrets Miner GOLD",
        "category": "Reconnaissance",
        "description": "JavaScript secret and API key extraction",
        "version": "1.0.0"
    },
    "ssrf": {
        "name": "SSRF Scanner GOLD v4.0",
        "category": "Injection",
        "description": "Server-Side Request Forgery with Scope Intelligence Engine",
        "version": "4.0.0"
    },
    "sqli": {
        "name": "SQLi Scanner GOLD",
        "category": "Injection",
        "description": "SQL Injection detection via error-based and blind techniques",
        "version": "1.0.0"
    },
    "xss": {
        "name": "XSS Scanner GOLD",
        "category": "Injection",
        "description": "Cross-Site Scripting detection with context-aware analysis",
        "version": "1.0.0"
    },
    "ssti": {
        "name": "SSTI Scanner GOLD",
        "category": "Injection",
        "description": "Server-Side Template Injection with 13 engine support",
        "version": "1.0.0"
    },
    "xxe": {
        "name": "XXE Scanner GOLD",
        "category": "Injection",
        "description": "XML External Entity detection with 9 validation engines",
        "version": "1.0.0"
    },
    "idor": {
        "name": "IDOR Scanner GOLD v1.1",
        "category": "Access Control",
        "description": "Insecure Direct Object Reference with two-account methodology",
        "version": "1.1.0"
    },
    "cors": {
        "name": "CORS Scanner GOLD",
        "category": "Access Control",
        "description": "Cross-Origin Resource Sharing misconfiguration detection",
        "version": "1.0.0"
    },
    "csrf": {
        "name": "CSRF Scanner GOLD",
        "category": "Access Control",
        "description": "Cross-Site Request Forgery token and origin validation",
        "version": "1.0.0"
    },
    "session": {
        "name": "Session Scanner GOLD",
        "category": "Access Control",
        "description": "Session management testing with state-transition analysis",
        "version": "1.0.0"
    },
    "jwt": {
        "name": "JWT Analyzer GOLD",
        "category": "Access Control",
        "description": "JSON Web Token vulnerability analysis",
        "version": "1.0.0"
    },
    "business_logic": {
        "name": "Business Logic Scanner GOLD",
        "category": "Business Logic",
        "description": "Business logic flaw detection via workflow analysis",
        "version": "1.0.0"
    },
    "price_manipulation": {
        "name": "Price Manipulation Scanner GOLD v2.0",
        "category": "Business Logic",
        "description": "E-commerce price and quantity manipulation testing",
        "version": "2.0.0"
    },
    "race_condition": {
        "name": "Race Condition Scanner GOLD",
        "category": "Business Logic",
        "description": "Concurrency and atomicity violation detection",
        "version": "1.0.0"
    },
    "file_upload": {
        "name": "File Upload Scanner GOLD",
        "category": "File Upload",
        "description": "File upload vulnerability detection with mutation engine",
        "version": "1.0.0"
    },
    "graphql": {
        "name": "GraphQL Scanner GOLD",
        "category": "API",
        "description": "GraphQL introspection, depth, and security testing",
        "version": "1.0.0"
    },
    "apk_analyzer": {
        "name": "APK Analyzer GOLD",
        "category": "Mobile",
        "description": "Android APK static security analysis",
        "version": "1.0.0"
    },
    "dependency": {
        "name": "Dependency Scanner GOLD",
        "category": "Dependencies",
        "description": "Vulnerable JavaScript library detection with CVE tracking",
        "version": "1.0.0"
    }
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_scanner(name: str):
    """
    Get scanner class by name.
    
    Args:
        name: Scanner name or alias
        
    Returns:
        Scanner class or None
        
    Example:
        >>> scanner_class = get_scanner("ssrf")
        >>> scanner = scanner_class(target="https://example.com")
    """
    return SCANNERS.get(name.lower())


def list_scanners() -> list:
    """
    List all available scanner names.
    
    Returns:
        List of scanner names
    """
    return sorted(set(SCANNERS.values()), key=lambda x: x.__name__)


def get_scanner_info(name: str) -> dict:
    """
    Get scanner metadata.
    
    Args:
        name: Scanner name
        
    Returns:
        Dict with name, category, description, version
    """
    # Normalize name
    name = name.lower().replace("-", "_")
    
    # Try direct lookup
    if name in SCANNER_INFO:
        return SCANNER_INFO[name]
    
    # Try alias resolution
    for key, info in SCANNER_INFO.items():
        if name in key or key in name:
            return info
    
    return {}


def get_scanners_by_category(category: str) -> list:
    """
    Get all scanners in a category.
    
    Args:
        category: Category name (Reconnaissance, Injection, Access Control, etc.)
        
    Returns:
        List of scanner classes
    """
    result = []
    category_lower = category.lower()
    
    for name, info in SCANNER_INFO.items():
        if info["category"].lower() == category_lower:
            scanner_class = SCANNERS.get(name)
            if scanner_class and scanner_class not in result:
                result.append(scanner_class)
    
    return result


def print_scanner_table():
    """Print formatted table of all scanners."""
    print("\n" + "=" * 80)
    print("REVUEX GOLD Scanner Suite")
    print("=" * 80)
    print(f"{'#':<4} {'Scanner':<30} {'Category':<18} {'Version':<10}")
    print("-" * 80)
    
    for i, (name, info) in enumerate(SCANNER_INFO.items(), 1):
        print(f"{i:<4} {info['name']:<30} {info['category']:<18} {info['version']:<10}")
    
    print("-" * 80)
    print(f"Total: {len(SCANNER_INFO)} GOLD Scanners")
    print("=" * 80 + "\n")


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Version info
    "__version__",
    "__author__",
    
    # Scanner classes
    "SubdomainHunter",
    "TechFingerprinter",
    "JSSecretsMiner",
    "SSRFScanner",
    "SQLiScanner",
    "IDORScanner",
    "XSSScanner",
    "BusinessLogicScanner",
    "FileUploadScanner",
    "XXEScanner",
    "SessionScanner",
    "CORSScanner",
    "CSRFScanner",
    "DependencyScanner",
    "GraphQLScanner",
    "JWTAnalyzer",
    "APKAnalyzer",
    "RaceConditionScanner",
    "PriceManipulationScanner",
    "SSTIScanner",
    
    # Registry and helpers
    "SCANNERS",
    "SCANNER_INFO",
    "get_scanner",
    "list_scanners",
    "get_scanner_info",
    "get_scanners_by_category",
    "print_scanner_table",
]
