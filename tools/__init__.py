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
    
    # Get scanner by name
    from tools import get_scanner
    scanner_class = get_scanner("ssrf")

Author: REVUEX Team (G33L0)
License: MIT (Private Research Use)
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "REVUEX Team (G33L0)"

# =============================================================================
# LAZY IMPORTS - Only load scanners when requested
# =============================================================================

# Scanner name to module path mapping
_SCANNER_MODULES = {
    # Reconnaissance
    "subdomain_hunter": ("tools.subdomain_hunter", "SubdomainHunter"),
    "tech_fingerprinter": ("tools.tech_fingerprinter", "TechFingerprinter"),
    "js_secrets_miner": ("tools.js_secrets_miner", "JSSecretsMiner"),
    
    # Injection
    "ssrf": ("tools.ssrf", "SSRFScanner"),
    "sqli": ("tools.sqli", "SQLiScanner"),
    "xss": ("tools.xss", "XSSScanner"),
    "ssti": ("tools.ssti", "SSTIScanner"),
    "xxe": ("tools.xxe", "XXEScanner"),
    
    # Access Control
    "idor": ("tools.idor", "IDORScanner"),
    "cors": ("tools.cors", "CORSScanner"),
    "csrf": ("tools.csrf", "CSRFScanner"),
    "session": ("tools.session", "SessionScanner"),
    "jwt": ("tools.jwt", "JWTAnalyzer"),
    
    # Business Logic
    "business_logic": ("tools.business_logic", "BusinessLogicScanner"),
    "race_condition": ("tools.race_condition", "RaceConditionScanner"),
    "price_manipulation": ("tools.price_manipulation", "PriceManipulationScanner"),
    
    # Other
    "file_upload": ("tools.file_upload", "FileUploadScanner"),
    "graphql": ("tools.graphql", "GraphQLScanner"),
    "dependency": ("tools.dependency", "DependencyScanner"),
    "apk_analyzer": ("tools.apk_analyzer", "APKAnalyzer"),
}

# Scanner aliases
_SCANNER_ALIASES = {
    "subdomain": "subdomain_hunter",
    "tech": "tech_fingerprinter",
    "fingerprint": "tech_fingerprinter",
    "secrets": "js_secrets_miner",
    "js_secrets": "js_secrets_miner",
    "sql": "sqli",
    "template": "ssti",
    "xml": "xxe",
    "jwt_analyzer": "jwt",
    "business": "business_logic",
    "race": "race_condition",
    "price": "price_manipulation",
    "upload": "file_upload",
    "apk": "apk_analyzer",
}

# Cache for loaded scanners
_loaded_scanners = {}


def get_scanner(name: str):
    """
    Get a scanner class by name.
    
    Args:
        name: Scanner name or alias
        
    Returns:
        Scanner class or None if not found
        
    Example:
        SSRFScanner = get_scanner("ssrf")
        scanner = SSRFScanner(target="https://example.com")
    """
    # Resolve alias
    scanner_name = _SCANNER_ALIASES.get(name, name)
    
    # Check cache
    if scanner_name in _loaded_scanners:
        return _loaded_scanners[scanner_name]
    
    # Get module info
    if scanner_name not in _SCANNER_MODULES:
        return None
    
    module_path, class_name = _SCANNER_MODULES[scanner_name]
    
    try:
        # Dynamic import
        module = __import__(module_path, fromlist=[class_name])
        scanner_class = getattr(module, class_name)
        
        # Cache it
        _loaded_scanners[scanner_name] = scanner_class
        return scanner_class
        
    except ImportError as e:
        print(f"[!] Cannot load {scanner_name}: {e}")
        print(f"    Try: pip install <missing_package>")
        return None
    except Exception as e:
        print(f"[!] Error loading {scanner_name}: {e}")
        return None


def list_scanners():
    """List all available scanner names."""
    return list(_SCANNER_MODULES.keys())


def get_scanner_info():
    """Get info about all scanners."""
    info = {}
    for name, (module_path, class_name) in _SCANNER_MODULES.items():
        info[name] = {
            "module": module_path,
            "class": class_name,
            "aliases": [k for k, v in _SCANNER_ALIASES.items() if v == name]
        }
    return info


# =============================================================================
# SCANNER DESCRIPTIONS
# =============================================================================

SCANNER_DESCRIPTIONS = {
    "subdomain_hunter": "Subdomain enumeration and discovery",
    "tech_fingerprinter": "Technology stack detection",
    "js_secrets_miner": "JavaScript secrets and API key extraction",
    "ssrf": "Server-Side Request Forgery",
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "ssti": "Server-Side Template Injection",
    "xxe": "XML External Entity Injection",
    "idor": "Insecure Direct Object Reference",
    "cors": "CORS Misconfiguration",
    "csrf": "Cross-Site Request Forgery",
    "session": "Session Management Analyzer",
    "jwt": "JWT Vulnerability Scanner",
    "business_logic": "Business Logic Flaw Scanner",
    "race_condition": "Race Condition Tester",
    "price_manipulation": "Price Manipulation Scanner",
    "file_upload": "File Upload Vulnerability Scanner",
    "graphql": "GraphQL Introspection and Security",
    "dependency": "Dependency Vulnerability Checker",
    "apk_analyzer": "Android APK Security Analyzer",
}

# =============================================================================
# TOOL CATEGORIES
# =============================================================================

TOOL_CATEGORIES = {
    "recon": ["subdomain_hunter", "tech_fingerprinter", "js_secrets_miner"],
    "injection": ["ssrf", "sqli", "xss", "ssti", "xxe"],
    "access_control": ["idor", "cors", "csrf", "session", "jwt"],
    "business_logic": ["business_logic", "race_condition", "price_manipulation"],
    "other": ["file_upload", "graphql", "dependency", "apk_analyzer"],
}

ALL_TOOLS = list(_SCANNER_MODULES.keys())


# =============================================================================
# CONVENIENCE EXPORTS
# =============================================================================

__all__ = [
    # Functions
    "get_scanner",
    "list_scanners",
    "get_scanner_info",
    # Data
    "ALL_TOOLS",
    "TOOL_CATEGORIES",
    "SCANNER_DESCRIPTIONS",
]
