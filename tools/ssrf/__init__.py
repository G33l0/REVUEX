#!/usr/bin/env python3
"""
REVUEX Tools Module
===================

Exports all 20 security scanners for import.

Usage:
    from tools import SSRFScanner, SQLiScanner, XSSScanner
    
    # Or import all
    from tools import ALL_SCANNERS
    
    # Get scanner by name
    from tools import get_scanner
    scanner_class = get_scanner("ssrf")

Each tool can also be run standalone:
    python -m tools.ssrf -t https://example.com
    python -m tools.sqli -t https://example.com

Author: REVUEX Team
License: MIT
"""

from typing import Dict, Type, Optional, List

# Version
__version__ = "1.0.0"

# =============================================================================
# SCANNER IMPORTS (Lazy loading to avoid circular imports)
# =============================================================================

def _lazy_import(module_path: str, class_name: str):
    """Lazy import helper"""
    def _import():
        import importlib
        module = importlib.import_module(module_path)
        return getattr(module, class_name)
    return _import


# Scanner registry with lazy loading
_SCANNER_REGISTRY: Dict[str, callable] = {
    # Recon Tools
    "subdomain_hunter": _lazy_import("tools.subdomain_hunter", "SubdomainHunterScanner"),
    "tech_fingerprinter": _lazy_import("tools.tech_fingerprinter", "TechFingerprinterScanner"),
    "js_secrets_miner": _lazy_import("tools.js_secrets_miner", "JsSecretsMinerScanner"),
    
    # Injection Tools
    "ssrf": _lazy_import("tools.ssrf", "SSRFScanner"),
    "sqli": _lazy_import("tools.sqli", "SQLiScanner"),
    "xss": _lazy_import("tools.xss", "XSSScanner"),
    "ssti": _lazy_import("tools.ssti", "SSTIScanner"),
    "xxe": _lazy_import("tools.xxe", "XXEScanner"),
    
    # Access Control Tools
    "idor": _lazy_import("tools.idor", "IDORScanner"),
    "cors": _lazy_import("tools.cors", "CORSScanner"),
    "csrf": _lazy_import("tools.csrf", "CSRFScanner"),
    
    # Authentication Tools
    "jwt": _lazy_import("tools.jwt", "JWTScanner"),
    "session": _lazy_import("tools.session", "SessionScanner"),
    
    # Business Logic Tools
    "business_logic": _lazy_import("tools.business_logic", "BusinessLogicScanner"),
    "race_condition": _lazy_import("tools.race_condition", "RaceConditionScanner"),
    "price_manipulation": _lazy_import("tools.price_manipulation", "PriceManipulationScanner"),
    
    # Other Tools
    "file_upload": _lazy_import("tools.file_upload", "FileUploadScanner"),
    "graphql": _lazy_import("tools.graphql", "GraphQLScanner"),
    "dependency": _lazy_import("tools.dependency", "DependencyScanner"),
    "apk": _lazy_import("tools.apk", "APKScanner"),
}


# =============================================================================
# PUBLIC API
# =============================================================================

def get_scanner(name: str) -> Optional[Type]:
    """
    Get scanner class by name.
    
    Args:
        name: Scanner name (e.g., 'ssrf', 'sqli', 'xss')
    
    Returns:
        Scanner class or None if not found
    
    Example:
        SSRFScanner = get_scanner('ssrf')
        scanner = SSRFScanner(target='https://example.com')
        result = scanner.run()
    """
    if name in _SCANNER_REGISTRY:
        try:
            return _SCANNER_REGISTRY[name]()
        except ImportError:
            return None
    return None


def list_scanners() -> List[str]:
    """
    List all available scanner names.
    
    Returns:
        List of scanner names
    """
    return list(_SCANNER_REGISTRY.keys())


def get_scanner_info() -> Dict[str, str]:
    """
    Get information about all scanners.
    
    Returns:
        Dict mapping scanner name to description
    """
    return {
        # Recon
        "subdomain_hunter": "Subdomain enumeration and discovery",
        "tech_fingerprinter": "Technology stack detection and fingerprinting",
        "js_secrets_miner": "JavaScript secrets and API key extraction",
        
        # Injection
        "ssrf": "Server-Side Request Forgery vulnerability scanner",
        "sqli": "SQL Injection vulnerability scanner",
        "xss": "Cross-Site Scripting vulnerability scanner",
        "ssti": "Server-Side Template Injection scanner",
        "xxe": "XML External Entity Injection scanner",
        
        # Access Control
        "idor": "Insecure Direct Object Reference tester",
        "cors": "CORS misconfiguration scanner",
        "csrf": "Cross-Site Request Forgery tester",
        
        # Authentication
        "jwt": "JWT vulnerability analyzer",
        "session": "Session management analyzer",
        
        # Business Logic
        "business_logic": "Business logic flaw scanner",
        "race_condition": "Race condition vulnerability tester",
        "price_manipulation": "Price manipulation vulnerability scanner",
        
        # Other
        "file_upload": "File upload vulnerability tester",
        "graphql": "GraphQL introspection and security scanner",
        "dependency": "Dependency vulnerability checker",
        "apk": "Android APK security analyzer",
    }


# =============================================================================
# CATEGORY HELPERS
# =============================================================================

SCANNER_CATEGORIES = {
    "recon": ["subdomain_hunter", "tech_fingerprinter", "js_secrets_miner"],
    "injection": ["ssrf", "sqli", "xss", "ssti", "xxe"],
    "access_control": ["idor", "cors", "csrf"],
    "authentication": ["jwt", "session"],
    "business_logic": ["business_logic", "race_condition", "price_manipulation"],
    "other": ["file_upload", "graphql", "dependency", "apk"],
}


def get_scanners_by_category(category: str) -> List[str]:
    """
    Get scanner names by category.
    
    Args:
        category: Category name (recon, injection, access_control, etc.)
    
    Returns:
        List of scanner names in that category
    """
    return SCANNER_CATEGORIES.get(category, [])


def get_all_categories() -> List[str]:
    """Get all category names"""
    return list(SCANNER_CATEGORIES.keys())


# =============================================================================
# CONVENIENCE EXPORTS
# =============================================================================

# All scanner names
ALL_SCANNER_NAMES = list(_SCANNER_REGISTRY.keys())

# Total count
SCANNER_COUNT = len(_SCANNER_REGISTRY)


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Version
    "__version__",
    
    # Core functions
    "get_scanner",
    "list_scanners",
    "get_scanner_info",
    
    # Category helpers
    "SCANNER_CATEGORIES",
    "get_scanners_by_category",
    "get_all_categories",
    
    # Convenience
    "ALL_SCANNER_NAMES",
    "SCANNER_COUNT",
]
