#!/usr/bin/env python3
"""
REVUEX - Setup Configuration
============================

Professional bug bounty automation framework.

Installation:
    pip install -e .                    # Development install (editable)
    pip install .                       # Standard install
    pip install .[dev]                  # With development dependencies
    pip install .[full]                 # All optional dependencies

After Installation:
    revuex --help                       # Main CLI
    revuex scan -t https://example.com  # Full vulnerability scan
    python revuex_suite.py              # Direct execution

Author: REVUEX Team
License: MIT
"""

import os
import sys
from pathlib import Path

try:
    from setuptools import setup, find_packages
except ImportError:
    print("Error: setuptools is required. Install with: pip install setuptools")
    sys.exit(1)


# =============================================================================
# METADATA
# =============================================================================

NAME = "revuex"
VERSION = "1.0.0"
DESCRIPTION = "Professional Bug Bounty Automation Framework"
AUTHOR = "REVUEX Team"
AUTHOR_EMAIL = "security@revuex.io"
URL = "https://github.com/revuex/revuex"
LICENSE = "MIT"
PYTHON_REQUIRES = ">=3.8"

# Read long description from README
HERE = Path(__file__).parent
README_PATH = HERE / "README.md"
LONG_DESCRIPTION = ""
if README_PATH.exists():
    LONG_DESCRIPTION = README_PATH.read_text(encoding="utf-8")


# =============================================================================
# CLASSIFIERS
# =============================================================================

CLASSIFIERS = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "Intended Audience :: Information Technology",
    "Topic :: Security",
    "Topic :: Internet :: WWW/HTTP",
    "Topic :: Software Development :: Testing",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Operating System :: POSIX :: Linux",
    "Operating System :: Microsoft :: Windows",
    "Operating System :: MacOS",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Environment :: Console",
    "Natural Language :: English",
]


# =============================================================================
# DEPENDENCIES
# =============================================================================

# Core dependencies - required for basic functionality
INSTALL_REQUIRES = [
    # HTTP clients
    "requests>=2.28.0",
    "urllib3>=1.26.0",
    "httpx>=0.24.0",
    
    # HTML/XML parsing
    "beautifulsoup4>=4.11.0",
    "lxml>=4.9.0",
    
    # URL/Domain handling
    "tldextract>=3.4.0",
    "furl>=2.1.0",
    "validators>=0.20.0",
    
    # CLI and display
    "click>=8.1.0",
    "colorama>=0.4.6",
    "rich>=13.0.0",
    "tqdm>=4.64.0",
    "tabulate>=0.9.0",
    
    # Configuration
    "pyyaml>=6.0",
    "python-dotenv>=1.0.0",
    
    # JSON handling
    "orjson>=3.8.0",
    
    # Templating
    "jinja2>=3.1.0",
    
    # DNS
    "dnspython>=2.3.0",
]

# Development dependencies
DEV_REQUIRES = [
    # Testing
    "pytest>=7.2.0",
    "pytest-cov>=4.0.0",
    "pytest-asyncio>=0.20.0",
    "pytest-mock>=3.10.0",
    "responses>=0.22.0",
    
    # Code quality
    "black>=23.0.0",
    "isort>=5.12.0",
    "flake8>=6.0.0",
    "mypy>=1.0.0",
    
    # Documentation
    "sphinx>=6.0.0",
    "sphinx-rtd-theme>=1.2.0",
]

# Optional dependencies for advanced features
EXTRAS_REQUIRE = {
    "dev": DEV_REQUIRES,
    
    # Async support
    "async": [
        "aiohttp>=3.8.0",
        "aiofiles>=23.0.0",
        "aiodns>=3.0.0",
    ],
    
    # Advanced crypto/JWT
    "crypto": [
        "pyjwt>=2.6.0",
        "cryptography>=40.0.0",
    ],
    
    # Enhanced parsing
    "parsing": [
        "xmltodict>=0.13.0",
        "chardet>=5.1.0",
    ],
    
    # Reporting
    "reporting": [
        "markdown>=3.4.0",
        "pygments>=2.14.0",
    ],
    
    # APK analysis
    "android": [
        "androguard>=3.4.0",
    ],
    
    # Full installation with all optional deps
    "full": [
        "aiohttp>=3.8.0",
        "aiofiles>=23.0.0",
        "pyjwt>=2.6.0",
        "cryptography>=40.0.0",
        "xmltodict>=0.13.0",
        "markdown>=3.4.0",
        "chardet>=5.1.0",
    ],
}


# =============================================================================
# ENTRY POINTS
# =============================================================================

ENTRY_POINTS = {
    "console_scripts": [
        # Main entry point
        "revuex=revuex_suite:main",
        
        # Individual scanner CLIs (will be implemented in tools/)
        "revuex-ssrf=tools.ssrf:main",
        "revuex-sqli=tools.sqli:main",
        "revuex-xss=tools.xss:main",
        "revuex-idor=tools.idor:main",
        "revuex-cors=tools.cors:main",
        "revuex-csrf=tools.csrf:main",
        "revuex-xxe=tools.xxe:main",
        "revuex-ssti=tools.ssti:main",
        "revuex-jwt=tools.jwt_scanner:main",
        "revuex-session=tools.session:main",
        "revuex-upload=tools.file_upload:main",
        "revuex-race=tools.race_condition:main",
        "revuex-logic=tools.business_logic:main",
        "revuex-price=tools.price_manipulation:main",
        "revuex-graphql=tools.graphql:main",
        "revuex-deps=tools.dependency:main",
        "revuex-subdomains=tools.subdomain_hunter:main",
        "revuex-tech=tools.tech_fingerprinter:main",
        "revuex-secrets=tools.js_secrets_miner:main",
        "revuex-apk=tools.apk:main",
    ],
}


# =============================================================================
# PACKAGE DATA
# =============================================================================

PACKAGE_DATA = {
    "": [
        # Payload files
        "payloads/*.txt",
        "payloads/*.json",
        "payloads/**/*.txt",
        "payloads/**/*.json",
    ],
}


# =============================================================================
# SETUP
# =============================================================================

setup(
    # Basic info
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    
    # Author info
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    
    # URLs
    url=URL,
    project_urls={
        "Documentation": "https://docs.revuex.io",
        "Source": "https://github.com/revuex/revuex",
        "Bug Tracker": "https://github.com/revuex/revuex/issues",
    },
    
    # License
    license=LICENSE,
    
    # Classifiers
    classifiers=CLASSIFIERS,
    
    # Keywords
    keywords=[
        "security",
        "bug-bounty",
        "penetration-testing",
        "vulnerability-scanner",
        "web-security",
        "ssrf",
        "sqli",
        "xss",
        "idor",
        "owasp",
        "infosec",
        "appsec",
        "hacking",
        "recon",
    ],
    
    # Python version
    python_requires=PYTHON_REQUIRES,
    
    # Package discovery
    packages=find_packages(exclude=[
        "tests",
        "tests.*",
        "docs",
        "docs.*",
    ]),
    py_modules=["revuex_suite"],
    
    # Package data
    package_data=PACKAGE_DATA,
    include_package_data=True,
    
    # Dependencies
    install_requires=INSTALL_REQUIRES,
    extras_require=EXTRAS_REQUIRE,
    
    # Entry points
    entry_points=ENTRY_POINTS,
    
    # Zip safe
    zip_safe=False,
    
    # Platforms
    platforms=["any"],
)


# =============================================================================
# POST-INSTALL MESSAGE
# =============================================================================

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗            ║
║   ██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝            ║
║   ██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝             ║
║   ██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗             ║
║   ██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗            ║
║   ╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝            ║
║                                                                  ║
║          Bug Bounty Automation Framework v1.0.0                  ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Installation Complete!                                          ║
║                                                                  ║
║  Quick Start:                                                    ║
║    revuex --help              Show all commands                  ║
║    revuex scan -t TARGET      Run full vulnerability scan        ║
║    python revuex_suite.py     Direct execution                   ║
║                                                                  ║
║  Individual Scanners:                                            ║
║    revuex-ssrf -t TARGET      SSRF scanner                       ║
║    revuex-sqli -t TARGET      SQL injection scanner              ║
║    revuex-xss -t TARGET       XSS scanner                        ║
║    revuex-idor -t TARGET      IDOR scanner                       ║
║                                                                  ║
║  Documentation: https://docs.revuex.io                           ║
║                                                                  ║
║  ⚠️  LEGAL DISCLAIMER:                                           ║
║  Only use on systems you have permission to test.                ║
║  Unauthorized access to computer systems is illegal.             ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")
