#!/usr/bin/env python3
"""
REVUEX - Setup Configuration
============================

Professional bug bounty automation framework.

Installation:
    pip install -e .                    # Development install
    pip install .                       # Standard install
    pip install .[dev]                  # With dev dependencies
    pip install .[all]                  # All optional dependencies

Usage after install:
    revuex --help                       # Main CLI
    revuex-ssrf -t https://example.com  # Individual scanner
    python -m revuex.tools.ssrf         # Module execution

Author: REVUEX Team
License: MIT
"""

import os
import sys
from pathlib import Path

# Handle different setuptools versions
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
    # Development Status
    "Development Status :: 4 - Beta",
    
    # Intended Audience
    "Intended Audience :: Developers",
    "Intended Audience :: Information Technology",
    "Intended Audience :: Science/Research",
    
    # Topic
    "Topic :: Security",
    "Topic :: Internet :: WWW/HTTP",
    "Topic :: Software Development :: Testing",
    "Topic :: Software Development :: Quality Assurance",
    
    # License
    "License :: OSI Approved :: MIT License",
    
    # Operating System
    "Operating System :: OS Independent",
    "Operating System :: POSIX :: Linux",
    "Operating System :: Microsoft :: Windows",
    "Operating System :: MacOS",
    
    # Python Versions
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    
    # Environment
    "Environment :: Console",
    "Environment :: Web Environment",
    
    # Natural Language
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
    "httpretty>=1.1.0",
    
    # Code quality
    "black>=23.0.0",
    "isort>=5.12.0",
    "flake8>=6.0.0",
    "mypy>=1.0.0",
    "pylint>=2.16.0",
    
    # Documentation
    "sphinx>=6.0.0",
    "sphinx-rtd-theme>=1.2.0",
    "myst-parser>=1.0.0",
    
    # Build tools
    "build>=0.10.0",
    "twine>=4.0.0",
    "wheel>=0.40.0",
]

# Optional dependencies for advanced features
EXTRAS_REQUIRE = {
    # Development
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
        "pycryptodome>=3.17.0",
    ],
    
    # Enhanced parsing
    "parsing": [
        "xmltodict>=0.13.0",
        "cssselect>=1.2.0",
        "html5lib>=1.1",
        "chardet>=5.1.0",
    ],
    
    # Reporting
    "reporting": [
        "markdown>=3.4.0",
        "weasyprint>=58.0",  # PDF generation
        "pygments>=2.14.0",
    ],
    
    # APK analysis
    "android": [
        "androguard>=3.4.0",
    ],
    
    # Data analysis
    "analysis": [
        "pandas>=1.5.0",
        "numpy>=1.24.0",
    ],
    
    # Full installation
    "all": [
        # Include all optional deps
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
# ENTRY POINTS (CLI COMMANDS)
# =============================================================================

ENTRY_POINTS = {
    "console_scripts": [
        # Main CLI
        "revuex=revuex.cli:main",
        
        # Individual scanner CLIs
        "revuex-ssrf=revuex.tools.ssrf:main",
        "revuex-sqli=revuex.tools.sqli:main",
        "revuex-xss=revuex.tools.xss:main",
        "revuex-idor=revuex.tools.idor:main",
        "revuex-cors=revuex.tools.cors:main",
        "revuex-csrf=revuex.tools.csrf:main",
        "revuex-xxe=revuex.tools.xxe:main",
        "revuex-ssti=revuex.tools.ssti:main",
        "revuex-jwt=revuex.tools.jwt:main",
        "revuex-session=revuex.tools.session:main",
        "revuex-upload=revuex.tools.file_upload:main",
        "revuex-race=revuex.tools.race_condition:main",
        "revuex-logic=revuex.tools.business_logic:main",
        "revuex-price=revuex.tools.price_manipulation:main",
        "revuex-graphql=revuex.tools.graphql:main",
        "revuex-deps=revuex.tools.dependency:main",
        
        # Recon tools
        "revuex-subdomains=revuex.tools.subdomain_hunter:main",
        "revuex-tech=revuex.tools.tech_fingerprinter:main",
        "revuex-secrets=revuex.tools.js_secrets_miner:main",
        "revuex-apk=revuex.tools.apk:main",
    ],
}


# =============================================================================
# PACKAGE DATA
# =============================================================================

PACKAGE_DATA = {
    "revuex": [
        # Payload files
        "payloads/*.txt",
        "payloads/*.json",
        "payloads/**/*.txt",
        "payloads/**/*.json",
        
        # Templates
        "templates/*.html",
        "templates/*.md",
        "templates/*.jinja2",
        
        # Configuration
        "config/*.yaml",
        "config/*.yml",
        
        # Wordlists
        "wordlists/*.txt",
    ],
}

# Files to include in source distribution
DATA_FILES = [
    ("", ["README.md", "LICENSE", "requirements.txt"]),
]


# =============================================================================
# SETUP CONFIGURATION
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
        "Changelog": "https://github.com/revuex/revuex/blob/main/CHANGELOG.md",
    },
    
    # License
    license=LICENSE,
    
    # Classifiers
    classifiers=CLASSIFIERS,
    
    # Keywords for PyPI
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
        "security-tools",
        "recon",
        "automation",
    ],
    
    # Python version
    python_requires=PYTHON_REQUIRES,
    
    # Package discovery
    packages=find_packages(exclude=[
        "tests",
        "tests.*",
        "docs",
        "docs.*",
        "examples",
        "examples.*",
    ]),
    
    # Package data
    package_data=PACKAGE_DATA,
    include_package_data=True,
    
    # Data files
    data_files=DATA_FILES,
    
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
ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
â                                                                  â
â   âââââââ âââââââââââ   ââââââ   ââââââââââââââ  âââ            â
â   âââââââââââââââââââ   ââââââ   âââââââââââââââââââ            â
â   ââââââââââââââ  âââ   ââââââ   âââââââââ   ââââââ             â
â   ââââââââââââââ  ââââ âââââââ   âââââââââ   ââââââ             â
â   âââ  âââââââââââ âââââââ âââââââââââââââââââââ âââ            â
â   âââ  âââââââââââ  âââââ   âââââââ âââââââââââ  âââ            â
â                                                                  â
â          Bug Bounty Automation Framework v1.0.0                  â
â                                                                  â
â âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ£
â                                                                  â
â  Installation Complete!                                          â
â                                                                  â
â  Quick Start:                                                    â
â    revuex --help              Show all commands                  â
â    revuex scan -t TARGET      Run full scan                      â
â    revuex-ssrf -t TARGET      SSRF scanner                       â
â    revuex-sqli -t TARGET      SQL injection scanner              â
â                                                                  â
â  Documentation: https://docs.revuex.io                           â
â                                                                  â
â  â ï¸  LEGAL DISCLAIMER:                                           â
â  Only use on systems you have permission to test.                â
â  Unauthorized access to computer systems is illegal.             â
â                                                                  â
ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
""")
