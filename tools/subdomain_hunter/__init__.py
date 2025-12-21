#!/usr/bin/env python3
"""
REVUEX Subdomain Hunter
=======================

Research-Grade Subdomain Intelligence Engine for Bug Bounty Hunters.

Usage:
    from tools.subdomain_hunter import SubdomainHunter
    
    scanner = SubdomainHunter(domain="example.com")
    result = scanner.run()

Author: REVUEX Team
License: MIT
"""

from .subdomain_hunter import SubdomainHunter, main

__all__ = ["SubdomainHunter", "main"]
__version__ = "1.0.0"
