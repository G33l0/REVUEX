#!/usr/bin/env python3
"""
REVUEX Dependency GOLD v4.0
===========================
High-confidence Dependency and Component Risk Analyzer

Detection Philosophy:
- No exploitation
- Version fingerprinting
- Known vulnerability matching
- CVE correlation
- Confidence-based findings only

Core Techniques:
- Script tag analysis
- CDN URL parsing
- Version extraction from URLs
- Inline script fingerprinting
- NPM/CDN version detection
- Known vulnerable version matching
- Security header analysis

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import re
import json
import time
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urljoin, urlparse
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.base_scanner import BaseScanner, Finding, ScanResult, Severity, ScanStatus
from core.utils import print_success, print_error, print_warning, print_info

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


# =============================================================================
# CONSTANTS
# =============================================================================

SCANNER_NAME = "Dependency Scanner GOLD"
SCANNER_VERSION = "1.0.0"

BANNER = r"""
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

Dependency Scanner GOLD — Component Risk Analysis
"""

CONFIDENCE_THRESHOLD = 75

# Security-relevant libraries with known vulnerabilities
RISKY_LIBRARIES = {
    "jquery": {
        "risk": "XSS / Prototype Pollution",
        "severity": "high",
        "vulnerable_ranges": ["1.", "2.", "3.0", "3.1", "3.2", "3.3", "3.4.0", "3.4.1"],
        "safe_version": "3.7.0",
        "cves": ["CVE-2020-11022", "CVE-2020-11023", "CVE-2019-11358"]
    },
    "angular": {
        "risk": "Template Injection / Sandbox Escape",
        "severity": "critical",
        "vulnerable_ranges": ["1."],
        "safe_version": "1.8.3",
        "cves": ["CVE-2020-7676", "CVE-2019-14863"]
    },
    "angularjs": {
        "risk": "Template Injection / Sandbox Escape",
        "severity": "critical",
        "vulnerable_ranges": ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6"],
        "safe_version": "1.8.3",
        "cves": ["CVE-2020-7676"]
    },
    "lodash": {
        "risk": "Prototype Pollution",
        "severity": "high",
        "vulnerable_ranges": ["4.17.0", "4.17.1", "4.17.2", "4.17.3", "4.17.4", "4.17.5",
                              "4.17.6", "4.17.7", "4.17.8", "4.17.9", "4.17.10", "4.17.11",
                              "4.17.12", "4.17.13", "4.17.14", "4.17.15", "4.17.16", "4.17.17",
                              "4.17.18", "4.17.19", "4.17.20"],
        "safe_version": "4.17.21",
        "cves": ["CVE-2021-23337", "CVE-2020-28500", "CVE-2020-8203"]
    },
    "moment": {
        "risk": "ReDoS / Path Traversal",
        "severity": "medium",
        "vulnerable_ranges": ["2.19", "2.20", "2.21", "2.22", "2.23", "2.24", "2.25", "2.26", "2.27", "2.28", "2.29.0", "2.29.1"],
        "safe_version": "2.29.4",
        "cves": ["CVE-2022-24785", "CVE-2022-31129"]
    },
    "bootstrap": {
        "risk": "XSS",
        "severity": "medium",
        "vulnerable_ranges": ["3.0", "3.1", "3.2", "3.3", "3.4.0", "4.0", "4.1", "4.2", "4.3.0", "4.3.1"],
        "safe_version": "5.3.0",
        "cves": ["CVE-2019-8331", "CVE-2018-14041"]
    },
    "vue": {
        "risk": "XSS / Template Injection",
        "severity": "high",
        "vulnerable_ranges": ["2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6.0", "2.6.1", "2.6.2", "2.6.3", "2.6.4",
                              "2.6.5", "2.6.6", "2.6.7", "2.6.8", "2.6.9", "2.6.10"],
        "safe_version": "2.7.14",
        "cves": ["CVE-2021-46831"]
    },
    "react": {
        "risk": "XSS via dangerouslySetInnerHTML",
        "severity": "medium",
        "vulnerable_ranges": ["0.", "15.", "16.0", "16.1", "16.2", "16.3"],
        "safe_version": "18.2.0",
        "cves": []
    },
    "handlebars": {
        "risk": "Prototype Pollution / RCE",
        "severity": "critical",
        "vulnerable_ranges": ["4.0", "4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7.0", "4.7.1", "4.7.2", "4.7.3", "4.7.4", "4.7.5", "4.7.6"],
        "safe_version": "4.7.7",
        "cves": ["CVE-2021-23369", "CVE-2021-23383", "CVE-2019-19919"]
    },
    "dompurify": {
        "risk": "XSS Bypass",
        "severity": "high",
        "vulnerable_ranges": ["2.0", "2.1", "2.2.0", "2.2.1", "2.2.2", "2.2.3", "2.2.4", "2.2.5", "2.2.6", "2.2.7", "2.2.8", "2.2.9"],
        "safe_version": "3.0.0",
        "cves": ["CVE-2022-23992"]
    },
    "axios": {
        "risk": "SSRF / Header Injection",
        "severity": "high",
        "vulnerable_ranges": ["0."],
        "safe_version": "1.4.0",
        "cves": ["CVE-2023-45857"]
    },
    "underscore": {
        "risk": "Arbitrary Code Execution",
        "severity": "critical",
        "vulnerable_ranges": ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9", "1.10", "1.11", "1.12.0"],
        "safe_version": "1.13.6",
        "cves": ["CVE-2021-23358"]
    },
    "serialize-javascript": {
        "risk": "RCE via deserialization",
        "severity": "critical",
        "vulnerable_ranges": ["1.", "2.", "3.0", "3.1.0"],
        "safe_version": "6.0.0",
        "cves": ["CVE-2020-7660"]
    },
    "highlight.js": {
        "risk": "ReDoS",
        "severity": "medium",
        "vulnerable_ranges": ["9.", "10.0", "10.1", "10.2", "10.3", "10.4.0", "10.4.1"],
        "safe_version": "11.0.0",
        "cves": ["CVE-2020-26237"]
    },
    "marked": {
        "risk": "ReDoS / XSS",
        "severity": "high",
        "vulnerable_ranges": ["0.", "1.", "2.", "3.", "4.0.0", "4.0.1", "4.0.2", "4.0.3", "4.0.4", "4.0.5", "4.0.6", "4.0.7", "4.0.8", "4.0.9", "4.0.10", "4.0.11"],
        "safe_version": "4.3.0",
        "cves": ["CVE-2022-21681", "CVE-2022-21680"]
    }
}

# Patterns to extract library names and versions from URLs
LIBRARY_PATTERNS = [
    # CDN patterns
    (r"/(jquery|angular|lodash|moment|bootstrap|vue|react|handlebars|dompurify|axios|underscore|highlight\.?js|marked)[\.-]?([\d\.]+)?(?:\.min)?\.js", None),
    # NPM CDN patterns
    (r"npm/(jquery|angular|lodash|moment|bootstrap|vue|react|handlebars|dompurify|axios|underscore|highlight\.?js|marked)@([\d\.]+)", None),
    # unpkg patterns
    (r"unpkg\.com/(jquery|angular|lodash|moment|bootstrap|vue|react|handlebars|dompurify|axios|underscore|highlight\.?js|marked)@([\d\.]+)", None),
    # cdnjs patterns
    (r"cdnjs\.cloudflare\.com/ajax/libs/(jquery|angular|lodash|moment|bootstrap|vue|react|handlebars|dompurify|axios|underscore|highlight\.?js|marked)/([\d\.]+)", None),
    # jsdelivr patterns
    (r"jsdelivr\.net/npm/(jquery|angular|lodash|moment|bootstrap|vue|react|handlebars|dompurify|axios|underscore|highlight\.?js|marked)@([\d\.]+)", None),
]


# =============================================================================
# DEPENDENCY CHECK RESULT DATACLASS
# =============================================================================

@dataclass
class DependencyCheckResult:
    """Result of a single dependency check."""
    library: str
    version: str
    severity: Severity
    confidence_score: int
    risk: str
    evidence: Dict[str, Any]
    is_vulnerable: bool
    cves: List[str]


# =============================================================================
# DEPENDENCY SCANNER GOLD CLASS
# =============================================================================

class DependencyScanner(BaseScanner):
    """
    GOLD-tier Dependency and Component Risk Analyzer.
    
    Methodology:
    1. Fetch target page
    2. Extract script tags
    3. Analyze CDN URLs for library/version
    4. Fetch and analyze inline scripts
    5. Match against known vulnerable versions
    6. Report with confidence scoring
    """
    
    def __init__(
        self,
        target: str,
        custom_headers: Optional[Dict[str, str]] = None,
        deep_scan: bool = False,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
        **kwargs
    ):
        """
        Initialize Dependency Scanner.
        
        Args:
            target: Target URL
            custom_headers: Custom HTTP headers
            deep_scan: Fetch and analyze script contents
            confidence_threshold: Minimum confidence for findings
        """
        super().__init__(
            name="DependencyScanner",
            description="Dependency vulnerability checker",
            target=target,
            **kwargs
        )
        
        self.custom_headers = custom_headers or {}
        self.deep_scan = deep_scan
        self.confidence_threshold = confidence_threshold
        
        # State tracking
        self.check_results: List[DependencyCheckResult] = []
        self.total_confidence: int = 0
        self.discovered_libraries: Dict[str, str] = {}
        self.analyzed_scripts: Set[str] = set()
        
        # Scanner info
        self.scanner_name = SCANNER_NAME
        self.scanner_version = SCANNER_VERSION
    
    def _validate_target(self) -> bool:
        """Validate target is accessible."""
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            return response.status_code < 500
        except Exception:
            return False
    
    def scan(self) -> None:
        """Execute the GOLD dependency scan."""
        self.logger.info(f"Starting Dependency GOLD scan")
        self.logger.info(f"Target: {self.target}")
        
        # Phase 1: Fetch target page
        self.logger.info("Phase 1: Fetching target page...")
        html = self._fetch_page()
        
        if not html:
            self.logger.error("Failed to fetch target page - aborting")
            return
        
        # Phase 2: Extract and analyze script tags
        self.logger.info("Phase 2: Analyzing script tags...")
        self._analyze_script_tags(html)
        
        # Phase 3: Analyze inline scripts
        self.logger.info("Phase 3: Analyzing inline scripts...")
        self._analyze_inline_scripts(html)
        
        # Phase 4: Deep scan (fetch script contents)
        if self.deep_scan:
            self.logger.info("Phase 4: Deep scanning script contents...")
            self._deep_scan_scripts(html)
        
        # Phase 5: Check for SRI (Subresource Integrity)
        self.logger.info("Phase 5: Checking Subresource Integrity...")
        self._check_sri(html)
        
        # Phase 6: Summarize findings
        self._summarize()
        
        self.logger.info(f"Dependency scan complete. Found {len(self.findings)} issue(s)")
    
    # =========================================================================
    # PAGE FETCHING
    # =========================================================================
    
    def _fetch_page(self) -> Optional[str]:
        """Fetch target page HTML."""
        try:
            self.rate_limiter.acquire()
            self.request_count += 1
            
            response = self.session.get(
                self.target,
                headers=self.custom_headers,
                timeout=self.timeout
            )
            
            print_info(f"Fetched page: {response.status_code}, {len(response.text)} bytes")
            time.sleep(self.delay)
            
            return response.text
            
        except Exception as e:
            self.logger.error(f"Page fetch error: {e}")
            return None
    
    # =========================================================================
    # SCRIPT TAG ANALYSIS
    # =========================================================================
    
    def _analyze_script_tags(self, html: str) -> None:
        """Analyze external script tags."""
        if HAS_BS4:
            soup = BeautifulSoup(html, "html.parser")
            scripts = soup.find_all("script", src=True)
            
            for script in scripts:
                src = script.get("src", "")
                self._analyze_script_url(src)
        else:
            # Fallback regex
            script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
            for match in script_pattern.finditer(html):
                self._analyze_script_url(match.group(1))
    
    def _analyze_script_url(self, src: str) -> None:
        """Analyze a script URL for library/version."""
        if src in self.analyzed_scripts:
            return
        self.analyzed_scripts.add(src)
        
        full_url = urljoin(self.target, src)
        
        # Try to extract library and version
        library, version = self._extract_library_version(src)
        
        if not library:
            return
        
        # Normalize library name
        library = library.lower().replace(".", "").replace("-", "")
        if library == "highlightjs":
            library = "highlight.js"
        
        if library not in RISKY_LIBRARIES:
            return
        
        self.discovered_libraries[library] = version or "unknown"
        
        # Calculate confidence and check vulnerability
        self._check_library_vulnerability(library, version, src)
    
    def _extract_library_version(self, src: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract library name and version from URL."""
        for pattern, _ in LIBRARY_PATTERNS:
            match = re.search(pattern, src, re.IGNORECASE)
            if match:
                return match.group(1), match.group(2) if len(match.groups()) > 1 else None
        
        # Fallback: simple name extraction
        for lib in RISKY_LIBRARIES.keys():
            if lib in src.lower():
                # Try to find version
                version_match = re.search(r'[\.-]([\d]+\.[\d]+(?:\.[\d]+)?)', src)
                version = version_match.group(1) if version_match else None
                return lib, version
        
        return None, None
    
    def _check_library_vulnerability(self, library: str, version: Optional[str], source: str) -> None:
        """Check if library version is vulnerable."""
        lib_info = RISKY_LIBRARIES.get(library)
        if not lib_info:
            return
        
        confidence = 25  # Base: detected in production
        evidence = {
            "source": source,
            "library": library
        }
        
        if version:
            confidence += 25
            evidence["version"] = version
            
            # Check vulnerable ranges
            is_vulnerable = any(version.startswith(v) for v in lib_info["vulnerable_ranges"])
            
            if is_vulnerable:
                confidence += 30
                evidence["vulnerable_range"] = True
                evidence["safe_version"] = lib_info["safe_version"]
                evidence["cves"] = lib_info["cves"]
        else:
            evidence["version"] = "unknown"
        
        # Security-sensitive library bonus
        confidence += 20
        
        # Determine severity
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM
        }
        severity = severity_map.get(lib_info["severity"], Severity.MEDIUM)
        
        if confidence >= self.confidence_threshold:
            self._add_check_result(
                library=library,
                version=version or "unknown",
                severity=severity,
                confidence_score=confidence,
                risk=lib_info["risk"],
                evidence=evidence,
                is_vulnerable=evidence.get("vulnerable_range", False),
                cves=lib_info.get("cves", [])
            )
    
    # =========================================================================
    # INLINE SCRIPT ANALYSIS
    # =========================================================================
    
    def _analyze_inline_scripts(self, html: str) -> None:
        """Analyze inline scripts for library fingerprints."""
        if HAS_BS4:
            soup = BeautifulSoup(html, "html.parser")
            scripts = soup.find_all("script", src=False)
            
            for script in scripts:
                content = script.string or ""
                self._fingerprint_inline_script(content)
        else:
            # Fallback regex
            script_pattern = re.compile(r'<script[^>]*>([^<]*)</script>', re.IGNORECASE | re.DOTALL)
            for match in script_pattern.finditer(html):
                self._fingerprint_inline_script(match.group(1))
    
    def _fingerprint_inline_script(self, content: str) -> None:
        """Fingerprint inline script for library usage."""
        # jQuery fingerprints
        if "jQuery" in content or "$.fn" in content:
            if "jquery" not in self.discovered_libraries:
                # Try to extract version from content
                version_match = re.search(r'jQuery\s+v?([\d\.]+)', content)
                version = version_match.group(1) if version_match else None
                self._check_library_vulnerability("jquery", version, "inline_script")
        
        # Angular fingerprints
        if "angular.module" in content or "ng-app" in content:
            if "angular" not in self.discovered_libraries:
                version_match = re.search(r'angular[^\d]*([\d\.]+)', content)
                version = version_match.group(1) if version_match else None
                self._check_library_vulnerability("angular", version, "inline_script")
        
        # Vue fingerprints
        if "Vue.component" in content or "new Vue" in content:
            if "vue" not in self.discovered_libraries:
                version_match = re.search(r'Vue[^\d]*([\d\.]+)', content)
                version = version_match.group(1) if version_match else None
                self._check_library_vulnerability("vue", version, "inline_script")
        
        # React fingerprints
        if "React.createElement" in content or "ReactDOM" in content:
            if "react" not in self.discovered_libraries:
                version_match = re.search(r'React[^\d]*([\d\.]+)', content)
                version = version_match.group(1) if version_match else None
                self._check_library_vulnerability("react", version, "inline_script")
    
    # =========================================================================
    # DEEP SCAN
    # =========================================================================
    
    def _deep_scan_scripts(self, html: str) -> None:
        """Fetch and analyze external script contents."""
        if HAS_BS4:
            soup = BeautifulSoup(html, "html.parser")
            scripts = soup.find_all("script", src=True)
            
            for script in scripts[:20]:  # Limit to 20 scripts
                src = script.get("src", "")
                self._fetch_and_analyze_script(src)
    
    def _fetch_and_analyze_script(self, src: str) -> None:
        """Fetch and analyze a single script."""
        # Skip CDNs we already analyzed via URL
        if any(cdn in src for cdn in ["cdnjs", "jsdelivr", "unpkg"]):
            return
        
        full_url = urljoin(self.target, src)
        
        try:
            self.rate_limiter.acquire()
            response = self.session.get(full_url, timeout=self.timeout)
            content = response.text
            
            # Look for version comments
            version_patterns = [
                r'/\*!?\s*(jQuery|Angular|Lodash|Moment|Bootstrap|Vue|React)\s+v?([\d\.]+)',
                r'\*\s*@version\s+([\d\.]+)',
                r'VERSION\s*[=:]\s*["\']?([\d\.]+)',
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, content[:5000], re.IGNORECASE)
                if match:
                    if len(match.groups()) == 2:
                        lib, version = match.group(1).lower(), match.group(2)
                        if lib in RISKY_LIBRARIES:
                            self._check_library_vulnerability(lib, version, full_url)
            
            time.sleep(self.delay)
            
        except Exception as e:
            self.logger.debug(f"Script fetch error: {e}")
    
    # =========================================================================
    # SRI CHECK
    # =========================================================================
    
    def _check_sri(self, html: str) -> None:
        """Check for Subresource Integrity usage."""
        if not HAS_BS4:
            return
        
        soup = BeautifulSoup(html, "html.parser")
        scripts = soup.find_all("script", src=True)
        
        scripts_without_sri = []
        
        for script in scripts:
            src = script.get("src", "")
            integrity = script.get("integrity")
            
            # Check external CDN scripts
            if any(cdn in src for cdn in ["cdnjs", "jsdelivr", "unpkg", "googleapis"]):
                if not integrity:
                    scripts_without_sri.append(src)
        
        if scripts_without_sri:
            print_info(f"Found {len(scripts_without_sri)} CDN script(s) without SRI")
    
    # =========================================================================
    # RESULT HANDLING
    # =========================================================================
    
    def _add_check_result(self, library: str, version: str, severity: Severity, confidence_score: int, risk: str, evidence: Dict[str, Any], is_vulnerable: bool, cves: List[str]) -> None:
        """Add a check result and create finding."""
        # Deduplicate
        for existing in self.check_results:
            if existing.library == library:
                return
        
        result = DependencyCheckResult(
            library=library,
            version=version,
            severity=severity,
            confidence_score=confidence_score,
            risk=risk,
            evidence=evidence,
            is_vulnerable=is_vulnerable,
            cves=cves
        )
        self.check_results.append(result)
        self.total_confidence += confidence_score
        self._create_finding(result)
        print_success(f"{library} {version}: {risk} (+{confidence_score})")
    
    def _create_finding(self, result: DependencyCheckResult) -> None:
        """Create finding from check result."""
        finding = Finding(
            id=self._generate_finding_id(result.library),
            title=f"Vulnerable Library: {result.library} {result.version}",
            severity=result.severity,
            description=f"Detected {result.library} version {result.version} with known security risk: {result.risk}",
            url=self.target,
            parameter=result.library,
            method="GET",
            payload=result.version,
            evidence=json.dumps(result.evidence, indent=2),
            impact=self._get_impact(result),
            remediation=self._get_remediation(result),
            vulnerability_type="vulnerable_dependency",
            confidence="high" if result.confidence_score >= 80 else "medium",
        )
        self.add_finding(finding)
    
    def _get_impact(self, result: DependencyCheckResult) -> str:
        """Get impact description."""
        cve_str = ", ".join(result.cves[:3]) if result.cves else "No specific CVE"
        
        if result.severity == Severity.CRITICAL:
            return (
                f"CRITICAL: {result.library} {result.version} is vulnerable to {result.risk}\n"
                f"CVEs: {cve_str}\n"
                "May enable remote code execution or complete compromise"
            )
        elif result.severity == Severity.HIGH:
            return (
                f"HIGH: {result.library} {result.version} is vulnerable to {result.risk}\n"
                f"CVEs: {cve_str}\n"
                "May enable XSS, data theft, or privilege escalation"
            )
        return f"MEDIUM: {result.library} {result.version} has known security issues"
    
    def _get_remediation(self, result: DependencyCheckResult) -> str:
        """Get remediation guidance."""
        lib_info = RISKY_LIBRARIES.get(result.library, {})
        safe_version = lib_info.get("safe_version", "latest")
        
        return (
            f"1. Upgrade {result.library} to version {safe_version} or later\n"
            "2. Implement Subresource Integrity (SRI) for CDN scripts\n"
            "3. Use automated dependency scanning in CI/CD\n"
            "4. Consider using npm audit or Snyk for monitoring\n"
            "5. Keep all frontend dependencies up to date"
        )
    
    def _summarize(self) -> None:
        """Summarize discovered libraries."""
        if self.discovered_libraries:
            print_info(f"\n[Discovered Libraries]")
            for lib, version in self.discovered_libraries.items():
                status = "⚠️  VULNERABLE" if any(r.library == lib and r.is_vulnerable for r in self.check_results) else "✓"
                print_info(f"  {lib}: {version} {status}")
    
    def _generate_finding_id(self, context: str) -> str:
        """Generate unique finding ID."""
        data = f"{self.target}:{context}:{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(prog="revuex-dependency", description="REVUEX Dependency GOLD - Component Risk Analyzer")
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-H", "--header", action="append", help="Custom headers (Key:Value)")
    parser.add_argument("--deep", action="store_true", help="Deep scan (fetch script contents)")
    parser.add_argument("--threshold", type=int, default=CONFIDENCE_THRESHOLD, help=f"Confidence threshold (default: {CONFIDENCE_THRESHOLD})")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--delay", type=float, default=0.5, help="Request delay")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    return parser


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    custom_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()
    
    if not args.quiet:
        print(BANNER)
        print(f"[+] Target: {args.target}")
        if args.deep:
            print(f"[+] Deep scan enabled")
        print()
    
    scanner = DependencyScanner(
        target=args.target,
        custom_headers=custom_headers,
        deep_scan=args.deep,
        confidence_threshold=args.threshold,
        delay=args.delay,
        timeout=args.timeout,
        verbose=args.verbose,
    )
    
    result = scanner.run()
    
    if not args.quiet:
        print(f"\n{'='*60}")
        print("SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"Target: {args.target}")
        print(f"Duration: {result.duration_seconds:.2f}s")
        print(f"Libraries Found: {len(scanner.discovered_libraries)}")
        print(f"Vulnerable: {sum(1 for r in scanner.check_results if r.is_vulnerable)}")
        print(f"Total Confidence: {scanner.total_confidence}")
    
    if args.output:
        output_data = {
            "scanner": SCANNER_NAME,
            "version": SCANNER_VERSION,
            "target": args.target,
            "libraries": scanner.discovered_libraries,
            "findings": [
                {
                    "id": f.id,
                    "library": f.parameter,
                    "version": f.payload,
                    "severity": f.severity.value
                }
                for f in result.findings
            ]
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        if not args.quiet:
            print(f"\nResults saved to: {args.output}")
    
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
