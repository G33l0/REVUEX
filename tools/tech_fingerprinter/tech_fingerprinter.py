#!/usr/bin/env python3
"""
REVUEX Tech-Fingerprinter GOLD v4.0
===================================
High-Confidence Technology Stack Detection via Invariants & Correlation.

Enhancements (v1.1):
- TLS & HTTP/2 invariants
- Passive WAF / CDN detection
- Header normalization behavior
- Framework vs Infrastructure separation
- Intelligence export for other GOLD tools

Design Philosophy:
- Passive only
- No fuzzing, no payloads
- Correlation > banners
- Confidence scoring (triager-defensible)

Techniques:
- Header Analysis (Server, X-Powered-By)
- Cookie Fingerprinting (Session names)
- Asset Pattern Detection (JS/CSS paths)
- Error Schema Analysis (JSON structure)
- TLS/SSL Analysis (Version, Cipher)
- WAF/CDN Detection (Signature headers)
- Meta Tag Analysis (Generator, Framework)
- Response Behavior Analysis
- Confidence Scoring

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import re
import ssl
import json
import socket
import hashlib
import argparse
import time
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.base_scanner import (
    BaseScanner,
    Finding,
    ScanResult,
    Severity,
    ScanStatus,
)
from core.utils import (
    print_success,
    print_error,
    print_warning,
    print_info,
)


# =============================================================================
# CONSTANTS
# =============================================================================

SCANNER_NAME = "Tech Fingerprinter GOLD"
SCANNER_VERSION = "1.1.0"

BANNER = r"""
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

Tech-Fingerprinter GOLD — Passive Stack Intelligence
"""

# Confidence threshold for confirmed detection
CONFIDENCE_THRESHOLD = 70

# Technology categories
class TechCategory(Enum):
    FRAMEWORK = "framework"
    INFRASTRUCTURE = "infrastructure"
    WAF_CDN = "waf_cdn"
    LANGUAGE = "language"
    CMS = "cms"
    DATABASE = "database"


# =============================================================================
# INVARIANT DATABASE
# =============================================================================

# Cookie-based fingerprints
COOKIE_FINGERPRINTS = {
    "django": ["csrftoken", "sessionid", "django_language"],
    "laravel": ["laravel_session", "XSRF-TOKEN"],
    "rails": ["_session_id", "_rails_session"],
    "express": ["connect.sid"],
    "spring": ["JSESSIONID"],
    "aspnet": [".AspNetCore", "ASP.NET_SessionId", ".AspNet.ApplicationCookie"],
    "flask": ["session"],
    "phoenix": ["_phoenix_session"],
    "play": ["PLAY_SESSION"],
    "tomcat": ["JSESSIONID"],
    "php": ["PHPSESSID"],
    "coldfusion": ["CFID", "CFTOKEN"],
}

# Header-based hints
HEADER_HINTS = {
    "nginx": ["nginx"],
    "apache": ["apache"],
    "iis": ["microsoft-iis", "asp.net"],
    "cloudflare": ["cloudflare"],
    "fastly": ["fastly"],
    "akamai": ["akamai"],
    "varnish": ["varnish"],
    "envoy": ["envoy"],
    "openresty": ["openresty"],
    "litespeed": ["litespeed"],
    "caddy": ["caddy"],
    "gunicorn": ["gunicorn"],
    "uvicorn": ["uvicorn"],
    "werkzeug": ["werkzeug"],
    "express": ["express"],
    "kestrel": ["kestrel"],
    "jetty": ["jetty"],
    "undertow": ["undertow"],
    "tomcat": ["tomcat", "coyote"],
}

# Asset path patterns
ASSET_PATTERNS = {
    "nextjs": [r"/_next/static/", r"/_next/image"],
    "nuxt": [r"/_nuxt/"],
    "react": [r"/static/js/main\.[a-f0-9]+", r"/static/js/\d+\.[a-f0-9]+\.chunk\.js"],
    "vue": [r"/js/app\.[a-f0-9]+", r"/js/chunk-vendors\.[a-f0-9]+"],
    "angular": [r"/main\.[a-f0-9]+\.js", r"/polyfills\.[a-f0-9]+\.js", r"/runtime\.[a-f0-9]+\.js"],
    "rails": [r"/assets/application-[a-f0-9]+"],
    "django": [r"/static/admin/", r"/static/rest_framework/"],
    "wordpress": [r"/wp-content/", r"/wp-includes/"],
    "drupal": [r"/sites/default/files/", r"/modules/system/"],
    "joomla": [r"/media/jui/", r"/templates/"],
    "magento": [r"/static/version\d+/", r"/pub/static/"],
    "shopify": [r"cdn\.shopify\.com"],
    "gatsby": [r"/static/[a-f0-9]+-[a-f0-9]+\.js"],
    "svelte": [r"/_app/immutable/"],
}

# Error response JSON schemas
ERROR_SCHEMAS = {
    "spring": {"timestamp", "status", "error", "path"},
    "spring_webflux": {"timestamp", "path", "status", "error", "requestId"},
    "dotnet": {"type", "title", "status", "traceId"},
    "dotnet_core": {"type", "title", "status", "detail"},
    "django": {"detail"},
    "django_rest": {"detail", "status_code"},
    "node_express": {"message", "stack"},
    "fastapi": {"detail"},
    "flask": {"message"},
    "rails": {"error", "status"},
    "laravel": {"message", "exception"},
}

# WAF/CDN header signatures
WAF_HEADERS = {
    "cloudflare": ["cf-ray", "cf-cache-status", "cf-request-id"],
    "akamai": ["akamai-x-cache", "x-akamai-transformed", "x-akamai-request-id"],
    "fastly": ["x-served-by", "x-cache", "x-cache-hits", "fastly-debug-digest"],
    "cloudfront": ["x-amz-cf-id", "x-amz-cf-pop"],
    "incapsula": ["x-iinfo", "x-cdn"],
    "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "stackpath": ["x-hw"],
    "varnish": ["x-varnish", "via"],
    "azure_cdn": ["x-azure-ref"],
    "google_cloud": ["x-goog-hash"],
}

# X-Powered-By patterns
POWERED_BY_PATTERNS = {
    "php": [r"PHP/[\d\.]+"],
    "aspnet": [r"ASP\.NET"],
    "express": [r"Express"],
    "next": [r"Next\.js"],
    "nuxt": [r"Nuxt"],
    "laravel": [r"Laravel"],
    "symfony": [r"Symfony"],
    "rails": [r"Phusion Passenger"],
    "jetbrains": [r"JetBrains"],
}

# Meta generator patterns
META_GENERATORS = {
    "wordpress": [r"WordPress\s*[\d\.]*"],
    "drupal": [r"Drupal\s*[\d\.]*"],
    "joomla": [r"Joomla"],
    "ghost": [r"Ghost\s*[\d\.]*"],
    "hugo": [r"Hugo\s*[\d\.]*"],
    "jekyll": [r"Jekyll"],
    "gatsby": [r"Gatsby"],
    "next": [r"Next\.js"],
    "nuxt": [r"Nuxt"],
    "wix": [r"Wix\.com"],
    "squarespace": [r"Squarespace"],
    "shopify": [r"Shopify"],
}


# =============================================================================
# TECH DETECTION RESULT DATACLASS
# =============================================================================

@dataclass
class TechDetection:
    """Result of a technology detection."""
    technology: str
    category: TechCategory
    confidence: int
    evidence: str
    version: Optional[str] = None


# =============================================================================
# TECH FINGERPRINTER GOLD CLASS
# =============================================================================

class TechFingerprinter(BaseScanner):
    """
    GOLD-tier Tech Fingerprinter with passive detection.
    
    Methodology:
    1. Collect HTTP responses passively
    2. Analyze headers for server hints
    3. Fingerprint cookies for framework detection
    4. Detect asset patterns for frontend frameworks
    5. Analyze error schemas
    6. Check TLS/SSL configuration
    7. Detect WAF/CDN presence
    8. Export intelligence for other tools
    
    Usage:
        scanner = TechFingerprinter(target="https://example.com")
        result = scanner.run()
        intel = scanner.get_intel()
    """
    
    def __init__(
        self,
        target: str,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
        check_tls: bool = True,
        **kwargs
    ):
        """
        Initialize Tech Fingerprinter.
        
        Args:
            target: Target URL
            confidence_threshold: Minimum confidence for confirmed detection
            check_tls: Perform TLS analysis
        """
        super().__init__(
            name="TechFingerprinter",
            description="Technology stack fingerprinter",
            target=target,
            **kwargs
        )
        
        self.confidence_threshold = confidence_threshold
        self.check_tls = check_tls
        
        # Detection state
        self.confidence: Dict[str, int] = {}
        self.responses: Dict[str, Any] = {}
        self.detections: List[TechDetection] = []
        
        # Intelligence export
        self.intel = {
            "frameworks": {},
            "infrastructure": {},
            "waf_cdn": {},
            "languages": {},
            "cms": {},
        }
        
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
        """Execute the GOLD tech fingerprinting scan."""
        self.logger.info(f"Starting Tech Fingerprinter GOLD")
        self.logger.info(f"Target: {self.target}")
        
        # Phase 1: Collect responses
        self.logger.info("Phase 1: Collecting passive HTTP responses...")
        self._collect_responses()
        
        # Phase 2: Header analysis
        self.logger.info("Phase 2: Analyzing headers...")
        self._analyze_headers()
        
        # Phase 3: Cookie analysis
        self.logger.info("Phase 3: Analyzing cookies...")
        self._analyze_cookies()
        
        # Phase 4: Asset analysis
        self.logger.info("Phase 4: Analyzing asset patterns...")
        self._analyze_assets()
        
        # Phase 5: Error schema analysis
        self.logger.info("Phase 5: Analyzing error schemas...")
        self._analyze_error_schemas()
        
        # Phase 6: Meta tag analysis
        self.logger.info("Phase 6: Analyzing meta tags...")
        self._analyze_meta_tags()
        
        # Phase 7: TLS analysis
        if self.check_tls:
            self.logger.info("Phase 7: Analyzing TLS/SSL...")
            self._analyze_tls()
        
        # Phase 8: WAF/CDN detection
        self.logger.info("Phase 8: Detecting WAF/CDN...")
        self._analyze_waf()
        
        # Phase 9: X-Powered-By analysis
        self.logger.info("Phase 9: Analyzing X-Powered-By...")
        self._analyze_powered_by()
        
        # Finalize
        self._finalize()
        self._export_intel()
        
        self.logger.info(f"Tech Fingerprinter complete. Detected {len(self.detections)} technologies")
    
    # =========================================================================
    # RESPONSE COLLECTION
    # =========================================================================
    
    def _collect_responses(self) -> None:
        """Collect HTTP responses passively."""
        parsed = urlparse(self.target)
        noise = hashlib.md5(self.target.encode()).hexdigest()[:6]
        
        # URLs to probe
        urls = [
            self.target,
            urljoin(self.target, f"/__tf_{noise}"),  # Trigger 404
            urljoin(self.target, "/robots.txt"),
            urljoin(self.target, "/favicon.ico"),
            urljoin(self.target, "/sitemap.xml"),
        ]
        
        for url in urls:
            self.rate_limiter.acquire()
            self.request_count += 1
            
            try:
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                self.responses[url] = response
                self.logger.debug(f"Collected: {url} ({response.status_code})")
            except Exception as e:
                self.logger.debug(f"Failed to collect {url}: {e}")
            
            time.sleep(self.delay)
        
        self.logger.info(f"Collected {len(self.responses)} responses")
    
    # =========================================================================
    # SCORING
    # =========================================================================
    
    def _score(self, tech: str, points: int, category: TechCategory, evidence: str, version: str = None) -> None:
        """Add confidence score for a technology."""
        self.confidence[tech] = self.confidence.get(tech, 0) + points
        
        # Update intel
        category_key = category.value + "s" if not category.value.endswith("s") else category.value
        if category_key not in self.intel:
            category_key = "frameworks"  # fallback
        self.intel.get(category_key, self.intel["frameworks"])[tech] = self.confidence[tech]
        
        # Create detection
        detection = TechDetection(
            technology=tech,
            category=category,
            confidence=self.confidence[tech],
            evidence=evidence,
            version=version
        )
        self.detections.append(detection)
    
    # =========================================================================
    # ANALYSIS MODULES
    # =========================================================================
    
    def _analyze_headers(self) -> None:
        """Analyze HTTP headers for technology hints."""
        for url, response in self.responses.items():
            # Check Server header
            server = response.headers.get("Server", "").lower()
            for tech, hints in HEADER_HINTS.items():
                if any(h in server for h in hints):
                    self._score(tech, 15, TechCategory.INFRASTRUCTURE, f"Server: {server}")
                    print_success(f"Header invariant → {tech}")
            
            # Check all header values
            for header, value in response.headers.items():
                value_lower = value.lower()
                for tech, hints in HEADER_HINTS.items():
                    if any(h in value_lower for h in hints):
                        if self.confidence.get(tech, 0) < 15:  # Avoid double counting
                            self._score(tech, 10, TechCategory.INFRASTRUCTURE, f"{header}: {value}")
                            print_success(f"Header invariant → {tech}")
    
    def _analyze_cookies(self) -> None:
        """Analyze cookies for framework fingerprints."""
        for url, response in self.responses.items():
            cookie_names = list(response.cookies.keys())
            
            for tech, names in COOKIE_FINGERPRINTS.items():
                if any(cookie in cookie_names for cookie in names):
                    matched = [c for c in names if c in cookie_names]
                    self._score(tech, 25, TechCategory.FRAMEWORK, f"Cookie: {', '.join(matched)}")
                    print_success(f"Cookie invariant → {tech}")
    
    def _analyze_assets(self) -> None:
        """Analyze asset patterns in HTML."""
        for url, response in self.responses.items():
            if response.status_code != 200:
                continue
            
            text = response.text
            for tech, patterns in ASSET_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, text):
                        self._score(tech, 20, TechCategory.FRAMEWORK, f"Asset pattern: {pattern}")
                        print_success(f"Asset invariant → {tech}")
                        break
    
    def _analyze_error_schemas(self) -> None:
        """Analyze JSON error response schemas."""
        for url, response in self.responses.items():
            if response.status_code < 400:
                continue
            
            try:
                data = response.json()
            except Exception:
                continue
            
            if isinstance(data, dict):
                keys = set(data.keys())
                for tech, schema in ERROR_SCHEMAS.items():
                    if schema.issubset(keys):
                        self._score(tech, 20, TechCategory.FRAMEWORK, f"Error schema: {schema}")
                        print_success(f"Error schema invariant → {tech}")
    
    def _analyze_meta_tags(self) -> None:
        """Analyze HTML meta tags for generators."""
        for url, response in self.responses.items():
            if response.status_code != 200:
                continue
            
            text = response.text
            
            # Check generator meta tag
            generator_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', text, re.I)
            if not generator_match:
                generator_match = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', text, re.I)
            
            if generator_match:
                generator = generator_match.group(1)
                for tech, patterns in META_GENERATORS.items():
                    for pattern in patterns:
                        match = re.search(pattern, generator, re.I)
                        if match:
                            version = re.search(r'[\d\.]+', generator)
                            self._score(
                                tech, 30, TechCategory.CMS,
                                f"Generator: {generator}",
                                version.group() if version else None
                            )
                            print_success(f"Meta generator → {tech}")
                            break
    
    def _analyze_tls(self) -> None:
        """Analyze TLS/SSL configuration."""
        parsed = urlparse(self.target)
        
        if parsed.scheme != "https":
            return
        
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((parsed.hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                    proto = ssock.version()
                    cipher = ssock.cipher()
                    
                    self._score(
                        proto, 10, TechCategory.INFRASTRUCTURE,
                        f"TLS: {proto}, Cipher: {cipher[0] if cipher else 'unknown'}"
                    )
                    print_success(f"TLS invariant → {proto}")
                    
                    # Get certificate info
                    cert = ssock.getpeercert()
                    if cert:
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        org = issuer.get('organizationName', '')
                        if 'Let\'s Encrypt' in org:
                            self._score("letsencrypt", 5, TechCategory.INFRASTRUCTURE, f"Cert issuer: {org}")
                        elif 'Cloudflare' in org:
                            self._score("cloudflare", 10, TechCategory.WAF_CDN, f"Cert issuer: {org}")
                            
        except Exception as e:
            self.logger.debug(f"TLS analysis failed: {e}")
    
    def _analyze_waf(self) -> None:
        """Detect WAF/CDN presence via headers."""
        for url, response in self.responses.items():
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            
            for waf, signature_headers in WAF_HEADERS.items():
                for sig_header in signature_headers:
                    if sig_header.lower() in headers_lower:
                        self._score(
                            waf, 25, TechCategory.WAF_CDN,
                            f"WAF header: {sig_header}"
                        )
                        print_success(f"WAF/CDN invariant → {waf}")
                        break
    
    def _analyze_powered_by(self) -> None:
        """Analyze X-Powered-By header."""
        for url, response in self.responses.items():
            powered_by = response.headers.get("X-Powered-By", "")
            
            if not powered_by:
                continue
            
            for tech, patterns in POWERED_BY_PATTERNS.items():
                for pattern in patterns:
                    match = re.search(pattern, powered_by, re.I)
                    if match:
                        version = re.search(r'[\d\.]+', powered_by)
                        self._score(
                            tech, 20, TechCategory.LANGUAGE,
                            f"X-Powered-By: {powered_by}",
                            version.group() if version else None
                        )
                        print_success(f"X-Powered-By → {tech}")
                        break
    
    # =========================================================================
    # FINALIZATION & EXPORT
    # =========================================================================
    
    def _finalize(self) -> None:
        """Finalize detection and create findings."""
        print(f"\n{'='*60}")
        print("DETECTION RESULTS")
        print(f"{'='*60}")
        
        # Sort by confidence
        sorted_techs = sorted(self.confidence.items(), key=lambda x: -x[1])
        
        for tech, score in sorted_techs:
            status = "CONFIRMED" if score >= self.confidence_threshold else "LIKELY"
            status_color = "\033[92m" if status == "CONFIRMED" else "\033[93m"
            reset = "\033[0m"
            print(f"  {status_color}{tech}: {score} ({status}){reset}")
            
            # Create finding for confirmed detections
            if score >= self.confidence_threshold:
                self._create_finding(tech, score)
    
    def _create_finding(self, tech: str, score: int) -> None:
        """Create finding for detected technology."""
        # Find the detection with evidence
        evidence_parts = []
        category = TechCategory.FRAMEWORK
        version = None
        
        for det in self.detections:
            if det.technology == tech:
                evidence_parts.append(det.evidence)
                category = det.category
                if det.version:
                    version = det.version
        
        finding = Finding(
            id=self._generate_finding_id(tech),
            title=f"Technology Detected: {tech.title()}" + (f" {version}" if version else ""),
            severity=Severity.LOW,  # Informational
            description=f"Detected {tech} with confidence score {score}. Category: {category.value}",
            url=self.target,
            parameter="N/A",
            method="GET",
            payload="N/A",
            evidence=" | ".join(evidence_parts[:3]),  # Limit evidence
            impact=self._get_impact(tech, category),
            remediation=self._get_remediation(tech),
            vulnerability_type="fingerprint",
            confidence="high" if score >= 80 else "medium",
        )
        self.add_finding(finding)
    
    def _get_impact(self, tech: str, category: TechCategory) -> str:
        """Get impact description."""
        return (
            f"Technology fingerprinting reveals {tech} ({category.value}):\n"
            "- Enables targeted vulnerability research\n"
            "- May expose version-specific weaknesses\n"
            "- Helps attackers craft specific exploits\n"
            "- Useful for security assessment scoping"
        )
    
    def _get_remediation(self, tech: str) -> str:
        """Get remediation recommendation."""
        return (
            "1. Remove or obfuscate version information in headers\n"
            "2. Customize error pages to avoid framework fingerprinting\n"
            "3. Use WAF rules to strip identifying headers\n"
            "4. Keep all software updated to latest versions\n"
            "5. Consider using security headers (X-Content-Type-Options, etc.)"
        )
    
    def _generate_finding_id(self, context: str) -> str:
        """Generate unique finding ID."""
        data = f"{self.target}:{context}:{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    def _export_intel(self) -> None:
        """Export intelligence for other tools."""
        print(f"\n{'='*60}")
        print("EXPORTABLE INTELLIGENCE")
        print(f"{'='*60}")
        print(json.dumps(self.intel, indent=2))
    
    def get_intel(self) -> Dict:
        """Get intelligence data for other GOLD tools."""
        return self.intel


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="revuex-tech-fingerprinter",
        description="REVUEX Tech-Fingerprinter GOLD - Passive Stack Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s -t https://example.com
    %(prog)s -t https://example.com --threshold 50 -v
    %(prog)s -t https://example.com --no-tls -o report.json

Author: REVUEX Team
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("--threshold", type=int, default=CONFIDENCE_THRESHOLD,
                        help=f"Confidence threshold (default: {CONFIDENCE_THRESHOLD})")
    parser.add_argument("--no-tls", action="store_true", help="Skip TLS analysis")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--delay", type=float, default=0.3, help="Request delay")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    return parser


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.quiet:
        print(BANNER)
        print(f"[+] Target: {args.target}\n")
    
    scanner = TechFingerprinter(
        target=args.target,
        confidence_threshold=args.threshold,
        check_tls=not args.no_tls,
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
        print(f"Technologies Detected: {len(scanner.confidence)}")
        print(f"Confirmed: {sum(1 for s in scanner.confidence.values() if s >= args.threshold)}")
        
        # Summary by category
        by_category: Dict[str, int] = {}
        for det in scanner.detections:
            cat = det.category.value
            by_category[cat] = by_category.get(cat, 0) + 1
        
        if by_category:
            print(f"\n[Category Summary]")
            for cat, count in by_category.items():
                print(f"  {cat}: {count}")
    
    if args.output:
        output_data = {
            "scanner": "REVUEX Tech Fingerprinter GOLD",
            "version": SCANNER_VERSION,
            "target": args.target,
            "scan_id": result.scan_id,
            "duration": result.duration_seconds,
            "intelligence": scanner.intel,
            "detections": [
                {
                    "technology": d.technology,
                    "category": d.category.value,
                    "confidence": d.confidence,
                    "evidence": d.evidence,
                    "version": d.version,
                }
                for d in scanner.detections
            ],
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                }
                for f in result.findings
            ]
        }
        
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        
        if not args.quiet:
            print(f"\nResults saved to: {args.output}")
    
    return 0  # Fingerprinting is informational


if __name__ == "__main__":
    sys.exit(main())
