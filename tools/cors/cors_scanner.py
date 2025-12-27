#!/usr/bin/env python3
"""
REVUEX CORS GOLD v4.0
=====================
High-confidence CORS Misconfiguration Scanner

Detection Philosophy:
- No exploitation
- Origin reflection detection
- Wildcard with credentials check
- Subdomain bypass testing
- Null origin testing
- Regex bypass patterns
- Confidence-based findings only

Core Techniques:
- External origin reflection
- Subdomain-based bypasses
- Null origin acceptance
- Wildcard misconfiguration
- Prefix/suffix bypasses
- Protocol downgrade testing
- Pre-domain bypass
- Post-domain bypass

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import re
import json
import time
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.base_scanner import BaseScanner, Finding, ScanResult, Severity, ScanStatus
from core.utils import print_success, print_error, print_warning, print_info


# =============================================================================
# CONSTANTS
# =============================================================================

SCANNER_NAME = "CORS Scanner GOLD"
SCANNER_VERSION = "4.0.0"

BANNER = r"""
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

CORS Scanner GOLD - A Cross-Origin Resource Sharing Analysis
"""

CONFIDENCE_THRESHOLD = 80

# Basic external origins to test
EXTERNAL_ORIGINS = [
    "https://evil.com",
    "https://attacker.example",
    "https://malicious.site",
    "http://evil.com",
]

# Null origin test
NULL_ORIGIN = "null"

# Subdomain bypass patterns
SUBDOMAIN_PATTERNS = [
    "https://evil.{domain}",           # Subdomain injection
    "https://{domain}.evil.com",       # Domain as subdomain
    "https://{domain}evil.com",        # Suffix bypass
    "https://evil{domain}",            # Prefix bypass
]

# Regex bypass patterns
REGEX_BYPASS_PATTERNS = [
    "https://{domain}.attacker.com",   # Domain prefix
    "https://attacker.com.{domain}",   # Attacker as subdomain
    "https://{domain}%60.evil.com",    # Backtick encoding
    "https://{domain}%0d.evil.com",    # CRLF injection
]

# Protocol downgrade patterns
PROTOCOL_PATTERNS = [
    "http://{domain}",                 # HTTP downgrade
]


# =============================================================================
# CORS CHECK RESULT DATACLASS
# =============================================================================

@dataclass
class CORSCheckResult:
    """Result of a single CORS check."""
    check_name: str
    endpoint: str
    origin: str
    severity: Severity
    confidence_score: int
    evidence: Dict[str, Any]
    is_vulnerable: bool


# =============================================================================
# CORS SCANNER GOLD CLASS
# =============================================================================

class CORSScanner(BaseScanner):
    """
    GOLD-tier CORS Misconfiguration Scanner.
    
    Methodology:
    1. Test external origin reflection
    2. Test null origin acceptance
    3. Test subdomain bypass patterns
    4. Test regex bypass patterns
    5. Test wildcard with credentials
    6. Test protocol downgrade
    7. Report with confidence scoring
    """
    
    def __init__(
        self,
        target: str,
        custom_origins: Optional[List[str]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
        **kwargs
    ):
        """
        Initialize CORS Scanner.
        
        Args:
            target: Target URL to test
            custom_origins: Additional origins to test
            custom_headers: Custom HTTP headers
            confidence_threshold: Minimum confidence for findings
        """
        super().__init__(
            name="CORSScanner",
            description="CORS misconfiguration scanner",
            target=target,
            **kwargs
        )
        
        self.custom_origins = custom_origins or []
        self.custom_headers = custom_headers or {}
        self.confidence_threshold = confidence_threshold
        
        # Extract domain info
        parsed = urlparse(target)
        self.base_domain = parsed.netloc
        self.scheme = parsed.scheme
        
        # State tracking
        self.check_results: List[CORSCheckResult] = []
        self.total_confidence: int = 0
        self.baseline_response = None
        
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
        """Execute the GOLD CORS scan."""
        self.logger.info(f"Starting CORS GOLD scan")
        self.logger.info(f"Target: {self.target}")
        self.logger.info(f"Domain: {self.base_domain}")
        
        # Phase 1: Capture baseline
        self.logger.info("Phase 1: Capturing baseline response...")
        self._capture_baseline()
        
        # Phase 2: Test external origins
        self.logger.info("Phase 2: Testing external origins...")
        self._test_external_origins()
        
        # Phase 3: Test null origin
        self.logger.info("Phase 3: Testing null origin...")
        self._test_null_origin()
        
        # Phase 4: Test subdomain bypasses
        self.logger.info("Phase 4: Testing subdomain bypasses...")
        self._test_subdomain_bypasses()
        
        # Phase 5: Test regex bypasses
        self.logger.info("Phase 5: Testing regex bypasses...")
        self._test_regex_bypasses()
        
        # Phase 6: Test protocol downgrade
        self.logger.info("Phase 6: Testing protocol downgrade...")
        self._test_protocol_downgrade()
        
        # Phase 7: Test pre-flight requests
        self.logger.info("Phase 7: Testing pre-flight requests...")
        self._test_preflight()
        
        # Phase 8: Test custom origins
        if self.custom_origins:
            self.logger.info("Phase 8: Testing custom origins...")
            for origin in self.custom_origins:
                self._test_origin(origin, "custom")
        
        self.logger.info(f"CORS scan complete. Found {len(self.findings)} issue(s)")
    
    # =========================================================================
    # BASELINE CAPTURE
    # =========================================================================
    
    def _capture_baseline(self) -> None:
        """Capture baseline response without Origin header."""
        try:
            self.rate_limiter.acquire()
            response = self.session.get(
                self.target,
                headers=self.custom_headers,
                timeout=self.timeout
            )
            self.baseline_response = {
                "status": response.status_code,
                "acao": response.headers.get("Access-Control-Allow-Origin"),
                "acac": response.headers.get("Access-Control-Allow-Credentials"),
            }
            print_info(f"Baseline ACAO: {self.baseline_response['acao']}")
            time.sleep(self.delay)
        except Exception as e:
            self.logger.debug(f"Baseline capture error: {e}")
    
    # =========================================================================
    # ORIGIN TESTING
    # =========================================================================
    
    def _test_origin(self, origin: str, test_type: str) -> None:
        """Test a single origin."""
        self.rate_limiter.acquire()
        self._request_count += 1
        
        headers = {**self.custom_headers, "Origin": origin}
        
        try:
            response = self.session.get(
                self.target,
                headers=headers,
                timeout=self.timeout
            )
            
            acao = response.headers.get("Access-Control-Allow-Origin")
            acac = response.headers.get("Access-Control-Allow-Credentials")
            acam = response.headers.get("Access-Control-Allow-Methods")
            acah = response.headers.get("Access-Control-Allow-Headers")
            
            confidence = 0
            evidence = {
                "origin_sent": origin,
                "test_type": test_type
            }
            
            # ACAO present
            if acao:
                confidence += 30
                evidence["acao"] = acao
            
            # Origin reflected exactly
            if acao == origin:
                confidence += 30
                evidence["origin_reflected"] = True
            
            # Wildcard with credentials (critical)
            if acao == "*" and acac and acac.lower() == "true":
                confidence += 40
                evidence["wildcard_with_credentials"] = True
            
            # Credentials allowed
            if acac and acac.lower() == "true":
                confidence += 30
                evidence["credentials_allowed"] = True
            
            # Cross-origin confirmation
            if acao and origin not in self.target and acao != "*":
                confidence += 20
                evidence["cross_origin_accepted"] = True
            
            # Determine severity
            if evidence.get("wildcard_with_credentials"):
                severity = Severity.CRITICAL
            elif evidence.get("origin_reflected") and evidence.get("credentials_allowed"):
                severity = Severity.CRITICAL
            elif evidence.get("origin_reflected"):
                severity = Severity.HIGH
            elif evidence.get("credentials_allowed"):
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM
            
            time.sleep(self.delay)
            
            if confidence >= self.confidence_threshold:
                self._add_check_result(
                    f"CORS Misconfiguration ({test_type})",
                    self.target,
                    origin,
                    severity,
                    confidence,
                    evidence,
                    True
                )
                
        except Exception as e:
            self.logger.debug(f"Origin test error: {e}")
    
    def _test_external_origins(self) -> None:
        """Test external origin reflection."""
        for origin in EXTERNAL_ORIGINS:
            self._test_origin(origin, "external")
    
    def _test_null_origin(self) -> None:
        """Test null origin acceptance."""
        self._test_origin(NULL_ORIGIN, "null")
    
    def _test_subdomain_bypasses(self) -> None:
        """Test subdomain-based bypass patterns."""
        for pattern in SUBDOMAIN_PATTERNS:
            origin = pattern.format(domain=self.base_domain)
            self._test_origin(origin, "subdomain_bypass")
    
    def _test_regex_bypasses(self) -> None:
        """Test regex bypass patterns."""
        for pattern in REGEX_BYPASS_PATTERNS:
            origin = pattern.format(domain=self.base_domain)
            self._test_origin(origin, "regex_bypass")
    
    def _test_protocol_downgrade(self) -> None:
        """Test HTTP protocol downgrade."""
        if self.scheme == "https":
            for pattern in PROTOCOL_PATTERNS:
                origin = pattern.format(domain=self.base_domain)
                self._test_origin(origin, "protocol_downgrade")
    
    # =========================================================================
    # PREFLIGHT TESTING
    # =========================================================================
    
    def _test_preflight(self) -> None:
        """Test CORS preflight requests."""
        self.rate_limiter.acquire()
        self._request_count += 1
        
        headers = {
            **self.custom_headers,
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "X-Custom-Header"
        }
        
        try:
            response = self.session.options(
                self.target,
                headers=headers,
                timeout=self.timeout
            )
            
            acao = response.headers.get("Access-Control-Allow-Origin")
            acam = response.headers.get("Access-Control-Allow-Methods")
            acah = response.headers.get("Access-Control-Allow-Headers")
            
            evidence = {}
            confidence = 0
            
            if acao == "https://evil.com":
                confidence += 40
                evidence["preflight_origin_reflected"] = True
            
            if acam and "PUT" in acam.upper():
                confidence += 20
                evidence["dangerous_methods_allowed"] = acam
            
            if acah:
                confidence += 20
                evidence["custom_headers_allowed"] = acah
            
            time.sleep(self.delay)
            
            if confidence >= self.confidence_threshold:
                self._add_check_result(
                    "CORS Preflight Misconfiguration",
                    self.target,
                    "https://evil.com",
                    Severity.HIGH,
                    confidence,
                    evidence,
                    True
                )
                
        except Exception as e:
            self.logger.debug(f"Preflight test error: {e}")
    
    # =========================================================================
    # RESULT HANDLING
    # =========================================================================
    
    def _add_check_result(self, check_name: str, endpoint: str, origin: str, severity: Severity, confidence_score: int, evidence: Dict[str, Any], is_vulnerable: bool) -> None:
        """Add a check result and create finding."""
        # Deduplicate by origin
        for existing in self.check_results:
            if existing.origin == origin and existing.endpoint == endpoint:
                return
        
        result = CORSCheckResult(
            check_name=check_name,
            endpoint=endpoint,
            origin=origin,
            severity=severity,
            confidence_score=confidence_score,
            evidence=evidence,
            is_vulnerable=is_vulnerable
        )
        self.check_results.append(result)
        self.total_confidence += confidence_score
        self._create_finding(result)
        print_success(f"{check_name}: {origin} (+{confidence_score})")
    
    def _create_finding(self, result: CORSCheckResult) -> None:
        """Create finding from check result."""
        finding = Finding(
            id=self._generate_finding_id(result.origin),
            title=result.check_name,
            severity=result.severity,
            description=self._get_description(result),
            url=result.endpoint,
            parameter="Origin",
            method="GET",
            payload=result.origin,
            evidence=json.dumps(result.evidence, indent=2),
            impact=self._get_impact(result),
            remediation=self._get_remediation(),
            vulnerability_type="cors",
            confidence="high" if result.confidence_score >= 80 else "medium",
        )
        self.add_finding(finding)
    
    def _get_description(self, result: CORSCheckResult) -> str:
        """Get description based on check type."""
        evidence = result.evidence
        
        if evidence.get("wildcard_with_credentials"):
            return "CORS allows wildcard (*) with credentials, exposing sensitive data to any origin"
        elif evidence.get("origin_reflected") and evidence.get("credentials_allowed"):
            return "CORS reflects arbitrary origin with credentials enabled, allowing cross-origin data theft"
        elif evidence.get("origin_reflected"):
            return "CORS reflects arbitrary origin, potentially allowing cross-origin access"
        elif "null" in result.origin:
            return "CORS accepts null origin, which can be triggered from sandboxed iframes"
        elif "subdomain" in result.check_name.lower():
            return "CORS validation can be bypassed via subdomain manipulation"
        
        return "CORS misconfiguration detected that may allow unauthorized cross-origin access"
    
    def _get_impact(self, result: CORSCheckResult) -> str:
        """Get impact description."""
        if result.severity == Severity.CRITICAL:
            return (
                "CRITICAL: CORS misconfiguration enables:\n"
                "- Cross-origin data theft\n"
                "- Session hijacking via credential exposure\n"
                "- Sensitive API data exfiltration\n"
                "- User impersonation attacks"
            )
        elif result.severity == Severity.HIGH:
            return (
                "HIGH: CORS weakness enables:\n"
                "- Potential cross-origin access\n"
                "- Data leakage to malicious sites\n"
                "- CSRF-like attacks"
            )
        return "MEDIUM: CORS configuration issue that should be reviewed"
    
    def _get_remediation(self) -> str:
        """Get remediation guidance."""
        return (
            "1. Implement strict origin allowlist validation\n"
            "2. Never reflect arbitrary Origin headers\n"
            "3. Avoid wildcard (*) with credentials\n"
            "4. Reject null origin requests\n"
            "5. Validate origin against exact matches, not regex\n"
            "6. Use proper subdomain validation\n"
            "7. Set Access-Control-Allow-Origin to specific trusted domains\n"
            "8. Only enable credentials when absolutely necessary"
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
    parser = argparse.ArgumentParser(prog="revuex-cors", description="REVUEX CORS GOLD - Cross-Origin Misconfiguration Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--origin", action="append", help="Additional origins to test")
    parser.add_argument("-H", "--header", action="append", help="Custom headers (Key:Value)")
    parser.add_argument("--threshold", type=int, default=CONFIDENCE_THRESHOLD, help=f"Confidence threshold (default: {CONFIDENCE_THRESHOLD})")
    parser.add_argument("--output", help="Output file (JSON)")
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
        print()
    
    scanner = CORSScanner(
        target=args.target,
        custom_origins=args.origin or [],
        custom_headers=custom_headers,
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
        print(f"Domain: {scanner.base_domain}")
        if result and hasattr(result, 'duration_seconds') and result.duration_seconds:
            print(f"Duration: {result.duration_seconds:.2f}s")
        if result and hasattr(result, 'findings'):
            print(f"Issues Found: {len(result.findings)}")
        print(f"Total Confidence: {scanner.total_confidence}")
        
        if scanner.baseline_response:
            print(f"\n[Baseline]")
            print(f"  ACAO: {scanner.baseline_response.get('acao', 'None')}")
            print(f"  ACAC: {scanner.baseline_response.get('acac', 'None')}")
    
    if args.output and result:
        output_data = {
            "scanner": SCANNER_NAME,
            "version": SCANNER_VERSION,
            "target": args.target,
            "domain": scanner.base_domain,
            "baseline": scanner.baseline_response,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "origin": f.payload
                }
                for f in getattr(result, 'findings', [])
            ]
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        if not args.quiet:
            print(f"\nResults saved to: {args.output}")
    
    return 1 if (result and result.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
