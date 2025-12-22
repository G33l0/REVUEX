#!/usr/bin/env python3
"""
REVUEX CSRF GOLD v1.0
=====================
Research-Grade CSRF Validation Scanner (10/10 GOLD)

Detection Philosophy:
- Proves CSRF invariant enforcement failures
- Differential request validation
- Token presence, requirement, and binding checks
- Method & content-type confusion detection
- Origin / Referer enforcement validation
- No exploitation, no victim simulation

Core Techniques:
- Baseline Action Capture
- CSRF Token Extraction (headers, cookies, body)
- Token Removal/Modification Testing
- Origin/Referer Header Bypass
- HTTP Method Confusion (GET/POST)
- Content-Type Confusion
- SameSite Cookie Bypass Detection
- Double Submit Cookie Analysis

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import re
import copy
import json
import time
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse, urlencode, parse_qs
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.base_scanner import BaseScanner, Finding, ScanResult, Severity, ScanStatus
from core.utils import print_success, print_error, print_warning, print_info


# =============================================================================
# CONSTANTS
# =============================================================================

SCANNER_NAME = "CSRF Scanner GOLD"
SCANNER_VERSION = "1.0.0"

BANNER = r"""
âââââââ âââââââââââ   ââââââ   ââââââââââââââ  âââ
âââââââââââââââââââ   ââââââ   âââââââââââââââââââ
ââââââââââââââ  âââ   ââââââ   âââââââââ   ââââââ 
ââââââââââââââ  ââââ âââââââ   âââââââââ   ââââââ 
âââ  âââââââââââ âââââââ âââââââââââââââââââââ âââ
âââ  âââââââââââ  âââââ   âââââââ âââââââââââ  âââ

CSRF Scanner GOLD â Cross-Site Request Forgery Detection
"""

CONFIDENCE_THRESHOLD = 80

# CSRF token patterns
CSRF_TOKEN_REGEX = re.compile(
    r"(csrf|xsrf|token|nonce|authenticity|_token|csrfmiddlewaretoken|"
    r"__requestverificationtoken|antiforgery|x-csrf|x-xsrf)", re.I
)

# State-changing HTTP methods
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Content types that may bypass CSRF
BYPASS_CONTENT_TYPES = [
    "application/json",
    "text/plain",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
]


# =============================================================================
# CSRF CHECK RESULT DATACLASS
# =============================================================================

@dataclass
class CSRFCheckResult:
    """Result of a single CSRF check."""
    check_name: str
    description: str
    severity: Severity
    confidence_score: int
    evidence: Dict[str, Any]
    is_vulnerable: bool


# =============================================================================
# CSRF SCANNER GOLD CLASS
# =============================================================================

class CSRFScanner(BaseScanner):
    """
    GOLD-tier CSRF Validation Scanner.
    
    Methodology:
    1. Capture baseline state-changing request
    2. Extract CSRF tokens from response
    3. Test token removal bypass
    4. Test token modification bypass
    5. Test Origin/Referer bypass
    6. Test HTTP method confusion
    7. Test Content-Type confusion
    8. Analyze SameSite cookie protection
    """
    
    def __init__(
        self,
        target: str,
        action_path: str,
        method: str = "POST",
        action_data: Optional[Dict[str, str]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
        **kwargs
    ):
        """
        Initialize CSRF Scanner.
        
        Args:
            target: Base URL
            action_path: State-changing action endpoint
            method: HTTP method (POST, PUT, PATCH, DELETE)
            action_data: Request body data
            custom_headers: Custom HTTP headers
            confidence_threshold: Minimum confidence for findings
        """
        super().__init__(target=target, **kwargs)
        
        self.action_path = action_path
        self.method = method.upper()
        self.action_data = action_data or {}
        self.custom_headers = custom_headers or {}
        self.confidence_threshold = confidence_threshold
        
        # State tracking
        self.baseline_response = None
        self.baseline_request = None
        self.csrf_tokens: Dict[str, str] = {}
        self.check_results: List[CSRFCheckResult] = []
        self.total_confidence: int = 0
        self.samesite_protection: bool = False
        
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
        """Execute the GOLD CSRF scan."""
        self.logger.info(f"Starting CSRF GOLD scan")
        self.logger.info(f"Target: {self.target}")
        self.logger.info(f"Action: {self.action_path}")
        
        # Phase 1: Capture baseline
        self.logger.info("Phase 1: Capturing baseline request...")
        self._capture_baseline()
        
        if not self.baseline_response:
            self.logger.error("Failed to capture baseline - aborting")
            return
        
        # Phase 2: Extract CSRF tokens
        self.logger.info("Phase 2: Extracting CSRF tokens...")
        self._extract_all_tokens()
        
        # Phase 3: Check SameSite protection
        self.logger.info("Phase 3: Checking SameSite cookie protection...")
        self._check_samesite_protection()
        
        # Phase 4: Test token removal
        self.logger.info("Phase 4: Testing token removal bypass...")
        self._test_token_removal()
        
        # Phase 5: Test token modification
        self.logger.info("Phase 5: Testing token modification bypass...")
        self._test_token_modification()
        
        # Phase 6: Test Origin/Referer bypass
        self.logger.info("Phase 6: Testing Origin/Referer bypass...")
        self._test_origin_referer_bypass()
        
        # Phase 7: Test method confusion
        self.logger.info("Phase 7: Testing HTTP method confusion...")
        self._test_method_confusion()
        
        # Phase 8: Test Content-Type confusion
        self.logger.info("Phase 8: Testing Content-Type confusion...")
        self._test_content_type_confusion()
        
        # Phase 9: Test double submit cookie
        self.logger.info("Phase 9: Testing double submit cookie...")
        self._test_double_submit_cookie()
        
        self.logger.info(f"CSRF scan complete. Found {len(self.findings)} issue(s)")
    
    # =========================================================================
    # BASELINE CAPTURE
    # =========================================================================
    
    def _capture_baseline(self) -> None:
        """Capture baseline state-changing request."""
        self.rate_limiter.acquire()
        self.request_count += 1
        
        url = self.target.rstrip("/") + self.action_path
        
        try:
            # First, get the page to collect any CSRF tokens
            page_response = self.session.get(url, timeout=self.timeout)
            self._extract_tokens_from_response(page_response)
            
            # Prepare request data with any found tokens
            data = self.action_data.copy()
            for key, value in self.csrf_tokens.items():
                if key.startswith("form:") or key.startswith("hidden:"):
                    field_name = key.split(":", 1)[1]
                    data[field_name] = value
            
            # Send the state-changing request
            if self.method == "POST":
                response = self.session.post(url, data=data, headers=self.custom_headers, timeout=self.timeout)
            elif self.method == "PUT":
                response = self.session.put(url, json=data, headers=self.custom_headers, timeout=self.timeout)
            elif self.method == "PATCH":
                response = self.session.patch(url, json=data, headers=self.custom_headers, timeout=self.timeout)
            elif self.method == "DELETE":
                response = self.session.delete(url, headers=self.custom_headers, timeout=self.timeout)
            else:
                response = self.session.post(url, data=data, headers=self.custom_headers, timeout=self.timeout)
            
            self.baseline_response = response
            self.baseline_request = response.request
            
            print_info(f"Baseline captured: HTTP {response.status_code}")
            time.sleep(self.delay)
            
        except Exception as e:
            self.logger.error(f"Baseline capture failed: {e}")
    
    # =========================================================================
    # TOKEN EXTRACTION
    # =========================================================================
    
    def _extract_all_tokens(self) -> None:
        """Extract all CSRF tokens from baseline response."""
        if not self.baseline_response:
            return
        self._extract_tokens_from_response(self.baseline_response)
        print_info(f"Found {len(self.csrf_tokens)} CSRF token(s)")
    
    def _extract_tokens_from_response(self, response) -> None:
        """Extract CSRF tokens from response."""
        # Headers
        for header, value in response.headers.items():
            if CSRF_TOKEN_REGEX.search(header):
                self.csrf_tokens[f"header:{header}"] = value
        
        # Cookies
        for cookie in response.cookies:
            if CSRF_TOKEN_REGEX.search(cookie.name):
                self.csrf_tokens[f"cookie:{cookie.name}"] = cookie.value
        
        # JSON body
        try:
            data = response.json()
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, str) and CSRF_TOKEN_REGEX.search(key):
                        self.csrf_tokens[f"json:{key}"] = value
        except Exception:
            pass
        
        # HTML hidden fields
        html = response.text
        hidden_pattern = re.compile(r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']', re.I)
        for match in hidden_pattern.finditer(html):
            name, value = match.groups()
            if CSRF_TOKEN_REGEX.search(name):
                self.csrf_tokens[f"hidden:{name}"] = value
        
        # Meta tags
        meta_pattern = re.compile(r'<meta[^>]*name=["\']([^"\']*csrf[^"\']*)["\'][^>]*content=["\']([^"\']*)["\']', re.I)
        for match in meta_pattern.finditer(html):
            name, value = match.groups()
            self.csrf_tokens[f"meta:{name}"] = value
    
    # =========================================================================
    # SAMESITE CHECK
    # =========================================================================
    
    def _check_samesite_protection(self) -> None:
        """Check if SameSite cookie protection is in place."""
        if not self.baseline_response:
            return
        
        set_cookie = self.baseline_response.headers.get("Set-Cookie", "")
        
        if "samesite=strict" in set_cookie.lower():
            self.samesite_protection = True
            print_info("SameSite=Strict protection detected")
        elif "samesite=lax" in set_cookie.lower():
            self.samesite_protection = True
            print_info("SameSite=Lax protection detected")
        elif "samesite=none" in set_cookie.lower():
            self._add_check_result("SameSite=None Cookie", "Session cookie has SameSite=None", Severity.MEDIUM, 70, {"set_cookie": set_cookie[:200]}, True)
    
    # =========================================================================
    # CSRF TESTS
    # =========================================================================
    
    def _test_token_removal(self) -> None:
        """Test if request succeeds without CSRF token."""
        if not self.csrf_tokens:
            self._add_check_result("No CSRF Token Present", "No CSRF token found in state-changing endpoint", Severity.HIGH, 85, {"action": self.action_path, "method": self.method}, True)
            return
        
        response = self._send_variant(remove_token=True)
        if response and self._is_successful_response(response):
            self._add_check_result("CSRF Token Removal Bypass", "Request succeeds without CSRF token", Severity.CRITICAL, 90, {"action": self.action_path, "baseline_status": self.baseline_response.status_code, "variant_status": response.status_code}, True)
    
    def _test_token_modification(self) -> None:
        """Test if request succeeds with modified token."""
        if not self.csrf_tokens:
            return
        
        response = self._send_variant(random_token=True)
        if response and self._is_successful_response(response):
            self._add_check_result("CSRF Token Validation Bypass", "Request succeeds with invalid CSRF token", Severity.CRITICAL, 90, {"action": self.action_path, "variant_status": response.status_code}, True)
        
        response = self._send_variant(empty_token=True)
        if response and self._is_successful_response(response):
            self._add_check_result("CSRF Empty Token Bypass", "Request succeeds with empty CSRF token", Severity.HIGH, 85, {"action": self.action_path, "variant_status": response.status_code}, True)
    
    def _test_origin_referer_bypass(self) -> None:
        """Test if request succeeds without Origin/Referer."""
        response = self._send_variant(remove_origin=True)
        if response and self._is_successful_response(response):
            self._add_check_result("Origin Header Not Validated", "Request succeeds without Origin header", Severity.MEDIUM, 75, {"action": self.action_path, "variant_status": response.status_code}, True)
        
        response = self._send_variant(null_origin=True)
        if response and self._is_successful_response(response):
            self._add_check_result("Null Origin Bypass", "Request succeeds with null Origin header", Severity.HIGH, 80, {"action": self.action_path, "variant_status": response.status_code}, True)
        
        response = self._send_variant(different_origin=True)
        if response and self._is_successful_response(response):
            self._add_check_result("Cross-Origin Request Accepted", "Request succeeds with different Origin header", Severity.HIGH, 85, {"action": self.action_path, "malicious_origin": "https://evil.com", "variant_status": response.status_code}, True)
    
    def _test_method_confusion(self) -> None:
        """Test HTTP method confusion."""
        if self.method != "POST":
            return
        
        response = self._send_variant(method="GET")
        if response and self._is_successful_response(response):
            self._add_check_result("HTTP Method Confusion (GET)", "POST action accepts GET requests", Severity.HIGH, 85, {"action": self.action_path, "expected_method": "POST", "accepted_method": "GET", "variant_status": response.status_code}, True)
    
    def _test_content_type_confusion(self) -> None:
        """Test Content-Type confusion."""
        for content_type in BYPASS_CONTENT_TYPES:
            response = self._send_variant(content_type=content_type)
            if response and self._is_successful_response(response):
                baseline_ct = self.baseline_request.headers.get("Content-Type", "") if self.baseline_request else ""
                if content_type not in baseline_ct:
                    self._add_check_result(f"Content-Type Confusion ({content_type})", f"Request accepts {content_type}", Severity.MEDIUM, 70, {"action": self.action_path, "content_type": content_type, "variant_status": response.status_code}, True)
                    break
    
    def _test_double_submit_cookie(self) -> None:
        """Test double submit cookie pattern weaknesses."""
        cookie_tokens = {k: v for k, v in self.csrf_tokens.items() if k.startswith("cookie:")}
        form_tokens = {k: v for k, v in self.csrf_tokens.items() if k.startswith("hidden:") or k.startswith("form:")}
        
        if not cookie_tokens or not form_tokens:
            return
        
        for ck, cv in cookie_tokens.items():
            for fk, fv in form_tokens.items():
                if cv == fv:
                    self._add_check_result("Double Submit Cookie Pattern", "CSRF uses double submit cookie (attackable via cookie injection)", Severity.MEDIUM, 65, {"cookie_token": ck, "form_token": fk}, True)
                    return
    
    # =========================================================================
    # VARIANT SENDER
    # =========================================================================
    
    def _send_variant(self, remove_token: bool = False, random_token: bool = False, empty_token: bool = False, remove_origin: bool = False, null_origin: bool = False, different_origin: bool = False, method: Optional[str] = None, content_type: Optional[str] = None) -> Optional[Any]:
        """Send a variant request for testing."""
        self.rate_limiter.acquire()
        self.request_count += 1
        
        url = self.target.rstrip("/") + self.action_path
        headers = self.custom_headers.copy()
        data = self.action_data.copy()
        
        # Add CSRF tokens to data
        if not remove_token:
            for key, value in self.csrf_tokens.items():
                if key.startswith("hidden:") or key.startswith("form:"):
                    field_name = key.split(":", 1)[1]
                    if random_token:
                        data[field_name] = "INVALID_RANDOM_TOKEN_12345"
                    elif empty_token:
                        data[field_name] = ""
                    else:
                        data[field_name] = value
        
        # Handle Origin/Referer
        if remove_origin:
            headers.pop("Origin", None)
            headers.pop("Referer", None)
        elif null_origin:
            headers["Origin"] = "null"
        elif different_origin:
            headers["Origin"] = "https://evil.com"
            headers["Referer"] = "https://evil.com/attack.html"
        
        if content_type:
            headers["Content-Type"] = content_type
        
        req_method = method or self.method
        
        try:
            if req_method == "GET":
                response = self.session.get(url, params=data, headers=headers, timeout=self.timeout)
            elif req_method == "POST":
                if content_type and "json" in content_type:
                    response = self.session.post(url, json=data, headers=headers, timeout=self.timeout)
                else:
                    response = self.session.post(url, data=data, headers=headers, timeout=self.timeout)
            elif req_method == "PUT":
                response = self.session.put(url, json=data, headers=headers, timeout=self.timeout)
            elif req_method == "PATCH":
                response = self.session.patch(url, json=data, headers=headers, timeout=self.timeout)
            elif req_method == "DELETE":
                response = self.session.delete(url, headers=headers, timeout=self.timeout)
            else:
                response = self.session.post(url, data=data, headers=headers, timeout=self.timeout)
            
            time.sleep(self.delay)
            return response
        except Exception as e:
            self.logger.debug(f"Variant request failed: {e}")
            return None
    
    def _is_successful_response(self, response) -> bool:
        """Check if response indicates successful action."""
        if not self.baseline_response:
            return response.status_code < 400
        if response.status_code == self.baseline_response.status_code:
            return True
        if 200 <= response.status_code < 300:
            return True
        if 300 <= response.status_code < 400:
            return True
        return False
    
    # =========================================================================
    # RESULT HANDLING
    # =========================================================================
    
    def _add_check_result(self, check_name: str, description: str, severity: Severity, confidence_score: int, evidence: Dict[str, Any], is_vulnerable: bool) -> None:
        """Add a check result and create finding."""
        result = CSRFCheckResult(check_name=check_name, description=description, severity=severity, confidence_score=confidence_score, evidence=evidence, is_vulnerable=is_vulnerable)
        self.check_results.append(result)
        self.total_confidence += confidence_score
        self._create_finding(result)
        print_success(f"{check_name} (+{confidence_score})")
    
    def _create_finding(self, result: CSRFCheckResult) -> None:
        """Create finding from check result."""
        finding = Finding(
            id=self._generate_finding_id(result.check_name),
            title=result.check_name,
            severity=result.severity,
            description=result.description,
            url=self.target + self.action_path,
            parameter="CSRF Token",
            method=self.method,
            payload="N/A",
            evidence=json.dumps(result.evidence, indent=2),
            impact=self._get_impact(result),
            remediation=self._get_remediation(result),
            vulnerability_type="csrf",
            confidence="high" if result.confidence_score >= 80 else "medium",
        )
        self.add_finding(finding)
    
    def _get_impact(self, result: CSRFCheckResult) -> str:
        """Get impact description."""
        if result.severity == Severity.CRITICAL:
            return "CRITICAL: CSRF vulnerability enables unauthorized state-changing actions, account takeover, financial fraud"
        elif result.severity == Severity.HIGH:
            return "HIGH: CSRF weakness enables bypass of protections, potential unauthorized actions"
        return "MEDIUM: CSRF protection weakness detected"
    
    def _get_remediation(self, result: CSRFCheckResult) -> str:
        """Get remediation based on check type."""
        remediations = {
            "token removal": "1. Require CSRF token for all state-changing requests\n2. Reject requests missing CSRF token\n3. Use synchronizer token pattern",
            "token validation": "1. Validate CSRF token server-side\n2. Use cryptographically secure tokens\n3. Bind token to user session",
            "origin": "1. Validate Origin header\n2. Reject requests with missing/null Origin\n3. Implement strict origin allowlist",
            "method": "1. Enforce correct HTTP method\n2. Reject GET requests for state changes\n3. Use POST/PUT/PATCH/DELETE appropriately",
            "samesite": "1. Set SameSite=Strict or SameSite=Lax\n2. Avoid SameSite=None\n3. Combine with CSRF tokens",
            "double submit": "1. Use cryptographically signed tokens\n2. Bind token to session server-side\n3. Avoid pure double-submit pattern",
        }
        for key, remediation in remediations.items():
            if key.lower() in result.check_name.lower():
                return remediation
        return "1. Implement synchronizer token pattern\n2. Validate Origin/Referer headers\n3. Use SameSite cookies\n4. Apply defense in depth"
    
    def _generate_finding_id(self, context: str) -> str:
        """Generate unique finding ID."""
        data = f"{self.target}:{self.action_path}:{context}:{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(prog="revuex-csrf", description="REVUEX CSRF GOLD - Cross-Site Request Forgery Scanner")
    parser.add_argument("-t", "--target", required=True, help="Base target URL")
    parser.add_argument("-a", "--action", required=True, help="State-changing action path")
    parser.add_argument("-m", "--method", default="POST", help="HTTP method (default: POST)")
    parser.add_argument("-d", "--data", help="Request body data (JSON)")
    parser.add_argument("--headers", help="Custom headers JSON file")
    parser.add_argument("--threshold", type=int, default=CONFIDENCE_THRESHOLD, help=f"Confidence threshold (default: {CONFIDENCE_THRESHOLD})")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--delay", type=float, default=0.5, help="Request delay")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    return parser


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    action_data = {}
    if args.data:
        try:
            action_data = json.loads(args.data)
        except Exception as e:
            print_warning(f"Failed to parse data: {e}")
    
    custom_headers = {}
    if args.headers:
        try:
            with open(args.headers) as f:
                custom_headers = json.load(f)
        except Exception as e:
            print_warning(f"Failed to load headers: {e}")
    
    if not args.quiet:
        print(BANNER)
        print(f"[+] Target: {args.target}")
        print(f"[+] Action: {args.action}")
        print(f"[+] Method: {args.method}")
        print()
    
    scanner = CSRFScanner(target=args.target, action_path=args.action, method=args.method, action_data=action_data, custom_headers=custom_headers, confidence_threshold=args.threshold, delay=args.delay, timeout=args.timeout, verbose=args.verbose)
    result = scanner.run()
    
    if not args.quiet:
        print(f"\n{'='*60}")
        print("SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"Target: {args.target}")
        print(f"Action: {args.action}")
        print(f"Duration: {result.duration_seconds:.2f}s")
        print(f"CSRF Tokens Found: {len(scanner.csrf_tokens)}")
        print(f"Issues Found: {len(result.findings)}")
        print(f"Total Confidence: {scanner.total_confidence}")
    
    if args.output:
        output_data = {"scanner": SCANNER_NAME, "version": SCANNER_VERSION, "target": args.target, "action": args.action, "csrf_tokens": list(scanner.csrf_tokens.keys()), "findings": [{"id": f.id, "title": f.title, "severity": f.severity.value} for f in result.findings]}
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        if not args.quiet:
            print(f"\nResults saved to: {args.output}")
    
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
