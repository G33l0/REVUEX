#!/usr/bin/env python3
"""
REVUEX Session GOLD v4.0
========================
Research-Grade Session Management Scanner (10/10 GOLD)

Detection Philosophy:
- Proves session invariant violations
- No hijacking, no replay, no brute force
- Differential state-transition validation
- Header/Cookie desynchronization
- Passive entropy & structure analysis
- Second-order session leakage detection

Core Techniques:
- Token Extraction (cookies, headers, JSON)
- State Capture (unauth, auth, post-logout)
- Session Fixation Detection
- Logout Invalidation Check
- Entropy Analysis
- Cookie Attribute Validation
- Header/Cookie Desync Detection

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import re
import math
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

SCANNER_NAME = "Session Scanner GOLD"
SCANNER_VERSION = "4.0.0"

BANNER = r"""
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

Session Scanner GOLD — Session Management Analysis
"""

CONFIDENCE_THRESHOLD = 80

# Session cookie name patterns
SESSION_COOKIE_REGEX = re.compile(
    r"(session|sess|sid|token|auth|jsessionid|phpsessid|aspsession|"
    r"cfid|cftoken|asp\.net_sessionid|laravel_session|connect\.sid)", re.I
)

# Minimum entropy threshold for secure tokens
MIN_ENTROPY_THRESHOLD = 3.5


# =============================================================================
# SESSION CHECK RESULT DATACLASS
# =============================================================================

@dataclass
class SessionCheckResult:
    """Result of a single session check."""
    check_name: str
    description: str
    severity: Severity
    confidence_score: int
    evidence: Dict[str, Any]
    is_vulnerable: bool


# =============================================================================
# UTILITIES
# =============================================================================

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = {c: data.count(c) / len(data) for c in set(data)}
    return -sum(p * math.log2(p) for p in freq.values())


def fingerprint_token(token: str) -> Dict[str, Any]:
    """Generate fingerprint of a session token."""
    return {
        "length": len(token),
        "entropy": round(shannon_entropy(token), 2),
        "charset": "".join(sorted(set(
            "A" if c.isalpha() else
            "9" if c.isdigit() else
            "_" for c in token
        ))),
        "hash": hashlib.sha256(token.encode()).hexdigest()[:12]
    }


# =============================================================================
# SESSION SCANNER GOLD CLASS
# =============================================================================

class SessionScanner(BaseScanner):
    """
    GOLD-tier Session Management Scanner.
    
    Methodology:
    1. Capture unauthenticated state
    2. Capture authenticated state (if login provided)
    3. Capture post-logout state (if logout provided)
    4. Check session fixation
    5. Check logout invalidation
    6. Check token entropy
    7. Check cookie attributes
    8. Check header/cookie desync
    """
    
    def __init__(
        self,
        target: str,
        login_path: Optional[str] = None,
        logout_path: Optional[str] = None,
        login_data: Optional[Dict[str, str]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
        **kwargs
    ):
        """
        Initialize Session Scanner.
        
        Args:
            target: Base URL
            login_path: Login endpoint path (POST)
            logout_path: Logout endpoint path
            login_data: Login credentials (optional)
            custom_headers: Custom HTTP headers
            confidence_threshold: Minimum confidence for findings
        """
        super().__init__(
            name="SessionScanner",
            description="Session management analyzer",
            target=target,
            **kwargs
        )
        
        self.login_path = login_path
        self.logout_path = logout_path
        self.login_data = login_data or {}
        self.custom_headers = custom_headers or {}
        self.confidence_threshold = confidence_threshold
        
        # State tracking
        self.states: Dict[str, Dict[str, str]] = {}
        self.baseline_text: Optional[str] = None
        self.check_results: List[SessionCheckResult] = []
        self.total_confidence: int = 0
        
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
        """Execute the GOLD session scan."""
        self.logger.info(f"Starting Session GOLD scan")
        self.logger.info(f"Target: {self.target}")
        
        # Phase 1: Capture unauthenticated state
        self.logger.info("Phase 1: Capturing unauthenticated state...")
        self._capture_state("unauth")
        
        # Phase 2: Capture authenticated state (if login path provided)
        if self.login_path:
            self.logger.info("Phase 2: Capturing authenticated state...")
            self._capture_state("auth", method="POST", path=self.login_path, data=self.login_data)
        
        # Phase 3: Capture post-logout state (if logout path provided)
        if self.logout_path:
            self.logger.info("Phase 3: Capturing post-logout state...")
            self._capture_state("post_logout", path=self.logout_path)
        
        # Phase 4: Check session fixation
        self.logger.info("Phase 4: Checking session fixation...")
        self._check_fixation()
        
        # Phase 5: Check logout invalidation
        self.logger.info("Phase 5: Checking logout invalidation...")
        self._check_logout_invalidation()
        
        # Phase 6: Check token entropy
        self.logger.info("Phase 6: Checking token entropy...")
        self._check_entropy()
        
        # Phase 7: Check cookie attributes
        self.logger.info("Phase 7: Checking cookie attributes...")
        self._check_cookie_attributes()
        
        # Phase 8: Check header/cookie desync
        self.logger.info("Phase 8: Checking header/cookie desync...")
        self._check_desync()
        
        self.logger.info(f"Session scan complete. Found {len(self.findings)} issue(s)")
    
    # =========================================================================
    # TOKEN EXTRACTION
    # =========================================================================
    
    def _extract_tokens(self, response) -> Dict[str, str]:
        """Extract session tokens from response."""
        tokens = {}
        
        # Cookies
        for cookie in response.cookies:
            if SESSION_COOKIE_REGEX.search(cookie.name):
                tokens[f"cookie:{cookie.name}"] = cookie.value
        
        # Headers
        for header, value in response.headers.items():
            if SESSION_COOKIE_REGEX.search(header):
                tokens[f"header:{header}"] = value
        
        # JSON body
        try:
            data = response.json()
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, str) and SESSION_COOKIE_REGEX.search(key):
                        tokens[f"json:{key}"] = value
        except Exception:
            pass
        
        return tokens
    
    # =========================================================================
    # STATE CAPTURE
    # =========================================================================
    
    def _capture_state(self, name: str, method: str = "GET", path: Optional[str] = None, data: Optional[Dict] = None) -> None:
        """Capture session state."""
        self.rate_limiter.acquire()
        self._request_count += 1
        
        url = self.target if not path else self.target.rstrip("/") + path
        
        try:
            response = self.session.request(method, url, json=data, headers=self.custom_headers, timeout=self.timeout)
            tokens = self._extract_tokens(response)
            self.states[name] = tokens
            
            if name == "unauth":
                self.baseline_text = response.text[:2000]
            
            print_info(f"Captured state [{name}] with {len(tokens)} session token(s)")
            time.sleep(self.delay)
            
        except Exception as e:
            self.logger.debug(f"State capture error: {e}")
    
    # =========================================================================
    # INVARIANT CHECKS
    # =========================================================================
    
    def _check_fixation(self) -> None:
        """Check for session fixation vulnerability."""
        unauth = self.states.get("unauth", {})
        auth = self.states.get("auth", {})
        
        if not unauth or not auth:
            return
        
        confidence = 0
        evidence = {}
        
        for key in unauth:
            if key in auth and unauth[key] == auth[key]:
                confidence += 60
                evidence["fixated_token"] = {
                    "key": key,
                    "value": unauth[key][:20] + "..."
                }
        
        if confidence >= self.confidence_threshold:
            self._add_check_result(
                "Session Fixation (No Rotation on Login)",
                "Session token not rotated after authentication",
                Severity.CRITICAL,
                confidence,
                evidence,
                True
            )
    
    def _check_logout_invalidation(self) -> None:
        """Check if session is invalidated on logout."""
        if not self.logout_path:
            return
        
        auth_tokens = self.states.get("auth", {})
        post_logout = self.states.get("post_logout", {})
        
        if not auth_tokens:
            return
        
        confidence = 0
        evidence = {}
        
        for key in auth_tokens:
            if key in post_logout and auth_tokens[key] == post_logout[key]:
                confidence += 60
                evidence["persistent_token"] = {
                    "key": key,
                    "value": auth_tokens[key][:20] + "..."
                }
        
        if confidence >= self.confidence_threshold:
            self._add_check_result(
                "Session Not Invalidated on Logout",
                "Session token persists after logout",
                Severity.HIGH,
                confidence,
                evidence,
                True
            )
    
    def _check_entropy(self) -> None:
        """Check token entropy for all captured states."""
        for state_name, tokens in self.states.items():
            for key, value in tokens.items():
                fp = fingerprint_token(value)
                
                if fp["entropy"] < MIN_ENTROPY_THRESHOLD:
                    self._add_check_result(
                        "Low Entropy Session Token",
                        f"Token has insufficient entropy: {fp['entropy']} bits",
                        Severity.MEDIUM,
                        80,
                        {"state": state_name, "token": key, "fingerprint": fp},
                        True
                    )
    
    def _check_cookie_attributes(self) -> None:
        """Check session cookie security attributes."""
        try:
            self.rate_limiter.acquire()
            response = self.session.get(self.target, timeout=self.timeout)
            
            for cookie in response.cookies:
                if not SESSION_COOKIE_REGEX.search(cookie.name):
                    continue
                
                missing = []
                
                if not cookie.secure:
                    missing.append("Secure")
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    missing.append("HttpOnly")
                
                if missing:
                    self._add_check_result(
                        "Weak Session Cookie Attributes",
                        f"Cookie missing security attributes: {', '.join(missing)}",
                        Severity.MEDIUM,
                        80,
                        {"cookie": cookie.name, "missing": missing},
                        True
                    )
        except Exception as e:
            self.logger.debug(f"Cookie attribute check error: {e}")
    
    def _check_desync(self) -> None:
        """Check for header/cookie session desynchronization."""
        auth = self.states.get("auth", {})
        
        for key, value in auth.items():
            if not key.startswith("cookie:"):
                continue
            
            cookie_name = key.replace("cookie:", "")
            test_headers = {cookie_name: "DESYNC_TEST"}
            
            try:
                self.rate_limiter.acquire()
                response = self.session.get(self.target, headers=test_headers, timeout=self.timeout)
                
                if response.status_code < 400:
                    self._add_check_result(
                        "Header/Cookie Session Desynchronization",
                        "Server may accept conflicting session identifiers",
                        Severity.HIGH,
                        85,
                        {"cookie": key, "header": test_headers},
                        True
                    )
                    return
            except Exception as e:
                self.logger.debug(f"Desync check error: {e}")
    
    # =========================================================================
    # RESULT HANDLING
    # =========================================================================
    
    def _add_check_result(self, check_name: str, description: str, severity: Severity, confidence_score: int, evidence: Dict[str, Any], is_vulnerable: bool) -> None:
        """Add a check result and create finding."""
        result = SessionCheckResult(
            check_name=check_name,
            description=description,
            severity=severity,
            confidence_score=confidence_score,
            evidence=evidence,
            is_vulnerable=is_vulnerable
        )
        self.check_results.append(result)
        self.total_confidence += confidence_score
        self._create_finding(result)
        print_success(f"{check_name} (+{confidence_score})")
    
    def _create_finding(self, result: SessionCheckResult) -> None:
        """Create finding from check result."""
        finding = Finding(
            id=self._generate_finding_id(result.check_name),
            title=result.check_name,
            severity=result.severity,
            description=result.description,
            url=self.target,
            parameter="Session",
            method="GET/POST",
            payload="N/A",
            evidence=json.dumps(result.evidence, indent=2),
            impact=self._get_impact(result),
            remediation=self._get_remediation(result),
            vulnerability_type="session_management",
            confidence="high" if result.confidence_score >= 80 else "medium",
        )
        self.add_finding(finding)
    
    def _get_impact(self, result: SessionCheckResult) -> str:
        """Get impact description."""
        if result.severity == Severity.CRITICAL:
            return "CRITICAL: Session fixation enables account takeover and identity theft"
        elif result.severity == Severity.HIGH:
            return "HIGH: Session weakness enables unauthorized access or session reuse"
        return "MEDIUM: Session token weakness may enable prediction or brute force"
    
    def _get_remediation(self, result: SessionCheckResult) -> str:
        """Get remediation based on check type."""
        remediations = {
            "fixation": "1. Regenerate session ID after login\n2. Invalidate old session\n3. Use framework session regeneration",
            "invalidated": "1. Destroy session server-side on logout\n2. Clear session cookie\n3. Implement session blacklist",
            "entropy": "1. Use cryptographically secure random generator\n2. Ensure 128+ bits of entropy\n3. Use framework session ID generation",
            "cookie": "1. Set Secure flag for HTTPS\n2. Set HttpOnly flag\n3. Set SameSite attribute",
            "desync": "1. Use single session source\n2. Validate session consistently\n3. Reject conflicting identifiers",
        }
        for key, remediation in remediations.items():
            if key.lower() in result.check_name.lower():
                return remediation
        return "1. Review session management\n2. Follow OWASP guidelines\n3. Use secure framework defaults"
    
    def _generate_finding_id(self, context: str) -> str:
        """Generate unique finding ID."""
        data = f"{self.target}:{context}:{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(prog="revuex-session", description="REVUEX Session GOLD - Session Management Scanner")
    parser.add_argument("-t", "--target", required=True, help="Base target URL")
    parser.add_argument("--login-path", help="Login endpoint path (POST)")
    parser.add_argument("--logout-path", help="Logout endpoint path")
    parser.add_argument("--login-data", help="Login credentials JSON")
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
    
    login_data = {}
    if args.login_data:
        try:
            login_data = json.loads(args.login_data)
        except Exception as e:
            print_warning(f"Failed to parse login data: {e}")
    
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
        if args.login_path:
            print(f"[+] Login path: {args.login_path}")
        if args.logout_path:
            print(f"[+] Logout path: {args.logout_path}")
        print()
    
    scanner = SessionScanner(
        target=args.target,
        login_path=args.login_path,
        logout_path=args.logout_path,
        login_data=login_data,
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
        if result and hasattr(result, "duration_seconds") and result.duration_seconds:
            print(f"Duration: {result.duration_seconds:.2f}s")
        print(f"States Captured: {len(scanner.states)}")
        print(f"Issues Found: {len(result.findings)}")
        print(f"Total Confidence: {scanner.total_confidence}")
    
    if args.output:
        output_data = {
            "scanner": SCANNER_NAME,
            "version": SCANNER_VERSION,
            "target": args.target,
            "states_captured": list(scanner.states.keys()),
            "findings": [{"id": f.id, "title": f.title, "severity": f.severity.value} for f in getattr(result, "findings", [])]
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        if not args.quiet:
            print(f"\nResults saved to: {args.output}")
    
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
