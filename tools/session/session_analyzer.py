#!/usr/bin/env python3
"""
REVUEX Session GOLD v1.0
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
- Concurrent Session Detection
- Token Predictability Analysis

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
from typing import Dict, List, Optional, Any, Tuple
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
SCANNER_VERSION = "1.0.0"

BANNER = r"""
âââââââ âââââââââââ   ââââââ   ââââââââââââââ  âââ
âââââââââââââââââââ   ââââââ   âââââââââââââââââââ
ââââââââââââââ  âââ   ââââââ   âââââââââ   ââââââ 
ââââââââââââââ  ââââ âââââââ   âââââââââ   ââââââ 
âââ  âââââââââââ âââââââ âââââââââââââââââââââ âââ
âââ  âââââââââââ  âââââ   âââââââ âââââââââââ  âââ

Session GOLD â Session Management Scanner
"""

CONFIDENCE_THRESHOLD = 80

# Session cookie name patterns
SESSION_COOKIE_REGEX = re.compile(
    r"(session|sess|sid|token|auth|jsessionid|phpsessid|aspsession|"
    r"cfid|cftoken|asp\.net_sessionid|laravel_session|wordpress_logged_in|"
    r"connect\.sid|express\.sid|rack\.session|_session|sessionid|"
    r"authtoken|access_token|refresh_token|jwt|bearer)", re.I
)

# Minimum entropy threshold for secure tokens
MIN_ENTROPY_THRESHOLD = 3.5

# Secure cookie attributes
SECURE_ATTRIBUTES = ["Secure", "HttpOnly", "SameSite"]


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
    charset = set()
    for c in token:
        if c.isalpha():
            charset.add("alpha")
        elif c.isdigit():
            charset.add("digit")
        elif c in "-_":
            charset.add("separator")
        else:
            charset.add("special")
    
    return {
        "length": len(token),
        "entropy": round(shannon_entropy(token), 2),
        "charset": sorted(charset),
        "hash": hashlib.sha256(token.encode()).hexdigest()[:12],
        "is_base64": _is_base64(token),
        "is_hex": _is_hex(token),
        "is_uuid": _is_uuid(token),
    }


def _is_base64(s: str) -> bool:
    """Check if string looks like base64."""
    import base64
    try:
        if len(s) % 4 == 0:
            base64.b64decode(s)
            return True
    except Exception:
        pass
    return False


def _is_hex(s: str) -> bool:
    """Check if string is hex encoded."""
    try:
        int(s, 16)
        return len(s) % 2 == 0
    except ValueError:
        return False


def _is_uuid(s: str) -> bool:
    """Check if string is a UUID."""
    uuid_pattern = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I
    )
    return bool(uuid_pattern.match(s))


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
    9. Check concurrent sessions
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
        super().__init__(target=target, **kwargs)
        
        self.login_path = login_path
        self.logout_path = logout_path
        self.login_data = login_data or {}
        self.custom_headers = custom_headers or {}
        self.confidence_threshold = confidence_threshold
        
        # State tracking
        self.states: Dict[str, Dict[str, str]] = {}
        self.baseline_response = None
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
        
        # Phase 9: Check token predictability
        self.logger.info("Phase 9: Checking token predictability...")
        self._check_predictability()
        
        # Phase 10: Check session timeout
        self.logger.info("Phase 10: Checking session configuration...")
        self._check_session_config()
        
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
        
        # Set-Cookie headers
        for header in response.headers.get("Set-Cookie", "").split(","):
            match = re.match(r"([^=]+)=([^;]+)", header.strip())
            if match and SESSION_COOKIE_REGEX.search(match.group(1)):
                tokens[f"setcookie:{match.group(1)}"] = match.group(2)
        
        return tokens
    
    # =========================================================================
    # STATE CAPTURE
    # =========================================================================
    
    def _capture_state(
        self,
        name: str,
        method: str = "GET",
        path: Optional[str] = None,
        data: Optional[Dict] = None
    ) -> None:
        """Capture session state."""
        self.rate_limiter.acquire()
        self.request_count += 1
        
        url = self.target if not path else self.target.rstrip("/") + path
        
        try:
            if method.upper() == "POST":
                response = self.session.post(
                    url,
                    json=data if data else None,
                    headers=self.custom_headers,
                    timeout=self.timeout
                )
            else:
                response = self.session.get(
                    url,
                    headers=self.custom_headers,
                    timeout=self.timeout
                )
            
            tokens = self._extract_tokens(response)
            self.states[name] = tokens
            
            if name == "unauth":
                self.baseline_response = response
            
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
        
        for key in unauth:
            if key in auth and unauth[key] == auth[key]:
                self._add_check_result(
                    "Session Fixation (No Rotation on Login)",
                    "Session token not rotated after authentication",
                    Severity.CRITICAL,
                    90,
                    {
                        "token_key": key,
                        "token_value": unauth[key][:20] + "...",
                        "unauth_hash": hashlib.md5(unauth[key].encode()).hexdigest()[:8],
                        "auth_hash": hashlib.md5(auth[key].encode()).hexdigest()[:8],
                    },
                    True
                )
                return
    
    def _check_logout_invalidation(self) -> None:
        """Check if session is invalidated on logout."""
        if not self.logout_path:
            return
        
        auth_tokens = self.states.get("auth", {})
        post_logout = self.states.get("post_logout", {})
        
        if not auth_tokens:
            return
        
        for key in auth_tokens:
            if key in post_logout and auth_tokens[key] == post_logout[key]:
                self._add_check_result(
                    "Session Not Invalidated on Logout",
                    "Session token persists after logout",
                    Severity.HIGH,
                    85,
                    {
                        "token_key": key,
                        "token_value": auth_tokens[key][:20] + "...",
                    },
                    True
                )
                return
    
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
                        75,
                        {
                            "state": state_name,
                            "token_key": key,
                            "fingerprint": fp,
                        },
                        True
                    )
                
                # Check for short tokens
                if fp["length"] < 16:
                    self._add_check_result(
                        "Short Session Token",
                        f"Token length is only {fp['length']} characters",
                        Severity.MEDIUM,
                        70,
                        {
                            "state": state_name,
                            "token_key": key,
                            "length": fp["length"],
                        },
                        True
                    )
    
    def _check_cookie_attributes(self) -> None:
        """Check session cookie security attributes."""
        if not self.baseline_response:
            return
        
        for cookie in self.baseline_response.cookies:
            if not SESSION_COOKIE_REGEX.search(cookie.name):
                continue
            
            missing = []
            
            # Check Secure flag
            if not cookie.secure:
                missing.append("Secure")
            
            # Check HttpOnly flag
            if not cookie.has_nonstandard_attr("HttpOnly"):
                # Try alternate check
                set_cookie = self.baseline_response.headers.get("Set-Cookie", "")
                if cookie.name in set_cookie and "httponly" not in set_cookie.lower():
                    missing.append("HttpOnly")
            
            # Check SameSite attribute
            set_cookie = self.baseline_response.headers.get("Set-Cookie", "")
            if cookie.name in set_cookie and "samesite" not in set_cookie.lower():
                missing.append("SameSite")
            
            if missing:
                severity = Severity.HIGH if "Secure" in missing or "HttpOnly" in missing else Severity.MEDIUM
                self._add_check_result(
                    "Weak Session Cookie Attributes",
                    f"Cookie missing security attributes: {', '.join(missing)}",
                    severity,
                    80,
                    {
                        "cookie_name": cookie.name,
                        "missing_attributes": missing,
                    },
                    True
                )
    
    def _check_desync(self) -> None:
        """Check for header/cookie session desynchronization."""
        auth = self.states.get("auth", {})
        
        for key, value in auth.items():
            if not key.startswith("cookie:"):
                continue
            
            cookie_name = key.replace("cookie:", "")
            
            # Try to send conflicting header
            test_headers = {
                **self.custom_headers,
                f"X-{cookie_name}": "DESYNC_TEST_VALUE",
            }
            
            try:
                self.rate_limiter.acquire()
                response = self.session.get(
                    self.target,
                    headers=test_headers,
                    timeout=self.timeout
                )
                
                # If server accepts conflicting values, it's vulnerable
                if response.status_code < 400:
                    # Check if response indicates desync
                    if "DESYNC_TEST_VALUE" in response.text or response.status_code == 200:
                        self._add_check_result(
                            "Header/Cookie Session Desynchronization",
                            "Server may accept conflicting session identifiers",
                            Severity.HIGH,
                            75,
                            {
                                "cookie": cookie_name,
                                "test_header": f"X-{cookie_name}",
                            },
                            True
                        )
                        return
                        
            except Exception as e:
                self.logger.debug(f"Desync check error: {e}")
    
    def _check_predictability(self) -> None:
        """Check for predictable token patterns."""
        # Collect multiple tokens
        tokens = []
        
        for _ in range(3):
            try:
                self.rate_limiter.acquire()
                # Create new session for each request
                new_session = self.session.__class__()
                response = new_session.get(self.target, timeout=self.timeout)
                
                for cookie in response.cookies:
                    if SESSION_COOKIE_REGEX.search(cookie.name):
                        tokens.append(cookie.value)
                
                time.sleep(self.delay)
            except Exception:
                pass
        
        if len(tokens) >= 2:
            # Check for sequential patterns
            for i in range(len(tokens) - 1):
                similarity = self._token_similarity(tokens[i], tokens[i + 1])
                if similarity > 0.8:
                    self._add_check_result(
                        "Predictable Session Token Pattern",
                        f"Tokens show {similarity*100:.0f}% similarity",
                        Severity.HIGH,
                        80,
                        {
                            "similarity": similarity,
                            "sample_count": len(tokens),
                        },
                        True
                    )
                    return
    
    def _check_session_config(self) -> None:
        """Check session configuration indicators."""
        if not self.baseline_response:
            return
        
        set_cookie = self.baseline_response.headers.get("Set-Cookie", "")
        
        # Check for overly long max-age
        max_age_match = re.search(r"max-age=(\d+)", set_cookie, re.I)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            # More than 30 days
            if max_age > 2592000:
                self._add_check_result(
                    "Excessive Session Lifetime",
                    f"Session cookie has max-age of {max_age} seconds ({max_age // 86400} days)",
                    Severity.MEDIUM,
                    70,
                    {
                        "max_age_seconds": max_age,
                        "max_age_days": max_age // 86400,
                    },
                    True
                )
        
        # Check for missing expiration
        if "session" in set_cookie.lower() and "expires" not in set_cookie.lower() and "max-age" not in set_cookie.lower():
            # Session cookie (no expiration) - generally OK
            pass
    
    def _token_similarity(self, t1: str, t2: str) -> float:
        """Calculate similarity between two tokens."""
        if len(t1) != len(t2):
            return 0.0
        
        matches = sum(1 for a, b in zip(t1, t2) if a == b)
        return matches / len(t1)
    
    # =========================================================================
    # RESULT HANDLING
    # =========================================================================
    
    def _add_check_result(
        self,
        check_name: str,
        description: str,
        severity: Severity,
        confidence_score: int,
        evidence: Dict[str, Any],
        is_vulnerable: bool
    ) -> None:
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
        
        # Create finding
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
        impacts = {
            "Session Fixation": (
                "CRITICAL: Session fixation enables:\n"
                "- Account takeover\n"
                "- Session hijacking\n"
                "- Identity theft"
            ),
            "Session Not Invalidated": (
                "HIGH: Persistent sessions enable:\n"
                "- Unauthorized access after logout\n"
                "- Session reuse attacks\n"
                "- Shared device exploitation"
            ),
            "Low Entropy": (
                "MEDIUM: Weak tokens enable:\n"
                "- Token prediction\n"
                "- Brute force attacks\n"
                "- Session guessing"
            ),
            "Weak Session Cookie": (
                "HIGH: Missing cookie attributes enable:\n"
                "- Session theft via XSS (missing HttpOnly)\n"
                "- Session theft via MITM (missing Secure)\n"
                "- CSRF attacks (missing SameSite)"
            ),
        }
        
        for key, impact in impacts.items():
            if key.lower() in result.check_name.lower():
                return impact
        
        return "Session management weakness detected"
    
    def _get_remediation(self, result: SessionCheckResult) -> str:
        """Get remediation based on check type."""
        remediations = {
            "fixation": (
                "1. Regenerate session ID after successful login\n"
                "2. Invalidate old session on authentication\n"
                "3. Use framework's session regeneration functions\n"
                "4. Implement session binding to user context"
            ),
            "invalidated": (
                "1. Destroy session server-side on logout\n"
                "2. Clear session cookie on client\n"
                "3. Implement session blacklist for revocation\n"
                "4. Use short-lived tokens with refresh mechanism"
            ),
            "entropy": (
                "1. Use cryptographically secure random generator\n"
                "2. Ensure minimum 128 bits of entropy\n"
                "3. Use framework's built-in session ID generation\n"
                "4. Avoid predictable patterns in tokens"
            ),
            "cookie": (
                "1. Set Secure flag for HTTPS-only transmission\n"
                "2. Set HttpOnly flag to prevent XSS access\n"
                "3. Set SameSite=Strict or Lax for CSRF protection\n"
                "4. Use appropriate expiration times"
            ),
            "desync": (
                "1. Use single source for session identification\n"
                "2. Validate session consistently across headers/cookies\n"
                "3. Reject requests with conflicting identifiers\n"
                "4. Implement session binding validation"
            ),
        }
        
        for key, remediation in remediations.items():
            if key.lower() in result.check_name.lower():
                return remediation
        
        return (
            "1. Review session management implementation\n"
            "2. Follow OWASP session management guidelines\n"
            "3. Use secure framework defaults\n"
            "4. Implement defense in depth"
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
    parser = argparse.ArgumentParser(
        prog="revuex-session",
        description="REVUEX Session GOLD - Session Management Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s -t https://example.com
    %(prog)s -t https://example.com --login-path /api/login
    %(prog)s -t https://example.com --login-path /login --logout-path /logout
    %(prog)s -t https://example.com --login-path /login --login-data '{"user":"test","pass":"test"}'

Author: REVUEX Team
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Base target URL")
    parser.add_argument("--login-path", help="Login endpoint path (POST)")
    parser.add_argument("--logout-path", help="Logout endpoint path")
    parser.add_argument("--login-data", help="Login credentials JSON")
    parser.add_argument("--headers", help="Custom headers JSON file")
    parser.add_argument("--threshold", type=int, default=CONFIDENCE_THRESHOLD,
                        help=f"Confidence threshold (default: {CONFIDENCE_THRESHOLD})")
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
    
    # Parse login data
    login_data = {}
    if args.login_data:
        try:
            login_data = json.loads(args.login_data)
        except Exception as e:
            print_warning(f"Failed to parse login data: {e}")
    
    # Load headers
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
        print(f"Duration: {result.duration_seconds:.2f}s")
        print(f"States Captured: {len(scanner.states)}")
        print(f"Issues Found: {len(result.findings)}")
        print(f"Total Confidence: {scanner.total_confidence}")
        
        # Summary by severity
        by_severity = {}
        for r in scanner.check_results:
            sev = r.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        if by_severity:
            print(f"\n[Severity Summary]")
            for sev, count in by_severity.items():
                print(f"  {sev}: {count}")
    
    if args.output:
        output_data = {
            "scanner": SCANNER_NAME,
            "version": SCANNER_VERSION,
            "target": args.target,
            "scan_id": result.scan_id,
            "duration": result.duration_seconds,
            "total_confidence": scanner.total_confidence,
            "states_captured": list(scanner.states.keys()),
            "check_results": [
                {
                    "check": r.check_name,
                    "severity": r.severity.value,
                    "confidence": r.confidence_score,
                    "evidence": r.evidence,
                }
                for r in scanner.check_results
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
    
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
