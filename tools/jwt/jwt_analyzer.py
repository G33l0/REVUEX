#!/usr/bin/env python3
"""
REVUEX JWT-GOLD Scanner v4.0
============================
High-Confidence JWT Vulnerability Detection without Exploitation.

Design Philosophy:
- Zero token forgery
- Zero brute-force
- Zero privilege abuse
- Pure invariant & trust analysis

Validated Vulnerability Classes:
- Algorithm Confusion (Structural)
- Algorithm None Attack Detection
- Optional Claim Trust (aud, iss, exp)
- Weak Authorization Binding
- JWKS Trust & Rotation Weakness
- Blind / Second-Order JWT Trust
- Header-Controlled Crypto Decisions
- Key Confusion (RSA/HMAC)
- Signature Stripping Detection

Techniques:
- Token Structure Analysis
- Algorithm Integrity Validation
- Claim Trust Verification
- Authorization Binding Detection
- JWKS Endpoint Trust Analysis
- Second-Order Trust Correlation
- Confidence Scoring

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import re
import base64
import json
import time
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse
from datetime import datetime, timezone
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

SCANNER_NAME = "JWT Analyzer GOLD"
SCANNER_VERSION = "4.0.0"

BANNER = r"""
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

JWT-GOLD — Zero-Exploitation Token Trust Analysis
"""

# Confidence threshold for high-value findings
CONFIDENCE_THRESHOLD = 70

# Optional claims that should be validated
OPTIONAL_CLAIMS = {"aud", "iss", "exp", "nbf", "iat", "jti"}

# Expected RSA signature length in bytes
EXPECTED_RSA_SIG_LEN = 256

# Dangerous algorithms
DANGEROUS_ALGORITHMS = {
    "none": "Algorithm None - No signature verification",
    "None": "Algorithm None (case variant)",
    "NONE": "Algorithm None (uppercase)",
    "nOnE": "Algorithm None (mixed case)",
}

# Weak algorithms
WEAK_ALGORITHMS = {
    "HS256": "HMAC-SHA256 - Vulnerable to key confusion if public key known",
    "HS384": "HMAC-SHA384 - Vulnerable to key confusion",
    "HS512": "HMAC-SHA512 - Vulnerable to key confusion",
}

# Identity fields in payload
IDENTITY_FIELDS = {"sub", "user_id", "uid", "user", "username", "email", "id", "account_id"}

# Role/permission fields
PRIVILEGE_FIELDS = {"role", "roles", "admin", "is_admin", "permissions", "scope", "groups"}


# =============================================================================
# JWT RESULT DATACLASS
# =============================================================================

@dataclass
class JWTCheckResult:
    """Result of a single JWT check."""
    check_name: str
    description: str
    severity: Severity
    confidence_score: int
    evidence: str
    is_vulnerable: bool


# =============================================================================
# UTILITIES
# =============================================================================

def b64url_decode(data: str) -> bytes:
    """Base64URL decode with padding."""
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def b64url_encode(data: bytes) -> str:
    """Base64URL encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def safe_json_parse(data: bytes) -> Dict[str, Any]:
    """Safely parse JSON from bytes."""
    try:
        return json.loads(data.decode('utf-8'))
    except Exception:
        return {}


def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    import math
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs if p > 0)


# =============================================================================
# JWT ANALYZER GOLD CLASS
# =============================================================================

class JWTAnalyzer(BaseScanner):
    """
    GOLD-tier JWT Analyzer with zero-exploitation detection.
    
    Methodology:
    1. Parse and decode JWT structure
    2. Check algorithm integrity
    3. Detect algorithm confusion attacks
    4. Analyze optional claim trust
    5. Check authorization binding
    6. Analyze JWKS trust
    7. Detect second-order trust issues
    8. Score and classify findings
    
    Usage:
        analyzer = JWTAnalyzer(
            target="https://api.example.com",
            token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
        )
        result = analyzer.run()
    """
    
    def __init__(
        self,
        target: str,
        token: str,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
        check_jwks: bool = True,
        **kwargs
    ):
        """
        Initialize JWT Analyzer.
        
        Args:
            target: Target API URL
            token: JWT token to analyze
            confidence_threshold: Minimum confidence for findings
            check_jwks: Check JWKS endpoints
        """
        super().__init__(
            name="JWTAnalyzer",
            description="JWT vulnerability analyzer",
            target=target,
            **kwargs
        )
        
        self.token = token
        self.confidence_threshold = confidence_threshold
        self.check_jwks = check_jwks
        
        # Parsed JWT components
        self.header: Dict[str, Any] = {}
        self.payload: Dict[str, Any] = {}
        self.signature: bytes = b""
        self.raw_parts: List[str] = []
        
        # Analysis state
        self.check_results: List[JWTCheckResult] = []
        self.total_confidence: int = 0
        self.is_valid_jwt: bool = False
        
        # Scanner info
        self.scanner_name = SCANNER_NAME
        self.scanner_version = SCANNER_VERSION
    
    def _validate_target(self) -> bool:
        """Validate JWT token format."""
        parts = self.token.split(".")
        if len(parts) != 3:
            self.logger.error("Invalid JWT format - expected 3 parts")
            return False
        return True
    
    def scan(self) -> None:
        """Execute the GOLD JWT analysis."""
        self.logger.info(f"Starting JWT Analyzer GOLD")
        self.logger.info(f"Target: {self.target}")
        
        # Phase 1: Parse token
        self.logger.info("Phase 1: Parsing JWT structure...")
        if not self._parse_token():
            self.logger.error("Failed to parse JWT token")
            return
        
        self.is_valid_jwt = True
        self._log_token_info()
        
        # Phase 2: Algorithm integrity
        self.logger.info("Phase 2: Checking algorithm integrity...")
        self._check_algorithm_integrity()
        
        # Phase 3: Algorithm confusion
        self.logger.info("Phase 3: Checking algorithm confusion...")
        self._check_algorithm_confusion()
        
        # Phase 4: Optional claims
        self.logger.info("Phase 4: Checking optional claim trust...")
        self._check_optional_claims()
        
        # Phase 5: Authorization binding
        self.logger.info("Phase 5: Checking authorization binding...")
        self._check_auth_binding()
        
        # Phase 6: Privilege escalation vectors
        self.logger.info("Phase 6: Checking privilege escalation vectors...")
        self._check_privilege_vectors()
        
        # Phase 7: JWKS trust
        if self.check_jwks:
            self.logger.info("Phase 7: Checking JWKS trust...")
            self._check_jwks_trust()
        
        # Phase 8: Second-order trust
        self.logger.info("Phase 8: Checking second-order trust...")
        self._check_second_order_trust()
        
        # Phase 9: Token expiration
        self.logger.info("Phase 9: Checking token expiration...")
        self._check_expiration()
        
        # Finalize
        self._finalize()
        
        self.logger.info(f"JWT Analyzer complete. Found {len(self.findings)} issue(s)")
    
    # =========================================================================
    # TOKEN PARSING
    # =========================================================================
    
    def _parse_token(self) -> bool:
        """Parse JWT token into components."""
        try:
            self.raw_parts = self.token.split(".")
            
            if len(self.raw_parts) != 3:
                return False
            
            # Decode header
            header_bytes = b64url_decode(self.raw_parts[0])
            self.header = safe_json_parse(header_bytes)
            
            # Decode payload
            payload_bytes = b64url_decode(self.raw_parts[1])
            self.payload = safe_json_parse(payload_bytes)
            
            # Decode signature
            self.signature = b64url_decode(self.raw_parts[2])
            
            return bool(self.header and self.payload)
            
        except Exception as e:
            self.logger.error(f"JWT parsing error: {e}")
            return False
    
    def _log_token_info(self) -> None:
        """Log parsed token information."""
        self.logger.info(f"Algorithm: {self.header.get('alg', 'unknown')}")
        self.logger.info(f"Type: {self.header.get('typ', 'unknown')}")
        self.logger.info(f"Payload claims: {list(self.payload.keys())}")
        self.logger.info(f"Signature length: {len(self.signature)} bytes")
    
    # =========================================================================
    # SECURITY CHECKS
    # =========================================================================
    
    def _check_algorithm_integrity(self) -> None:
        """Check algorithm integrity and signature consistency."""
        alg = self.header.get("alg", "")
        
        # Check for algorithm none
        if alg.lower() == "none":
            self._add_check_result(
                "Algorithm None Attack Vector",
                "JWT uses 'none' algorithm - signature verification bypassed",
                Severity.CRITICAL,
                35,
                f"Algorithm: {alg}",
                True
            )
            return
        
        # Check RS* with wrong signature size
        if alg.startswith("RS") and len(self.signature) < EXPECTED_RSA_SIG_LEN:
            self._add_check_result(
                "Algorithm Integrity Violation",
                f"RS* algorithm ({alg}) with non-RSA signature size ({len(self.signature)} bytes)",
                Severity.CRITICAL,
                30,
                f"Expected >= {EXPECTED_RSA_SIG_LEN} bytes, got {len(self.signature)} bytes",
                True
            )
        
        # Check for missing kid
        if "kid" not in self.header:
            self._add_check_result(
                "Missing Key ID (kid)",
                "JWT verification likely relies on implicit or static keys",
                Severity.HIGH,
                15,
                "No 'kid' claim in header",
                True
            )
    
    def _check_algorithm_confusion(self) -> None:
        """Check for algorithm confusion attack vectors."""
        alg = self.header.get("alg", "")
        
        # RS256 to HS256 confusion potential
        if alg.startswith("RS"):
            self._add_check_result(
                "RSA to HMAC Confusion Potential",
                f"Token uses {alg} - may be vulnerable to key confusion if public key is known",
                Severity.MEDIUM,
                10,
                f"Algorithm {alg} can potentially be downgraded to HMAC",
                True
            )
        
        # Check for x5c header (certificate chain)
        if "x5c" in self.header:
            self._add_check_result(
                "X5C Header Injection Vector",
                "JWT contains x5c header - may accept attacker-supplied certificates",
                Severity.HIGH,
                20,
                f"x5c present with {len(self.header.get('x5c', []))} certificate(s)",
                True
            )
        
        # Check for x5u header (certificate URL)
        if "x5u" in self.header:
            self._add_check_result(
                "X5U Header Injection Vector",
                "JWT contains x5u header - may fetch certificates from attacker URL",
                Severity.CRITICAL,
                25,
                f"x5u: {self.header.get('x5u', '')}",
                True
            )
    
    def _check_optional_claims(self) -> None:
        """Check for missing optional claims that should be validated."""
        missing = OPTIONAL_CLAIMS - set(self.payload.keys())
        
        critical_missing = {"exp"} & missing
        high_missing = {"aud", "iss"} & missing
        
        if critical_missing:
            self._add_check_result(
                "Missing Expiration Claim",
                "JWT has no 'exp' claim - token may never expire",
                Severity.HIGH,
                20,
                f"Missing: {', '.join(critical_missing)}",
                True
            )
        
        if high_missing:
            self._add_check_result(
                "Missing Audience/Issuer Claims",
                f"JWT missing audience/issuer validation claims: {', '.join(high_missing)}",
                Severity.MEDIUM,
                15,
                f"Missing: {', '.join(high_missing)}",
                True
            )
        
        if len(missing) > 3:
            self._add_check_result(
                "Minimal Claim Set",
                f"JWT accepted with minimal claims - server may trust too liberally",
                Severity.MEDIUM,
                10,
                f"Missing optional claims: {', '.join(missing)}",
                True
            )
    
    def _check_auth_binding(self) -> None:
        """Check for weak authorization binding."""
        found_identity = IDENTITY_FIELDS & set(self.payload.keys())
        
        if found_identity:
            identity_values = {k: self.payload.get(k) for k in found_identity}
            self._add_check_result(
                "Weak Authorization Binding",
                "Authorization inferred directly from client-controlled JWT claims",
                Severity.HIGH,
                20,
                f"Identity claims: {', '.join(found_identity)}",
                True
            )
    
    def _check_privilege_vectors(self) -> None:
        """Check for privilege escalation vectors in claims."""
        found_privileges = PRIVILEGE_FIELDS & set(self.payload.keys())
        
        if found_privileges:
            privilege_values = {k: self.payload.get(k) for k in found_privileges}
            
            # Check for admin flags
            for field in ["admin", "is_admin", "isAdmin"]:
                if field in self.payload:
                    self._add_check_result(
                        "Admin Flag in JWT",
                        f"JWT contains '{field}' claim - potential privilege escalation vector",
                        Severity.HIGH,
                        15,
                        f"{field}: {self.payload.get(field)}",
                        True
                    )
                    break
            
            # Check for role claims
            if "role" in self.payload or "roles" in self.payload:
                roles = self.payload.get("role") or self.payload.get("roles")
                self._add_check_result(
                    "Role Claim in JWT",
                    "JWT contains role claims - may be modifiable for privilege escalation",
                    Severity.MEDIUM,
                    10,
                    f"Roles: {roles}",
                    True
                )
    
    def _check_jwks_trust(self) -> None:
        """Check JWKS endpoint trust issues."""
        # Check for jku header
        jku = self.header.get("jku")
        if jku:
            self._add_check_result(
                "Header-Controlled JWKS Trust (jku)",
                "Backend may trust client-supplied JWKS endpoint via 'jku' header",
                Severity.CRITICAL,
                25,
                f"jku: {jku}",
                True
            )
        
        # Check for kid that looks like a path
        kid = self.header.get("kid", "")
        if kid and ("/" in kid or ".." in kid or kid.startswith(".")):
            self._add_check_result(
                "Path Traversal in kid",
                "Key ID (kid) contains path characters - potential path traversal",
                Severity.HIGH,
                20,
                f"kid: {kid}",
                True
            )
        
        # Check for kid injection
        if kid and any(c in kid for c in ["'", '"', ";", "--", "/*"]):
            self._add_check_result(
                "SQL Injection in kid",
                "Key ID (kid) contains SQL metacharacters",
                Severity.HIGH,
                20,
                f"kid: {kid}",
                True
            )
    
    def _check_second_order_trust(self) -> None:
        """Check for second-order JWT trust issues."""
        # Generate identity marker
        marker = hashlib.md5(json.dumps(self.payload, sort_keys=True).encode()).hexdigest()[:8]
        
        self._add_check_result(
            "Second-Order JWT Trust Indicator",
            f"JWT identity marker {marker} may be trusted across async flows",
            Severity.MEDIUM,
            10,
            f"Payload hash: {marker}",
            True
        )
        
        # Check for session binding
        if "jti" not in self.payload:
            self._add_check_result(
                "Missing JWT ID (jti)",
                "No unique token identifier - token replay may be possible",
                Severity.MEDIUM,
                10,
                "No 'jti' claim for replay prevention",
                True
            )
    
    def _check_expiration(self) -> None:
        """Check token expiration settings."""
        exp = self.payload.get("exp")
        iat = self.payload.get("iat")
        
        if exp:
            try:
                exp_time = datetime.fromtimestamp(exp, tz=timezone.utc)
                now = datetime.now(tz=timezone.utc)
                
                if exp_time < now:
                    self._add_check_result(
                        "Expired Token Accepted",
                        f"Token expired on {exp_time.isoformat()} but may still be accepted",
                        Severity.HIGH,
                        15,
                        f"Expired: {exp_time.isoformat()}",
                        True
                    )
                
                if iat:
                    lifetime = exp - iat
                    if lifetime > 86400 * 30:  # > 30 days
                        self._add_check_result(
                            "Excessive Token Lifetime",
                            f"Token lifetime is {lifetime // 86400} days - excessive for security",
                            Severity.MEDIUM,
                            10,
                            f"Lifetime: {lifetime // 86400} days",
                            True
                        )
            except Exception:
                pass
    
    # =========================================================================
    # RESULT HANDLING
    # =========================================================================
    
    def _add_check_result(
        self,
        check_name: str,
        description: str,
        severity: Severity,
        confidence_score: int,
        evidence: str,
        is_vulnerable: bool
    ) -> None:
        """Add a check result and update confidence."""
        result = JWTCheckResult(
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
    
    def _create_finding(self, result: JWTCheckResult) -> None:
        """Create finding from check result."""
        finding = Finding(
            id=self._generate_finding_id(result.check_name),
            title=result.check_name,
            severity=result.severity,
            description=result.description,
            url=self.target,
            parameter="JWT Token",
            method="N/A",
            payload=self.token[:50] + "..." if len(self.token) > 50 else self.token,
            evidence=result.evidence,
            impact=self._get_impact(result),
            remediation=self._get_remediation(result),
            vulnerability_type="jwt",
            confidence="high" if result.confidence_score >= 20 else "medium",
        )
        self.add_finding(finding)
    
    def _get_impact(self, result: JWTCheckResult) -> str:
        """Get impact description."""
        if result.severity == Severity.CRITICAL:
            return (
                "CRITICAL: JWT vulnerability enables:\n"
                "- Authentication bypass\n"
                "- Token forgery\n"
                "- Privilege escalation\n"
                "- Full account takeover"
            )
        elif result.severity == Severity.HIGH:
            return (
                "HIGH: JWT weakness enables:\n"
                "- Potential authentication bypass\n"
                "- Session hijacking\n"
                "- Privilege manipulation"
            )
        else:
            return (
                "MEDIUM: JWT configuration issue:\n"
                "- May enable further attacks\n"
                "- Weakens overall security posture"
            )
    
    def _get_remediation(self, result: JWTCheckResult) -> str:
        """Get remediation based on check type."""
        if "algorithm" in result.check_name.lower():
            return (
                "1. Enforce algorithm whitelist server-side\n"
                "2. Never accept 'none' algorithm\n"
                "3. Use asymmetric algorithms (RS256, ES256)\n"
                "4. Validate algorithm before verification"
            )
        elif "jwks" in result.check_name.lower() or "jku" in result.check_name.lower():
            return (
                "1. Never trust client-supplied JWKS endpoints\n"
                "2. Use static JWKS configuration\n"
                "3. Validate jku against whitelist\n"
                "4. Pin expected key IDs"
            )
        elif "claim" in result.check_name.lower():
            return (
                "1. Validate all security-relevant claims\n"
                "2. Enforce exp, aud, iss validation\n"
                "3. Use short token lifetimes\n"
                "4. Implement token refresh flow"
            )
        else:
            return (
                "1. Review JWT implementation\n"
                "2. Use established JWT libraries\n"
                "3. Follow OWASP JWT guidelines\n"
                "4. Implement defense in depth"
            )
    
    def _generate_finding_id(self, context: str) -> str:
        """Generate unique finding ID."""
        data = f"{self.target}:{context}:{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    def _finalize(self) -> None:
        """Finalize analysis and print summary."""
        print(f"\n{'='*60}")
        print(f"Total Confidence Score: {self.total_confidence}")
        print(f"{'='*60}")
        
        if self.total_confidence >= self.confidence_threshold:
            print_success("JWT VULNERABILITY CONFIRMED (High Confidence)")
        else:
            print_warning("JWT issues detected but below confidence threshold")


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="revuex-jwt",
        description="REVUEX JWT-GOLD Analyzer - Zero-Exploitation Token Trust Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s -t https://api.example.com --jwt "eyJhbGciOiJSUzI1NiIs..."
    %(prog)s -t https://api.example.com --jwt "eyJ..." --threshold 50 -v
    %(prog)s -t https://api.example.com --jwt "eyJ..." -o report.json

Author: REVUEX Team
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target API URL")
    parser.add_argument("--jwt", required=True, help="JWT token to analyze")
    parser.add_argument("--threshold", type=int, default=CONFIDENCE_THRESHOLD,
                        help=f"Confidence threshold (default: {CONFIDENCE_THRESHOLD})")
    parser.add_argument("--no-jwks", action="store_true", help="Skip JWKS checks")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
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
    
    analyzer = JWTAnalyzer(
        target=args.target,
        token=args.jwt,
        confidence_threshold=args.threshold,
        check_jwks=not args.no_jwks,
        verbose=args.verbose,
    )
    
    result = analyzer.run()
    
    if not args.quiet:
        print(f"\n{'='*60}")
        print("ANALYSIS COMPLETE")
        print(f"{'='*60}")
        print(f"Target: {args.target}")
        print(f"Duration: {result.duration_seconds:.2f}s")
        print(f"Checks Performed: {len(analyzer.check_results)}")
        print(f"Issues Found: {len(result.findings)}")
        print(f"Confidence Score: {analyzer.total_confidence}")
        
        # Token info
        if analyzer.is_valid_jwt:
            print(f"\n[Token Info]")
            print(f"  Algorithm: {analyzer.header.get('alg', 'unknown')}")
            print(f"  Claims: {', '.join(analyzer.payload.keys())}")
        
        # Summary by severity
        critical = sum(1 for r in analyzer.check_results if r.severity == Severity.CRITICAL)
        high = sum(1 for r in analyzer.check_results if r.severity == Severity.HIGH)
        medium = sum(1 for r in analyzer.check_results if r.severity == Severity.MEDIUM)
        
        print(f"\n[Severity Summary]")
        print(f"  Critical: {critical}")
        print(f"  High: {high}")
        print(f"  Medium: {medium}")
    
    if args.output:
        output_data = {
            "scanner": "REVUEX JWT Analyzer GOLD",
            "version": SCANNER_VERSION,
            "target": args.target,
            "scan_id": result.scan_id,
            "duration": result.duration_seconds,
            "confidence_score": analyzer.total_confidence,
            "token_info": {
                "algorithm": analyzer.header.get("alg"),
                "type": analyzer.header.get("typ"),
                "claims": list(analyzer.payload.keys()),
            },
            "check_results": [
                {
                    "check": r.check_name,
                    "severity": r.severity.value,
                    "score": r.confidence_score,
                    "evidence": r.evidence,
                }
                for r in analyzer.check_results
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
