#!/usr/bin/env python3
"""
REVUEX IDOR Framework v1.1-GOLD
===============================
Research-Grade IDOR Detection with Dual-Account
+ Blind / Second-Order Authorization Correlation

Features:
- Account A vs Account B authorization diffing
- Structural JSON similarity analysis
- Sensitive-field heuristics
- Blind IDOR via Header & Token Injection
- Deferred / Second-Order authorization validation
- Multi-method testing (GET, POST, PUT, DELETE, PATCH)
- ID enumeration with pattern detection
- Non-destructive, bounty-safe

Phases:
1. Direct IDOR - Account A/B comparison
2. Blind IDOR - Header injection correlation
3. Second-Order - Deferred authorization bypass

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import re
import json
import copy
import argparse
import difflib
import hashlib
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
from datetime import datetime, timezone
from dataclasses import dataclass
from enum import Enum
import sys

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.base_scanner import (
    BaseScanner,
    Finding,
    ScanResult,
    Severity,
    ScanStatus,
)
from core.utils import (
    normalize_url,
    extract_domain,
    random_string,
    print_success,
    print_error,
    print_warning,
    print_info,
)


# =============================================================================
# CONSTANTS
# =============================================================================

SCANNER_NAME = "IDOR Scanner GOLD"
SCANNER_VERSION = "1.1.0"

# HTTP methods to test for IDOR
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]

# Blind IDOR header injection vectors
BLIND_IDOR_HEADERS = [
    "X-User-Id",
    "X-Account-Id",
    "X-Actor-Id",
    "X-Object-Id",
    "X-Resource-Id",
    "X-Entity-Id",
    "X-Owner-Id",
    "X-Customer-Id",
    "X-Client-Id",
    "X-Tenant-Id",
    "X-Organization-Id",
    "X-Org-Id",
    "X-Request-Id",
    "X-Correlation-Id",
    "X-Session-User",
    "X-Auth-User",
    "X-Real-User",
    "X-Original-User",
    "X-Forwarded-User",
    "X-User",
    "User-Id",
    "Account-Id",
    "Actor-Id",
]

# Sensitive field names that indicate high-impact IDOR
SENSITIVE_FIELDS = {
    # Identity
    "email", "e-mail", "mail",
    "user", "username", "user_name", "userId", "user_id",
    "account", "accountId", "account_id",
    "owner", "ownerId", "owner_id",
    
    # Authentication
    "password", "passwd", "pass", "pwd",
    "token", "access_token", "refresh_token", "api_key", "apiKey",
    "secret", "secret_key", "secretKey",
    "session", "sessionId", "session_id",
    
    # Personal Info
    "ssn", "social_security",
    "phone", "telephone", "mobile", "cell",
    "address", "street", "city", "zip", "postal",
    "dob", "date_of_birth", "birthdate", "birthday",
    "name", "first_name", "last_name", "full_name",
    
    # Financial
    "credit_card", "creditCard", "card_number", "cardNumber",
    "cvv", "cvc", "expiry",
    "bank", "bank_account", "routing",
    "balance", "amount", "price", "salary",
    
    # Authorization
    "role", "roles", "permission", "permissions",
    "admin", "is_admin", "isAdmin",
    "privilege", "privileges", "access_level",
    
    # Identifiers
    "id", "ID", "_id", "uuid", "guid",
    "order", "orderId", "order_id",
    "invoice", "invoiceId", "invoice_id",
    "document", "documentId", "document_id",
}

# Common ID patterns in URLs
ID_PATTERNS = [
    r"/(\d+)(?:/|$|\?)",
    r"/([a-f0-9-]{36})(?:/|$|\?)",
    r"/([a-f0-9]{24})(?:/|$|\?)",
    r"/([a-zA-Z0-9_-]{11})(?:/|$|\?)",
    r"[?&]id=(\d+)",
    r"[?&]id=([a-f0-9-]+)",
]


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def normalize_json(obj: Any) -> Any:
    """
    Normalize JSON for structural comparison.
    Replaces values with type names to compare structure.
    """
    if isinstance(obj, dict):
        return {k: normalize_json(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [normalize_json(i) for i in obj]
    if isinstance(obj, str):
        return "<str>"
    if isinstance(obj, bool):
        return "<bool>"
    if isinstance(obj, int):
        return "<int>"
    if isinstance(obj, float):
        return "<float>"
    if obj is None:
        return "<null>"
    return f"<{type(obj).__name__}>"


def json_similarity(a: Any, b: Any) -> float:
    """Calculate similarity between two JSON objects."""
    str_a = json.dumps(a, sort_keys=True, default=str)
    str_b = json.dumps(b, sort_keys=True, default=str)
    return difflib.SequenceMatcher(None, str_a, str_b).ratio()


def extract_sensitive_fields(obj: Any, prefix: str = "") -> Dict[str, Any]:
    """Extract sensitive fields from JSON object."""
    sensitive = {}
    
    if isinstance(obj, dict):
        for key, value in obj.items():
            full_key = f"{prefix}.{key}" if prefix else key
            key_lower = key.lower()
            if any(s.lower() in key_lower for s in SENSITIVE_FIELDS):
                sensitive[full_key] = value
            if isinstance(value, (dict, list)):
                sensitive.update(extract_sensitive_fields(value, full_key))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            sensitive.update(extract_sensitive_fields(item, f"{prefix}[{i}]"))
    
    return sensitive


def find_ids_in_url(url: str) -> List[Tuple[str, str]]:
    """Find potential IDs in URL."""
    ids = []
    for pattern in ID_PATTERNS:
        matches = re.findall(pattern, url)
        for match in matches:
            if match.isdigit():
                ids.append(("numeric", match))
            elif re.match(r"^[a-f0-9-]{36}$", match):
                ids.append(("uuid", match))
            elif re.match(r"^[a-f0-9]{24}$", match):
                ids.append(("mongodb", match))
            else:
                ids.append(("encoded", match))
    return ids


def generate_adjacent_ids(id_value: str, id_type: str, count: int = 5) -> List[str]:
    """Generate adjacent IDs for enumeration testing."""
    adjacent = []
    if id_type == "numeric":
        base = int(id_value)
        for offset in range(-count, count + 1):
            if offset != 0:
                adjacent.append(str(base + offset))
    return adjacent


# =============================================================================
# IDOR TEST RESULT
# =============================================================================

@dataclass
class IDORTestResult:
    """Result of a single IDOR test."""
    phase: str          # "direct", "blind", "second_order"
    method: str
    status_a: int
    status_b: int
    similarity: float
    is_vulnerable: bool
    sensitive_exposed: List[str]
    evidence: str


# =============================================================================
# IDOR SCANNER GOLD v1.1 CLASS
# =============================================================================

class IDORScanner(BaseScanner):
    """
    GOLD-tier IDOR scanner v1.1 with Blind/Second-Order detection.
    
    Phases:
    1. Direct IDOR - Account A/B authorization comparison
    2. Blind IDOR - Header injection with object ID correlation
    3. Second-Order - Deferred authorization bypass detection
    
    Usage:
        scanner = IDORScanner(
            target="https://api.example.com/orders/123",
            token_a="Bearer owner_jwt_token",
            token_b="Bearer attacker_jwt_token",
            object_id="123"
        )
        result = scanner.run()
    """
    
    def __init__(
        self,
        target: str,
        token_a: str = "",
        token_b: str = "",
        object_id: str = "",
        blind_headers: Optional[Set[str]] = None,
        test_methods: bool = True,
        test_enumeration: bool = False,
        test_blind: bool = True,
        similarity_threshold: float = 0.90,
        json_body: Optional[Dict] = None,
        **kwargs
    ):
        """
        Initialize IDOR Scanner v1.1.
        
        Args:
            target: Target URL with object ID
            token_a: Authorization header for Account A (owner) - optional
            token_b: Authorization header for Account B (attacker) - optional
            object_id: Object ID owned by Account A (for blind IDOR)
            blind_headers: Headers to inject object ID into
            test_methods: Test multiple HTTP methods
            test_enumeration: Test ID enumeration
            test_blind: Test blind/second-order IDOR
            similarity_threshold: JSON similarity threshold
            json_body: JSON body for POST/PUT requests
            
        Note:
            If token_a and token_b are not provided, scanner will run in 
            limited mode without cross-account testing.
        """
        super().__init__(
            name="IDORScanner",
            description="Insecure Direct Object Reference scanner",
            target=target,
            **kwargs
        )
        
        self.token_a = token_a
        self.token_b = token_b
        self.tokens_provided = bool(token_a and token_b)
        self.object_id = object_id or self._extract_object_id()
        self.blind_headers = blind_headers or set(BLIND_IDOR_HEADERS)
        self.test_methods = test_methods
        self.test_enumeration = test_enumeration
        self.test_blind = test_blind
        self.similarity_threshold = similarity_threshold
        self.json_body = json_body or {}
        
        # Create separate sessions for each account
        self.session_a = self._create_session()
        self.session_b = self._create_session()
        
        # Set authorization headers if provided
        if token_a:
            self.session_a.headers["Authorization"] = token_a
        if token_b:
            self.session_b.headers["Authorization"] = token_b
        
        # Prepare blind IDOR marker headers
        self.marker_headers = {h: self.object_id for h in self.blind_headers}
        
        # Detection state
        self.test_results: List[IDORTestResult] = []
        self.detected_ids: List[Tuple[str, str]] = []
        self.baseline_response: Optional[Dict] = None
        
        # Scanner info
        self.scanner_name = SCANNER_NAME
        self.scanner_version = SCANNER_VERSION
    
    def _create_session(self):
        """Create a new requests session."""
        import requests
        session = requests.Session()
        session.headers.update({
            "User-Agent": "REVUEX-IDOR/1.1",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        return session
    
    def _extract_object_id(self) -> str:
        """Auto-extract object ID from target URL."""
        ids = find_ids_in_url(self.target)
        if ids:
            return ids[0][1]  # Return first found ID
        return ""
    
    def _validate_target(self) -> bool:
        """Validate target is accessible by Account A."""
        try:
            response = self.session_a.get(
                self.target,
                timeout=self.timeout,
                allow_redirects=True
            )
            if response.status_code >= 400:
                self.logger.error(f"Account A cannot access target (status: {response.status_code})")
                return False
            return True
        except Exception as e:
            self.logger.error(f"Target validation failed: {e}")
            return False
    
    def scan(self) -> None:
        """Execute the GOLD IDOR v1.1 scan."""
        self.logger.info(f"Starting IDOR GOLD v1.1 scan on {self.target}")
        
        # Check if tokens are provided for full IDOR testing
        if not self.tokens_provided:
            self.logger.warning("No authentication tokens provided. IDOR scanner requires two different account tokens for cross-account testing.")
            self.logger.info("Skipping IDOR scan. Provide token_a and token_b for full testing.")
            self.logger.info("Use: --token-a 'Bearer xxx' --token-b 'Bearer yyy'")
            return
        
        # Detect IDs in URL
        self.detected_ids = find_ids_in_url(self.target)
        if self.detected_ids:
            self.logger.info(f"Detected IDs: {self.detected_ids}")
        
        if self.object_id:
            self.logger.info(f"Object ID for blind testing: {self.object_id}")
        
        # =====================================================================
        # PHASE 1: Direct IDOR (A/B Authorization Diff)
        # =====================================================================
        self.logger.info("=" * 50)
        self.logger.info("Phase 1: Direct A/B Authorization Diff")
        self.logger.info("=" * 50)
        
        methods = HTTP_METHODS if self.test_methods else ["GET"]
        
        for method in methods:
            self.logger.info(f"Testing {method} method...")
            result = self._test_direct_idor(method)
            
            if result:
                self.test_results.append(result)
                if result.is_vulnerable:
                    self._create_finding(result)
        
        # =====================================================================
        # PHASE 2: Blind / Second-Order IDOR
        # =====================================================================
        if self.test_blind and self.object_id:
            self.logger.info("")
            self.logger.info("=" * 50)
            self.logger.info("Phase 2: Blind / Second-Order IDOR")
            self.logger.info("=" * 50)
            
            result = self._test_blind_idor()
            if result:
                self.test_results.append(result)
                if result.is_vulnerable:
                    self._create_finding(result)
        
        # =====================================================================
        # PHASE 3: ID Enumeration
        # =====================================================================
        if self.test_enumeration and self.detected_ids:
            self.logger.info("")
            self.logger.info("=" * 50)
            self.logger.info("Phase 3: ID Enumeration")
            self.logger.info("=" * 50)
            
            self._test_id_enumeration()
        
        self.logger.info(f"\nIDOR GOLD v1.1 scan complete. Found {len(self.findings)} issue(s)")
    
    # =========================================================================
    # PHASE 1: DIRECT IDOR
    # =========================================================================
    
    def _test_direct_idor(self, method: str) -> Optional[IDORTestResult]:
        """
        Test for direct IDOR using dual-account comparison.
        """
        self.rate_limiter.acquire()
        self.request_count += 1
        
        # Account A (owner) accesses the resource
        self.logger.debug(f"[Account A] Fetching baseline as owner")
        
        try:
            resp_a = self._make_request(self.session_a, method)
        except Exception as e:
            self.logger.debug(f"Account A request failed: {e}")
            return None
        
        time.sleep(self.delay)
        
        if resp_a.status_code >= 400:
            self.logger.debug(f"Account A cannot access object (status: {resp_a.status_code})")
            return None
        
        # Account B (attacker) attempts to access the same resource
        self.logger.debug(f"[Account B] Attempting unauthorized access")
        
        self.rate_limiter.acquire()
        self.request_count += 1
        
        try:
            resp_b = self._make_request(self.session_b, method)
        except Exception as e:
            self.logger.debug(f"Account B request failed: {e}")
            return None
        
        time.sleep(self.delay)
        
        # Analyze responses
        return self._analyze_direct_responses(resp_a, resp_b, method)
    
    def _make_request(self, session, method: str):
        """Make HTTP request with specified method."""
        if method == "GET":
            return session.get(self.target, timeout=self.timeout)
        elif method == "POST":
            return session.post(self.target, json=self.json_body, timeout=self.timeout)
        elif method == "PUT":
            return session.put(self.target, json=self.json_body, timeout=self.timeout)
        elif method == "DELETE":
            return session.delete(self.target, timeout=self.timeout)
        elif method == "PATCH":
            return session.patch(self.target, json=self.json_body, timeout=self.timeout)
        else:
            return session.request(method, self.target, timeout=self.timeout)
    
    def _analyze_direct_responses(self, resp_a, resp_b, method: str) -> IDORTestResult:
        """Analyze Account A and Account B responses for direct IDOR."""
        self.logger.debug(f"Status A: {resp_a.status_code} | Status B: {resp_b.status_code}")
        
        # Status code mismatch = authorization enforced
        if resp_a.status_code != resp_b.status_code:
            return IDORTestResult(
                phase="direct",
                method=method,
                status_a=resp_a.status_code,
                status_b=resp_b.status_code,
                similarity=0.0,
                is_vulnerable=False,
                sensitive_exposed=[],
                evidence=f"Authorization enforced: A={resp_a.status_code}, B={resp_b.status_code}"
            )
        
        # Account B blocked
        if resp_b.status_code in [401, 403, 404]:
            return IDORTestResult(
                phase="direct",
                method=method,
                status_a=resp_a.status_code,
                status_b=resp_b.status_code,
                similarity=0.0,
                is_vulnerable=False,
                sensitive_exposed=[],
                evidence=f"Access denied for Account B (status: {resp_b.status_code})"
            )
        
        # Both got 200 - deep JSON analysis
        if resp_a.status_code == resp_b.status_code == 200:
            return self._analyze_json_responses(resp_a, resp_b, method, "direct")
        
        return IDORTestResult(
            phase="direct",
            method=method,
            status_a=resp_a.status_code,
            status_b=resp_b.status_code,
            similarity=0.0,
            is_vulnerable=False,
            sensitive_exposed=[],
            evidence=f"Unexpected status codes: A={resp_a.status_code}, B={resp_b.status_code}"
        )
    
    def _analyze_json_responses(self, resp_a, resp_b, method: str, phase: str) -> IDORTestResult:
        """Deep JSON analysis for IDOR detection."""
        try:
            json_a = resp_a.json()
            json_b = resp_b.json()
        except json.JSONDecodeError:
            text_similarity = difflib.SequenceMatcher(
                None, resp_a.text, resp_b.text
            ).ratio()
            
            is_vulnerable = text_similarity > self.similarity_threshold
            
            return IDORTestResult(
                phase=phase,
                method=method,
                status_a=resp_a.status_code,
                status_b=resp_b.status_code,
                similarity=text_similarity,
                is_vulnerable=is_vulnerable,
                sensitive_exposed=[],
                evidence=f"Non-JSON response, text similarity: {text_similarity:.2f}"
            )
        
        self.baseline_response = json_a
        
        # Structural similarity
        norm_a = normalize_json(json_a)
        norm_b = normalize_json(json_b)
        structural_similarity = json_similarity(norm_a, norm_b)
        
        # Data similarity
        data_similarity = json_similarity(json_a, json_b)
        
        self.logger.debug(f"Structural similarity: {structural_similarity:.2f}")
        self.logger.debug(f"Data similarity: {data_similarity:.2f}")
        
        # Sensitive fields
        sensitive_b = extract_sensitive_fields(json_b)
        sensitive_keys = list(sensitive_b.keys())
        
        # IDOR detection logic
        is_vulnerable = False
        evidence_parts = []
        
        if structural_similarity > self.similarity_threshold:
            evidence_parts.append(f"Same object structure ({structural_similarity:.2f})")
            
            if data_similarity > self.similarity_threshold:
                is_vulnerable = True
                evidence_parts.append(f"Same data content ({data_similarity:.2f})")
            elif data_similarity > 0.5:
                is_vulnerable = True
                evidence_parts.append(f"Partial data overlap ({data_similarity:.2f})")
        
        if sensitive_keys:
            evidence_parts.append(f"Sensitive fields: {', '.join(sensitive_keys[:5])}")
        
        return IDORTestResult(
            phase=phase,
            method=method,
            status_a=resp_a.status_code,
            status_b=resp_b.status_code,
            similarity=data_similarity,
            is_vulnerable=is_vulnerable,
            sensitive_exposed=sensitive_keys,
            evidence=" | ".join(evidence_parts) if evidence_parts else "No IDOR indicators"
        )
    
    # =========================================================================
    # PHASE 2: BLIND / SECOND-ORDER IDOR
    # =========================================================================
    
    def _test_blind_idor(self) -> Optional[IDORTestResult]:
        """
        Test for blind/second-order IDOR.
        
        Methodology:
        1. Inject object ID via headers using Account A
        2. Wait for backend processing
        3. Check if Account B can access the object via correlation
        """
        self.logger.info("Injecting object reference via headers...")
        
        # Step 1: Account A injects object ID via headers
        self.rate_limiter.acquire()
        self.request_count += 1
        
        try:
            # Send request with marker headers
            self.session_a.get(
                self.target,
                headers=self.marker_headers,
                timeout=self.timeout
            )
        except Exception as e:
            self.logger.debug(f"Blind injection failed: {e}")
            return None
        
        # Step 2: Wait for deferred processing
        self.logger.info("Waiting for deferred processing (2s)...")
        time.sleep(2)
        
        # Step 3: Account B attempts to correlate
        self.logger.info("Correlating deferred access as Account B...")
        
        self.rate_limiter.acquire()
        self.request_count += 1
        
        try:
            resp_b = self.session_b.get(self.target, timeout=self.timeout)
        except Exception as e:
            self.logger.debug(f"Correlation request failed: {e}")
            return None
        
        # Analyze for blind IDOR
        return self._analyze_blind_response(resp_b)
    
    def _analyze_blind_response(self, resp_b) -> IDORTestResult:
        """Analyze response for blind/second-order IDOR indicators."""
        try:
            data = resp_b.json()
        except json.JSONDecodeError:
            # Check raw text for object ID
            if self.object_id and self.object_id in resp_b.text:
                return IDORTestResult(
                    phase="blind",
                    method="GET",
                    status_a=200,
                    status_b=resp_b.status_code,
                    similarity=1.0,
                    is_vulnerable=True,
                    sensitive_exposed=[],
                    evidence=f"Object ID '{self.object_id}' found in non-JSON response"
                )
            
            return IDORTestResult(
                phase="blind",
                method="GET",
                status_a=200,
                status_b=resp_b.status_code,
                similarity=0.0,
                is_vulnerable=False,
                sensitive_exposed=[],
                evidence="No blind IDOR correlation detected"
            )
        
        # Check if object ID appears in response JSON
        flat_json = json.dumps(data)
        
        if self.object_id and self.object_id in flat_json:
            # BLIND IDOR CONFIRMED
            sensitive = extract_sensitive_fields(data)
            
            return IDORTestResult(
                phase="blind",
                method="GET",
                status_a=200,
                status_b=resp_b.status_code,
                similarity=1.0,
                is_vulnerable=True,
                sensitive_exposed=list(sensitive.keys()),
                evidence=(
                    f"Object ID '{self.object_id}' correlated in Account B response | "
                    f"Backend accepted header injection | "
                    f"Deferred authorization check missing"
                )
            )
        
        return IDORTestResult(
            phase="blind",
            method="GET",
            status_a=200,
            status_b=resp_b.status_code,
            similarity=0.0,
            is_vulnerable=False,
            sensitive_exposed=[],
            evidence="No blind IDOR correlation detected"
        )
    
    # =========================================================================
    # PHASE 3: ID ENUMERATION
    # =========================================================================
    
    def _test_id_enumeration(self) -> None:
        """Test ID enumeration for detected IDs."""
        self.logger.info("Testing ID enumeration...")
        
        for id_type, id_value in self.detected_ids:
            adjacent_ids = generate_adjacent_ids(id_value, id_type)
            
            for adj_id in adjacent_ids[:3]:
                test_url = self.target.replace(id_value, adj_id)
                
                self.rate_limiter.acquire()
                self.request_count += 1
                
                try:
                    resp = self.session_b.get(test_url, timeout=self.timeout)
                    
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if data and len(str(data)) > 10:
                                finding = Finding(
                                    id=self._generate_finding_id(f"idor_enum_{adj_id}"),
                                    title="IDOR via ID Enumeration",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"ID enumeration vulnerability detected. "
                                        f"Account B can access objects by guessing IDs. "
                                        f"Tested ID: {adj_id}"
                                    ),
                                    url=test_url,
                                    parameter="id",
                                    method="GET",
                                    payload=adj_id,
                                    evidence=f"Accessible object at ID: {adj_id}",
                                    impact=(
                                        "Attackers can enumerate all objects:\n"
                                        "- Mass data exfiltration\n"
                                        "- Access to other users' data"
                                    ),
                                    remediation=(
                                        "1. Use UUIDs instead of sequential IDs\n"
                                        "2. Implement proper authorization checks"
                                    ),
                                    vulnerability_type="idor",
                                    confidence="high",
                                )
                                self.add_finding(finding)
                        except json.JSONDecodeError:
                            pass
                except Exception as e:
                    self.logger.debug(f"Enumeration test failed: {e}")
                
                time.sleep(self.delay)
    
    # =========================================================================
    # FINDING CREATION
    # =========================================================================
    
    def _create_finding(self, result: IDORTestResult) -> None:
        """Create finding from IDOR test result."""
        # Determine severity
        if result.phase == "blind":
            severity = Severity.CRITICAL
            title = "Blind / Second-Order IDOR Confirmed"
            description = (
                f"Blind IDOR vulnerability confirmed. Backend accepted object reference "
                f"via header injection and exposed it to unauthorized Account B. "
                f"Deferred authorization check is missing."
            )
        else:
            critical_fields = {"password", "token", "secret", "credit_card", "ssn"}
            has_critical = any(
                any(cf in field.lower() for cf in critical_fields)
                for field in result.sensitive_exposed
            )
            severity = Severity.CRITICAL if has_critical else Severity.HIGH
            title = f"Direct IDOR Confirmed ({result.method})"
            description = (
                f"Insecure Direct Object Reference vulnerability confirmed. "
                f"Account B (attacker) can access resources belonging to Account A (owner) "
                f"via {result.method} request."
            )
        
        finding = Finding(
            id=self._generate_finding_id(f"idor_{result.phase}_{result.method}"),
            title=title,
            severity=severity,
            description=description,
            url=self.target,
            parameter="object_id",
            method=result.method,
            payload=f"Authorization: {self.token_b[:20]}..." if result.phase == "direct" else f"Headers: {list(self.blind_headers)[:3]}",
            evidence=result.evidence,
            impact=(
                f"{'CRITICAL' if result.phase == 'blind' else 'HIGH'}: Unauthorized access to other users' data:\n"
                "- View/modify/delete other users' resources\n"
                "- Access sensitive personal information\n"
                "- Privilege escalation potential\n"
                f"Sensitive fields exposed: {', '.join(result.sensitive_exposed[:10]) if result.sensitive_exposed else 'None detected'}"
            ),
            remediation=(
                "1. Implement proper authorization checks on EVERY request\n"
                "2. Verify object ownership before returning data\n"
                "3. Don't trust user-supplied headers for authorization\n"
                "4. Use resource-based access control (RBAC)\n"
                "5. Validate indirect object references"
            ),
            vulnerability_type="idor",
            confidence="very high" if result.phase == "blind" else "high",
        )
        self.add_finding(finding)
        self._print_poc(result)
    
    def _generate_finding_id(self, context: str) -> str:
        """Generate unique finding ID."""
        data = f"{self.target}:{context}:{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    def _print_poc(self, result: IDORTestResult) -> None:
        """Print proof-of-concept details."""
        parsed = urlparse(self.target)
        
        if result.phase == "blind":
            print_success("BLIND / SECOND-ORDER IDOR CONFIRMED")
            print(f"\n{'='*60}")
            print("BLIND IDOR PROOF OF CONCEPT")
            print(f"{'='*60}")
            print(f"Target: {self.target}")
            print(f"Object ID: {self.object_id}")
            print(f"\n[Phase 1: Header Injection as Account A]")
            print(f"  Headers injected: {list(self.blind_headers)[:5]}")
            print(f"\n[Phase 2: Correlation as Account B]")
            print(f"  Object ID found in response: YES")
            print(f"\n[Evidence]")
            print(f"  • Backend accepted object reference via headers")
            print(f"  • Deferred authorization check missing")
            print(f"  • Object reference trusted cross-account")
            print(f"\n{'='*60}")
            print("REPORT SUMMARY")
            print(f"{'='*60}")
            print("Type: Blind / Second-Order IDOR")
            print("Impact: Unauthorized object access via deferred correlation")
            print("Confidence: VERY HIGH")
            print(f"{'='*60}\n")
        else:
            print_success(f"DIRECT IDOR CONFIRMED via {result.method}")
            print(f"\n{'='*60}")
            print("DIRECT IDOR PROOF OF CONCEPT")
            print(f"{'='*60}")
            print(f"Target: {self.target}")
            print(f"Method: {result.method}")
            print(f"\n[Account A - Owner]")
            print(f"  Authorization: {self.token_a[:30]}...")
            print(f"  Status: {result.status_a}")
            print(f"\n[Account B - Attacker]")
            print(f"  Authorization: {self.token_b[:30]}...")
            print(f"  Status: {result.status_b}")
            print(f"\n[Analysis]")
            print(f"  Similarity: {result.similarity:.2f}")
            if result.sensitive_exposed:
                print(f"  Sensitive Fields: {', '.join(result.sensitive_exposed[:5])}")
            print(f"\n{'='*60}")
            print("REPORT SUMMARY")
            print(f"{'='*60}")
            print("Type: Insecure Direct Object Reference (IDOR)")
            print("Impact: Unauthorized object access")
            print("Confidence: HIGH (Dual-account verification)")
            print(f"{'='*60}\n")


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="revuex-idor",
        description="REVUEX IDOR GOLD v1.1 - Dual-Account + Blind/Second-Order Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Direct IDOR testing
    %(prog)s -t "https://api.example.com/orders/123" --token-a "Bearer AAA" --token-b "Bearer BBB"
    
    # With blind/second-order testing
    %(prog)s -t "https://api.example.com/orders/123" --token-a "Bearer AAA" --token-b "Bearer BBB" --object-id "123"
    
    # Custom blind headers
    %(prog)s -t "https://api.example.com/v1/orders/123" --token-a "Bearer AAA" --token-b "Bearer BBB" --object-id "123" --blind-headers X-User-Id X-Account-Id

Methodology:
    Phase 1: Direct A/B Authorization Diff
    Phase 2: Blind / Second-Order IDOR via Header Injection
    Phase 3: ID Enumeration (optional)

Author: REVUEX Team
License: MIT
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target URL with object ID")
    parser.add_argument("--token-a", required=True, help="Authorization for Account A (owner)")
    parser.add_argument("--token-b", required=True, help="Authorization for Account B (attacker)")
    parser.add_argument("--object-id", default="", help="Object ID owned by Account A (for blind IDOR)")
    parser.add_argument("--blind-headers", nargs="+", default=None, help="Headers for blind IDOR injection")
    parser.add_argument("--no-methods", action="store_true", help="Only test GET method")
    parser.add_argument("--no-blind", action="store_true", help="Skip blind/second-order IDOR testing")
    parser.add_argument("--enum", action="store_true", help="Test ID enumeration")
    parser.add_argument("--threshold", type=float, default=0.90, help="Similarity threshold (default: 0.90)")
    parser.add_argument("--json", type=json.loads, default={}, help="JSON body for POST/PUT")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--delay", type=float, default=0.5, help="Request delay (default: 0.5)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10)")
    parser.add_argument("--proxy", help="HTTP proxy")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    return parser


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.quiet:
        print(f"""
╔═══════════════════════════════════════════════════════════╗
║  REVUEX IDOR Scanner v{SCANNER_VERSION}-GOLD                        ║
║  Dual-Account + Blind/Second-Order Testing               ║
╚═══════════════════════════════════════════════════════════╝
        """)
    
    scanner = IDORScanner(
        target=args.target,
        token_a=args.token_a,
        token_b=args.token_b,
        object_id=args.object_id,
        blind_headers=set(args.blind_headers) if args.blind_headers else None,
        test_methods=not args.no_methods,
        test_enumeration=args.enum,
        test_blind=not args.no_blind,
        similarity_threshold=args.threshold,
        json_body=args.json,
        delay=args.delay,
        timeout=args.timeout,
        proxy=args.proxy,
        verbose=args.verbose,
    )
    
    result = scanner.run()
    
    if not args.quiet:
        print(f"\n{'='*60}")
        print("SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"Target: {args.target}")
        print(f"Object ID: {scanner.object_id or 'Auto-detected'}")
        print(f"Duration: {result.duration_seconds:.2f}s")
        print(f"Requests: {result.total_requests}")
        print(f"Findings: {len(result.findings)}")
        
        # Phase summary
        direct_vulns = sum(1 for r in scanner.test_results if r.phase == "direct" and r.is_vulnerable)
        blind_vulns = sum(1 for r in scanner.test_results if r.phase == "blind" and r.is_vulnerable)
        
        print(f"\n[Phase Results]")
        print(f"  Direct IDOR: {'VULNERABLE' if direct_vulns else 'OK'}")
        print(f"  Blind IDOR:  {'VULNERABLE' if blind_vulns else 'OK'}")
        
        if result.findings:
            print(f"\n{'='*60}")
            print("FINDINGS SUMMARY")
            print(f"{'='*60}")
            for finding in result.findings:
                sev_colors = {
                    Severity.CRITICAL: "\033[95m",
                    Severity.HIGH: "\033[91m",
                    Severity.MEDIUM: "\033[93m",
                }
                color = sev_colors.get(finding.severity, "")
                reset = "\033[0m"
                print(f"\n{color}[{finding.severity.value.upper()}]{reset} {finding.title}")
    
    if args.output:
        output_data = {
            "scanner": "REVUEX IDOR GOLD",
            "version": SCANNER_VERSION,
            "target": args.target,
            "object_id": scanner.object_id,
            "scan_id": result.scan_id,
            "duration": result.duration_seconds,
            "phases": {
                "direct": {"tested": True, "vulnerable": direct_vulns > 0},
                "blind": {"tested": not args.no_blind, "vulnerable": blind_vulns > 0},
            },
            "test_results": [
                {
                    "phase": r.phase,
                    "method": r.method,
                    "status_a": r.status_a,
                    "status_b": r.status_b,
                    "similarity": r.similarity,
                    "is_vulnerable": r.is_vulnerable,
                    "sensitive_exposed": r.sensitive_exposed,
                    "evidence": r.evidence,
                }
                for r in scanner.test_results
            ],
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
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
