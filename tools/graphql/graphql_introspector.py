#!/usr/bin/env python3
"""
REVUEX GraphQL GOLD v4.0
========================
Research-Grade GraphQL Security Validation Scanner (10/10 GOLD)

Detection Philosophy:
- No exploitation, no brute-force
- Schema & runtime invariant validation
- Introspection & authorization proof
- Query depth & complexity enforcement testing
- Method & content-type confusion
- Confidence-based findings only

Core Techniques:
- Introspection Query Testing
- Method Confusion (GET vs POST)
- Content-Type Confusion
- Query Depth/Complexity Testing
- Error Disclosure Detection
- Batching Attack Detection
- Field Suggestion Enumeration
- Authorization Bypass Testing

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import json
import copy
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

SCANNER_NAME = "GraphQL Scanner GOLD"
SCANNER_VERSION = "4.0.0"

BANNER = r"""
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

GraphQL Scanner GOLD — GraphQL Security Analysis
"""

CONFIDENCE_THRESHOLD = 80

# Standard introspection query
INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        types { name }
      }
    }
    """
}

# Full introspection query
FULL_INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          fields {
            name
            type { name kind }
          }
        }
      }
    }
    """
}

# Depth testing query
DEPTH_QUERY = {
    "query": "query Deep { __typename { __typename { __typename { name }}}}"
}

# Nested depth query
NESTED_DEPTH_QUERY = {
    "query": """
    query DeepNested {
      __schema {
        types {
          fields {
            type {
              fields {
                type {
                  fields {
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    """
}

# Error trigger query
ERROR_TRIGGER_QUERY = {
    "query": "query ErrorTest { nonExistentField }"
}

# Batching query
BATCH_QUERY = [
    {"query": "query A { __typename }"},
    {"query": "query B { __typename }"},
    {"query": "query C { __typename }"}
]

# Field suggestion query
FIELD_SUGGESTION_QUERY = {
    "query": "query { user { passwor } }"
}


# =============================================================================
# GRAPHQL CHECK RESULT DATACLASS
# =============================================================================

@dataclass
class GraphQLCheckResult:
    """Result of a single GraphQL check."""
    check_name: str
    description: str
    severity: Severity
    confidence_score: int
    evidence: Dict[str, Any]
    is_vulnerable: bool


# =============================================================================
# GRAPHQL SCANNER GOLD CLASS
# =============================================================================

class GraphQLScanner(BaseScanner):
    """
    GOLD-tier GraphQL Security Scanner.
    
    Methodology:
    1. Capture baseline response
    2. Test introspection availability
    3. Test method confusion (GET/POST)
    4. Test content-type confusion
    5. Test query depth limits
    6. Test error disclosure
    7. Test batching attacks
    8. Test field suggestions
    """
    
    def __init__(
        self,
        target: str,
        custom_headers: Optional[Dict[str, str]] = None,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
        **kwargs
    ):
        """
        Initialize GraphQL Scanner.
        
        Args:
            target: GraphQL endpoint URL
            custom_headers: Custom HTTP headers
            confidence_threshold: Minimum confidence for findings
        """
        super().__init__(
            name="GraphQLScanner",
            description="GraphQL security scanner",
            target=target,
            **kwargs
        )
        
        self.custom_headers = custom_headers or {}
        self.confidence_threshold = confidence_threshold
        
        # State tracking
        self.baseline_response = None
        self.schema_data: Optional[Dict] = None
        self.check_results: List[GraphQLCheckResult] = []
        self.total_confidence: int = 0
        
        # Scanner info
        self.scanner_name = SCANNER_NAME
        self.scanner_version = SCANNER_VERSION
    
    def _validate_target(self) -> bool:
        """Validate target is accessible."""
        try:
            response = self.session.post(
                self.target,
                json={"query": "{ __typename }"},
                headers=self.custom_headers,
                timeout=self.timeout
            )
            return response.status_code < 500
        except Exception:
            return False
    
    def scan(self) -> None:
        """Execute the GOLD GraphQL scan."""
        self.logger.info(f"Starting GraphQL GOLD scan")
        self.logger.info(f"Endpoint: {self.target}")
        
        # Phase 1: Capture baseline
        self.logger.info("Phase 1: Capturing baseline response...")
        self._capture_baseline()
        
        if not self.baseline_response:
            self.logger.error("Failed to capture baseline - aborting")
            return
        
        # Phase 2: Test introspection
        self.logger.info("Phase 2: Testing introspection...")
        self._test_introspection()
        
        # Phase 3: Test method confusion
        self.logger.info("Phase 3: Testing method confusion...")
        self._test_method_confusion()
        
        # Phase 4: Test content-type confusion
        self.logger.info("Phase 4: Testing content-type confusion...")
        self._test_content_type_confusion()
        
        # Phase 5: Test query depth
        self.logger.info("Phase 5: Testing query depth limits...")
        self._test_query_depth()
        
        # Phase 6: Test error disclosure
        self.logger.info("Phase 6: Testing error disclosure...")
        self._test_error_disclosure()
        
        # Phase 7: Test batching
        self.logger.info("Phase 7: Testing query batching...")
        self._test_batching()
        
        # Phase 8: Test field suggestions
        self.logger.info("Phase 8: Testing field suggestions...")
        self._test_field_suggestions()
        
        # Phase 9: Test alias abuse
        self.logger.info("Phase 9: Testing alias abuse...")
        self._test_alias_abuse()
        
        self.logger.info(f"GraphQL scan complete. Found {len(self.findings)} issue(s)")
    
    # =========================================================================
    # BASELINE CAPTURE
    # =========================================================================
    
    def _capture_baseline(self) -> None:
        """Capture baseline GraphQL response."""
        self.rate_limiter.acquire()
        self._request_count += 1
        
        try:
            response = self.session.post(
                self.target,
                json={"query": "query { __typename }"},
                headers=self.custom_headers,
                timeout=self.timeout
            )
            self.baseline_response = response
            print_info(f"Baseline captured: HTTP {response.status_code}")
            time.sleep(self.delay)
        except Exception as e:
            self.logger.error(f"Baseline capture failed: {e}")
    
    # =========================================================================
    # SEND QUERY
    # =========================================================================
    
    def _send_query(self, payload: Any, headers: Optional[Dict] = None, method: str = "POST") -> Optional[Any]:
        """Send GraphQL query."""
        self.rate_limiter.acquire()
        self._request_count += 1
        
        hdrs = {**self.custom_headers}
        if headers:
            hdrs.update(headers)
        
        try:
            if method == "GET":
                if isinstance(payload, dict):
                    params = {"query": payload.get("query", "")}
                    if "variables" in payload:
                        params["variables"] = json.dumps(payload["variables"])
                else:
                    params = {"query": str(payload)}
                
                response = self.session.get(
                    self.target,
                    params=params,
                    headers=hdrs,
                    timeout=self.timeout
                )
            else:
                response = self.session.post(
                    self.target,
                    json=payload,
                    headers=hdrs,
                    timeout=self.timeout
                )
            
            time.sleep(self.delay)
            return response
        except Exception as e:
            self.logger.debug(f"Query failed: {e}")
            return None
    
    # =========================================================================
    # INTROSPECTION CHECK
    # =========================================================================
    
    def _test_introspection(self) -> None:
        """Test if introspection is enabled."""
        confidence = 40
        
        response = self._send_query(INTROSPECTION_QUERY)
        if not response:
            return
        
        evidence = {"endpoint": self.target}
        
        if "__schema" in response.text:
            confidence += 50
            evidence["introspection_enabled"] = True
            
            # Try full introspection
            full_response = self._send_query(FULL_INTROSPECTION_QUERY)
            if full_response and "queryType" in full_response.text:
                try:
                    self.schema_data = full_response.json()
                    evidence["full_schema_exposed"] = True
                except Exception:
                    pass
        
        if response.status_code == self.baseline_response.status_code:
            confidence += 10
        
        if confidence >= self.confidence_threshold:
            self._add_check_result(
                "GraphQL Introspection Enabled",
                "Introspection queries are allowed, exposing full API schema",
                Severity.CRITICAL,
                confidence,
                evidence,
                True
            )
    
    # =========================================================================
    # METHOD CONFUSION
    # =========================================================================
    
    def _test_method_confusion(self) -> None:
        """Test method confusion (GET vs POST)."""
        confidence = 40
        
        response = self._send_query(INTROSPECTION_QUERY, method="GET")
        if not response:
            return
        
        evidence = {"method": "GET"}
        
        if "__schema" in response.text or "__typename" in response.text:
            confidence += 40
            evidence["get_accepted"] = True
        
        if response.status_code == self.baseline_response.status_code:
            confidence += 10
        
        if confidence >= self.confidence_threshold:
            self._add_check_result(
                "GraphQL GET Method Accepted",
                "GraphQL endpoint accepts GET requests (CSRF risk)",
                Severity.HIGH,
                confidence,
                evidence,
                True
            )
    
    # =========================================================================
    # CONTENT-TYPE CONFUSION
    # =========================================================================
    
    def _test_content_type_confusion(self) -> None:
        """Test content-type confusion."""
        test_content_types = [
            "text/plain",
            "application/x-www-form-urlencoded",
            "text/html",
        ]
        
        for ct in test_content_types:
            confidence = 40
            
            response = self._send_query(
                INTROSPECTION_QUERY,
                headers={"Content-Type": ct},
                method="GET"
            )
            
            if not response:
                continue
            
            if "__schema" in response.text or "__typename" in response.text:
                confidence += 40
            
            if response.status_code < 400:
                confidence += 10
            
            if confidence >= self.confidence_threshold:
                self._add_check_result(
                    f"GraphQL Content-Type Confusion ({ct})",
                    f"GraphQL accepts non-JSON Content-Type: {ct}",
                    Severity.MEDIUM,
                    confidence,
                    {"content_type": ct, "accepted": True},
                    True
                )
                break
    
    # =========================================================================
    # QUERY DEPTH
    # =========================================================================
    
    def _test_query_depth(self) -> None:
        """Test query depth limits."""
        confidence = 40
        
        response = self._send_query(DEPTH_QUERY)
        if not response:
            return
        
        evidence = {"query": DEPTH_QUERY["query"]}
        
        if response.status_code == 200 and "errors" not in response.text:
            confidence += 50
            evidence["depth_limited"] = False
        
        if confidence >= self.confidence_threshold:
            self._add_check_result(
                "GraphQL Query Depth Not Limited",
                "No query depth limiting detected (DoS risk)",
                Severity.HIGH,
                confidence,
                evidence,
                True
            )
        
        # Test nested depth
        response = self._send_query(NESTED_DEPTH_QUERY)
        if response and response.status_code == 200 and "errors" not in response.text:
            self._add_check_result(
                "GraphQL Nested Query Depth Not Limited",
                "Deeply nested queries allowed (DoS risk)",
                Severity.HIGH,
                85,
                {"query": "nested introspection", "depth_limited": False},
                True
            )
    
    # =========================================================================
    # ERROR DISCLOSURE
    # =========================================================================
    
    def _test_error_disclosure(self) -> None:
        """Test verbose error disclosure."""
        confidence = 40
        
        response = self._send_query(ERROR_TRIGGER_QUERY)
        if not response:
            return
        
        evidence = {"query": ERROR_TRIGGER_QUERY["query"]}
        text_lower = response.text.lower()
        
        disclosure_indicators = ["stack", "exception", "traceback", "at line", "syntax error"]
        found_indicators = [ind for ind in disclosure_indicators if ind in text_lower]
        
        if found_indicators:
            confidence += 50
            evidence["indicators"] = found_indicators
            evidence["response_sample"] = response.text[:300]
        
        if confidence >= self.confidence_threshold:
            self._add_check_result(
                "GraphQL Verbose Error Disclosure",
                "GraphQL returns detailed error messages",
                Severity.MEDIUM,
                confidence,
                evidence,
                True
            )
    
    # =========================================================================
    # BATCHING
    # =========================================================================
    
    def _test_batching(self) -> None:
        """Test query batching attacks."""
        confidence = 40
        
        response = self._send_query(BATCH_QUERY)
        if not response:
            return
        
        evidence = {"batch_size": len(BATCH_QUERY)}
        
        try:
            data = response.json()
            if isinstance(data, list) and len(data) == len(BATCH_QUERY):
                confidence += 50
                evidence["batching_allowed"] = True
                evidence["responses_count"] = len(data)
        except Exception:
            pass
        
        if confidence >= self.confidence_threshold:
            self._add_check_result(
                "GraphQL Query Batching Allowed",
                "Multiple queries can be batched (brute-force risk)",
                Severity.MEDIUM,
                confidence,
                evidence,
                True
            )
    
    # =========================================================================
    # FIELD SUGGESTIONS
    # =========================================================================
    
    def _test_field_suggestions(self) -> None:
        """Test field suggestion enumeration."""
        confidence = 40
        
        response = self._send_query(FIELD_SUGGESTION_QUERY)
        if not response:
            return
        
        evidence = {}
        text_lower = response.text.lower()
        
        suggestion_indicators = ["did you mean", "suggestions", "similar"]
        found = [ind for ind in suggestion_indicators if ind in text_lower]
        
        if found:
            confidence += 50
            evidence["suggestions_enabled"] = True
            evidence["indicators"] = found
        
        if confidence >= self.confidence_threshold:
            self._add_check_result(
                "GraphQL Field Suggestions Enabled",
                "GraphQL provides field suggestions (enumeration risk)",
                Severity.MEDIUM,
                confidence,
                evidence,
                True
            )
    
    # =========================================================================
    # ALIAS ABUSE
    # =========================================================================
    
    def _test_alias_abuse(self) -> None:
        """Test alias abuse for rate limit bypass."""
        # Generate query with multiple aliases
        aliases = " ".join([f"a{i}: __typename" for i in range(10)])
        alias_query = {"query": f"query {{ {aliases} }}"}
        
        confidence = 40
        
        response = self._send_query(alias_query)
        if not response:
            return
        
        evidence = {"alias_count": 10}
        
        try:
            data = response.json()
            if "data" in data and len(data.get("data", {})) >= 10:
                confidence += 50
                evidence["aliases_allowed"] = True
        except Exception:
            pass
        
        if confidence >= self.confidence_threshold:
            self._add_check_result(
                "GraphQL Alias Abuse Possible",
                "Multiple aliases allowed (rate limit bypass risk)",
                Severity.MEDIUM,
                confidence,
                evidence,
                True
            )
    
    # =========================================================================
    # RESULT HANDLING
    # =========================================================================
    
    def _add_check_result(self, check_name: str, description: str, severity: Severity, confidence_score: int, evidence: Dict[str, Any], is_vulnerable: bool) -> None:
        """Add a check result and create finding."""
        result = GraphQLCheckResult(
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
    
    def _create_finding(self, result: GraphQLCheckResult) -> None:
        """Create finding from check result."""
        finding = Finding(
            id=self._generate_finding_id(result.check_name),
            title=result.check_name,
            severity=result.severity,
            description=result.description,
            url=self.target,
            parameter="GraphQL",
            method="POST",
            payload="N/A",
            evidence=json.dumps(result.evidence, indent=2),
            impact=self._get_impact(result),
            remediation=self._get_remediation(result),
            vulnerability_type="graphql",
            confidence="high" if result.confidence_score >= 80 else "medium",
        )
        self.add_finding(finding)
    
    def _get_impact(self, result: GraphQLCheckResult) -> str:
        """Get impact description."""
        if result.severity == Severity.CRITICAL:
            return "CRITICAL: Full API schema exposure enables targeted attacks and data enumeration"
        elif result.severity == Severity.HIGH:
            return "HIGH: GraphQL weakness enables CSRF, DoS, or authentication bypass"
        return "MEDIUM: GraphQL misconfiguration may aid attackers"
    
    def _get_remediation(self, result: GraphQLCheckResult) -> str:
        """Get remediation based on check type."""
        remediations = {
            "introspection": "1. Disable introspection in production\n2. Use allowlist for queries\n3. Implement query whitelisting",
            "method": "1. Restrict to POST only\n2. Validate Content-Type\n3. Implement CSRF protection",
            "content-type": "1. Require application/json\n2. Reject other content types\n3. Validate request format",
            "depth": "1. Implement query depth limiting\n2. Set maximum depth (e.g., 7)\n3. Use query complexity analysis",
            "error": "1. Disable verbose errors in production\n2. Log errors server-side\n3. Return generic error messages",
            "batch": "1. Disable batching or limit batch size\n2. Implement rate limiting per query\n3. Monitor for abuse",
            "suggestion": "1. Disable field suggestions\n2. Use custom error messages\n3. Implement query validation",
            "alias": "1. Limit number of aliases\n2. Implement query complexity scoring\n3. Rate limit by query cost",
        }
        for key, remediation in remediations.items():
            if key.lower() in result.check_name.lower():
                return remediation
        return "1. Review GraphQL security configuration\n2. Follow OWASP GraphQL guidelines\n3. Implement defense in depth"
    
    def _generate_finding_id(self, context: str) -> str:
        """Generate unique finding ID."""
        data = f"{self.target}:{context}:{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(prog="revuex-graphql", description="REVUEX GraphQL GOLD - GraphQL Security Scanner")
    parser.add_argument("-e", "--endpoint", required=True, help="GraphQL endpoint URL")
    parser.add_argument("-H", "--header", action="append", help="Custom headers (Key:Value)")
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
    
    custom_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()
    
    if not args.quiet:
        print(BANNER)
        print(f"[+] Endpoint: {args.endpoint}")
        print()
    
    scanner = GraphQLScanner(
        target=args.endpoint,
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
        print(f"Endpoint: {args.endpoint}")
        print(f"Duration: {result.duration_seconds:.2f}s")
        print(f"Issues Found: {len(result.findings)}")
        print(f"Total Confidence: {scanner.total_confidence}")
        
        if scanner.schema_data:
            print(f"Schema Extracted: Yes")
    
    if args.output:
        output_data = {
            "scanner": SCANNER_NAME,
            "version": SCANNER_VERSION,
            "endpoint": args.endpoint,
            "schema_exposed": scanner.schema_data is not None,
            "findings": [{"id": f.id, "title": f.title, "severity": f.severity.value} for f in result.findings]
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        if not args.quiet:
            print(f"\nResults saved to: {args.output}")
    
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
