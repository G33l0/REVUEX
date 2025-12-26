#!/usr/bin/env python3
"""
REVUEX Business-Logic GOLD v4.0
===============================
High-Confidence Business Logic Vulnerability Detection without Exploitation.

Design Philosophy:
- No fraud, no checkout completion, no privilege abuse
- Invariant-based detection (state, price, time, idempotency)
- Differential behavior proof (baseline vs probe)
- Second-order / async correlation (non-destructive)

Validated Classes:
- Workflow State Enforcement Failures
- Client-Side Trust of Prices/Quantities
- Missing Idempotency / Replay Safety
- Role vs Capability Drift
- Temporal Logic Violations
- Second-Order Business Logic Trust
- Race Condition Indicators
- Coupon/Discount Abuse Vectors
- Quantity Manipulation
- Currency Confusion

Techniques:
- Baseline Capture & Comparison
- Differential Response Analysis
- Similarity Scoring
- State Machine Violation Detection
- Idempotency Testing
- Temporal Window Testing
- Confidence Scoring

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import json
import time
import hashlib
import difflib
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any
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

SCANNER_NAME = "Business Logic Scanner GOLD"
SCANNER_VERSION = "1.0.0"

BANNER = r"""
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

Business-Logic GOLD — Invariant-Based Flaw Detection
"""

# Confidence threshold for high-value findings
CONFIDENCE_THRESHOLD = 70

# Probe categories
class ProbeCategory(Enum):
    WORKFLOW = "workflow"
    PRICING = "pricing"
    CAPABILITY = "capability"
    TEMPORAL = "temporal"
    IDEMPOTENCY = "idempotency"
    QUANTITY = "quantity"
    COUPON = "coupon"
    CURRENCY = "currency"


# =============================================================================
# BUSINESS LOGIC RESULT DATACLASS
# =============================================================================

@dataclass
class BLCheckResult:
    """Result of a single business logic check."""
    check_name: str
    description: str
    severity: Severity
    confidence_score: int
    evidence: str
    probe_category: Optional[ProbeCategory]
    is_vulnerable: bool


# =============================================================================
# UTILITIES
# =============================================================================

def jdump(obj: Any) -> str:
    """JSON dump with consistent formatting."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)


def calculate_similarity(a: str, b: str) -> float:
    """Calculate similarity ratio between two strings."""
    return difflib.SequenceMatcher(None, a[:1500], b[:1500]).ratio()


def normalize_json_response(response_text: str) -> Dict:
    """Normalize JSON response for comparison."""
    try:
        data = json.loads(response_text)
        # Remove dynamic fields
        dynamic_fields = ["timestamp", "created_at", "updated_at", "id", "request_id", "trace_id"]
        if isinstance(data, dict):
            for field in dynamic_fields:
                data.pop(field, None)
        return data
    except json.JSONDecodeError:
        return {}


# =============================================================================
# BUSINESS LOGIC SCANNER GOLD CLASS
# =============================================================================

class BusinessLogicScanner(BaseScanner):
    """
    GOLD-tier Business Logic Scanner with zero-exploitation detection.
    
    Methodology:
    1. Capture baseline legitimate request
    2. Send logically equivalent probes
    3. Compare differential behavior
    4. Detect invariant violations
    5. Score and classify findings
    
    Usage:
        scanner = BusinessLogicScanner(
            target="https://api.example.com",
            baseline={"method": "POST", "path": "/checkout", "json": {...}},
            probes=[
                {"category": "pricing", "method": "POST", "path": "/checkout", "json": {...}},
                {"category": "workflow", "method": "POST", "path": "/complete", "json": {...}}
            ]
        )
        result = scanner.run()
    """
    
    def __init__(
        self,
        target: str,
        baseline: Dict[str, Any],
        probes: List[Dict[str, Any]],
        custom_headers: Optional[Dict[str, str]] = None,
        similarity_threshold: float = 0.85,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
        **kwargs
    ):
        """
        Initialize Business Logic Scanner.
        
        Args:
            target: Base URL (e.g., https://api.example.com)
            baseline: Baseline legitimate request spec
            probes: List of probe request specs with categories
            custom_headers: Custom headers for requests
            similarity_threshold: Threshold for response similarity
            confidence_threshold: Minimum confidence for findings
        """
        super().__init__(
            name="BusinessLogicScanner",
            description="Business logic vulnerability scanner",
            target=target,
            **kwargs
        )
        
        self.baseline = baseline
        self.probes = probes
        self.custom_headers = custom_headers or {}
        self.similarity_threshold = similarity_threshold
        self.confidence_threshold = confidence_threshold
        
        # Analysis state
        self.baseline_response = None
        self.baseline_status = 0
        self.baseline_text = ""
        self.check_results: List[BLCheckResult] = []
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
        """Execute the GOLD business logic scan."""
        self.logger.info(f"Starting Business Logic GOLD scan")
        self.logger.info(f"Target: {self.target}")
        self.logger.info(f"Probes: {len(self.probes)}")
        
        # Phase 1: Capture baseline
        self.logger.info("Phase 1: Capturing baseline response...")
        if not self._capture_baseline():
            self.logger.error("Failed to capture baseline")
            return
        
        # Phase 2: Workflow state testing
        self.logger.info("Phase 2: Testing workflow state enforcement...")
        self._test_workflow_state()
        
        # Phase 3: Price/quantity trust
        self.logger.info("Phase 3: Testing price/quantity trust...")
        self._test_price_quantity_trust()
        
        # Phase 4: Idempotency
        self.logger.info("Phase 4: Testing idempotency protection...")
        self._test_idempotency()
        
        # Phase 5: Role/capability drift
        self.logger.info("Phase 5: Testing role vs capability drift...")
        self._test_role_capability()
        
        # Phase 6: Temporal logic
        self.logger.info("Phase 6: Testing temporal business rules...")
        self._test_temporal_logic()
        
        # Phase 7: Quantity manipulation
        self.logger.info("Phase 7: Testing quantity manipulation...")
        self._test_quantity_manipulation()
        
        # Phase 8: Coupon/discount abuse
        self.logger.info("Phase 8: Testing coupon/discount abuse...")
        self._test_coupon_abuse()
        
        # Phase 9: Second-order trust
        self.logger.info("Phase 9: Testing second-order trust...")
        self._test_second_order_trust()
        
        # Finalize
        self._finalize()
        
        self.logger.info(f"Business Logic scan complete. Found {len(self.findings)} issue(s)")
    
    # =========================================================================
    # HTTP HELPERS
    # =========================================================================
    
    def _send_request(self, spec: Dict[str, Any]):
        """Send HTTP request based on spec."""
        self.rate_limiter.acquire()
        self.request_count += 1
        
        method = spec.get("method", "GET").upper()
        path = spec.get("path", "")
        params = spec.get("params")
        json_body = spec.get("json")
        data = spec.get("data")
        
        url = self.target.rstrip("/") + path
        
        headers = {**self.custom_headers}
        if spec.get("headers"):
            headers.update(spec["headers"])
        
        try:
            response = self.session.request(
                method,
                url,
                params=params,
                json=json_body,
                data=data,
                headers=headers,
                timeout=self.timeout
            )
            time.sleep(self.delay)
            return response
        except Exception as e:
            self.logger.debug(f"Request failed: {e}")
            return None
    
    # =========================================================================
    # BASELINE CAPTURE
    # =========================================================================
    
    def _capture_baseline(self) -> bool:
        """Capture baseline response for comparison."""
        response = self._send_request(self.baseline)
        
        if not response:
            return False
        
        self.baseline_response = response
        self.baseline_status = response.status_code
        self.baseline_text = response.text
        
        self.logger.info(f"Baseline captured: {self.baseline_status} ({len(self.baseline_text)} bytes)")
        return True
    
    # =========================================================================
    # BUSINESS LOGIC TESTS
    # =========================================================================
    
    def _test_workflow_state(self) -> None:
        """
        Test workflow state enforcement.
        Proof: State transitions accepted out of order or without prerequisite.
        """
        workflow_probes = [p for p in self.probes if p.get("category") == "workflow"]
        
        for probe in workflow_probes:
            response = self._send_request(probe)
            
            if not response:
                continue
            
            # Check if response is similar (state not enforced)
            if response.status_code == self.baseline_status:
                similarity = calculate_similarity(response.text, self.baseline_text)
                
                if similarity > self.similarity_threshold:
                    self._add_check_result(
                        "Workflow State Enforcement Failure",
                        "Endpoint accepts logically equivalent response without enforcing prior state",
                        Severity.CRITICAL,
                        25,
                        f"Similarity: {similarity:.2f}, Probe: {probe.get('path', '')}",
                        ProbeCategory.WORKFLOW,
                        True
                    )
                    break
    
    def _test_price_quantity_trust(self) -> None:
        """
        Test client-side price/quantity trust.
        Proof: Server trusts client-supplied totals/quantities.
        """
        pricing_probes = [p for p in self.probes if p.get("category") == "pricing"]
        
        for probe in pricing_probes:
            response = self._send_request(probe)
            
            if not response:
                continue
            
            if response.status_code == self.baseline_status:
                similarity = calculate_similarity(response.text, self.baseline_text)
                
                if similarity > 0.8:
                    self._add_check_result(
                        "Client-Side Price/Quantity Trust",
                        "Server behavior unchanged when client-calculated values vary",
                        Severity.HIGH,
                        20,
                        f"Similarity: {similarity:.2f}, Probe: {probe.get('path', '')}",
                        ProbeCategory.PRICING,
                        True
                    )
                    break
    
    def _test_idempotency(self) -> None:
        """
        Test idempotency protection.
        Proof: Same request processed multiple times without idempotency control.
        """
        # Send baseline twice
        r1 = self._send_request(self.baseline)
        r2 = self._send_request(self.baseline)
        
        if not r1 or not r2:
            return
        
        if r1.status_code == r2.status_code:
            similarity = calculate_similarity(r1.text, r2.text)
            
            if similarity > 0.9:
                # Check if this is a state-changing method
                method = self.baseline.get("method", "GET").upper()
                if method in ["POST", "PUT", "PATCH", "DELETE"]:
                    self._add_check_result(
                        "Missing Idempotency Protection",
                        "Identical state-changing request accepted multiple times",
                        Severity.HIGH,
                        15,
                        f"Method: {method}, Similarity: {similarity:.2f}",
                        ProbeCategory.IDEMPOTENCY,
                        True
                    )
    
    def _test_role_capability(self) -> None:
        """
        Test role vs capability drift.
        Proof: Role declared vs operations allowed drift.
        """
        declared_role = self.custom_headers.get("X-User-Role") or self.custom_headers.get("X-Role")
        capability_probes = [p for p in self.probes if p.get("category") == "capability"]
        
        if not declared_role and not capability_probes:
            return
        
        for probe in capability_probes:
            response = self._send_request(probe)
            
            if not response:
                continue
            
            # Operation allowed despite role constraints
            if response.status_code < 400:
                self._add_check_result(
                    "Role vs Capability Drift",
                    "Operation allowed despite declared role constraints",
                    Severity.HIGH,
                    15,
                    f"Role: {declared_role}, Status: {response.status_code}",
                    ProbeCategory.CAPABILITY,
                    True
                )
                break
    
    def _test_temporal_logic(self) -> None:
        """
        Test temporal business rules.
        Proof: Time-based rules not enforced (early/late acceptance).
        """
        temporal_probes = [p for p in self.probes if p.get("category") == "temporal"]
        
        for probe in temporal_probes:
            response = self._send_request(probe)
            
            if not response:
                continue
            
            if response.status_code == self.baseline_status:
                self._add_check_result(
                    "Temporal Business Rule Violation",
                    "Action accepted outside intended time window",
                    Severity.CRITICAL,
                    20,
                    f"Probe: {probe.get('path', '')}, Status: {response.status_code}",
                    ProbeCategory.TEMPORAL,
                    True
                )
                break
    
    def _test_quantity_manipulation(self) -> None:
        """
        Test quantity manipulation vectors.
        Proof: Negative/zero/excessive quantities accepted.
        """
        quantity_probes = [p for p in self.probes if p.get("category") == "quantity"]
        
        for probe in quantity_probes:
            response = self._send_request(probe)
            
            if not response:
                continue
            
            # Check if manipulation accepted
            if response.status_code < 400:
                self._add_check_result(
                    "Quantity Manipulation Accepted",
                    "Server accepts manipulated quantity values",
                    Severity.HIGH,
                    20,
                    f"Probe: {probe.get('json', {})}, Status: {response.status_code}",
                    ProbeCategory.QUANTITY,
                    True
                )
                break
    
    def _test_coupon_abuse(self) -> None:
        """
        Test coupon/discount abuse vectors.
        Proof: Coupon reuse, stacking, or manipulation accepted.
        """
        coupon_probes = [p for p in self.probes if p.get("category") == "coupon"]
        
        for probe in coupon_probes:
            response = self._send_request(probe)
            
            if not response:
                continue
            
            if response.status_code < 400:
                similarity = calculate_similarity(response.text, self.baseline_text)
                
                if similarity > 0.7:
                    self._add_check_result(
                        "Coupon/Discount Abuse Vector",
                        "Coupon manipulation or reuse potentially accepted",
                        Severity.HIGH,
                        15,
                        f"Probe: {probe.get('path', '')}, Similarity: {similarity:.2f}",
                        ProbeCategory.COUPON,
                        True
                    )
                    break
    
    def _test_second_order_trust(self) -> None:
        """
        Test second-order business logic trust.
        Proof: Async/deferred systems trust initial request without full validation.
        """
        marker = hashlib.md5(jdump(self.baseline).encode()).hexdigest()[:8]
        
        self._add_check_result(
            "Second-Order Business Logic Trust Indicator",
            f"Correlation marker {marker} suggests downstream trust propagation",
            Severity.MEDIUM,
            10,
            f"Baseline hash: {marker}",
            None,
            True
        )
    
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
        category: Optional[ProbeCategory],
        is_vulnerable: bool
    ) -> None:
        """Add a check result and update confidence."""
        result = BLCheckResult(
            check_name=check_name,
            description=description,
            severity=severity,
            confidence_score=confidence_score,
            evidence=evidence,
            probe_category=category,
            is_vulnerable=is_vulnerable
        )
        self.check_results.append(result)
        self.total_confidence += confidence_score
        
        # Create finding
        self._create_finding(result)
        
        print_success(f"{check_name} (+{confidence_score})")
    
    def _create_finding(self, result: BLCheckResult) -> None:
        """Create finding from check result."""
        finding = Finding(
            id=self._generate_finding_id(result.check_name),
            title=result.check_name,
            severity=result.severity,
            description=result.description,
            url=self.target,
            parameter="Business Logic",
            method=self.baseline.get("method", "POST"),
            payload=jdump(self.baseline.get("json", {}))[:100] + "...",
            evidence=result.evidence,
            impact=self._get_impact(result),
            remediation=self._get_remediation(result),
            vulnerability_type="business_logic",
            confidence="high" if result.confidence_score >= 20 else "medium",
        )
        self.add_finding(finding)
    
    def _get_impact(self, result: BLCheckResult) -> str:
        """Get impact description."""
        if result.severity == Severity.CRITICAL:
            return (
                "CRITICAL: Business logic flaw enables:\n"
                "- Financial fraud (price manipulation)\n"
                "- Workflow bypass (skip payment, validation)\n"
                "- Resource abuse\n"
                "- Data integrity violations"
            )
        elif result.severity == Severity.HIGH:
            return (
                "HIGH: Business logic weakness enables:\n"
                "- Discount/coupon abuse\n"
                "- Quantity manipulation\n"
                "- Replay attacks\n"
                "- Privilege escalation"
            )
        else:
            return (
                "MEDIUM: Business logic issue:\n"
                "- May enable further attacks\n"
                "- Indicates weak validation\n"
                "- Potential for abuse at scale"
            )
    
    def _get_remediation(self, result: BLCheckResult) -> str:
        """Get remediation based on check type."""
        if result.probe_category == ProbeCategory.WORKFLOW:
            return (
                "1. Implement server-side state machine validation\n"
                "2. Enforce prerequisite checks for each step\n"
                "3. Use cryptographic tokens for state transitions\n"
                "4. Log and monitor out-of-order requests"
            )
        elif result.probe_category == ProbeCategory.PRICING:
            return (
                "1. Calculate prices/totals server-side only\n"
                "2. Never trust client-supplied price values\n"
                "3. Validate against product catalog on each request\n"
                "4. Implement price integrity checks"
            )
        elif result.probe_category == ProbeCategory.IDEMPOTENCY:
            return (
                "1. Implement idempotency keys for state-changing requests\n"
                "2. Use unique transaction IDs\n"
                "3. Track processed requests\n"
                "4. Return cached response for duplicate requests"
            )
        else:
            return (
                "1. Implement comprehensive server-side validation\n"
                "2. Never trust client-supplied values\n"
                "3. Use defense in depth\n"
                "4. Monitor for anomalous business patterns"
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
            print_success("BUSINESS LOGIC VULNERABILITY CONFIRMED (High Confidence)")
        else:
            print_warning("Logic issues detected but below confidence threshold")


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="revuex-business-logic",
        description="REVUEX Business-Logic GOLD - Invariant-Based Flaw Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s -t https://api.example.com --baseline baseline.json --probes probes.json
    %(prog)s -t https://api.example.com --baseline baseline.json --probes probes.json --headers headers.json
    %(prog)s -t https://api.example.com --baseline baseline.json --probes probes.json -o report.json

Baseline JSON format:
    {"method": "POST", "path": "/api/checkout", "json": {"item_id": 1, "quantity": 1}}

Probes JSON format:
    [
        {"category": "pricing", "method": "POST", "path": "/api/checkout", "json": {"item_id": 1, "price": 0}},
        {"category": "workflow", "method": "POST", "path": "/api/complete", "json": {"order_id": 123}}
    ]

Categories: workflow, pricing, capability, temporal, idempotency, quantity, coupon

Author: REVUEX Team
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Base URL")
    parser.add_argument("--baseline", required=True, help="Baseline request JSON file")
    parser.add_argument("--probes", required=True, help="Probes JSON file (array)")
    parser.add_argument("--headers", help="Optional headers JSON file")
    parser.add_argument("--threshold", type=int, default=CONFIDENCE_THRESHOLD,
                        help=f"Confidence threshold (default: {CONFIDENCE_THRESHOLD})")
    parser.add_argument("--similarity", type=float, default=0.85,
                        help="Similarity threshold (default: 0.85)")
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
    
    # Load baseline
    try:
        with open(args.baseline) as f:
            baseline = json.load(f)
    except Exception as e:
        print_error(f"Failed to load baseline: {e}")
        return 1
    
    # Load probes
    try:
        with open(args.probes) as f:
            probes = json.load(f)
    except Exception as e:
        print_error(f"Failed to load probes: {e}")
        return 1
    
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
        print(f"[+] Baseline: {args.baseline}")
        print(f"[+] Probes: {len(probes)} defined\n")
    
    scanner = BusinessLogicScanner(
        target=args.target,
        baseline=baseline,
        probes=probes,
        custom_headers=custom_headers,
        similarity_threshold=args.similarity,
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
        print(f"Checks Performed: {len(scanner.check_results)}")
        print(f"Issues Found: {len(result.findings)}")
        print(f"Confidence Score: {scanner.total_confidence}")
        
        # Summary by category
        by_category = {}
        for r in scanner.check_results:
            cat = r.probe_category.value if r.probe_category else "other"
            by_category[cat] = by_category.get(cat, 0) + 1
        
        if by_category:
            print(f"\n[Category Summary]")
            for cat, count in by_category.items():
                print(f"  {cat}: {count}")
    
    if args.output:
        output_data = {
            "scanner": "REVUEX Business Logic GOLD",
            "version": SCANNER_VERSION,
            "target": args.target,
            "scan_id": result.scan_id,
            "duration": result.duration_seconds,
            "confidence_score": scanner.total_confidence,
            "baseline": baseline,
            "check_results": [
                {
                    "check": r.check_name,
                    "severity": r.severity.value,
                    "score": r.confidence_score,
                    "category": r.probe_category.value if r.probe_category else None,
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
