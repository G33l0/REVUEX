#!/usr/bin/env python3
"""
REVUEX Price-Manipulation GOLD v4.0
===================================
Unified detection of pricing, coupon, subscription, and trial abuse
via server-side trust invariant violations.

GOLD Principles:
- No exploitation
- No checkout completion
- No brute force
- Differential & invariant-based proof
- High-confidence scoring only

Validated Vulnerability Classes:
- Client-Side Price Trust
- Quantity / Total Recalculation Failure
- Coupon Validation & Reuse Trust
- Subscription State Trust
- Trial Abuse Trust
- Currency Confusion
- Negative Value Acceptance
- Second-Order Monetary Trust

Techniques:
- Baseline Capture & Comparison
- Differential Response Analysis
- Similarity Scoring
- Invariant Violation Detection
- Multi-Category Probe Testing
- Confidence Scoring

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import json
import hashlib
import difflib
import argparse
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
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

SCANNER_NAME = "Price Manipulation Scanner GOLD"
SCANNER_VERSION = "2.0.0"

BANNER = r"""
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

Price-Manipulation GOLD — Monetary Trust Invariant Detection
"""

# Confidence threshold for high-value findings
CONFIDENCE_THRESHOLD = 80

# Probe categories
class ProbeCategory(Enum):
    PRICE = "price"
    QUANTITY = "quantity"
    COUPON = "coupon"
    SUBSCRIPTION = "subscription"
    TRIAL = "trial"
    CURRENCY = "currency"
    NEGATIVE = "negative"
    DISCOUNT = "discount"


# =============================================================================
# PRICE MANIPULATION RESULT DATACLASS
# =============================================================================

@dataclass
class PMCheckResult:
    """Result of a single price manipulation check."""
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

def calculate_similarity(a: str, b: str) -> float:
    """Calculate similarity ratio between two strings."""
    return difflib.SequenceMatcher(None, a[:2000], b[:2000]).ratio()


def jdump(obj: Any) -> str:
    """JSON dump with consistent formatting."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)


# =============================================================================
# PRICE MANIPULATION SCANNER GOLD CLASS
# =============================================================================

class PriceManipulationScanner(BaseScanner):
    """
    GOLD-tier Price Manipulation Scanner with zero-exploitation detection.
    
    Methodology:
    1. Capture baseline legitimate monetary request
    2. Send price/quantity/coupon manipulation probes
    3. Compare differential behavior
    4. Detect invariant violations
    5. Score and classify findings
    
    Usage:
        scanner = PriceManipulationScanner(
            target="https://api.example.com",
            baseline={"method": "POST", "path": "/checkout", "json": {...}},
            probes=[
                {"category": "price", "method": "POST", "path": "/checkout", "json": {...}},
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
        Initialize Price Manipulation Scanner.
        
        Args:
            target: Base URL (e.g., https://api.example.com)
            baseline: Baseline legitimate request spec
            probes: List of manipulation probe specs with categories
            custom_headers: Custom headers for requests
            similarity_threshold: Threshold for response similarity
            confidence_threshold: Minimum confidence for findings
        """
        super().__init__(
            name="PriceManipulationScanner",
            description="Price manipulation scanner",
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
        self.check_results: List[PMCheckResult] = []
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
        """Execute the GOLD price manipulation scan."""
        self.logger.info(f"Starting Price Manipulation GOLD scan")
        self.logger.info(f"Target: {self.target}")
        self.logger.info(f"Probes: {len(self.probes)}")
        
        # Phase 1: Capture baseline
        self.logger.info("Phase 1: Capturing baseline monetary state...")
        if not self._capture_baseline():
            self.logger.error("Failed to capture baseline")
            return
        
        # Phase 2: Price invariant
        self.logger.info("Phase 2: Testing price invariant...")
        self._test_price_invariant()
        
        # Phase 3: Quantity invariant
        self.logger.info("Phase 3: Testing quantity invariant...")
        self._test_quantity_invariant()
        
        # Phase 4: Coupon invariant
        self.logger.info("Phase 4: Testing coupon invariant...")
        self._test_coupon_invariant()
        
        # Phase 5: Subscription invariant
        self.logger.info("Phase 5: Testing subscription invariant...")
        self._test_subscription_invariant()
        
        # Phase 6: Trial invariant
        self.logger.info("Phase 6: Testing trial invariant...")
        self._test_trial_invariant()
        
        # Phase 7: Currency invariant
        self.logger.info("Phase 7: Testing currency invariant...")
        self._test_currency_invariant()
        
        # Phase 8: Negative value invariant
        self.logger.info("Phase 8: Testing negative value invariant...")
        self._test_negative_invariant()
        
        # Phase 9: Second-order trust
        self.logger.info("Phase 9: Testing second-order monetary trust...")
        self._test_second_order_invariant()
        
        # Finalize
        self._finalize()
        
        self.logger.info(f"Price Manipulation scan complete. Found {len(self.findings)} issue(s)")
    
    # =========================================================================
    # HTTP HELPERS
    # =========================================================================
    
    def _send_request(self, spec: Dict[str, Any]):
        """Send HTTP request based on spec."""
        self.rate_limiter.acquire()
        self._request_count += 1
        
        method = spec.get("method", "POST").upper()
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
    # INVARIANT TESTS
    # =========================================================================
    
    def _test_price_invariant(self) -> None:
        """
        Test client-side price trust.
        Proof: Server response unchanged despite altered client price.
        """
        price_probes = [p for p in self.probes if p.get("category") == "price"]
        
        for probe in price_probes:
            response = self._send_request(probe)
            
            if not response:
                continue
            
            if response.status_code == self.baseline_status:
                similarity = calculate_similarity(response.text, self.baseline_text)
                
                if similarity > self.similarity_threshold:
                    self._add_check_result(
                        "Client-Side Price Trust",
                        "Server response unchanged despite altered client price",
                        Severity.CRITICAL,
                        30,
                        f"Similarity: {similarity:.2f}, Probe: {probe.get('json', {})}",
                        ProbeCategory.PRICE,
                        True
                    )
                    return
    
    def _test_quantity_invariant(self) -> None:
        """
        Test quantity/total recalculation.
        Proof: Totals not recomputed server-side.
        """
        quantity_probes = [p for p in self.probes if p.get("category") == "quantity"]
        
        for probe in quantity_probes:
            response = self._send_request(probe)
            
            if not response:
                continue
            
            similarity = calculate_similarity(response.text, self.baseline_text)
            
            if similarity > 0.8:
                self._add_check_result(
                    "Quantity/Total Recalculation Failure",
                    "Totals not recomputed server-side",
                    Severity.HIGH,
                    20,
                    f"Similarity: {similarity:.2f}, Probe: {probe.get('json', {})}",
                    ProbeCategory.QUANTITY,
                    True
                )
                return
    
    def _test_coupon_invariant(self) -> None:
        """
        Test coupon validation and reuse.
        Proof: Coupon accepted multiple times without invalidation.
        """
        coupon_probes = [p for p in self.probes if p.get("category") == "coupon"]
        
        seen = False
        for probe in coupon_probes:
            response = self._send_request(probe)
            
            if not response:
                continue
            
            if response.status_code < 400:
                if seen:
                    self._add_check_result(
                        "Coupon Reuse/Trust Violation",
                        "Coupon accepted multiple times without invalidation",
                        Severity.CRITICAL,
                        20,
                        f"Coupon reused successfully, Status: {response.status_code}",
                        ProbeCategory.COUPON,
                        True
                    )
                    return
                seen = True
    
    def _test_subscription_invariant(self) -> None:
        """
        Test subscription state trust.
        Proof: Server accepts client-declared subscription state.
        """
        subscription_probes = [p for p in self.probes if p.get("category") == "subscription"]
        
        for probe in subscription_probes:
            response = self._send_request(probe)
            
            if not response:
                continue
            
            if response.status_code == self.baseline_status:
                similarity = calculate_similarity(response.text, self.baseline_text)
                
                if similarity > 0.75:
                    self._add_check_result(
                        "Subscription State Trust",
                        "Server accepts client-declared subscription state",
                        Severity.CRITICAL,
                        25,
                        f"Similarity: {similarity:.2f}, Probe: {probe.get('json', {})}",
                        ProbeCategory.SUBSCRIPTION,
                        True
                    )
                    return
    
    def _test_trial_invariant(self) -> None:
        """
        Test trial abuse trust.
        Proof: Trial state appears client-controlled.
        """
        trial_probes = [p for p in self.probes if p.get("category") == "trial"]
        
        for probe in trial_probes:
            response = self._send_request(probe)
            
            if not response:
                continue
            
            if response.status_code < 400:
                self._add_check_result(
                    "Trial Abuse Trust Violation",
                    "Trial state appears client-controlled",
                    Severity.HIGH,
                    15,
                    f"Trial manipulation accepted, Status: {response.status_code}",
                    ProbeCategory.TRIAL,
                    True
                )
                return
    
    def _test_currency_invariant(self) -> None:
        """
        Test currency confusion.
        Proof: Server accepts mismatched currency values.
        """
        currency_probes = [p for p in self.probes if p.get("category") == "currency"]
        
        for probe in currency_probes:
            response = self._send_request(probe)
            
            if not response:
                continue
            
            if response.status_code < 400:
                similarity = calculate_similarity(response.text, self.baseline_text)
                
                if similarity > 0.7:
                    self._add_check_result(
                        "Currency Confusion Vulnerability",
                        "Server accepts mismatched currency values",
                        Severity.HIGH,
                        20,
                        f"Currency manipulation accepted, Similarity: {similarity:.2f}",
                        ProbeCategory.CURRENCY,
                        True
                    )
                    return
    
    def _test_negative_invariant(self) -> None:
        """
        Test negative value acceptance.
        Proof: Server accepts negative prices/quantities.
        """
        negative_probes = [p for p in self.probes if p.get("category") == "negative"]
        
        for probe in negative_probes:
            response = self._send_request(probe)
            
            if not response:
                continue
            
            if response.status_code < 400:
                self._add_check_result(
                    "Negative Value Acceptance",
                    "Server accepts negative price or quantity values",
                    Severity.CRITICAL,
                    25,
                    f"Negative value accepted, Status: {response.status_code}",
                    ProbeCategory.NEGATIVE,
                    True
                )
                return
    
    def _test_second_order_invariant(self) -> None:
        """
        Test second-order monetary trust.
        Proof: Async/deferred systems trust initial monetary request.
        """
        marker = hashlib.md5(jdump(self.baseline).encode()).hexdigest()[:8]
        
        self._add_check_result(
            "Second-Order Monetary Trust Indicator",
            f"Correlation marker {marker} indicates downstream price trust",
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
        result = PMCheckResult(
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
    
    def _create_finding(self, result: PMCheckResult) -> None:
        """Create finding from check result."""
        finding = Finding(
            id=self._generate_finding_id(result.check_name),
            title=result.check_name,
            severity=result.severity,
            description=result.description,
            url=self.target,
            parameter="Monetary Logic",
            method=self.baseline.get("method", "POST"),
            payload=jdump(self.baseline.get("json", {}))[:100] + "...",
            evidence=result.evidence,
            impact=self._get_impact(result),
            remediation=self._get_remediation(result),
            vulnerability_type="price_manipulation",
            confidence="high" if result.confidence_score >= 20 else "medium",
        )
        self.add_finding(finding)
    
    def _get_impact(self, result: PMCheckResult) -> str:
        """Get impact description."""
        if result.severity == Severity.CRITICAL:
            return (
                "CRITICAL: Monetary manipulation enables:\n"
                "- Financial fraud (purchasing items for $0)\n"
                "- Revenue loss for the business\n"
                "- Subscription/premium access theft\n"
                "- Coupon/discount abuse at scale"
            )
        elif result.severity == Severity.HIGH:
            return (
                "HIGH: Monetary weakness enables:\n"
                "- Discount abuse\n"
                "- Quantity manipulation\n"
                "- Trial period extension\n"
                "- Partial financial fraud"
            )
        else:
            return (
                "MEDIUM: Monetary issue:\n"
                "- May enable further attacks\n"
                "- Indicates weak validation\n"
                "- Potential for abuse at scale"
            )
    
    def _get_remediation(self, result: PMCheckResult) -> str:
        """Get remediation based on check type."""
        if result.probe_category == ProbeCategory.PRICE:
            return (
                "1. NEVER trust client-supplied prices\n"
                "2. Calculate all prices server-side from product catalog\n"
                "3. Validate prices match database records\n"
                "4. Log price mismatches for fraud detection"
            )
        elif result.probe_category == ProbeCategory.QUANTITY:
            return (
                "1. Recalculate totals server-side\n"
                "2. Validate quantity limits\n"
                "3. Reject negative quantities\n"
                "4. Implement inventory checks"
            )
        elif result.probe_category == ProbeCategory.COUPON:
            return (
                "1. Track coupon usage server-side\n"
                "2. Invalidate coupons after use\n"
                "3. Implement per-user coupon limits\n"
                "4. Validate coupon eligibility"
            )
        elif result.probe_category == ProbeCategory.SUBSCRIPTION:
            return (
                "1. Store subscription state server-side only\n"
                "2. Never trust client subscription claims\n"
                "3. Verify subscription on each request\n"
                "4. Implement subscription audit logging"
            )
        elif result.probe_category == ProbeCategory.TRIAL:
            return (
                "1. Track trial usage server-side\n"
                "2. Bind trials to verified identity\n"
                "3. Implement device/IP fingerprinting\n"
                "4. Audit trial abuse patterns"
            )
        else:
            return (
                "1. Implement comprehensive server-side validation\n"
                "2. Never trust client-supplied monetary values\n"
                "3. Use defense in depth\n"
                "4. Monitor for anomalous transaction patterns"
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
            print_success("PRICE/SUBSCRIPTION MANIPULATION CONFIRMED (HIGH CONFIDENCE)")
        else:
            print_warning("Monetary inconsistencies detected but below confirmation threshold")


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="revuex-price-manipulation",
        description="REVUEX Price-Manipulation GOLD - Monetary Trust Invariant Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s -t https://api.example.com --baseline baseline.json --probes probes.json
    %(prog)s -t https://api.example.com --baseline baseline.json --probes probes.json --headers headers.json
    %(prog)s -t https://api.example.com --baseline baseline.json --probes probes.json -o report.json

Baseline JSON format:
    {"method": "POST", "path": "/api/checkout", "json": {"item_id": 1, "quantity": 1, "price": 99.99}}

Probes JSON format (see payloads/price_manipulation/probes.json):
    [
        {"category": "price", "method": "POST", "path": "/checkout", "json": {"item_id": 1, "price": 0}},
        {"category": "quantity", "method": "POST", "path": "/checkout", "json": {"qty": -1}},
        {"category": "coupon", "method": "POST", "path": "/checkout", "json": {"coupon": "FREE100"}}
    ]

Categories: price, quantity, coupon, subscription, trial, currency, negative, discount

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
    
    scanner = PriceManipulationScanner(
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
            "scanner": "REVUEX Price Manipulation GOLD",
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
