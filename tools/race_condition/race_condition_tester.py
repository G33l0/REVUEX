#!/usr/bin/env python3
"""
REVUEX Race Condition GOLD v4.0
===============================
Research-Grade Race Condition & Concurrency Scanner (10/10 GOLD)

Detection Philosophy:
- No exploitation
- No brute-force
- Deterministic concurrency validation
- Idempotency & atomicity proof
- Differential response analysis
- Bug bounty defensible

Core Techniques:
- Baseline Request Capture
- Concurrent Request Firing
- Response Differential Analysis
- Idempotency Validation
- Atomicity Proof
- Time-Window Analysis
- Response Variance Detection

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import threading
import time
import copy
import json
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.base_scanner import BaseScanner, Finding, ScanResult, Severity, ScanStatus
from core.utils import print_success, print_error, print_warning, print_info


# =============================================================================
# CONSTANTS
# =============================================================================

SCANNER_NAME = "Race Condition Scanner GOLD"
SCANNER_VERSION = "1.0.0"

BANNER = r"""
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

Race Condition GOLD — Concurrency & Atomicity Scanner
"""

CONFIDENCE_THRESHOLD = 85
DEFAULT_THREAD_COUNT = 5
CONCURRENCY_WINDOW = 0.05  # seconds between thread starts


# =============================================================================
# RACE CONDITION CHECK RESULT DATACLASS
# =============================================================================

@dataclass
class RaceCheckResult:
    """Result of a single race condition check."""
    check_name: str
    description: str
    severity: Severity
    confidence_score: int
    evidence: Dict[str, Any]
    is_vulnerable: bool


@dataclass
class ConcurrentResponse:
    """Captured concurrent response."""
    thread_id: int
    status_code: int
    response_length: int
    response_time: float
    response_hash: str
    success_indicator: bool


# =============================================================================
# RACE CONDITION SCANNER GOLD CLASS
# =============================================================================

class RaceConditionScanner(BaseScanner):
    """
    GOLD-tier Race Condition Scanner.
    
    Methodology:
    1. Capture baseline request
    2. Fire concurrent requests
    3. Analyze response variance
    4. Check idempotency violations
    5. Detect atomicity failures
    6. Report with confidence scoring
    """
    
    def __init__(
        self,
        target: str,
        method: str = "POST",
        request_data: Optional[Any] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        thread_count: int = DEFAULT_THREAD_COUNT,
        concurrency_window: float = CONCURRENCY_WINDOW,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
        **kwargs
    ):
        """
        Initialize Race Condition Scanner.
        
        Args:
            target: Target action URL
            method: HTTP method (POST, PUT, PATCH, DELETE)
            request_data: Request body data
            custom_headers: Custom HTTP headers
            thread_count: Number of concurrent threads
            concurrency_window: Time between thread starts
            confidence_threshold: Minimum confidence for findings
        """
        super().__init__(
            name="RaceConditionScanner",
            description="Race condition tester",
            target=target,
            **kwargs
        )
        
        self.method = method.upper()
        self.request_data = request_data
        self.custom_headers = custom_headers or {}
        self.thread_count = thread_count
        self.concurrency_window = concurrency_window
        self.confidence_threshold = confidence_threshold
        
        # State tracking
        self.baseline_response = None
        self.concurrent_responses: List[ConcurrentResponse] = []
        self.check_results: List[RaceCheckResult] = []
        self.total_confidence: int = 0
        
        # Thread safety
        self._lock = threading.Lock()
        
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
        """Execute the GOLD race condition scan."""
        self.logger.info(f"Starting Race Condition GOLD scan")
        self.logger.info(f"Target: {self.target}")
        self.logger.info(f"Method: {self.method}")
        self.logger.info(f"Threads: {self.thread_count}")
        
        # Phase 1: Capture baseline
        self.logger.info("Phase 1: Capturing baseline request...")
        self._capture_baseline()
        
        if not self.baseline_response:
            self.logger.error("Failed to capture baseline - aborting")
            return
        
        # Phase 2: Fire concurrent requests
        self.logger.info("Phase 2: Firing concurrent requests...")
        self._fire_concurrent_requests()
        
        # Phase 3: Analyze responses
        self.logger.info("Phase 3: Analyzing response variance...")
        self._analyze_responses()
        
        # Phase 4: Check idempotency
        self.logger.info("Phase 4: Checking idempotency...")
        self._check_idempotency()
        
        # Phase 5: Check atomicity
        self.logger.info("Phase 5: Checking atomicity...")
        self._check_atomicity()
        
        # Phase 6: Time-window analysis
        self.logger.info("Phase 6: Analyzing time windows...")
        self._analyze_time_windows()
        
        self.logger.info(f"Race condition scan complete. Found {len(self.findings)} issue(s)")
    
    # =========================================================================
    # BASELINE CAPTURE
    # =========================================================================
    
    def _capture_baseline(self) -> None:
        """Capture baseline request."""
        self.rate_limiter.acquire()
        self.request_count += 1
        
        try:
            start_time = time.time()
            response = self.session.request(
                self.method,
                self.target,
                headers=self.custom_headers,
                data=self.request_data if isinstance(self.request_data, str) else None,
                json=self.request_data if isinstance(self.request_data, dict) else None,
                timeout=self.timeout
            )
            response_time = time.time() - start_time
            
            self.baseline_response = {
                "status_code": response.status_code,
                "response_length": len(response.text),
                "response_time": response_time,
                "response_hash": hashlib.md5(response.text.encode()).hexdigest()[:12],
                "text": response.text[:500]
            }
            
            print_info(f"Baseline captured: HTTP {response.status_code}, {len(response.text)} bytes")
            time.sleep(self.delay)
            
        except Exception as e:
            self.logger.error(f"Baseline capture failed: {e}")
    
    # =========================================================================
    # CONCURRENT EXECUTION
    # =========================================================================
    
    def _send_concurrent_request(self, thread_id: int) -> Optional[ConcurrentResponse]:
        """Send a single concurrent request."""
        try:
            start_time = time.time()
            response = self.session.request(
                self.method,
                self.target,
                headers=copy.deepcopy(self.custom_headers),
                data=copy.deepcopy(self.request_data) if isinstance(self.request_data, str) else None,
                json=copy.deepcopy(self.request_data) if isinstance(self.request_data, dict) else None,
                timeout=self.timeout
            )
            response_time = time.time() - start_time
            
            # Determine success indicator
            success = response.status_code == self.baseline_response["status_code"]
            
            return ConcurrentResponse(
                thread_id=thread_id,
                status_code=response.status_code,
                response_length=len(response.text),
                response_time=response_time,
                response_hash=hashlib.md5(response.text.encode()).hexdigest()[:12],
                success_indicator=success
            )
        except Exception as e:
            self.logger.debug(f"Thread {thread_id} failed: {e}")
            return None
    
    def _fire_concurrent_requests(self) -> None:
        """Fire multiple concurrent requests."""
        threads = []
        
        def worker(tid):
            result = self._send_concurrent_request(tid)
            if result:
                with self._lock:
                    self.concurrent_responses.append(result)
        
        # Start threads with small delays
        for i in range(self.thread_count):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
        
        # Fire all threads nearly simultaneously
        for t in threads:
            t.start()
            time.sleep(self.concurrency_window)
        
        # Wait for all threads
        for t in threads:
            t.join()
        
        print_info(f"Executed {len(self.concurrent_responses)} concurrent requests")
    
    # =========================================================================
    # ANALYSIS
    # =========================================================================
    
    def _analyze_responses(self) -> None:
        """Analyze response variance."""
        if not self.baseline_response or not self.concurrent_responses:
            return
        
        confidence = 40
        evidence = {}
        
        baseline_code = self.baseline_response["status_code"]
        baseline_len = self.baseline_response["response_length"]
        
        # Count successful responses
        success_count = sum(1 for r in self.concurrent_responses if r.success_indicator)
        
        # Collect distinct response bodies
        distinct_lengths = set(r.response_length for r in self.concurrent_responses)
        distinct_hashes = set(r.response_hash for r in self.concurrent_responses)
        
        # Status code variance
        status_codes = [r.status_code for r in self.concurrent_responses]
        distinct_codes = set(status_codes)
        
        evidence["baseline_status"] = baseline_code
        evidence["concurrent_successes"] = success_count
        evidence["threads"] = self.thread_count
        evidence["distinct_status_codes"] = list(distinct_codes)
        evidence["distinct_response_lengths"] = list(distinct_lengths)
        
        # Multiple successful acceptances (strong indicator)
        if success_count > 1:
            confidence += 30
        
        # Response body variance (side-effect inconsistency)
        if len(distinct_hashes) > 1:
            confidence += 20
            evidence["response_variance"] = True
        
        # All requests succeeded (non-idempotent)
        if success_count == len(self.concurrent_responses):
            confidence += 15
        
        if confidence >= self.confidence_threshold:
            self._add_check_result(
                "Race Condition / Missing Atomicity Detected",
                "Multiple concurrent requests were accepted, indicating missing atomicity controls",
                Severity.CRITICAL,
                confidence,
                evidence,
                True
            )
    
    def _check_idempotency(self) -> None:
        """Check idempotency violations."""
        if not self.concurrent_responses:
            return
        
        # All responses should be identical for idempotent operations
        hashes = [r.response_hash for r in self.concurrent_responses]
        
        if len(set(hashes)) > 1:
            # Different responses indicate non-idempotent behavior
            confidence = 75
            
            # Check if status codes also vary
            status_codes = [r.status_code for r in self.concurrent_responses]
            if len(set(status_codes)) > 1:
                confidence += 15
            
            if confidence >= self.confidence_threshold:
                self._add_check_result(
                    "Idempotency Violation Detected",
                    "Concurrent identical requests returned different responses",
                    Severity.HIGH,
                    confidence,
                    {
                        "distinct_responses": len(set(hashes)),
                        "distinct_status_codes": list(set(status_codes))
                    },
                    True
                )
    
    def _check_atomicity(self) -> None:
        """Check atomicity failures."""
        if not self.concurrent_responses:
            return
        
        # Look for partial success patterns
        success_responses = [r for r in self.concurrent_responses if r.success_indicator]
        failure_responses = [r for r in self.concurrent_responses if not r.success_indicator]
        
        # If we have both successes and failures, atomicity may be compromised
        if success_responses and failure_responses:
            confidence = 80
            
            self._add_check_result(
                "Potential Atomicity Failure",
                "Mixed success/failure responses indicate possible atomicity issues",
                Severity.HIGH,
                confidence,
                {
                    "success_count": len(success_responses),
                    "failure_count": len(failure_responses),
                    "success_codes": list(set(r.status_code for r in success_responses)),
                    "failure_codes": list(set(r.status_code for r in failure_responses))
                },
                True
            )
    
    def _analyze_time_windows(self) -> None:
        """Analyze response time windows."""
        if len(self.concurrent_responses) < 2:
            return
        
        response_times = [r.response_time for r in self.concurrent_responses]
        
        # Calculate variance
        avg_time = sum(response_times) / len(response_times)
        variance = sum((t - avg_time) ** 2 for t in response_times) / len(response_times)
        
        # High variance may indicate locking/queuing behavior
        if variance > 0.5:  # More than 500ms variance
            print_info(f"High response time variance detected: {variance:.3f}s")
    
    # =========================================================================
    # RESULT HANDLING
    # =========================================================================
    
    def _add_check_result(self, check_name: str, description: str, severity: Severity, confidence_score: int, evidence: Dict[str, Any], is_vulnerable: bool) -> None:
        """Add a check result and create finding."""
        result = RaceCheckResult(
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
    
    def _create_finding(self, result: RaceCheckResult) -> None:
        """Create finding from check result."""
        finding = Finding(
            id=self._generate_finding_id(result.check_name),
            title=result.check_name,
            severity=result.severity,
            description=result.description,
            url=self.target,
            parameter="Concurrency",
            method=self.method,
            payload=f"{self.thread_count} concurrent requests",
            evidence=json.dumps(result.evidence, indent=2),
            impact=self._get_impact(result),
            remediation=self._get_remediation(result),
            vulnerability_type="race_condition",
            confidence="high" if result.confidence_score >= 85 else "medium",
        )
        self.add_finding(finding)
    
    def _get_impact(self, result: RaceCheckResult) -> str:
        """Get impact description."""
        if result.severity == Severity.CRITICAL:
            return (
                "CRITICAL: Race condition enables:\n"
                "- Double spending / duplicate transactions\n"
                "- Coupon/voucher abuse\n"
                "- Inventory manipulation\n"
                "- Account balance manipulation"
            )
        elif result.severity == Severity.HIGH:
            return (
                "HIGH: Concurrency weakness enables:\n"
                "- Inconsistent state\n"
                "- Data corruption\n"
                "- Business logic bypass"
            )
        return "MEDIUM: Potential concurrency issue detected"
    
    def _get_remediation(self, result: RaceCheckResult) -> str:
        """Get remediation based on check type."""
        return (
            "1. Implement database-level locking (SELECT FOR UPDATE)\n"
            "2. Use optimistic locking with version numbers\n"
            "3. Implement idempotency keys for API endpoints\n"
            "4. Use distributed locks (Redis, etc.) for critical sections\n"
            "5. Implement request deduplication\n"
            "6. Add unique constraints at database level\n"
            "7. Use atomic operations where possible"
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
    parser = argparse.ArgumentParser(prog="revuex-race", description="REVUEX Race Condition GOLD - Concurrency Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target action URL")
    parser.add_argument("-X", "--method", default="POST", help="HTTP method (default: POST)")
    parser.add_argument("-H", "--header", action="append", help="Custom headers (Key:Value)")
    parser.add_argument("-d", "--data", help="Request body data (JSON)")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREAD_COUNT, help=f"Thread count (default: {DEFAULT_THREAD_COUNT})")
    parser.add_argument("--window", type=float, default=CONCURRENCY_WINDOW, help=f"Concurrency window in seconds (default: {CONCURRENCY_WINDOW})")
    parser.add_argument("--threshold", type=int, default=CONFIDENCE_THRESHOLD, help=f"Confidence threshold (default: {CONFIDENCE_THRESHOLD})")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
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
    
    request_data = None
    if args.data:
        try:
            request_data = json.loads(args.data)
        except json.JSONDecodeError:
            request_data = args.data
    
    if not args.quiet:
        print(BANNER)
        print(f"[+] Target: {args.url}")
        print(f"[+] Method: {args.method}")
        print(f"[+] Threads: {args.threads}")
        print()
    
    scanner = RaceConditionScanner(
        target=args.url,
        method=args.method,
        request_data=request_data,
        custom_headers=custom_headers,
        thread_count=args.threads,
        concurrency_window=args.window,
        confidence_threshold=args.threshold,
        timeout=args.timeout,
        verbose=args.verbose,
    )
    
    result = scanner.run()
    
    if not args.quiet:
        print(f"\n{'='*60}")
        print("SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"Target: {args.url}")
        print(f"Duration: {result.duration_seconds:.2f}s")
        print(f"Concurrent Requests: {len(scanner.concurrent_responses)}")
        print(f"Issues Found: {len(result.findings)}")
        print(f"Total Confidence: {scanner.total_confidence}")
    
    if args.output:
        output_data = {
            "scanner": SCANNER_NAME,
            "version": SCANNER_VERSION,
            "target": args.url,
            "method": args.method,
            "threads": args.threads,
            "concurrent_responses": len(scanner.concurrent_responses),
            "findings": [{"id": f.id, "title": f.title, "severity": f.severity.value} for f in result.findings]
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        if not args.quiet:
            print(f"\nResults saved to: {args.output}")
    
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
