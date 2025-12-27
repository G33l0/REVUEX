#!/usr/bin/env python3
"""
REVUEX XXE GOLD v4.0
====================
Enterprise-Grade Non-Exploitational XXE Vulnerability Validator

Detection Philosophy:
- Zero-destructive testing
- No sensitive file exfiltration
- No network callback abuse
- Evidence-backed confidence scoring
- Multi-engine verdict correlation
- Designed for responsible bug bounty workflow

Validation Engines:
1. Parser Behavior Fingerprinting Engine
2. Safe Entity Acceptance Engine
3. Blind Timing & Error Pattern Engine
4. Content-Type & Parser-Mismatch Engine
5. Schema Relaxation Heuristic
6. Header-Correlation Engine
7. Parameter Entity Detection Engine
8. Error-Based XXE Detection Engine
9. DOCTYPE Processing Engine

Author: REVUEX Team (G33L0)
License: MIT (Private Research Use)
"""

import re
import json
import time
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.base_scanner import BaseScanner, Finding, ScanResult, Severity, ScanStatus
from core.utils import print_success, print_error, print_warning, print_info


# =============================================================================
# CONSTANTS
# =============================================================================

SCANNER_NAME = "XXE Scanner GOLD"
SCANNER_VERSION = "4.0.0"

BANNER = r"""
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

XXE Scanner GOLD — XML External Entity Detection
"""

CONFIDENCE_THRESHOLD = 75
BLIND_DELAY_THRESHOLD = 3  # seconds

# Safe entity test - harmless internal entity
SAFE_ENTITY_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY harmless "REVUEX_XXE_SAFE_TEST">
]>
<root>&harmless;</root>
"""

# Benign expansion test - single entity, no recursion
BENIGN_EXPANSION_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY single "test_value">
]>
<root>&single;</root>
"""

# DOCTYPE processing test
DOCTYPE_TEST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ELEMENT root (#PCDATA)>
]>
<root>test</root>
"""

# Parameter entity hint (non-exploitative)
PARAM_ENTITY_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY % param "test">
]>
<root>param_test</root>
"""

# Error trigger XML (malformed to trigger parser errors)
ERROR_TRIGGER_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY undefined_ref "value">
]>
<root>&undefined_entity;</root>
"""

# Basic XML for baseline
BASIC_XML = """<?xml version="1.0" encoding="UTF-8"?>
<root>test</root>
"""

# XML parser fingerprints
PARSER_FINGERPRINTS = [
    "libxml", "xerces", "expat", "dom4j", "saxon",
    "woodstox", "stax", "jaxp", "msxml", "xmlreader",
    "sax", "dom", "pull", "stream"
]

# XXE error indicators
XXE_ERROR_INDICATORS = [
    "entity", "dtd", "doctype", "external", "system",
    "public", "notation", "xml declaration", "parsing",
    "malformed", "undefined entity", "forbidden",
    "not allowed", "disabled", "security"
]


# =============================================================================
# XXE CHECK RESULT DATACLASS
# =============================================================================

@dataclass
class XXECheckResult:
    """Result of a single XXE check."""
    engine_name: str
    description: str
    severity: Severity
    confidence_score: int
    evidence: Dict[str, Any]
    is_vulnerable: bool


# =============================================================================
# XXE SCANNER GOLD CLASS
# =============================================================================

class XXEScanner(BaseScanner):
    """
    GOLD-tier XXE Vulnerability Scanner.
    
    Multi-engine validation approach:
    1. Parser Behavior Fingerprinting
    2. Safe Entity Acceptance
    3. Blind Timing Analysis
    4. Content-Type Mismatch
    5. Schema Relaxation
    6. Header Correlation
    7. Parameter Entity Detection
    8. Error-Based Detection
    9. DOCTYPE Processing
    """
    
    def __init__(
        self,
        target: str,
        custom_headers: Optional[Dict[str, str]] = None,
        custom_xml: Optional[str] = None,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
        **kwargs
    ):
        """
        Initialize XXE Scanner.
        
        Args:
            target: Target XML endpoint URL
            custom_headers: Custom HTTP headers
            custom_xml: Custom XML payload to test
            confidence_threshold: Minimum confidence for findings
        """
        super().__init__(
            name="XXEScanner",
            description="XML External Entity Injection scanner",
            target=target,
            **kwargs
        )
        
        self.custom_headers = custom_headers or {}
        self.custom_xml = custom_xml
        self.confidence_threshold = confidence_threshold
        
        # State tracking
        self.check_results: List[XXECheckResult] = []
        self.total_confidence: int = 0
        self.reasons: List[str] = []
        self.baseline_response = None
        self.detected_parser: Optional[str] = None
        
        # Scanner info
        self.scanner_name = SCANNER_NAME
        self.scanner_version = SCANNER_VERSION
    
    def _validate_target(self) -> bool:
        """Validate target accepts XML."""
        try:
            response = self._post_xml(BASIC_XML)
            return response is not None and response.status_code < 500
        except Exception:
            return False
    
    def _post_xml(self, xml_body: str, extra_headers: Optional[Dict[str, str]] = None):
        """Send XML POST request."""
        headers = {
            "Content-Type": "application/xml",
            "Accept": "application/xml, text/xml, */*",
            **self.custom_headers
        }
        if extra_headers:
            headers.update(extra_headers)
        
        try:
            self.rate_limiter.acquire()
            self._request_count += 1
            
            response = self.session.post(
                self.target,
                data=xml_body,
                headers=headers,
                timeout=self.timeout
            )
            
            time.sleep(self.delay)
            return response
            
        except Exception as e:
            self.logger.debug(f"XML POST error: {e}")
            return None
    
    def scan(self) -> None:
        """Execute the GOLD XXE scan."""
        self.logger.info(f"Starting XXE GOLD scan")
        self.logger.info(f"Target: {self.target}")
        
        # Phase 1: Capture baseline
        self.logger.info("Phase 1: Capturing baseline response...")
        self._capture_baseline()
        
        # Phase 2: Parser Fingerprinting
        self.logger.info("Phase 2: Parser behavior fingerprinting...")
        self._engine_parser_fingerprints()
        
        # Phase 3: Safe Entity Acceptance
        self.logger.info("Phase 3: Testing safe entity acceptance...")
        self._engine_safe_entity_acceptance()
        
        # Phase 4: Blind Timing Analysis
        self.logger.info("Phase 4: Blind timing analysis...")
        self._engine_blind_timing()
        
        # Phase 5: Content-Type Mismatch
        self.logger.info("Phase 5: Content-type mismatch testing...")
        self._engine_content_type_mismatch()
        
        # Phase 6: Schema Relaxation
        self.logger.info("Phase 6: Schema relaxation heuristic...")
        self._engine_schema_relaxed()
        
        # Phase 7: Header Correlation
        self.logger.info("Phase 7: Header correlation analysis...")
        self._engine_header_correlation()
        
        # Phase 8: Parameter Entity Detection
        self.logger.info("Phase 8: Parameter entity detection...")
        self._engine_parameter_entity()
        
        # Phase 9: Error-Based Detection
        self.logger.info("Phase 9: Error-based detection...")
        self._engine_error_based()
        
        # Phase 10: DOCTYPE Processing
        self.logger.info("Phase 10: DOCTYPE processing test...")
        self._engine_doctype_processing()
        
        # Phase 11: Correlate and report
        self._correlate_findings()
        
        self.logger.info(f"XXE scan complete. Found {len(self.findings)} issue(s)")
    
    # =========================================================================
    # BASELINE CAPTURE
    # =========================================================================
    
    def _capture_baseline(self) -> None:
        """Capture baseline response."""
        response = self._post_xml(BASIC_XML)
        
        if response:
            self.baseline_response = {
                "status": response.status_code,
                "body": response.text,
                "headers": dict(response.headers),
                "length": len(response.text)
            }
            print_info(f"Baseline: {response.status_code}, {len(response.text)} bytes")
    
    # =========================================================================
    # ENGINE 1: PARSER FINGERPRINTING
    # =========================================================================
    
    def _engine_parser_fingerprints(self) -> None:
        """Detect XML parser from response."""
        response = self._post_xml(BASIC_XML)
        
        if not response:
            return
        
        # Combine headers and body for fingerprinting
        banner = response.headers.get("Server", "") + " "
        banner += response.headers.get("X-Powered-By", "") + " "
        banner += response.text[:500]
        banner = banner.lower()
        
        for parser in PARSER_FINGERPRINTS:
            if parser in banner:
                self.detected_parser = parser
                self._add_reason(f"XML parser fingerprint detected: {parser}", 15)
                break
    
    # =========================================================================
    # ENGINE 2: SAFE ENTITY ACCEPTANCE
    # =========================================================================
    
    def _engine_safe_entity_acceptance(self) -> None:
        """Test if safe internal entities are expanded."""
        response = self._post_xml(SAFE_ENTITY_XML)
        
        if not response:
            return
        
        # Check if entity was expanded (reflected in response)
        if "REVUEX_XXE_SAFE_TEST" in response.text:
            self._add_reason("Internal ENTITY expansion accepted (safe entity reflected)", 30)
            self._add_check_result(
                "Safe Entity Expansion",
                "Server expands internal XML entities - DTD processing is enabled",
                Severity.HIGH,
                30,
                {"entity_reflected": True, "marker": "REVUEX_XXE_SAFE_TEST"},
                True
            )
    
    # =========================================================================
    # ENGINE 3: BLIND TIMING ANALYSIS
    # =========================================================================
    
    def _engine_blind_timing(self) -> None:
        """Detect XXE via timing anomalies."""
        # Get baseline timing
        start = time.time()
        self._post_xml(BASIC_XML)
        baseline_time = time.time() - start
        
        # Test with entity expansion
        start = time.time()
        self._post_xml(BENIGN_EXPANSION_XML)
        expansion_time = time.time() - start
        
        # Check for significant delay
        delta = expansion_time - baseline_time
        
        if delta > BLIND_DELAY_THRESHOLD:
            self._add_reason(f"Timing anomaly suggests DTD processing (+{delta:.2f}s)", 20)
    
    # =========================================================================
    # ENGINE 4: CONTENT-TYPE MISMATCH
    # =========================================================================
    
    def _engine_content_type_mismatch(self) -> None:
        """Test if XML is parsed with wrong content-type."""
        # Send XML with text/plain content-type
        response = self._post_xml(BASIC_XML, {"Content-Type": "text/plain"})
        
        if not response:
            return
        
        # Check if it was still parsed as XML
        body_lower = response.text.lower()
        if response.status_code in [200, 400] and any(x in body_lower for x in ["xml", "element", "tag", "root"]):
            self._add_reason("XML parsed despite Content-Type mismatch (parser auto-detection)", 15)
    
    # =========================================================================
    # ENGINE 5: SCHEMA RELAXATION
    # =========================================================================
    
    def _engine_schema_relaxed(self) -> None:
        """Test if DTD/schema errors are visible."""
        response = self._post_xml(DOCTYPE_TEST_XML)
        
        if not response:
            return
        
        body_lower = response.text.lower()
        
        # Check for DTD-related content in response
        if any(x in body_lower for x in ["doctype", "entity", "dtd", "element"]):
            self._add_reason("DTD/schema parsing surface visible in response", 15)
    
    # =========================================================================
    # ENGINE 6: HEADER CORRELATION
    # =========================================================================
    
    def _engine_header_correlation(self) -> None:
        """Correlate headers for XXE indicators."""
        response = self._post_xml(SAFE_ENTITY_XML)
        
        if not response:
            return
        
        header_blob = str(response.headers).lower()
        
        # Check for entity/DTD related headers
        if any(x in header_blob for x in ["entity", "dtd", "xml", "parser"]):
            self._add_reason("Server headers suggest XXE parser behavior", 10)
    
    # =========================================================================
    # ENGINE 7: PARAMETER ENTITY DETECTION
    # =========================================================================
    
    def _engine_parameter_entity(self) -> None:
        """Test parameter entity processing."""
        response = self._post_xml(PARAM_ENTITY_XML)
        
        if not response:
            return
        
        # Check for error messages related to parameter entities
        body_lower = response.text.lower()
        
        if "parameter" in body_lower and "entity" in body_lower:
            self._add_reason("Parameter entity processing detected", 20)
        
        # No error about parameter entities = might be processing them
        if response.status_code == 200 and "error" not in body_lower:
            self._add_reason("Parameter entity syntax accepted without error", 10)
    
    # =========================================================================
    # ENGINE 8: ERROR-BASED DETECTION
    # =========================================================================
    
    def _engine_error_based(self) -> None:
        """Detect XXE via error messages."""
        response = self._post_xml(ERROR_TRIGGER_XML)
        
        if not response:
            return
        
        body_lower = response.text.lower()
        
        # Look for XXE-related error messages
        for indicator in XXE_ERROR_INDICATORS:
            if indicator in body_lower:
                self._add_reason(f"XXE-related error indicator: '{indicator}'", 15)
                break
        
        # Verbose error messages can leak info
        if "undefined" in body_lower and "entity" in body_lower:
            self._add_reason("Undefined entity error reveals DTD processing", 20)
            self._add_check_result(
                "Error-Based XXE Indicator",
                "XML parser reveals entity processing via error messages",
                Severity.MEDIUM,
                20,
                {"error_type": "undefined_entity"},
                True
            )
    
    # =========================================================================
    # ENGINE 9: DOCTYPE PROCESSING
    # =========================================================================
    
    def _engine_doctype_processing(self) -> None:
        """Test DOCTYPE declaration processing."""
        response = self._post_xml(DOCTYPE_TEST_XML)
        
        if not response:
            return
        
        # Compare with baseline
        if self.baseline_response:
            baseline_len = self.baseline_response["length"]
            response_len = len(response.text)
            
            # Different response suggests DOCTYPE was processed
            if abs(response_len - baseline_len) > 50:
                self._add_reason("DOCTYPE declaration affects response (DTD enabled)", 15)
        
        # Check for DOCTYPE in response
        if "DOCTYPE" in response.text:
            self._add_reason("DOCTYPE reflected in response", 10)
    
    # =========================================================================
    # CORRELATION AND FINDINGS
    # =========================================================================
    
    def _add_reason(self, reason: str, score: int) -> None:
        """Add a detection reason with score."""
        if reason not in self.reasons:
            self.reasons.append(reason)
            self.total_confidence += score
            print_info(f"{reason} (+{score})")
    
    def _correlate_findings(self) -> None:
        """Correlate all signals and create main finding."""
        if self.total_confidence >= self.confidence_threshold:
            self._add_check_result(
                "XXE Vulnerability Capability",
                "Multiple signals indicate XXE vulnerability capability",
                Severity.HIGH if self.total_confidence >= 80 else Severity.MEDIUM,
                self.total_confidence,
                {
                    "signals": self.reasons,
                    "parser_detected": self.detected_parser,
                    "engines_triggered": len(self.reasons)
                },
                True
            )
    
    # =========================================================================
    # RESULT HANDLING
    # =========================================================================
    
    def _add_check_result(self, engine_name: str, description: str, severity: Severity, confidence_score: int, evidence: Dict[str, Any], is_vulnerable: bool) -> None:
        """Add a check result and create finding."""
        result = XXECheckResult(
            engine_name=engine_name,
            description=description,
            severity=severity,
            confidence_score=confidence_score,
            evidence=evidence,
            is_vulnerable=is_vulnerable
        )
        self.check_results.append(result)
        self._create_finding(result)
        print_success(f"{engine_name}: {description[:50]}...")
    
    def _create_finding(self, result: XXECheckResult) -> None:
        """Create finding from check result."""
        finding = Finding(
            id=self._generate_finding_id(result.engine_name),
            title=f"XXE: {result.engine_name}",
            severity=result.severity,
            description=result.description,
            url=self.target,
            parameter="XML Body",
            method="POST",
            payload="XML with DOCTYPE/ENTITY",
            evidence=json.dumps(result.evidence, indent=2),
            impact=self._get_impact(result),
            remediation=self._get_remediation(),
            vulnerability_type="xxe",
            confidence="high" if result.confidence_score >= 80 else "medium",
        )
        self.add_finding(finding)
    
    def _get_impact(self, result: XXECheckResult) -> str:
        """Get impact description."""
        if result.severity == Severity.HIGH:
            return (
                "HIGH: XXE vulnerability can lead to:\n"
                "- Local file disclosure (/etc/passwd, config files)\n"
                "- SSRF (Server-Side Request Forgery)\n"
                "- Denial of Service (Billion Laughs)\n"
                "- Port scanning internal network\n"
                "- Potential Remote Code Execution"
            )
        return (
            "MEDIUM: XML parser behavior indicates:\n"
            "- DTD processing is enabled\n"
            "- Entity expansion is active\n"
            "- Further XXE testing recommended"
        )
    
    def _get_remediation(self) -> str:
        """Get remediation guidance."""
        return (
            "1. Disable DTD processing entirely\n"
            "2. Disable external entity resolution\n"
            "3. Use defusedxml or similar safe parser\n"
            "4. Set XMLReader features:\n"
            "   - FEATURE_SECURE_PROCESSING = true\n"
            "   - disallow-doctype-decl = true\n"
            "   - external-general-entities = false\n"
            "   - external-parameter-entities = false\n"
            "5. Validate and sanitize XML input\n"
            "6. Use JSON instead of XML where possible"
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
    parser = argparse.ArgumentParser(prog="revuex-xxe", description="REVUEX XXE GOLD - XML External Entity Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target XML endpoint URL")
    parser.add_argument("-H", "--header", action="append", help="Custom headers (Key:Value)")
    parser.add_argument("--xml", help="Custom XML payload file")
    parser.add_argument("--threshold", type=int, default=CONFIDENCE_THRESHOLD, help=f"Confidence threshold (default: {CONFIDENCE_THRESHOLD})")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--delay", type=float, default=0.5, help="Request delay")
    parser.add_argument("--timeout", type=int, default=12, help="Request timeout")
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
    
    custom_xml = None
    if args.xml:
        try:
            with open(args.xml, 'r') as f:
                custom_xml = f.read()
        except Exception as e:
            print_error(f"Failed to read XML file: {e}")
            return 1
    
    if not args.quiet:
        print(BANNER)
        print(f"[+] Target: {args.url}")
        print(f"[+] Engines: 9")
        print()
    
    scanner = XXEScanner(
        target=args.url,
        custom_headers=custom_headers,
        custom_xml=custom_xml,
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
        print(f"Target: {args.url}")
        if result and hasattr(result, "duration_seconds") and result.duration_seconds:
            print(f"Duration: {result.duration_seconds:.2f}s")
        print(f"Parser Detected: {scanner.detected_parser or 'Unknown'}")
        print(f"Total Confidence: {scanner.total_confidence}%")
        print(f"Vulnerable: {'YES' if scanner.total_confidence >= CONFIDENCE_THRESHOLD else 'NO'}")
        
        if scanner.reasons:
            print(f"\n[Detection Signals]")
            for reason in scanner.reasons:
                print(f"  • {reason}")
    
    if args.output:
        output_data = {
            "scanner": SCANNER_NAME,
            "version": SCANNER_VERSION,
            "target": args.url,
            "parser_detected": scanner.detected_parser,
            "confidence": scanner.total_confidence,
            "vulnerable": scanner.total_confidence >= CONFIDENCE_THRESHOLD,
            "signals": scanner.reasons,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value
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
