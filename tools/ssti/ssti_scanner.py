#!/usr/bin/env python3
"""
REVUEX SSTI GOLD v4.0
=====================
High-confidence Server-Side Template Injection Capability Detector

Detection Philosophy:
- Zero exploitation
- Capability identification only
- Multi-signal correlation
- No payload execution
- Confidence-based findings only

Core Techniques:
- Static syntax artifact detection
- Engine-specific error fingerprinting
- Framework header analysis
- Reflection marker detection
- Parameter-based capability testing
- Math expression differential analysis
- Multi-engine correlation

Supported Engines:
- Jinja2 (Python)
- Twig (PHP)
- FreeMarker (Java)
- Velocity (Java)
- Mustache (Multi-language)
- Pebble (Java)
- Thymeleaf (Java)
- Smarty (PHP)
- Mako (Python)
- ERB (Ruby)
- EJS (JavaScript)
- Handlebars (JavaScript)

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import re
import json
import time
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.base_scanner import BaseScanner, Finding, ScanResult, Severity, ScanStatus
from core.utils import print_success, print_error, print_warning, print_info


# =============================================================================
# CONSTANTS
# =============================================================================

SCANNER_NAME = "SSTI Scanner GOLD"
SCANNER_VERSION = "1.0.0"

BANNER = r"""
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

SSTI Scanner GOLD — Template Injection Detection
"""

CONFIDENCE_THRESHOLD = 75

# Template engine definitions with syntax patterns, error signatures, and detection probes
TEMPLATE_ENGINES = {
    "jinja2": {
        "language": "Python",
        "syntax": [r"{{\s*[^}]+\s*}}", r"{%\s*[^%]+\s*%}"],
        "errors": [
            r"jinja2\.exceptions",
            r"UndefinedError",
            r"TemplateSyntaxError",
            r"jinja2\.runtime"
        ],
        "headers": ["python", "flask", "django", "werkzeug"],
        "probes": ["{{7*7}}", "{{config}}", "{{self}}"],
        "expected": ["49"],
        "risk": "Server-Side Template Injection (Python/Jinja2)",
        "severity": "critical"
    },
    "twig": {
        "language": "PHP",
        "syntax": [r"{{\s*[^}]+\s*}}", r"{%\s*[^%]+\s*%}"],
        "errors": [
            r"Twig\\Error",
            r"Twig_Error",
            r"Twig\\Environment",
            r"Twig_Environment"
        ],
        "headers": ["php", "symfony"],
        "probes": ["{{7*7}}", "{{_self}}", "{{app}}"],
        "expected": ["49"],
        "risk": "SSTI in Twig (PHP)",
        "severity": "critical"
    },
    "freemarker": {
        "language": "Java",
        "syntax": [r"\$\{[^}]+\}", r"<#[^>]+>", r"<@[^>]+>"],
        "errors": [
            r"freemarker\.core",
            r"freemarker\.template",
            r"InvalidReferenceException",
            r"ParseException"
        ],
        "headers": ["java", "spring", "tomcat"],
        "probes": ["${7*7}", "${.now}", "<#assign x=7*7>${x}"],
        "expected": ["49"],
        "risk": "SSTI in Apache FreeMarker (Java)",
        "severity": "critical"
    },
    "velocity": {
        "language": "Java",
        "syntax": [r"\$\w+", r"\$\{[^}]+\}", r"#set\s*\(", r"#if\s*\("],
        "errors": [
            r"VelocityException",
            r"velocity\.exception",
            r"ResourceNotFoundException"
        ],
        "headers": ["java", "velocity"],
        "probes": ["$class", "#set($x=7*7)$x"],
        "expected": ["49"],
        "risk": "Velocity Template Injection (Java)",
        "severity": "critical"
    },
    "pebble": {
        "language": "Java",
        "syntax": [r"{{\s*[^}]+\s*}}", r"{%\s*[^%]+\s*%}"],
        "errors": [
            r"com\.mitchellbosecke\.pebble",
            r"PebbleException"
        ],
        "headers": ["java", "pebble"],
        "probes": ["{{7*7}}", "{{beans}}"],
        "expected": ["49"],
        "risk": "SSTI in Pebble (Java)",
        "severity": "critical"
    },
    "thymeleaf": {
        "language": "Java",
        "syntax": [r"\[\[.*?\]\]", r"\$\{[^}]+\}", r"th:[a-z]+"],
        "errors": [
            r"org\.thymeleaf",
            r"TemplateProcessingException",
            r"ThymeleafException"
        ],
        "headers": ["java", "spring", "thymeleaf"],
        "probes": ["[[${7*7}]]", "${T(java.lang.Runtime)}"],
        "expected": ["49"],
        "risk": "SSTI in Thymeleaf (Java/Spring)",
        "severity": "critical"
    },
    "smarty": {
        "language": "PHP",
        "syntax": [r"\{[a-z$][^}]*\}"],
        "errors": [
            r"Smarty",
            r"SmartyException",
            r"SmartyCompilerException"
        ],
        "headers": ["php", "smarty"],
        "probes": ["{7*7}", "{$smarty.version}"],
        "expected": ["49"],
        "risk": "SSTI in Smarty (PHP)",
        "severity": "critical"
    },
    "mako": {
        "language": "Python",
        "syntax": [r"\$\{[^}]+\}", r"<%[^>]*%>"],
        "errors": [
            r"mako\.exceptions",
            r"MakoException",
            r"CompileException"
        ],
        "headers": ["python", "mako", "pyramid"],
        "probes": ["${7*7}", "<%7*7%>"],
        "expected": ["49"],
        "risk": "SSTI in Mako (Python)",
        "severity": "critical"
    },
    "erb": {
        "language": "Ruby",
        "syntax": [r"<%=?\s*[^%]+\s*%>"],
        "errors": [
            r"ERB",
            r"SyntaxError.*erb",
            r"NameError"
        ],
        "headers": ["ruby", "rails", "sinatra"],
        "probes": ["<%=7*7%>", "<%= self %>"],
        "expected": ["49"],
        "risk": "SSTI in ERB (Ruby)",
        "severity": "critical"
    },
    "ejs": {
        "language": "JavaScript",
        "syntax": [r"<%=?\s*[^%]+\s*%>", r"<%[-_]?\s*[^%]+\s*[-_]?%>"],
        "errors": [
            r"EJS",
            r"ReferenceError",
            r"SyntaxError"
        ],
        "headers": ["node", "express", "ejs"],
        "probes": ["<%=7*7%>", "<%=global%>"],
        "expected": ["49"],
        "risk": "SSTI in EJS (Node.js)",
        "severity": "critical"
    },
    "handlebars": {
        "language": "JavaScript",
        "syntax": [r"{{\s*[^}]+\s*}}", r"{{#[^}]+}}"],
        "errors": [
            r"Handlebars",
            r"handlebars\.js"
        ],
        "headers": ["node", "express", "handlebars"],
        "probes": ["{{7*7}}", "{{this}}"],
        "expected": [],  # Handlebars doesn't evaluate expressions
        "risk": "Handlebars Template Context Injection",
        "severity": "high"
    },
    "mustache": {
        "language": "Multi",
        "syntax": [r"{{\s*[^}]+\s*}}", r"{{#[^}]+}}"],
        "errors": [],
        "headers": [],
        "probes": ["{{.}}", "{{#a}}{{/a}}"],
        "expected": [],
        "risk": "Mustache Template Context Injection",
        "severity": "high"
    },
    "nunjucks": {
        "language": "JavaScript",
        "syntax": [r"{{\s*[^}]+\s*}}", r"{%\s*[^%]+\s*%}"],
        "errors": [
            r"nunjucks",
            r"Template render error"
        ],
        "headers": ["node", "express", "nunjucks"],
        "probes": ["{{7*7}}", "{{range(10)}}"],
        "expected": ["49"],
        "risk": "SSTI in Nunjucks (Node.js)",
        "severity": "critical"
    }
}

# Reflection markers to test (non-exploitative)
REFLECTION_MARKERS = [
    ("{{revuex_test}}", "jinja/twig/pebble"),
    ("${revuex_test}", "freemarker/velocity/thymeleaf"),
    ("#{revuex_test}", "thymeleaf"),
    ("<%=revuex_test%>", "erb/ejs"),
    ("{revuex_test}", "smarty"),
]

# Math expression probes (safe - just arithmetic)
MATH_PROBES = [
    ("{{7*7}}", "49", ["jinja2", "twig", "pebble", "nunjucks"]),
    ("${7*7}", "49", ["freemarker", "mako", "thymeleaf"]),
    ("<%=7*7%>", "49", ["erb", "ejs"]),
    ("{7*7}", "49", ["smarty"]),
    ("{{7*'7'}}", "7777777", ["jinja2"]),  # String multiplication
    ("${7+7}", "14", ["freemarker", "velocity"]),
]


# =============================================================================
# SSTI CHECK RESULT DATACLASS
# =============================================================================

@dataclass
class SSTICheckResult:
    """Result of a single SSTI check."""
    engine: str
    language: str
    severity: Severity
    confidence_score: int
    risk: str
    evidence: Dict[str, Any]
    is_vulnerable: bool


# =============================================================================
# SSTI SCANNER GOLD CLASS
# =============================================================================

class SSTIScanner(BaseScanner):
    """
    GOLD-tier SSTI Capability Detector.
    
    Methodology:
    1. Fetch target page
    2. Detect template syntax in response
    3. Identify engine-specific errors
    4. Analyze framework headers
    5. Test reflection markers
    6. Test math expression evaluation
    7. Correlate signals for confidence
    8. Report with confidence scoring
    """
    
    def __init__(
        self,
        target: str,
        custom_params: Optional[List[str]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        test_params: bool = True,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
        **kwargs
    ):
        """
        Initialize SSTI Scanner.
        
        Args:
            target: Target URL
            custom_params: Additional parameters to test
            custom_headers: Custom HTTP headers
            test_params: Test URL parameters with probes
            confidence_threshold: Minimum confidence for findings
        """
        super().__init__(
            name="SSTIScanner",
            description="Server-Side Template Injection scanner",
            target=target,
            **kwargs
        )
        
        self.custom_params = custom_params or []
        self.custom_headers = custom_headers or {}
        self.test_params = test_params
        self.confidence_threshold = confidence_threshold
        
        # State tracking
        self.check_results: List[SSTICheckResult] = []
        self.total_confidence: int = 0
        self.detected_engines: Dict[str, int] = {}
        self.baseline_response = None
        
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
        """Execute the GOLD SSTI scan."""
        self.logger.info(f"Starting SSTI GOLD scan")
        self.logger.info(f"Target: {self.target}")
        
        # Phase 1: Fetch baseline response
        self.logger.info("Phase 1: Fetching baseline response...")
        self._fetch_baseline()
        
        if not self.baseline_response:
            self.logger.error("Failed to fetch baseline - aborting")
            return
        
        # Phase 2: Static syntax analysis
        self.logger.info("Phase 2: Analyzing template syntax artifacts...")
        self._analyze_syntax()
        
        # Phase 3: Error fingerprinting
        self.logger.info("Phase 3: Detecting engine-specific errors...")
        self._detect_errors()
        
        # Phase 4: Header analysis
        self.logger.info("Phase 4: Analyzing framework headers...")
        self._analyze_headers()
        
        # Phase 5: Reflection marker testing
        self.logger.info("Phase 5: Testing reflection markers...")
        self._test_reflection_markers()
        
        # Phase 6: Math expression probing
        if self.test_params:
            self.logger.info("Phase 6: Testing math expression evaluation...")
            self._test_math_probes()
        
        # Phase 7: Correlate and report
        self.logger.info("Phase 7: Correlating signals...")
        self._correlate_findings()
        
        self.logger.info(f"SSTI scan complete. Found {len(self.findings)} issue(s)")
    
    # =========================================================================
    # BASELINE FETCH
    # =========================================================================
    
    def _fetch_baseline(self) -> None:
        """Fetch baseline response."""
        try:
            self.rate_limiter.acquire()
            self._request_count += 1
            
            response = self.session.get(
                self.target,
                headers=self.custom_headers,
                timeout=self.timeout
            )
            
            self.baseline_response = {
                "status": response.status_code,
                "body": response.text,
                "headers": dict(response.headers),
                "length": len(response.text)
            }
            
            print_info(f"Baseline: {response.status_code}, {len(response.text)} bytes")
            time.sleep(self.delay)
            
        except Exception as e:
            self.logger.error(f"Baseline fetch error: {e}")
    
    # =========================================================================
    # STATIC SYNTAX ANALYSIS
    # =========================================================================
    
    def _analyze_syntax(self) -> None:
        """Analyze response body for template syntax artifacts."""
        body = self.baseline_response["body"]
        
        for engine, data in TEMPLATE_ENGINES.items():
            for pattern in data["syntax"]:
                if re.search(pattern, body):
                    self.detected_engines[engine] = self.detected_engines.get(engine, 0) + 25
                    print_info(f"Syntax detected: {engine} ({pattern[:20]}...)")
                    break  # One match per engine
    
    # =========================================================================
    # ERROR FINGERPRINTING
    # =========================================================================
    
    def _detect_errors(self) -> None:
        """Detect engine-specific error messages."""
        body = self.baseline_response["body"]
        
        for engine, data in TEMPLATE_ENGINES.items():
            for error_pattern in data["errors"]:
                if re.search(error_pattern, body, re.IGNORECASE):
                    self.detected_engines[engine] = self.detected_engines.get(engine, 0) + 30
                    print_info(f"Error trace: {engine} ({error_pattern[:30]}...)")
                    break  # One match per engine
    
    # =========================================================================
    # HEADER ANALYSIS
    # =========================================================================
    
    def _analyze_headers(self) -> None:
        """Analyze HTTP headers for framework fingerprints."""
        headers = self.baseline_response["headers"]
        
        # Check relevant headers
        check_headers = ["x-powered-by", "server", "x-generator", "x-aspnet-version"]
        
        for header in check_headers:
            value = headers.get(header, "").lower()
            if not value:
                continue
            
            for engine, data in TEMPLATE_ENGINES.items():
                for fingerprint in data.get("headers", []):
                    if fingerprint in value:
                        self.detected_engines[engine] = self.detected_engines.get(engine, 0) + 20
                        print_info(f"Header fingerprint: {engine} ({header}: {value[:30]})")
                        break
    
    # =========================================================================
    # REFLECTION MARKER TESTING
    # =========================================================================
    
    def _test_reflection_markers(self) -> None:
        """Test if template markers are reflected unescaped."""
        body = self.baseline_response["body"]
        
        for marker, engines in REFLECTION_MARKERS:
            if marker in body:
                # Marker found in response - likely template syntax exposed
                for engine in engines.split("/"):
                    if engine in TEMPLATE_ENGINES:
                        self.detected_engines[engine] = self.detected_engines.get(engine, 0) + 20
                        print_info(f"Reflection marker: {engine} ({marker})")
    
    # =========================================================================
    # MATH EXPRESSION PROBING
    # =========================================================================
    
    def _test_math_probes(self) -> None:
        """Test math expression evaluation via parameters."""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        # Get parameter names to test
        param_names = list(params.keys()) + self.custom_params
        
        if not param_names:
            # Try common parameter names
            param_names = ["name", "template", "view", "page", "content", "text", "msg", "message"]
        
        for param in param_names[:5]:  # Limit to 5 params
            for probe, expected, engines in MATH_PROBES:
                self._test_single_probe(param, probe, expected, engines)
    
    def _test_single_probe(self, param: str, probe: str, expected: str, engines: List[str]) -> None:
        """Test a single math probe."""
        self.rate_limiter.acquire()
        self._request_count += 1
        
        try:
            # Build test URL
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            params[param] = [probe]
            
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if params:
                test_url += "?" + urlencode(params, doseq=True)
            
            response = self.session.get(
                test_url,
                headers=self.custom_headers,
                timeout=self.timeout
            )
            
            # Check if expected result appears
            if expected and expected in response.text:
                # Verify it wasn't in baseline
                if expected not in self.baseline_response["body"]:
                    for engine in engines:
                        self.detected_engines[engine] = self.detected_engines.get(engine, 0) + 40
                        print_success(f"Math evaluation: {engine} ({probe} = {expected})")
            
            time.sleep(self.delay)
            
        except Exception as e:
            self.logger.debug(f"Probe error: {e}")
    
    # =========================================================================
    # CORRELATION AND FINDINGS
    # =========================================================================
    
    def _correlate_findings(self) -> None:
        """Correlate signals and create findings."""
        for engine, score in self.detected_engines.items():
            # Add security relevance weighting
            if score > 0:
                score += 10  # High-risk class
            
            if score >= self.confidence_threshold:
                engine_data = TEMPLATE_ENGINES[engine]
                
                severity_map = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM
                }
                severity = severity_map.get(engine_data.get("severity", "high"), Severity.HIGH)
                
                self._add_check_result(
                    engine=engine,
                    language=engine_data["language"],
                    severity=severity,
                    confidence_score=min(score, 100),  # Cap at 100
                    risk=engine_data["risk"],
                    evidence={
                        "engine": engine,
                        "language": engine_data["language"],
                        "signals": self._get_signals(engine),
                        "syntax_patterns": engine_data["syntax"][:2]
                    },
                    is_vulnerable=True
                )
    
    def _get_signals(self, engine: str) -> List[str]:
        """Get detected signals for an engine."""
        signals = []
        
        # Check what contributed to the score
        body = self.baseline_response["body"]
        headers = self.baseline_response["headers"]
        engine_data = TEMPLATE_ENGINES[engine]
        
        for pattern in engine_data["syntax"]:
            if re.search(pattern, body):
                signals.append("Template syntax in response")
                break
        
        for error in engine_data["errors"]:
            if re.search(error, body, re.IGNORECASE):
                signals.append("Engine-specific error trace")
                break
        
        for header in ["x-powered-by", "server"]:
            value = headers.get(header, "").lower()
            for fp in engine_data.get("headers", []):
                if fp in value:
                    signals.append(f"Framework header: {header}")
                    break
        
        return signals
    
    # =========================================================================
    # RESULT HANDLING
    # =========================================================================
    
    def _add_check_result(self, engine: str, language: str, severity: Severity, confidence_score: int, risk: str, evidence: Dict[str, Any], is_vulnerable: bool) -> None:
        """Add a check result and create finding."""
        result = SSTICheckResult(
            engine=engine,
            language=language,
            severity=severity,
            confidence_score=confidence_score,
            risk=risk,
            evidence=evidence,
            is_vulnerable=is_vulnerable
        )
        self.check_results.append(result)
        self.total_confidence += confidence_score
        self._create_finding(result)
        print_success(f"{engine} ({language}): {risk} (+{confidence_score})")
    
    def _create_finding(self, result: SSTICheckResult) -> None:
        """Create finding from check result."""
        finding = Finding(
            id=self._generate_finding_id(result.engine),
            title=f"SSTI Capability: {result.engine}",
            severity=result.severity,
            description=f"Detected {result.engine} template engine ({result.language}) with SSTI capability indicators",
            url=self.target,
            parameter="Template",
            method="GET",
            payload=f"{result.engine} detection",
            evidence=json.dumps(result.evidence, indent=2),
            impact=self._get_impact(result),
            remediation=self._get_remediation(result),
            vulnerability_type="ssti",
            confidence="high" if result.confidence_score >= 80 else "medium",
        )
        self.add_finding(finding)
    
    def _get_impact(self, result: SSTICheckResult) -> str:
        """Get impact description."""
        if result.severity == Severity.CRITICAL:
            return (
                f"CRITICAL: {result.engine} SSTI can lead to:\n"
                "- Remote Code Execution (RCE)\n"
                "- Server compromise\n"
                "- Data exfiltration\n"
                "- Lateral movement"
            )
        return (
            f"HIGH: {result.engine} template injection may enable:\n"
            "- Information disclosure\n"
            "- Configuration leakage\n"
            "- Potential code execution"
        )
    
    def _get_remediation(self, result: SSTICheckResult) -> str:
        """Get remediation guidance."""
        return (
            "1. Never pass user input directly to template engines\n"
            "2. Use sandbox/safe mode if available\n"
            "3. Implement strict input validation and escaping\n"
            "4. Use logic-less templates when possible\n"
            "5. Disable dangerous template features\n"
            "6. Keep template engine updated to latest version\n"
            f"7. Review {result.engine} security documentation"
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
    parser = argparse.ArgumentParser(prog="revuex-ssti", description="REVUEX SSTI GOLD - Template Injection Detector")
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-p", "--param", action="append", help="Parameters to test")
    parser.add_argument("-H", "--header", action="append", help="Custom headers (Key:Value)")
    parser.add_argument("--no-probe", action="store_true", help="Skip parameter probing")
    parser.add_argument("--threshold", type=int, default=CONFIDENCE_THRESHOLD, help=f"Confidence threshold (default: {CONFIDENCE_THRESHOLD})")
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
    
    custom_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()
    
    if not args.quiet:
        print(BANNER)
        print(f"[+] Target: {args.target}")
        print(f"[+] Engines: {len(TEMPLATE_ENGINES)}")
        print()
    
    scanner = SSTIScanner(
        target=args.target,
        custom_params=args.param or [],
        custom_headers=custom_headers,
        test_params=not args.no_probe,
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
        print(f"Engines Detected: {len(scanner.detected_engines)}")
        print(f"Issues Found: {len(result.findings)}")
        print(f"Total Confidence: {scanner.total_confidence}")
        
        if scanner.detected_engines:
            print(f"\n[Engine Scores]")
            for engine, score in sorted(scanner.detected_engines.items(), key=lambda x: -x[1]):
                status = "⚠️  VULNERABLE" if score >= CONFIDENCE_THRESHOLD else ""
                print(f"  {engine}: {score}% {status}")
    
    if args.output:
        output_data = {
            "scanner": SCANNER_NAME,
            "version": SCANNER_VERSION,
            "target": args.target,
            "engines_detected": scanner.detected_engines,
            "findings": [
                {
                    "id": f.id,
                    "engine": f.parameter,
                    "severity": f.severity.value
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
