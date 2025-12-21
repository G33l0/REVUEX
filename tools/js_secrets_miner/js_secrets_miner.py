#!/usr/bin/env python3
"""
REVUEX JS-Secrets-Miner GOLD v1.0
=================================
10/10 Research-Grade JavaScript Secret & Trust-Leak Discovery Engine

Purpose:
- Discover real, security-relevant secrets in JavaScript
- Eliminate regex noise via structural + contextual analysis
- Infer ownership and impact without exploiting secrets
- Detect second-order (deferred) secret usage
- Produce bug-bounty ready, high-confidence findings

Techniques:
- JS File Discovery (script src, inline references)
- Esprima-Style Structural Parsing
- Secret Heuristic Analysis (keywords, entropy, length)
- Third-Party Provider Detection (AWS, Stripe, Google, GitHub, Slack)
- Contextual Validation (SERVER_SECRET_LEAK, THIRD_PARTY_KEY, CLIENT_TOKEN)
- Second-Order Correlation (sink pattern detection)
- Impact Classification (CRITICAL, HIGH, MEDIUM, LOW)
- Confidence Scoring (0-100)

Aligned with:
- REVUEX SQLi GOLD
- REVUEX XSS GOLD
- REVUEX IDOR GOLD
- REVUEX Subdomain-Hunter GOLD

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import re
import json
import math
import argparse
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
from urllib.parse import urljoin, urlparse
from collections import defaultdict
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

SCANNER_NAME = "JS Secrets Miner GOLD"
SCANNER_VERSION = "1.0.0"

BANNER = r"""
âââââââ âââââââââââ   ââââââ   ââââââââââââââ  âââ
âââââââââââââââââââ   ââââââ   âââââââââââââââââââ
ââââââââââââââ  âââ   ââââââ   âââââââââ   ââââââ 
ââââââââââââââ  ââââ âââââââ   âââââââââ   ââââââ 
âââ  âââââââââââ âââââââ âââââââââââââââââââââ âââ
âââ  âââââââââââ  âââââ   âââââââ âââââââââââ  âââ

JS-Secrets-Miner GOLD â Client-Side Trust Leak Intelligence
"""

# Confidence threshold for high-value findings
CONFIDENCE_THRESHOLD = 70

# Secret keyword indicators
SECRET_KEYWORDS = [
    "key", "token", "secret", "auth", "apikey",
    "access", "private", "credential", "passwd",
    "password", "api_key", "api_secret", "apiSecret",
    "accessToken", "access_token", "refreshToken",
    "refresh_token", "client_secret", "clientSecret",
    "bearer", "jwt", "oauth", "firebase", "supabase",
]

# Third-party API key prefixes
THIRD_PARTY_HINTS = {
    "AIza": "Google API",
    "sk_live": "Stripe Secret",
    "pk_live": "Stripe Public",
    "sk_test": "Stripe Test Secret",
    "pk_test": "Stripe Test Public",
    "AKIA": "AWS Access Key",
    "ASIA": "AWS Temporary Key",
    "ABIA": "AWS STS",
    "ACCA": "AWS",
    "ghp_": "GitHub Personal Token",
    "gho_": "GitHub OAuth Token",
    "ghu_": "GitHub User Token",
    "ghs_": "GitHub Server Token",
    "ghr_": "GitHub Refresh Token",
    "xox": "Slack Token",
    "xoxb": "Slack Bot Token",
    "xoxp": "Slack User Token",
    "xoxa": "Slack App Token",
    "xoxr": "Slack Refresh Token",
    "EAACEdEose0cBA": "Facebook Access Token",
    "sq0csp-": "Square OAuth Secret",
    "sq0atp-": "Square Access Token",
    "sk-": "OpenAI API Key",
    "SG.": "SendGrid API Key",
    "key-": "Mailgun API Key",
    "AC": "Twilio Account SID",
    "SK": "Twilio API Key",
    "shppa_": "Shopify Private App",
    "shpat_": "Shopify Access Token",
    "shpca_": "Shopify Custom App",
    "shpss_": "Shopify Shared Secret",
    "glpat-": "GitLab Personal Token",
    "dop_v1_": "DigitalOcean Token",
    "npm_": "NPM Token",
    "pypi-": "PyPI Token",
}

# Sink patterns indicating secret usage
SINK_PATTERNS = [
    r"Authorization\s*:",
    r"X-API-Key",
    r"X-Auth-Token",
    r"Bearer\s+",
    r"fetch\s*\(",
    r"axios\s*[\.\(]",
    r"XMLHttpRequest",
    r"WebSocket\s*\(",
    r"\.ajax\s*\(",
    r"\.post\s*\(",
    r"\.get\s*\(",
    r"headers\s*:",
    r"credentials\s*:",
]

# Secret category classification
class SecretCategory(Enum):
    SERVER_SECRET_LEAK = "server_secret_leak"
    THIRD_PARTY_KEY = "third_party_key"
    CLIENT_TOKEN = "client_token"
    PUBLIC_CONFIG = "public_config"


# Impact levels
class ImpactLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# =============================================================================
# UTILITIES
# =============================================================================

def sha1_hash(data: str) -> str:
    """Generate short SHA1 hash."""
    return hashlib.sha1(data.encode()).hexdigest()[:10]


def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs if p > 0)


# =============================================================================
# SECRET RESULT DATACLASS
# =============================================================================

@dataclass
class SecretResult:
    """Result for a discovered secret."""
    js_file: str
    variable: str
    value: str
    value_preview: str
    signals: List[str]
    category: SecretCategory
    provider: str
    second_order: bool
    impact: ImpactLevel
    confidence: int
    line_context: str


# =============================================================================
# JS DISCOVERY ENGINE
# =============================================================================

class JsDiscoveryEngine:
    """Discover JavaScript files from target."""
    
    def __init__(self, target: str, session, timeout: int = 8):
        self.target = target
        self.session = session
        self.timeout = timeout
        self.js_urls: Set[str] = set()
    
    def discover(self) -> Set[str]:
        """Discover all JS files from target."""
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            
            if response.status_code != 200:
                return self.js_urls
            
            # Script src discovery
            for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', response.text, re.I):
                full_url = urljoin(self.target, src)
                if full_url.endswith('.js') or '.js?' in full_url:
                    self.js_urls.add(full_url)
            
            # Inline JS second-order references
            for match in re.findall(r'(https?://[^\s"\'<>]+\.js(?:\?[^\s"\'<>]*)?)', response.text):
                self.js_urls.add(match)
            
            # Check for common JS paths
            base_url = f"{urlparse(self.target).scheme}://{urlparse(self.target).netloc}"
            common_paths = [
                "/static/js/main.js",
                "/js/app.js",
                "/assets/js/main.js",
                "/bundle.js",
                "/app.js",
                "/main.js",
            ]
            
            for path in common_paths:
                try:
                    test_url = urljoin(base_url, path)
                    test_resp = self.session.head(test_url, timeout=3)
                    if test_resp.status_code == 200:
                        self.js_urls.add(test_url)
                except:
                    pass
                    
        except Exception:
            pass
        
        return self.js_urls


# =============================================================================
# JS FETCHER
# =============================================================================

class JsFetcher:
    """Fetch and cache JavaScript files."""
    
    def __init__(self, session, timeout: int = 8):
        self.session = session
        self.timeout = timeout
        self.cache: Dict[str, Dict] = {}
    
    def get(self, url: str) -> Dict:
        """Fetch JS file and return data."""
        if url in self.cache:
            return self.cache[url]
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code != 200:
                return {}
            
            data = {
                "url": url,
                "body": response.text,
                "hash": sha1_hash(response.text),
                "size": len(response.text),
            }
            self.cache[url] = data
            return data
            
        except Exception:
            return {}


# =============================================================================
# ESPRIMA-STYLE PARSER (STRUCTURAL EXTRACTION)
# =============================================================================

class EsprimaStyleParser:
    """Extract variable assignments from JavaScript."""
    
    # Pattern for variable assignments with string values
    ASSIGN_RE = re.compile(
        r'(?:var|let|const)?\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']{6,})["\']',
        re.MULTILINE
    )
    
    # Pattern for object property assignments
    PROP_RE = re.compile(
        r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*["\']([^"\']{6,})["\']',
        re.MULTILINE
    )
    
    # Pattern for template literals
    TEMPLATE_RE = re.compile(
        r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*`([^`]{6,})`',
        re.MULTILINE
    )
    
    def extract_assignments(self, js: str) -> List[Dict]:
        """Extract all variable assignments with string values."""
        results = []
        
        # Regular assignments
        for var, val in self.ASSIGN_RE.findall(js):
            results.append({
                "var": var,
                "value": val,
                "type": "assignment"
            })
        
        # Object properties
        for var, val in self.PROP_RE.findall(js):
            results.append({
                "var": var,
                "value": val,
                "type": "property"
            })
        
        # Template literals
        for var, val in self.TEMPLATE_RE.findall(js):
            # Skip if contains ${} (dynamic)
            if "${" not in val:
                results.append({
                    "var": var,
                    "value": val,
                    "type": "template"
                })
        
        return results


# =============================================================================
# SECRET HEURISTIC ENGINE
# =============================================================================

class SecretHeuristicEngine:
    """Analyze potential secrets using heuristics."""
    
    def analyze(self, var: str, value: str) -> Dict:
        """Analyze a variable and value for secret indicators."""
        signals = []
        
        # Check for keyword match
        var_lower = var.lower()
        if any(k in var_lower for k in SECRET_KEYWORDS):
            signals.append("keyword")
        
        # Check entropy
        ent = calculate_entropy(value)
        if ent > 3.5:
            signals.append("entropy")
        
        # Check length
        if len(value) >= 16:
            signals.append("length")
        
        # Check for hex-like patterns
        if re.match(r'^[a-fA-F0-9]{16,}$', value):
            signals.append("hex_pattern")
        
        # Check for base64-like patterns
        if re.match(r'^[A-Za-z0-9+/=]{20,}$', value):
            signals.append("base64_pattern")
        
        # Check for third-party provider
        provider = ""
        for prefix, name in THIRD_PARTY_HINTS.items():
            if value.startswith(prefix):
                provider = name
                signals.append("third_party")
                break
        
        return {
            "signals": signals,
            "provider": provider,
            "entropy": ent,
        }


# =============================================================================
# CONTEXTUAL VALIDATOR
# =============================================================================

class ContextualValidator:
    """Classify secrets based on contextual signals."""
    
    def classify(self, signals: List[str], provider: str) -> SecretCategory:
        """Classify secret based on signals and provider."""
        if "third_party" in signals and provider:
            return SecretCategory.THIRD_PARTY_KEY
        
        if "keyword" in signals and "entropy" in signals:
            return SecretCategory.SERVER_SECRET_LEAK
        
        if "keyword" in signals:
            return SecretCategory.CLIENT_TOKEN
        
        return SecretCategory.PUBLIC_CONFIG


# =============================================================================
# SECOND-ORDER CORRELATION
# =============================================================================

class SecondOrderCorrelation:
    """Detect if secrets are used in dangerous sinks."""
    
    def detect(self, js: str, value: str) -> bool:
        """Check if value is used in API calls or auth headers."""
        for pattern in SINK_PATTERNS:
            if re.search(pattern, js, re.I) and value in js:
                # Check if value appears near the sink pattern
                for match in re.finditer(pattern, js, re.I):
                    start = max(0, match.start() - 500)
                    end = min(len(js), match.end() + 500)
                    context = js[start:end]
                    if value in context:
                        return True
        return False
    
    def get_sink_context(self, js: str, value: str) -> str:
        """Get the context around where the secret is used."""
        for pattern in SINK_PATTERNS:
            for match in re.finditer(pattern, js, re.I):
                start = max(0, match.start() - 100)
                end = min(len(js), match.end() + 100)
                context = js[start:end]
                if value in context:
                    return context.strip()
        return ""


# =============================================================================
# IMPACT CLASSIFIER
# =============================================================================

class ImpactClassifier:
    """Classify impact level of discovered secrets."""
    
    def classify(self, category: SecretCategory, second_order: bool, provider: str) -> ImpactLevel:
        """Determine impact level based on category and usage."""
        if category == SecretCategory.SERVER_SECRET_LEAK and second_order:
            return ImpactLevel.CRITICAL
        
        if category == SecretCategory.SERVER_SECRET_LEAK:
            return ImpactLevel.HIGH
        
        if category == SecretCategory.THIRD_PARTY_KEY:
            # Elevate if it's a sensitive provider
            sensitive_providers = ["AWS", "Stripe Secret", "OpenAI", "Twilio"]
            if any(sp in provider for sp in sensitive_providers):
                return ImpactLevel.HIGH
            return ImpactLevel.MEDIUM
        
        if category == SecretCategory.CLIENT_TOKEN:
            return ImpactLevel.LOW
        
        return ImpactLevel.INFO


# =============================================================================
# CONFIDENCE SCORER
# =============================================================================

class ConfidenceScorer:
    """Score secrets by confidence level."""
    
    def score(self, meta: Dict) -> int:
        """Calculate confidence score (0-100)."""
        score = 0
        
        # Entropy signal
        if "entropy" in meta.get("signals", []):
            score += 25
        
        # Keyword signal
        if "keyword" in meta.get("signals", []):
            score += 25
        
        # Third-party detection
        if "third_party" in meta.get("signals", []):
            score += 15
        
        # Pattern detection (hex, base64)
        if "hex_pattern" in meta.get("signals", []) or "base64_pattern" in meta.get("signals", []):
            score += 10
        
        # Second-order usage
        if meta.get("second_order"):
            score += 20
        
        # High impact
        impact = meta.get("impact", ImpactLevel.INFO)
        if impact in (ImpactLevel.HIGH, ImpactLevel.CRITICAL):
            score += 20
        elif impact == ImpactLevel.MEDIUM:
            score += 10
        
        return min(score, 100)


# =============================================================================
# JS SECRETS MINER GOLD CLASS
# =============================================================================

class JSSecretsMiner(BaseScanner):
    """
    GOLD-tier JS Secrets Miner with high-confidence discovery.
    
    Methodology:
    1. Discover JavaScript files from target
    2. Extract variable assignments (Esprima-style)
    3. Analyze secrets using heuristics
    4. Validate context and classify
    5. Detect second-order usage in sinks
    6. Classify impact level
    7. Score and filter by confidence
    
    Usage:
        miner = JSSecretsMiner(target="https://example.com")
        result = miner.run()
    """
    
    def __init__(
        self,
        target: str,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
        include_low_confidence: bool = False,
        **kwargs
    ):
        """
        Initialize JS Secrets Miner.
        
        Args:
            target: Target URL
            confidence_threshold: Minimum confidence for findings
            include_low_confidence: Include low confidence results
        """
        super().__init__(target=target, **kwargs)
        
        self.confidence_threshold = confidence_threshold
        self.include_low_confidence = include_low_confidence
        
        # Initialize engines
        self.discoverer = JsDiscoveryEngine(self.target, self.session, self.timeout)
        self.fetcher = JsFetcher(self.session, self.timeout)
        self.parser = EsprimaStyleParser()
        self.heuristic = SecretHeuristicEngine()
        self.validator = ContextualValidator()
        self.second_order = SecondOrderCorrelation()
        self.impact_classifier = ImpactClassifier()
        self.scorer = ConfidenceScorer()
        
        # Results
        self.secret_results: List[SecretResult] = []
        self.js_files_scanned: Set[str] = set()
        
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
        """Execute the GOLD JS secrets scan."""
        self.logger.info(f"Starting JS Secrets Miner GOLD on {self.target}")
        
        # Phase 1: Discover JS files
        self.logger.info("Phase 1: Discovering JavaScript files...")
        js_files = self.discoverer.discover()
        self.js_files_scanned = js_files
        self.logger.info(f"Found {len(js_files)} JavaScript file(s)")
        
        # Phase 2: Analyze each JS file
        self.logger.info("Phase 2: Analyzing JavaScript files for secrets...")
        
        for js_url in js_files:
            self.rate_limiter.acquire()
            self.request_count += 1
            
            js_data = self.fetcher.get(js_url)
            if not js_data:
                continue
            
            self.logger.debug(f"Analyzing: {js_url}")
            
            # Extract assignments
            assignments = self.parser.extract_assignments(js_data["body"])
            
            for assign in assignments:
                # Analyze with heuristics
                heuristics = self.heuristic.analyze(assign["var"], assign["value"])
                
                # Skip if not enough signals
                if len(heuristics["signals"]) < 2:
                    continue
                
                # Classify category
                category = self.validator.classify(
                    heuristics["signals"],
                    heuristics["provider"]
                )
                
                # Check second-order usage
                is_second_order = self.second_order.detect(
                    js_data["body"],
                    assign["value"]
                )
                
                # Classify impact
                impact = self.impact_classifier.classify(
                    category,
                    is_second_order,
                    heuristics["provider"]
                )
                
                # Calculate confidence
                meta = {
                    "signals": heuristics["signals"],
                    "second_order": is_second_order,
                    "impact": impact,
                }
                confidence = self.scorer.score(meta)
                
                # Get context
                line_context = self.second_order.get_sink_context(
                    js_data["body"],
                    assign["value"]
                ) if is_second_order else ""
                
                # Create result
                result = SecretResult(
                    js_file=js_url,
                    variable=assign["var"],
                    value=assign["value"],
                    value_preview=assign["value"][:6] + "..." if len(assign["value"]) > 6 else assign["value"],
                    signals=heuristics["signals"],
                    category=category,
                    provider=heuristics["provider"],
                    second_order=is_second_order,
                    impact=impact,
                    confidence=confidence,
                    line_context=line_context,
                )
                self.secret_results.append(result)
                
                # Create finding if above threshold
                if confidence >= self.confidence_threshold or self.include_low_confidence:
                    self._create_finding(result)
            
            time.sleep(self.delay)
        
        self.logger.info(f"JS Secrets Miner complete. Found {len(self.findings)} high-confidence secrets")
    
    def _create_finding(self, result: SecretResult) -> None:
        """Create finding from secret result."""
        # Map impact to severity
        severity_map = {
            ImpactLevel.CRITICAL: Severity.CRITICAL,
            ImpactLevel.HIGH: Severity.HIGH,
            ImpactLevel.MEDIUM: Severity.MEDIUM,
            ImpactLevel.LOW: Severity.LOW,
            ImpactLevel.INFO: Severity.LOW,
        }
        severity = severity_map.get(result.impact, Severity.MEDIUM)
        
        # Build title
        if result.provider:
            title = f"Exposed {result.provider} in JavaScript"
        else:
            title = f"Exposed {result.category.value.replace('_', ' ').title()} in JavaScript"
        
        if result.second_order:
            title += " (Active Usage Detected)"
        
        # Build evidence
        evidence_parts = [
            f"Variable: {result.variable}",
            f"Value Preview: {result.value_preview}",
            f"Signals: {', '.join(result.signals)}",
            f"Category: {result.category.value}",
            f"Confidence: {result.confidence}%",
        ]
        if result.provider:
            evidence_parts.append(f"Provider: {result.provider}")
        if result.second_order:
            evidence_parts.append("Second-Order: Active sink usage detected")
        
        finding = Finding(
            id=self._generate_finding_id(f"js_secret_{result.variable}"),
            title=title,
            severity=severity,
            description=(
                f"Sensitive secret or API key exposed in JavaScript file. "
                f"Variable '{result.variable}' contains what appears to be a "
                f"{result.category.value.replace('_', ' ')}."
                f"{' This secret is actively used in API calls or authentication headers.' if result.second_order else ''}"
            ),
            url=result.js_file,
            parameter=result.variable,
            method="GET",
            payload=result.value_preview,
            evidence=" | ".join(evidence_parts),
            impact=self._get_impact(result),
            remediation=self._get_remediation(result),
            vulnerability_type="secrets_exposure",
            confidence="high" if result.confidence >= 80 else "medium",
        )
        self.add_finding(finding)
        self._print_result(result)
    
    def _get_impact(self, result: SecretResult) -> str:
        """Get impact description based on result."""
        if result.impact == ImpactLevel.CRITICAL:
            return (
                "CRITICAL: Server-side secret exposed and actively used:\n"
                "- Full API access with exposed credentials\n"
                "- Potential data breach\n"
                "- Account takeover possible\n"
                "- Financial loss if payment keys exposed"
            )
        elif result.impact == ImpactLevel.HIGH:
            return (
                "HIGH: Sensitive secret exposed in client-side code:\n"
                "- API abuse using exposed keys\n"
                "- Unauthorized access to third-party services\n"
                "- Potential data exfiltration"
            )
        elif result.impact == ImpactLevel.MEDIUM:
            return (
                "MEDIUM: Third-party API key exposed:\n"
                "- Service abuse possible\n"
                "- Rate limit exhaustion\n"
                "- Cost implications for paid APIs"
            )
        else:
            return (
                "LOW: Client token or configuration exposed:\n"
                "- Limited impact\n"
                "- May enable further enumeration"
            )
    
    def _get_remediation(self, result: SecretResult) -> str:
        """Get remediation based on result."""
        base_remediation = (
            "1. Immediately rotate the exposed secret/key\n"
            "2. Remove secrets from client-side JavaScript\n"
            "3. Use environment variables on the server\n"
            "4. Implement proper API key restrictions\n"
            "5. Use backend proxy for API calls requiring secrets\n"
        )
        
        if result.provider:
            base_remediation += f"\n6. Review {result.provider} dashboard for unauthorized usage"
        
        if result.second_order:
            base_remediation += "\n7. Audit all endpoints using this credential"
        
        return base_remediation
    
    def _generate_finding_id(self, context: str) -> str:
        """Generate unique finding ID."""
        data = f"{self.target}:{context}:{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    def _print_result(self, result: SecretResult) -> None:
        """Print secret result."""
        impact_colors = {
            ImpactLevel.CRITICAL: "\033[95m",
            ImpactLevel.HIGH: "\033[91m",
            ImpactLevel.MEDIUM: "\033[93m",
            ImpactLevel.LOW: "\033[94m",
        }
        color = impact_colors.get(result.impact, "")
        reset = "\033[0m"
        
        print_success(f"[{result.confidence}%] {result.variable}")
        print(f"  {color}Impact: {result.impact.value.upper()}{reset}")
        print(f"  Category: {result.category.value}")
        print(f"  Value: {result.value_preview}")
        if result.provider:
            print(f"  Provider: {result.provider}")
        if result.second_order:
            print(f"  Second-Order: YES (active usage)")
        print()


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="revuex-js-secrets",
        description="REVUEX JS-Secrets-Miner GOLD - Client-Side Trust Leak Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s -t https://example.com
    %(prog)s -t https://example.com --threshold 50 -v
    %(prog)s -t https://example.com -o secrets.json

Author: REVUEX Team
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("--threshold", type=int, default=CONFIDENCE_THRESHOLD,
                        help=f"Confidence threshold (default: {CONFIDENCE_THRESHOLD})")
    parser.add_argument("--include-low", action="store_true",
                        help="Include low confidence results")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--delay", type=float, default=0.3, help="Request delay")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout")
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
    
    miner = JSSecretsMiner(
        target=args.target,
        confidence_threshold=args.threshold,
        include_low_confidence=args.include_low,
        delay=args.delay,
        timeout=args.timeout,
        verbose=args.verbose,
    )
    
    result = miner.run()
    
    if not args.quiet:
        print(f"\n{'='*60}")
        print("SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"Target: {args.target}")
        print(f"Duration: {result.duration_seconds:.2f}s")
        print(f"JS Files Scanned: {len(miner.js_files_scanned)}")
        print(f"Secrets Found: {len(miner.secret_results)}")
        print(f"High-Confidence: {len(result.findings)}")
        
        # Summary by impact
        critical = sum(1 for r in miner.secret_results if r.impact == ImpactLevel.CRITICAL)
        high = sum(1 for r in miner.secret_results if r.impact == ImpactLevel.HIGH)
        medium = sum(1 for r in miner.secret_results if r.impact == ImpactLevel.MEDIUM)
        
        print(f"\n[Impact Summary]")
        print(f"  Critical: {critical}")
        print(f"  High: {high}")
        print(f"  Medium: {medium}")
    
    if args.output:
        output_data = {
            "scanner": "REVUEX JS Secrets Miner GOLD",
            "version": SCANNER_VERSION,
            "target": args.target,
            "scan_id": result.scan_id,
            "duration": result.duration_seconds,
            "js_files_scanned": list(miner.js_files_scanned),
            "results": [
                {
                    "js_file": r.js_file,
                    "variable": r.variable,
                    "value_preview": r.value_preview,
                    "signals": r.signals,
                    "category": r.category.value,
                    "provider": r.provider,
                    "second_order": r.second_order,
                    "impact": r.impact.value,
                    "confidence": r.confidence,
                }
                for r in miner.secret_results
            ],
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "variable": f.parameter,
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
