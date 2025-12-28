#!/usr/bin/env python3
"""
REVUEX Subdomain-Hunter GOLD v4.1
=================================
Enhanced with subdomain list export for pipeline chaining.

New in v4.1:
- --export-subs: Export subdomain list to text file (one per line)
- --export-format: Choose txt, json, or urls format
- Auto-export to reports/ directory
- Pipeline-friendly output

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import re
import ssl
import json
import socket
import hashlib
import argparse
import time
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
from urllib.parse import urlparse
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

SCANNER_NAME = "Subdomain Hunter GOLD"
SCANNER_VERSION = "4.1.0"

BANNER = r"""
âââââââ âââââââââââ   ââââââ   ââââââââââââââ  âââ
âââââââââââââââââââ   ââââââ   âââââââââââââââââââ
ââââââââââââââ  âââ   ââââââ   âââââââââ   ââââââ 
ââââââââââââââ  ââââ âââââââ   âââââââââ   ââââââ 
âââ  âââââââââââ âââââââ âââââââââââââââââââââ âââ
âââ  âââââââââââ  âââââ   âââââââ âââââââââââ  âââ

Subdomain-Hunter GOLD v4.1 - Pipeline-Ready Recon
"""

# Confidence threshold for high-value findings
CONFIDENCE_THRESHOLD = 70

# Known subdomain takeover patterns
KNOWN_TAKEOVER_PATTERNS = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "amazonaws.com": "AWS S3",
    "azurewebsites.net": "Azure",
    "cloudfront.net": "CloudFront",
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3",
    "zendesk.com": "Zendesk",
    "shopify.com": "Shopify",
    "fastly.net": "Fastly",
    "ghost.io": "Ghost",
    "helpjuice.com": "Helpjuice",
    "helpscoutdocs.com": "HelpScout",
    "pantheon.io": "Pantheon",
    "readme.io": "ReadMe",
    "surge.sh": "Surge",
    "bitbucket.io": "Bitbucket",
    "ghost.org": "Ghost",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "pages.dev": "Cloudflare Pages",
    "fly.dev": "Fly.io",
    "render.com": "Render",
}

# Sensitive subdomain keywords
SENSITIVE_KEYWORDS = [
    "admin", "dev", "stage", "staging", "test", "testing",
    "internal", "api", "graphql", "dashboard", "monitor",
    "jenkins", "gitlab", "jira", "confluence", "vpn",
    "mail", "smtp", "pop", "imap", "ftp", "sftp",
    "db", "database", "mysql", "postgres", "mongo", "redis",
    "backup", "bak", "old", "legacy", "beta", "alpha",
    "secret", "private", "corp", "intranet", "extranet",
    "uat", "qa", "preprod", "pre-prod", "sandbox",
]

# Ownership classification
class OwnershipType(Enum):
    OWNED = "owned"
    THIRD_PARTY = "third_party"
    DANGLING = "dangling"
    UNKNOWN = "unknown"


# =============================================================================
# UTILITIES
# =============================================================================

def sha1_hash(data: str) -> str:
    """Generate short SHA1 hash."""
    return hashlib.sha1(data.encode()).hexdigest()[:8]


def resolve_dns(domain: str) -> bool:
    """Check if domain resolves via DNS."""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return False


# =============================================================================
# SUBDOMAIN RESULT DATACLASS
# =============================================================================

@dataclass
class SubdomainResult:
    """Result for a discovered subdomain."""
    subdomain: str
    sources: Set[str]
    ownership: OwnershipType
    provider: str
    resolves: bool
    risk: str
    service: str
    trust_boundary_issue: bool
    confidence: int
    evidence: Dict[str, Any]


# =============================================================================
# BASELINE PROFILER
# =============================================================================

class BaselineProfiler:
    """Capture baseline profile of the main domain."""
    
    def __init__(self, domain: str, session):
        self.domain = domain
        self.session = session
        self.profile = {}
    
    def capture(self, timeout: int = 8) -> Dict:
        """Capture baseline response characteristics."""
        url = f"https://{self.domain}"
        
        try:
            response = self.session.get(url, timeout=timeout, allow_redirects=True)
            
            self.profile = {
                "status": response.status_code,
                "headers": dict(response.headers),
                "server": response.headers.get("Server", ""),
                "length": len(response.text),
                "hash": sha1_hash(response.text[:2000]),
                "technologies": self._detect_technologies(response),
            }
        except Exception as e:
            self.profile = {"error": str(e)}
        
        return self.profile
    
    def _detect_technologies(self, response) -> List[str]:
        """Basic technology detection from headers."""
        techs = []
        headers = response.headers
        
        if "X-Powered-By" in headers:
            techs.append(headers["X-Powered-By"])
        if "Server" in headers:
            techs.append(headers["Server"])
        if "X-AspNet-Version" in headers:
            techs.append("ASP.NET")
        if "X-Drupal" in headers:
            techs.append("Drupal")
        
        return techs


# =============================================================================
# ENUMERATION ENGINE
# =============================================================================

class EnumerationEngine:
    """Multi-source subdomain enumeration."""
    
    def __init__(self, domain: str, session, timeout: int = 8):
        self.domain = domain
        self.session = session
        self.timeout = timeout
        self.sources = defaultdict(set)
    
    def from_ct_logs(self) -> None:
        """Enumerate from Certificate Transparency logs via crt.sh."""
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code != 200:
                return
            
            for entry in response.json():
                name_value = entry.get("name_value", "")
                for subdomain in name_value.splitlines():
                    subdomain = subdomain.strip().lower()
                    # Remove wildcard prefix
                    if subdomain.startswith("*."):
                        subdomain = subdomain[2:]
                    if subdomain.endswith(self.domain) and subdomain != self.domain:
                        self.sources[subdomain].add("ct_logs")
        except Exception:
            pass
    
    def from_html_js(self) -> None:
        """Extract subdomains from HTML/JS content."""
        url = f"https://{self.domain}"
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            # Find all URLs in the response
            url_pattern = r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.)*' + re.escape(self.domain)
            matches = re.findall(r'https?://([a-zA-Z0-9\.-]+)', response.text)
            
            for match in matches:
                match = match.lower()
                if match.endswith(self.domain) and match != self.domain:
                    self.sources[match].add("html_js")
        except Exception:
            pass
    
    def from_dns_common(self) -> None:
        """Check common subdomain prefixes via DNS."""
        common_prefixes = [
            "www", "mail", "ftp", "api", "dev", "staging", "admin",
            "blog", "shop", "app", "m", "mobile", "cdn", "assets",
        ]
        
        for prefix in common_prefixes:
            subdomain = f"{prefix}.{self.domain}"
            if resolve_dns(subdomain):
                self.sources[subdomain].add("dns_common")
    
    def run(self) -> Dict[str, Set[str]]:
        """Run all enumeration techniques."""
        self.from_ct_logs()
        self.from_html_js()
        self.from_dns_common()
        return dict(self.sources)


# =============================================================================
# CORRELATION ENGINE
# =============================================================================

class CorrelationEngine:
    """Filter subdomains by multi-source correlation."""
    
    def filter(self, sources: Dict[str, Set[str]], min_sources: int = 1) -> Dict[str, Set[str]]:
        """Filter subdomains appearing in multiple sources."""
        return {k: v for k, v in sources.items() if len(v) >= min_sources}


# =============================================================================
# OWNERSHIP INFERENCE
# =============================================================================

class OwnershipInference:
    """Classify subdomain ownership and detect takeover potential."""
    
    def classify(self, subdomain: str) -> Dict:
        """Classify ownership of a subdomain."""
        info = {
            "resolves": False,
            "ownership": OwnershipType.UNKNOWN,
            "provider": "",
            "takeover_risk": False,
        }
        
        info["resolves"] = resolve_dns(subdomain)
        
        # Check for known third-party patterns
        for pattern, provider in KNOWN_TAKEOVER_PATTERNS.items():
            if pattern in subdomain:
                info["ownership"] = OwnershipType.THIRD_PARTY
                info["provider"] = provider
                
                # If third-party but doesn't resolve = potential takeover
                if not info["resolves"]:
                    info["takeover_risk"] = True
                
                return info
        
        # Classify based on resolution
        if not info["resolves"]:
            info["ownership"] = OwnershipType.DANGLING
        else:
            info["ownership"] = OwnershipType.OWNED
        
        return info


# =============================================================================
# SERVICE FINGERPRINT
# =============================================================================

class ServiceFingerprint:
    """Fingerprint services running on subdomains."""
    
    def __init__(self, session, timeout: int = 8):
        self.session = session
        self.timeout = timeout
    
    def analyze(self, subdomain: str) -> Dict:
        """Analyze service running on subdomain."""
        result = {
            "service": "unknown",
            "risk": "low",
            "status_code": 0,
            "title": "",
        }
        
        try:
            response = self.session.get(
                f"https://{subdomain}",
                timeout=self.timeout,
                allow_redirects=True
            )
            result["status_code"] = response.status_code
            
            # Extract title
            title_match = re.search(r'<title>([^<]+)</title>', response.text, re.I)
            if title_match:
                result["title"] = title_match.group(1).strip()[:100]
            
            # Check for sensitive keywords
            text_lower = response.text.lower()
            subdomain_lower = subdomain.lower()
            
            for keyword in SENSITIVE_KEYWORDS:
                if keyword in subdomain_lower or keyword in text_lower:
                    result["risk"] = "high"
                    result["service"] = keyword
                    break
            
            # Check for login pages
            if any(x in text_lower for x in ["login", "sign in", "password", "authenticate"]):
                result["risk"] = "high"
                result["service"] = "login_portal"
            
        except Exception:
            pass
        
        return result


# =============================================================================
# SECOND-ORDER DISCOVERY
# =============================================================================

class SecondOrderDiscovery:
    """Discover additional subdomains from discovered ones."""
    
    def __init__(self, session, timeout: int = 8):
        self.session = session
        self.timeout = timeout
    
    def extract(self, subdomain: str, root_domain: str) -> Set[str]:
        """Extract new subdomains from a discovered subdomain."""
        discovered = set()
        
        try:
            response = self.session.get(
                f"https://{subdomain}",
                timeout=self.timeout
            )
            
            # Find subdomains in the response
            pattern = r'[a-zA-Z0-9][-a-zA-Z0-9]*\.' + re.escape(root_domain)
            matches = re.findall(pattern, response.text)
            
            for match in matches:
                full_subdomain = match.lower()
                if full_subdomain != subdomain and full_subdomain != root_domain:
                    discovered.add(full_subdomain)
                    
        except Exception:
            pass
        
        return discovered


# =============================================================================
# TRUST BOUNDARY ANALYZER
# =============================================================================

class TrustBoundaryAnalyzer:
    """Analyze trust boundary issues (CORS, cookies)."""
    
    def __init__(self, session, timeout: int = 8):
        self.session = session
        self.timeout = timeout
    
    def analyze(self, subdomain: str) -> Dict:
        """Check for trust boundary misconfigurations."""
        result = {
            "has_issue": False,
            "cors_wildcard": False,
            "cookie_domain_wide": False,
            "details": [],
        }
        
        try:
            response = self.session.get(
                f"https://{subdomain}",
                timeout=self.timeout
            )
            
            # Check CORS
            cors = response.headers.get("Access-Control-Allow-Origin", "")
            if cors == "*":
                result["has_issue"] = True
                result["cors_wildcard"] = True
                result["details"].append("CORS allows all origins (*)")
            
            # Check cookies
            cookies = response.headers.get("Set-Cookie", "")
            if "Domain=." in cookies:
                result["has_issue"] = True
                result["cookie_domain_wide"] = True
                result["details"].append("Cookie set with wide domain scope")
                
        except Exception:
            pass
        
        return result


# =============================================================================
# CONFIDENCE SCORER
# =============================================================================

class ConfidenceScorer:
    """Score subdomain findings by confidence level."""
    
    def score(self, meta: Dict) -> int:
        """Calculate confidence score (0-100)."""
        score = 0
        
        # Multiple sources = higher confidence
        sources = meta.get("sources", 1)
        if sources >= 3:
            score += 35
        elif sources >= 2:
            score += 30
        else:
            score += 15
        
        # Ownership classification
        ownership = meta.get("ownership", OwnershipType.UNKNOWN)
        if ownership == OwnershipType.DANGLING:
            score += 25  # Dangling = potential takeover
        elif ownership == OwnershipType.THIRD_PARTY:
            score += 20
        elif ownership == OwnershipType.OWNED:
            score += 15
        
        # Risk level
        if meta.get("risk") == "high":
            score += 20
        elif meta.get("risk") == "medium":
            score += 10
        
        # Trust boundary issues
        if meta.get("trust_boundary"):
            score += 15
        
        # Takeover risk
        if meta.get("takeover_risk"):
            score += 10
        
        return min(score, 100)


# =============================================================================
# SUBDOMAIN EXPORTER (NEW IN v4.1)
# =============================================================================

class SubdomainExporter:
    """Export subdomains in various formats for pipeline chaining."""
    
    def __init__(self, domain: str, subdomains: Dict[str, Set[str]], results: List[SubdomainResult]):
        self.domain = domain
        self.subdomains = subdomains
        self.results = results
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def export_txt(self, filepath: str, resolving_only: bool = False) -> str:
        """Export subdomains as plain text (one per line)."""
        subs = self._get_subdomain_list(resolving_only)
        
        with open(filepath, 'w') as f:
            for sub in sorted(subs):
                f.write(f"{sub}\n")
        
        return filepath
    
    def export_urls(self, filepath: str, resolving_only: bool = True) -> str:
        """Export as full URLs (https://)."""
        subs = self._get_subdomain_list(resolving_only)
        
        with open(filepath, 'w') as f:
            for sub in sorted(subs):
                f.write(f"https://{sub}\n")
        
        return filepath
    
    def export_json_simple(self, filepath: str) -> str:
        """Export as simple JSON array."""
        subs = list(self.subdomains.keys())
        
        with open(filepath, 'w') as f:
            json.dump(sorted(subs), f, indent=2)
        
        return filepath
    
    def export_detailed_json(self, filepath: str) -> str:
        """Export detailed JSON with metadata."""
        data = {
            "scanner": "REVUEX Subdomain Hunter GOLD",
            "version": SCANNER_VERSION,
            "domain": self.domain,
            "timestamp": self.timestamp,
            "total_found": len(self.subdomains),
            "subdomains": {
                "all": sorted(self.subdomains.keys()),
                "resolving": [r.subdomain for r in self.results if r.resolves],
                "high_risk": [r.subdomain for r in self.results if r.risk == "high"],
                "dangling": [r.subdomain for r in self.results if r.ownership == OwnershipType.DANGLING],
            },
            "results": [
                {
                    "subdomain": r.subdomain,
                    "sources": list(r.sources),
                    "ownership": r.ownership.value,
                    "resolves": r.resolves,
                    "risk": r.risk,
                    "confidence": r.confidence,
                }
                for r in self.results
            ]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        return filepath
    
    def _get_subdomain_list(self, resolving_only: bool) -> List[str]:
        """Get subdomain list with optional filtering."""
        if resolving_only:
            return [r.subdomain for r in self.results if r.resolves]
        return list(self.subdomains.keys())
    
    def auto_export(self, output_dir: str = "reports") -> Dict[str, str]:
        """Auto-export in all formats to reports directory."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        base_name = f"subdomains_{self.domain.replace('.', '_')}_{self.timestamp}"
        
        exports = {}
        
        # Plain text list (all)
        txt_path = f"{output_dir}/{base_name}.txt"
        self.export_txt(txt_path, resolving_only=False)
        exports["txt_all"] = txt_path
        
        # Plain text list (resolving only)
        txt_live_path = f"{output_dir}/{base_name}_live.txt"
        self.export_txt(txt_live_path, resolving_only=True)
        exports["txt_live"] = txt_live_path
        
        # URLs (resolving only)
        urls_path = f"{output_dir}/{base_name}_urls.txt"
        self.export_urls(urls_path, resolving_only=True)
        exports["urls"] = urls_path
        
        # Detailed JSON
        json_path = f"{output_dir}/{base_name}.json"
        self.export_detailed_json(json_path)
        exports["json"] = json_path
        
        return exports


# =============================================================================
# SUBDOMAIN HUNTER GOLD CLASS
# =============================================================================

class SubdomainHunter(BaseScanner):
    """
    GOLD-tier Subdomain Hunter with high-confidence discovery.
    
    Methodology:
    1. Capture baseline profile of main domain
    2. Enumerate from multiple passive sources
    3. Correlate findings across sources
    4. Classify ownership and takeover risk
    5. Fingerprint services
    6. Discover second-order subdomains
    7. Analyze trust boundaries
    8. Score and filter by confidence
    
    Usage:
        hunter = SubdomainHunter(domain="example.com")
        result = hunter.run()
    """
    
    def __init__(
        self,
        domain: str,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
        enable_second_order: bool = True,
        min_sources: int = 1,
        **kwargs
    ):
        """
        Initialize Subdomain Hunter.
        
        Args:
            domain: Target root domain
            confidence_threshold: Minimum confidence for findings
            enable_second_order: Enable second-order discovery
            min_sources: Minimum sources for correlation
        """
        # Use domain as target for BaseScanner
        super().__init__(
            name="SubdomainHunter",
            description="Subdomain enumeration and discovery",
            target=f"https://{domain}",
            **kwargs
        )
        
        self.domain = domain.lower().strip()
        self.confidence_threshold = confidence_threshold
        self.enable_second_order = enable_second_order
        self.min_sources = min_sources
        
        # Initialize engines
        self.baseline = BaselineProfiler(self.domain, self.session)
        self.enumerator = EnumerationEngine(self.domain, self.session, self.timeout)
        self.correlator = CorrelationEngine()
        self.ownership = OwnershipInference()
        self.fingerprint = ServiceFingerprint(self.session, self.timeout)
        self.second_order = SecondOrderDiscovery(self.session, self.timeout)
        self.trust = TrustBoundaryAnalyzer(self.session, self.timeout)
        self.scorer = ConfidenceScorer()
        
        # Results
        self.subdomain_results: List[SubdomainResult] = []
        self.all_subdomains: Dict[str, Set[str]] = {}
        
        # Exporter (initialized after scan)
        self.exporter: Optional[SubdomainExporter] = None
        
        # Scanner info
        self.scanner_name = SCANNER_NAME
        self.scanner_version = SCANNER_VERSION
    
    def _validate_target(self) -> bool:
        """Validate domain is accessible."""
        try:
            response = self.session.get(
                f"https://{self.domain}",
                timeout=self.timeout
            )
            return response.status_code < 500
        except Exception:
            # Try HTTP if HTTPS fails
            try:
                response = self.session.get(
                    f"http://{self.domain}",
                    timeout=self.timeout
                )
                return response.status_code < 500
            except:
                return False
    
    def scan(self) -> None:
        """Execute the GOLD subdomain hunt."""
        self.logger.info(f"Starting Subdomain Hunter GOLD on {self.domain}")
        
        # Phase 1: Capture baseline
        self.logger.info("Phase 1: Capturing baseline profile...")
        baseline_profile = self.baseline.capture(self.timeout)
        
        # Phase 2: Enumerate subdomains
        self.logger.info("Phase 2: Enumerating subdomains...")
        raw_subdomains = self.enumerator.run()
        self.logger.info(f"Found {len(raw_subdomains)} raw subdomains")
        
        # Phase 3: Correlate
        self.logger.info("Phase 3: Correlating across sources...")
        correlated = self.correlator.filter(raw_subdomains, self.min_sources)
        self.logger.info(f"Correlated to {len(correlated)} subdomains")
        
        # Store all subdomains
        self.all_subdomains = raw_subdomains
        
        # Phase 4: Analyze each subdomain
        self.logger.info("Phase 4: Analyzing subdomains...")
        
        for subdomain, sources in correlated.items():
            self.rate_limiter.acquire()
            self._request_count += 1
            
            # Ownership classification
            own_info = self.ownership.classify(subdomain)
            
            # Service fingerprinting
            svc_info = self.fingerprint.analyze(subdomain)
            
            # Trust boundary analysis
            trust_info = self.trust.analyze(subdomain)
            
            # Build metadata
            meta = {
                "subdomain": subdomain,
                "sources": len(sources),
                "ownership": own_info["ownership"],
                "provider": own_info.get("provider", ""),
                "takeover_risk": own_info.get("takeover_risk", False),
                "risk": svc_info["risk"],
                "service": svc_info["service"],
                "trust_boundary": trust_info["has_issue"],
            }
            
            # Calculate confidence
            confidence = self.scorer.score(meta)
            
            # Create result
            result = SubdomainResult(
                subdomain=subdomain,
                sources=sources,
                ownership=own_info["ownership"],
                provider=own_info.get("provider", ""),
                resolves=own_info["resolves"],
                risk=svc_info["risk"],
                service=svc_info["service"],
                trust_boundary_issue=trust_info["has_issue"],
                confidence=confidence,
                evidence={
                    "sources": list(sources),
                    "service_info": svc_info,
                    "trust_info": trust_info,
                    "ownership_info": own_info,
                }
            )
            self.subdomain_results.append(result)
            
            # Create finding if above threshold
            if confidence >= self.confidence_threshold:
                self._create_finding(result)
            
            time.sleep(self.delay)
        
        # Phase 5: Second-order discovery
        if self.enable_second_order:
            self.logger.info("Phase 5: Second-order discovery...")
            self._run_second_order_discovery()
        
        # Initialize exporter
        self.exporter = SubdomainExporter(self.domain, self.all_subdomains, self.subdomain_results)
        
        self.logger.info(f"Subdomain Hunter complete. Found {len(self.findings)} high-confidence subdomains")
    
    def _run_second_order_discovery(self) -> None:
        """Discover additional subdomains from discovered ones."""
        high_value = [r for r in self.subdomain_results if r.confidence >= 50]
        
        for result in high_value[:10]:  # Limit for speed
            new_subs = self.second_order.extract(result.subdomain, self.domain)
            
            for new_sub in new_subs:
                if new_sub not in self.all_subdomains:
                    self.all_subdomains[new_sub] = {"second_order"}
                    self.logger.debug(f"Second-order discovery: {new_sub}")
    
    def _create_finding(self, result: SubdomainResult) -> None:
        """Create finding from subdomain result."""
        # Determine severity
        if result.ownership == OwnershipType.DANGLING or result.evidence.get("ownership_info", {}).get("takeover_risk"):
            severity = Severity.CRITICAL
            title = f"Subdomain Takeover Risk: {result.subdomain}"
        elif result.risk == "high":
            severity = Severity.HIGH
            title = f"High-Risk Subdomain: {result.subdomain}"
        elif result.trust_boundary_issue:
            severity = Severity.HIGH
            title = f"Trust Boundary Issue: {result.subdomain}"
        else:
            severity = Severity.MEDIUM
            title = f"Discovered Subdomain: {result.subdomain}"
        
        # Build evidence string
        evidence_parts = [
            f"Sources: {', '.join(result.sources)}",
            f"Ownership: {result.ownership.value}",
            f"Resolves: {result.resolves}",
            f"Risk: {result.risk}",
            f"Confidence: {result.confidence}%",
        ]
        if result.provider:
            evidence_parts.append(f"Provider: {result.provider}")
        if result.service and result.service != "unknown":
            evidence_parts.append(f"Service: {result.service}")
        if result.trust_boundary_issue:
            evidence_parts.append("Trust boundary issue detected")
        
        finding = Finding(
            id=self._generate_finding_id(result.subdomain),
            title=title,
            severity=severity,
            description=(
                f"Discovered subdomain '{result.subdomain}' with confidence score {result.confidence}%. "
                f"Ownership classified as {result.ownership.value}."
                f"{' This subdomain may be vulnerable to takeover.' if result.ownership == OwnershipType.DANGLING else ''}"
            ),
            url=f"https://{result.subdomain}",
            parameter="subdomain",
            method="GET",
            payload=result.subdomain,
            evidence=" | ".join(evidence_parts),
            impact=self._get_impact(result),
            remediation=self._get_remediation(result),
            vulnerability_type="subdomain",
            confidence="high" if result.confidence >= 80 else "medium",
        )
        self.add_finding(finding)
        self._print_result(result)
    
    def _get_impact(self, result: SubdomainResult) -> str:
        """Get impact description based on result."""
        if result.ownership == OwnershipType.DANGLING:
            return (
                "CRITICAL: Dangling subdomain vulnerable to takeover:\n"
                "- Attacker can claim the subdomain\n"
                "- Phishing attacks using trusted domain\n"
                "- Cookie theft if same-site cookies used\n"
                "- Bypass security controls"
            )
        elif result.risk == "high":
            return (
                "HIGH: Sensitive subdomain discovered:\n"
                "- Potential access to internal systems\n"
                "- Information disclosure\n"
                "- Expanded attack surface"
            )
        else:
            return (
                "MEDIUM: Subdomain expands attack surface:\n"
                "- Additional entry point for testing\n"
                "- May contain different vulnerabilities"
            )
    
    def _get_remediation(self, result: SubdomainResult) -> str:
        """Get remediation based on result."""
        if result.ownership == OwnershipType.DANGLING:
            return (
                "1. Remove dangling DNS records immediately\n"
                "2. Claim the subdomain on the third-party service\n"
                "3. Implement DNS monitoring for subdomain changes\n"
                "4. Regular audit of DNS records"
            )
        elif result.trust_boundary_issue:
            return (
                "1. Fix CORS configuration (remove wildcard)\n"
                "2. Restrict cookie domain scope\n"
                "3. Implement proper origin validation"
            )
        else:
            return (
                "1. Review subdomain for security issues\n"
                "2. Ensure proper access controls\n"
                "3. Include in security testing scope"
            )
    
    def _generate_finding_id(self, context: str) -> str:
        """Generate unique finding ID."""
        data = f"{self.domain}:{context}:{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    def _print_result(self, result: SubdomainResult) -> None:
        """Print subdomain result."""
        risk_color = "\033[91m" if result.risk == "high" else "\033[93m"
        reset = "\033[0m"
        
        print_success(f"[{result.confidence}%] {result.subdomain}")
        print(f"  Ownership: {result.ownership.value}")
        print(f"  Risk: {risk_color}{result.risk}{reset}")
        if result.provider:
            print(f"  Provider: {result.provider}")
        print()
    
    # ==========================================================================
    # EXPORT METHODS (NEW IN v4.1)
    # ==========================================================================
    
    def export_subdomains(self, filepath: str, format: str = "txt", resolving_only: bool = False) -> str:
        """
        Export discovered subdomains to file.
        
        Args:
            filepath: Output file path
            format: Export format (txt, urls, json)
            resolving_only: Only export resolving subdomains
        
        Returns:
            Path to exported file
        """
        if not self.exporter:
            self.exporter = SubdomainExporter(self.domain, self.all_subdomains, self.subdomain_results)
        
        if format == "txt":
            return self.exporter.export_txt(filepath, resolving_only)
        elif format == "urls":
            return self.exporter.export_urls(filepath, resolving_only)
        elif format == "json":
            return self.exporter.export_detailed_json(filepath)
        else:
            return self.exporter.export_txt(filepath, resolving_only)
    
    def get_subdomain_list(self, resolving_only: bool = False) -> List[str]:
        """Get list of discovered subdomains."""
        if resolving_only:
            return [r.subdomain for r in self.subdomain_results if r.resolves]
        return list(self.all_subdomains.keys())
    
    def print_subdomain_list(self) -> None:
        """Print subdomain list to stdout (for piping)."""
        for sub in sorted(self.all_subdomains.keys()):
            print(sub)


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="revuex-subdomain",
        description="REVUEX Subdomain-Hunter GOLD v4.1 - Pipeline-Ready Recon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic scan
    %(prog)s -d example.com
    
    # Export subdomains to text file
    %(prog)s -d example.com --export-subs subs.txt
    
    # Export only live (resolving) subdomains
    %(prog)s -d example.com --export-subs live.txt --live-only
    
    # Export as URLs for other tools
    %(prog)s -d example.com --export-subs targets.txt --export-format urls
    
    # Pipeline: subdomain â fingerprint
    %(prog)s -d example.com --export-subs subs.txt && revuex tech_fingerprint --list subs.txt
    
    # Print to stdout for piping
    %(prog)s -d example.com --print-subs | revuex tech_fingerprint --stdin

Author: REVUEX Team
        """
    )
    
    # Target
    parser.add_argument("-d", "--domain", required=True, help="Target root domain")
    
    # Scan options
    parser.add_argument("--threshold", type=int, default=CONFIDENCE_THRESHOLD,
                        help=f"Confidence threshold (default: {CONFIDENCE_THRESHOLD})")
    parser.add_argument("--min-sources", type=int, default=1,
                        help="Minimum sources for correlation (default: 1)")
    parser.add_argument("--no-second-order", action="store_true",
                        help="Disable second-order discovery")
    
    # Export options (NEW)
    export_group = parser.add_argument_group("Export Options")
    export_group.add_argument("--export-subs", metavar="FILE",
                              help="Export subdomain list to file")
    export_group.add_argument("--export-format", choices=["txt", "urls", "json"],
                              default="txt", help="Export format (default: txt)")
    export_group.add_argument("--live-only", action="store_true",
                              help="Only export resolving subdomains")
    export_group.add_argument("--print-subs", action="store_true",
                              help="Print subdomains to stdout (for piping)")
    export_group.add_argument("--auto-export", action="store_true",
                              help="Auto-export all formats to reports/")
    
    # Output options
    parser.add_argument("-o", "--output", help="Output file (detailed JSON report)")
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
        print(f"[+] Target: {args.domain}\n")
    
    hunter = SubdomainHunter(
        domain=args.domain,
        confidence_threshold=args.threshold,
        enable_second_order=not args.no_second_order,
        min_sources=args.min_sources,
        delay=args.delay,
        timeout=args.timeout,
        verbose=args.verbose,
    )
    
    result = hunter.run()
    
    # Handle subdomain export (NEW)
    if args.export_subs:
        export_path = hunter.export_subdomains(
            args.export_subs,
            format=args.export_format,
            resolving_only=args.live_only
        )
        if not args.quiet:
            print(f"\n[+] Subdomains exported to: {export_path}")
    
    # Auto-export all formats
    if args.auto_export:
        exports = hunter.exporter.auto_export()
        if not args.quiet:
            print(f"\n[+] Auto-exported files:")
            for name, path in exports.items():
                print(f"    {name}: {path}")
    
    # Print to stdout for piping
    if args.print_subs:
        hunter.print_subdomain_list()
        return 0  # Exit after printing for clean piping
    
    if not args.quiet:
        print(f"\n{'='*60}")
        print("SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"Domain: {args.domain}")
        if result and hasattr(result, "duration_seconds") and result.duration_seconds:
            print(f"Duration: {result.duration_seconds:.2f}s")
        print(f"Subdomains Found: {len(hunter.all_subdomains)}")
        print(f"High-Confidence: {len(getattr(result, 'findings', []) or [])}")
        
        # Summary by ownership
        dangling = sum(1 for r in hunter.subdomain_results if r.ownership == OwnershipType.DANGLING)
        third_party = sum(1 for r in hunter.subdomain_results if r.ownership == OwnershipType.THIRD_PARTY)
        
        print(f"\n[Ownership Summary]")
        print(f"  Dangling (takeover risk): {dangling}")
        print(f"  Third-Party: {third_party}")
        print(f"  Owned: {len(hunter.subdomain_results) - dangling - third_party}")
        
        # Show export hint if not exported
        if not args.export_subs and not args.auto_export:
            print(f"\n[TIP] Export subdomains with: --export-subs subs.txt")
    
    if args.output:
        output_data = {
            "scanner": "REVUEX Subdomain Hunter GOLD",
            "version": SCANNER_VERSION,
            "domain": args.domain,
            "scan_id": getattr(result, "scan_id", "unknown") if result else "unknown",
            "duration": getattr(result, "duration_seconds", 0) if result else 0,
            "all_subdomains": list(hunter.all_subdomains.keys()),
            "results": [
                {
                    "subdomain": r.subdomain,
                    "sources": list(r.sources),
                    "ownership": r.ownership.value,
                    "provider": r.provider,
                    "resolves": r.resolves,
                    "risk": r.risk,
                    "confidence": r.confidence,
                }
                for r in hunter.subdomain_results
            ],
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "subdomain": f.payload,
                }
                for f in getattr(result, "findings", []) or []
            ]
        }
        
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        
        if not args.quiet:
            print(f"\nResults saved to: {args.output}")
    
    findings = getattr(result, "findings", []) or []
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
