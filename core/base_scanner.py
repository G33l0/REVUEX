#!/usr/bin/env python3
"""
REVUEX - Base Scanner Module
============================

Foundation class for all REVUEX security scanners.
Provides unified architecture, safety controls, rate limiting,
session management, and reporting integration.

Author: REVUEX Team
License: MIT
"""

import os
import sys
import time
import json
import hashlib
import logging
import requests
import urllib3
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Union, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# Disable SSL warnings for testing (targets may have self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================================================
# CONSTANTS & CONFIGURATION
# =============================================================================

REVUEX_VERSION = "4.0.0"
REVUEX_BANNER = r"""
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
        Bug Bounty Automation Framework GOLD v4.0
"""

# Default configuration values
DEFAULT_CONFIG = {
    "timeout": 10,
    "delay": 1.0,
    "max_retries": 3,
    "retry_delay": 2.0,
    "max_requests_per_minute": 30,
    "max_concurrent_requests": 5,
    "verify_ssl": False,
    "follow_redirects": True,
    "max_redirects": 5,
    "output_dir": "scans",
}

# Standard User-Agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
]


# =============================================================================
# ENUMS & DATA CLASSES
# =============================================================================

class Severity(Enum):
    """Vulnerability severity levels aligned with CVSS v3.1"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    @property
    def color(self) -> str:
        """ANSI color codes for terminal output"""
        colors = {
            "critical": "\033[95m",  # Magenta
            "high": "\033[91m",       # Red
            "medium": "\033[93m",     # Yellow
            "low": "\033[94m",        # Blue
            "info": "\033[96m",       # Cyan
        }
        return colors.get(self.value, "\033[0m")
    
    @property
    def score_range(self) -> Tuple[float, float]:
        """CVSS score ranges"""
        ranges = {
            "critical": (9.0, 10.0),
            "high": (7.0, 8.9),
            "medium": (4.0, 6.9),
            "low": (0.1, 3.9),
            "info": (0.0, 0.0),
        }
        return ranges.get(self.value, (0.0, 0.0))


class ScanStatus(Enum):
    """Scan execution status"""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    ERROR = auto()      # Alias for FAILED
    PARTIAL = auto()    # Completed with some errors
    CANCELLED = auto()
    PAUSED = auto()


class RequestMethod(Enum):
    """HTTP request methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


@dataclass
class Finding:
    """
    Represents a security finding/vulnerability.
    
    This is the core data structure for all discovered issues.
    Designed to be directly exportable to bug bounty reports.
    """
    # Required fields
    title: str
    severity: Severity
    description: str
    
    # Location information
    url: str = ""
    endpoint: str = ""
    parameter: str = ""
    method: str = "GET"
    
    # Evidence
    payload: str = ""
    request: str = ""
    response: str = ""
    evidence: str = ""
    screenshot_path: str = ""
    
    # Classification
    vulnerability_type: str = ""
    cwe_id: str = ""
    cve_id: str = ""
    owasp_category: str = ""
    
    # Impact & Remediation
    impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    # Metadata
    id: str = ""  # Alias for finding_id
    finding_id: str = ""
    timestamp: str = ""
    scanner_name: str = ""
    confidence: str = "high"  # high, medium, low
    false_positive: bool = False
    verified: bool = False
    
    # Additional context
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Generate finding ID and timestamp if not provided"""
        # Handle both id and finding_id
        if self.id and not self.finding_id:
            self.finding_id = self.id
        if not self.finding_id:
            unique_str = f"{self.title}{self.url}{self.payload}{time.time()}"
            self.finding_id = hashlib.sha256(unique_str.encode()).hexdigest()[:16]
        # Sync id with finding_id
        self.id = self.finding_id
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON export"""
        data = asdict(self)
        data["severity"] = self.severity.value
        return data
    
    def to_markdown(self) -> str:
        """Generate markdown report section for this finding"""
        md = f"""
## {self.title}

**Severity:** {self.severity.value.upper()}  
**Confidence:** {self.confidence}  
**URL:** `{self.url}`  
**Parameter:** `{self.parameter}`  
**Method:** {self.method}

### Description
{self.description}

### Evidence
```
{self.evidence or self.response[:500] if self.response else 'N/A'}
```

### Payload Used
```
{self.payload or 'N/A'}
```

### Impact
{self.impact or 'See description above.'}

### Remediation
{self.remediation or 'Consult security best practices for this vulnerability type.'}

### References
{chr(10).join(f'- {ref}' for ref in self.references) if self.references else '- N/A'}

---
"""
        return md


@dataclass
class ScanResult:
    """
    Complete scan result container.
    
    Aggregates all findings, statistics, and metadata
    from a single scan execution.
    """
    # Scan identification
    scan_id: str = ""
    scanner_name: str = ""
    scanner_version: str = REVUEX_VERSION
    
    # Target information
    target: str = ""
    target_domain: str = ""
    scope: List[str] = field(default_factory=list)
    
    # Timing
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0
    
    # Status
    status: ScanStatus = ScanStatus.PENDING
    error_message: str = ""
    errors: List[str] = field(default_factory=list)  # List of error messages
    
    # Results
    findings: List[Finding] = field(default_factory=list)
    
    # Statistics
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    endpoints_tested: int = 0
    parameters_tested: int = 0
    payloads_tested: int = 0
    
    # Configuration used
    config: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.scan_id:
            self.scan_id = hashlib.sha256(
                f"{self.target}{time.time()}".encode()
            ).hexdigest()[:12]
    
    @property
    def finding_count(self) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts
    
    @property
    def has_critical(self) -> bool:
        """Check if any critical findings exist"""
        return any(f.severity == Severity.CRITICAL for f in self.findings)
    
    @property
    def has_high(self) -> bool:
        """Check if any high severity findings exist"""
        return any(f.severity == Severity.HIGH for f in self.findings)
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to results"""
        finding.scanner_name = self.scanner_name
        self.findings.append(finding)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON export"""
        return {
            "scan_id": self.scan_id,
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "target": self.target,
            "target_domain": self.target_domain,
            "scope": self.scope,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "status": self.status.name,
            "error_message": self.error_message,
            "statistics": {
                "total_requests": self.total_requests,
                "successful_requests": self.successful_requests,
                "failed_requests": self.failed_requests,
                "endpoints_tested": self.endpoints_tested,
                "parameters_tested": self.parameters_tested,
                "payloads_tested": self.payloads_tested,
                "findings_by_severity": self.finding_count,
            },
            "findings": [f.to_dict() for f in self.findings],
            "config": self.config,
        }


# =============================================================================
# RATE LIMITER
# =============================================================================

class RateLimiter:
    """
    Token bucket rate limiter for responsible scanning.
    
    Ensures we don't overwhelm targets and stay within
    acceptable request rates for bug bounty programs.
    """
    
    def __init__(self, requests_per_minute: int = 30):
        self.requests_per_minute = requests_per_minute
        self.tokens = requests_per_minute
        self.max_tokens = requests_per_minute
        self.last_update = time.time()
        self.lock = Lock()
    
    def acquire(self) -> bool:
        """
        Acquire a token for making a request.
        Blocks until a token is available.
        """
        with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            
            # Replenish tokens based on elapsed time
            tokens_to_add = elapsed * (self.requests_per_minute / 60.0)
            self.tokens = min(self.max_tokens, self.tokens + tokens_to_add)
            self.last_update = now
            
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            
            # Calculate wait time for next token
            wait_time = (1 - self.tokens) * (60.0 / self.requests_per_minute)
            time.sleep(wait_time)
            self.tokens = 0
            return True
    
    def set_rate(self, requests_per_minute: int) -> None:
        """Dynamically adjust rate limit"""
        with self.lock:
            self.requests_per_minute = requests_per_minute
            self.max_tokens = requests_per_minute


# =============================================================================
# BASE SCANNER CLASS
# =============================================================================

class BaseScanner(ABC):
    """
    Abstract base class for all REVUEX security scanners.
    
    Provides unified infrastructure for:
    - HTTP session management with retry logic
    - Rate limiting and request throttling
    - Safety validations and scope checking
    - Finding collection and deduplication
    - Report generation integration
    - Logging and debugging
    
    All scanner implementations must inherit from this class
    and implement the abstract methods.
    
    Example:
        class MyScanner(BaseScanner):
            def __init__(self, target, **kwargs):
                super().__init__(
                    name="My Scanner",
                    description="Custom vulnerability scanner",
                    target=target,
                    **kwargs
                )
            
            def scan(self):
                # Implementation here
                pass
            
            def _validate_target(self):
                # Validation logic
                return True
    """
    
    # Class-level configuration
    SCANNER_NAME = "Base Scanner"
    SCANNER_DESCRIPTION = "Abstract base scanner"
    SCANNER_VERSION = REVUEX_VERSION
    VULNERABILITY_TYPE = "generic"
    
    def __init__(
        self,
        name: str,
        description: str,
        target: str,
        timeout: int = DEFAULT_CONFIG["timeout"],
        delay: float = DEFAULT_CONFIG["delay"],
        max_retries: int = DEFAULT_CONFIG["max_retries"],
        verify_ssl: bool = DEFAULT_CONFIG["verify_ssl"],
        follow_redirects: bool = DEFAULT_CONFIG["follow_redirects"],
        max_redirects: int = DEFAULT_CONFIG["max_redirects"],
        requests_per_minute: int = DEFAULT_CONFIG["max_requests_per_minute"],
        max_concurrent: int = DEFAULT_CONFIG["max_concurrent_requests"],
        output_dir: str = DEFAULT_CONFIG["output_dir"],
        proxy: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        scope: Optional[List[str]] = None,
        verbose: bool = False,
        quiet: bool = False,
        color: bool = True,
        **kwargs
    ):
        """
        Initialize the base scanner.
        
        Args:
            name: Scanner name for identification
            description: Brief description of scanner purpose
            target: Target URL or domain
            timeout: Request timeout in seconds
            delay: Delay between requests in seconds
            max_retries: Maximum retry attempts for failed requests
            verify_ssl: Verify SSL certificates
            follow_redirects: Follow HTTP redirects
            max_redirects: Maximum redirects to follow
            requests_per_minute: Rate limit (requests per minute)
            max_concurrent: Maximum concurrent requests
            output_dir: Directory for scan output
            proxy: Proxy URL (e.g., http://127.0.0.1:8080)
            headers: Additional HTTP headers
            cookies: Cookies to include in requests
            auth: Basic auth tuple (username, password)
            scope: List of in-scope domains/patterns
            verbose: Enable verbose output
            quiet: Suppress non-essential output
            color: Enable colored output
        """
        # Scanner identification
        self.name = name
        self.description = description
        self.version = self.SCANNER_VERSION
        
        # Target configuration
        self.target = self._normalize_url(target)
        self.target_domain = self._extract_domain(self.target)
        self.scope = scope or [self.target_domain]
        
        # Request configuration
        self.timeout = timeout
        self.delay = delay
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.proxy = proxy
        self.custom_headers = headers or {}
        self.cookies = cookies or {}
        self.auth = auth
        
        # Rate limiting
        self.rate_limiter = RateLimiter(requests_per_minute)
        self.max_concurrent = max_concurrent
        
        # Output configuration
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Display options
        self.verbose = verbose
        self.quiet = quiet
        self.color = color
        
        # Internal state
        self._session: Optional[requests.Session] = None
        self._findings: List[Finding] = []
        self._finding_hashes: set = set()  # For deduplication
        self._request_count = 0
        self._successful_requests = 0
        self._failed_requests = 0
        self._start_time: Optional[datetime] = None
        self._status = ScanStatus.PENDING
        self._user_agent_index = 0
        self._lock = Lock()
        
        # Store full config for reporting
        self._config = {
            "timeout": timeout,
            "delay": delay,
            "max_retries": max_retries,
            "verify_ssl": verify_ssl,
            "requests_per_minute": requests_per_minute,
            "max_concurrent": max_concurrent,
            "proxy": proxy,
            "scope": self.scope,
        }
        
        # Setup logging
        self._setup_logging()
        
        # Extra kwargs for subclasses
        self.extra_config = kwargs
    
    # =========================================================================
    # ABSTRACT METHODS (Must be implemented by subclasses)
    # =========================================================================
    
    @abstractmethod
    def scan(self) -> ScanResult:
        """
        Execute the vulnerability scan.
        
        This is the main entry point for running the scanner.
        Must be implemented by all subclasses.
        
        Returns:
            ScanResult containing all findings and statistics
        """
        pass
    
    @abstractmethod
    def _validate_target(self) -> bool:
        """
        Validate the target is appropriate for this scanner.
        
        Returns:
            True if target is valid, False otherwise
        """
        pass
    
    # =========================================================================
    # SESSION MANAGEMENT
    # =========================================================================
    
    def _create_session(self) -> requests.Session:
        """
        Create and configure a requests session.
        
        Sets up connection pooling, retry logic, and default headers.
        """
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = requests.adapters.HTTPAdapter(
            max_retries=urllib3.Retry(
                total=self.max_retries,
                backoff_factor=0.5,
                status_forcelist=[500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE", "PATCH"]
            ),
            pool_connections=self.max_concurrent,
            pool_maxsize=self.max_concurrent * 2,
        )
        session.mount("http://", retry_strategy)
        session.mount("https://", retry_strategy)
        
        # Set default headers
        session.headers.update({
            "User-Agent": self._get_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
        })
        
        # Add custom headers
        if self.custom_headers:
            session.headers.update(self.custom_headers)
        
        # Set cookies
        if self.cookies:
            session.cookies.update(self.cookies)
        
        # Set auth
        if self.auth:
            session.auth = self.auth
        
        # Set proxy
        if self.proxy:
            session.proxies = {
                "http": self.proxy,
                "https": self.proxy,
            }
        
        # SSL verification
        session.verify = self.verify_ssl
        
        return session
    
    @property
    def session(self) -> requests.Session:
        """Get or create the HTTP session (lazy initialization)"""
        if self._session is None:
            self._session = self._create_session()
        return self._session
    
    def close_session(self) -> None:
        """Close the HTTP session and cleanup resources"""
        if self._session:
            self._session.close()
            self._session = None
    
    # =========================================================================
    # HTTP REQUEST METHODS
    # =========================================================================
    
    def request(
        self,
        method: Union[str, RequestMethod],
        url: str,
        **kwargs
    ) -> Optional[requests.Response]:
        """
        Make an HTTP request with rate limiting and error handling.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            **kwargs: Additional arguments passed to requests
        
        Returns:
            Response object or None if request failed
        """
        # Convert enum to string if needed
        if isinstance(method, RequestMethod):
            method = method.value
        
        # Validate URL is in scope
        if not self._is_in_scope(url):
            self.log_warning(f"URL out of scope: {url}")
            return None
        
        # Rate limiting
        self.rate_limiter.acquire()
        
        # Apply delay
        if self.delay > 0:
            time.sleep(self.delay)
        
        # Rotate User-Agent
        kwargs.setdefault("headers", {})
        kwargs["headers"]["User-Agent"] = self._get_user_agent(rotate=True)
        
        # Set timeout
        kwargs.setdefault("timeout", self.timeout)
        
        # Handle redirects
        kwargs.setdefault("allow_redirects", self.follow_redirects)
        if self.follow_redirects:
            kwargs.setdefault("max_redirects", self.max_redirects)
        
        # Increment request counter
        with self._lock:
            self._request_count += 1
        
        try:
            response = self.session.request(method, url, **kwargs)
            
            with self._lock:
                self._successful_requests += 1
            
            if self.verbose:
                self.log_debug(
                    f"{method} {url} -> {response.status_code} "
                    f"({len(response.content)} bytes)"
                )
            
            return response
            
        except requests.exceptions.Timeout:
            self.log_warning(f"Request timeout: {url}")
        except requests.exceptions.ConnectionError as e:
            self.log_warning(f"Connection error for {url}: {str(e)[:100]}")
        except requests.exceptions.TooManyRedirects:
            self.log_warning(f"Too many redirects: {url}")
        except requests.exceptions.RequestException as e:
            self.log_error(f"Request failed for {url}: {str(e)[:100]}")
        
        with self._lock:
            self._failed_requests += 1
        
        return None
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a GET request"""
        return self.request("GET", url, **kwargs)
    
    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a POST request"""
        return self.request("POST", url, **kwargs)
    
    def put(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a PUT request"""
        return self.request("PUT", url, **kwargs)
    
    def delete(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a DELETE request"""
        return self.request("DELETE", url, **kwargs)
    
    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a HEAD request"""
        return self.request("HEAD", url, **kwargs)
    
    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make an OPTIONS request"""
        return self.request("OPTIONS", url, **kwargs)
    
    # =========================================================================
    # CONCURRENT REQUEST HANDLING
    # =========================================================================
    
    def request_batch(
        self,
        requests_data: List[Dict[str, Any]],
        max_workers: Optional[int] = None
    ) -> List[Optional[requests.Response]]:
        """
        Execute multiple requests concurrently.
        
        Args:
            requests_data: List of dicts with 'method', 'url', and optional kwargs
            max_workers: Maximum concurrent workers (default: self.max_concurrent)
        
        Returns:
            List of response objects (or None for failed requests)
        """
        max_workers = max_workers or self.max_concurrent
        results = [None] * len(requests_data)
        
        def make_request(index: int, req_data: Dict) -> Tuple[int, Optional[requests.Response]]:
            method = req_data.get("method", "GET")
            url = req_data.get("url", "")
            kwargs = {k: v for k, v in req_data.items() if k not in ["method", "url"]}
            response = self.request(method, url, **kwargs)
            return index, response
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(make_request, i, req): i
                for i, req in enumerate(requests_data)
            }
            
            for future in as_completed(futures):
                try:
                    index, response = future.result()
                    results[index] = response
                except Exception as e:
                    self.log_error(f"Batch request error: {e}")
        
        return results
    
    # =========================================================================
    # FINDING MANAGEMENT
    # =========================================================================
    
    def add_finding(self, finding: Finding) -> bool:
        """
        Add a finding with deduplication.
        
        Args:
            finding: Finding object to add
        
        Returns:
            True if finding was added, False if duplicate
        """
        # Generate hash for deduplication
        finding_hash = hashlib.sha256(
            f"{finding.title}{finding.url}{finding.parameter}{finding.payload}".encode()
        ).hexdigest()
        
        with self._lock:
            if finding_hash in self._finding_hashes:
                self.log_debug(f"Duplicate finding skipped: {finding.title}")
                return False
            
            self._finding_hashes.add(finding_hash)
            finding.scanner_name = self.name
            self._findings.append(finding)
        
        # Log the finding
        severity_color = finding.severity.color if self.color else ""
        reset = "\033[0m" if self.color else ""
        
        if not self.quiet:
            self.log_success(
                f"[{severity_color}{finding.severity.value.upper()}{reset}] "
                f"{finding.title} @ {finding.url}"
            )
        
        return True
    
    def create_finding(
        self,
        title: str,
        severity: Severity,
        description: str,
        **kwargs
    ) -> Finding:
        """
        Create and add a finding in one step.
        
        Convenience method that creates a Finding object
        and adds it to the findings list.
        
        Returns:
            The created Finding object
        """
        finding = Finding(
            title=title,
            severity=severity,
            description=description,
            vulnerability_type=self.VULNERABILITY_TYPE,
            **kwargs
        )
        self.add_finding(finding)
        return finding
    
    @property
    def findings(self) -> List[Finding]:
        """Get all findings"""
        return self._findings.copy()
    
    def clear_findings(self) -> None:
        """Clear all findings"""
        with self._lock:
            self._findings.clear()
            self._finding_hashes.clear()
    
    # =========================================================================
    # SCAN RESULT GENERATION
    # =========================================================================
    
    def generate_result(self, error_message: str = "") -> ScanResult:
        """
        Generate the final scan result.
        
        Returns:
            ScanResult object with all findings and statistics
        """
        end_time = datetime.now(timezone.utc)
        duration = 0.0
        
        if self._start_time:
            duration = (end_time - self._start_time).total_seconds()
        
        result = ScanResult(
            scanner_name=self.name,
            scanner_version=self.version,
            target=self.target,
            target_domain=self.target_domain,
            scope=self.scope,
            start_time=self._start_time.isoformat() if self._start_time else "",
            end_time=end_time.isoformat(),
            duration_seconds=duration,
            status=self._status,
            error_message=error_message,
            findings=self._findings.copy(),
            total_requests=self._request_count,
            successful_requests=self._successful_requests,
            failed_requests=self._failed_requests,
            config=self._config,
        )
        
        return result
    
    # =========================================================================
    # OUTPUT & EXPORT
    # =========================================================================
    
    def save_results(
        self,
        result: ScanResult,
        formats: List[str] = ["json", "html", "txt"]
    ) -> Dict[str, str]:
        """
        Save scan results in multiple formats.
        
        Args:
            result: ScanResult to save
            formats: List of output formats (json, html, txt, md)
        
        Returns:
            Dictionary mapping format to file path
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{self.name.lower().replace(' ', '_')}_{self.target_domain}_{timestamp}"
        output_paths = {}
        
        for fmt in formats:
            output_path = self.output_dir / f"{base_name}.{fmt}"
            
            if fmt == "json":
                self._save_json(result, output_path)
            elif fmt == "html":
                self._save_html(result, output_path)
            elif fmt == "txt":
                self._save_txt(result, output_path)
            elif fmt == "md":
                self._save_markdown(result, output_path)
            
            output_paths[fmt] = str(output_path)
        
        return output_paths
    
    def _save_json(self, result: ScanResult, path: Path) -> None:
        """Save result as JSON"""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        self.log_info(f"JSON report saved: {path}")
    
    def _save_txt(self, result: ScanResult, path: Path) -> None:
        """Save result as plain text"""
        lines = [
            "=" * 70,
            f"REVUEX {self.name} Scan Report",
            "=" * 70,
            "",
            f"Target: {result.target}",
            f"Scan ID: {result.scan_id}",
            f"Start Time: {result.start_time}",
            f"End Time: {result.end_time}",
            f"Duration: {result.duration_seconds:.2f} seconds",
            "",
            "Statistics:",
            f"  Total Requests: {result.total_requests}",
            f"  Successful: {result.successful_requests}",
            f"  Failed: {result.failed_requests}",
            "",
            f"Findings Summary:",
            f"  Critical: {result.finding_count.get('critical', 0)}",
            f"  High: {result.finding_count.get('high', 0)}",
            f"  Medium: {result.finding_count.get('medium', 0)}",
            f"  Low: {result.finding_count.get('low', 0)}",
            f"  Info: {result.finding_count.get('info', 0)}",
            "",
            "-" * 70,
            "DETAILED FINDINGS",
            "-" * 70,
        ]
        
        for i, finding in enumerate(result.findings, 1):
            lines.extend([
                "",
                f"[{i}] {finding.title}",
                f"    Severity: {finding.severity.value.upper()}",
                f"    URL: {finding.url}",
                f"    Parameter: {finding.parameter}",
                f"    Payload: {finding.payload[:100]}..." if len(finding.payload) > 100 else f"    Payload: {finding.payload}",
                f"    Description: {finding.description}",
            ])
        
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        self.log_info(f"Text report saved: {path}")
    
    def _save_markdown(self, result: ScanResult, path: Path) -> None:
        """Save result as Markdown"""
        md_content = f"""# REVUEX {self.name} Scan Report

## Executive Summary

| Metric | Value |
|--------|-------|
| Target | `{result.target}` |
| Scan ID | `{result.scan_id}` |
| Duration | {result.duration_seconds:.2f}s |
| Total Requests | {result.total_requests} |
| Findings | {len(result.findings)} |

## Findings by Severity

| Severity | Count |
|----------|-------|
| Critical | {result.finding_count.get('critical', 0)} |
| High | {result.finding_count.get('high', 0)} |
| Medium | {result.finding_count.get('medium', 0)} |
| Low | {result.finding_count.get('low', 0)} |
| Info | {result.finding_count.get('info', 0)} |

## Detailed Findings

"""
        for finding in result.findings:
            md_content += finding.to_markdown()
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(md_content)
        self.log_info(f"Markdown report saved: {path}")
    
    def _save_html(self, result: ScanResult, path: Path) -> None:
        """Save result as HTML (professional report)"""
        # This will be enhanced by report_generator.py
        # For now, generate a basic HTML report
        severity_colors = {
            "critical": "#9b59b6",
            "high": "#e74c3c",
            "medium": "#f39c12",
            "low": "#3498db",
            "info": "#1abc9c",
        }
        
        findings_html = ""
        for finding in result.findings:
            color = severity_colors.get(finding.severity.value, "#95a5a6")
            findings_html += f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="severity" style="background-color: {color}">
                        {finding.severity.value.upper()}
                    </span>
                    <span class="title">{finding.title}</span>
                </div>
                <div class="finding-body">
                    <p><strong>URL:</strong> <code>{finding.url}</code></p>
                    <p><strong>Parameter:</strong> <code>{finding.parameter}</code></p>
                    <p><strong>Description:</strong> {finding.description}</p>
                    <p><strong>Payload:</strong></p>
                    <pre><code>{finding.payload}</code></pre>
                    <p><strong>Impact:</strong> {finding.impact or 'See description'}</p>
                    <p><strong>Remediation:</strong> {finding.remediation or 'Consult security guidelines'}</p>
                </div>
            </div>
            """
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>REVUEX {self.name} Report - {result.target_domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0a0a0a;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 3rem 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            border: 1px solid #333;
        }}
        .header h1 {{
            font-size: 2.5rem;
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        .header .target {{ color: #888; font-size: 1.1rem; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: #1a1a2e;
            padding: 1.5rem;
            border-radius: 8px;
            border: 1px solid #333;
        }}
        .stat-card .value {{ font-size: 2rem; font-weight: bold; color: #00d4ff; }}
        .stat-card .label {{ color: #888; }}
        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .severity-card {{
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }}
        .severity-card .count {{ font-size: 2rem; font-weight: bold; }}
        .finding {{
            background: #1a1a2e;
            border-radius: 8px;
            margin-bottom: 1rem;
            border: 1px solid #333;
            overflow: hidden;
        }}
        .finding-header {{
            padding: 1rem;
            background: #16213e;
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        .severity {{
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            color: white;
            text-transform: uppercase;
        }}
        .title {{ font-weight: 600; }}
        .finding-body {{
            padding: 1.5rem;
        }}
        .finding-body p {{ margin-bottom: 0.75rem; }}
        .finding-body pre {{
            background: #0a0a0a;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            margin: 0.5rem 0;
        }}
        code {{ color: #00d4ff; }}
        .footer {{
            text-align: center;
            padding: 2rem;
            color: #666;
            border-top: 1px solid #333;
            margin-top: 2rem;
        }}
        .disclaimer {{
            background: #2c1810;
            border: 1px solid #8b4513;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 2rem;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>REVUEX {self.name}</h1>
            <p class="target">Target: {result.target}</p>
            <p style="color: #666; margin-top: 0.5rem;">
                Scan ID: {result.scan_id} | Duration: {result.duration_seconds:.2f}s
            </p>
        </div>
        
        <div class="disclaimer">
            <strong>⚠️ Legal Disclaimer:</strong> This report is generated for authorized security testing only.
            Unauthorized access to computer systems is illegal. The findings in this report should be used
            for remediation purposes by authorized personnel only.
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="value">{result.total_requests}</div>
                <div class="label">Total Requests</div>
            </div>
            <div class="stat-card">
                <div class="value">{result.successful_requests}</div>
                <div class="label">Successful</div>
            </div>
            <div class="stat-card">
                <div class="value">{result.failed_requests}</div>
                <div class="label">Failed</div>
            </div>
            <div class="stat-card">
                <div class="value">{len(result.findings)}</div>
                <div class="label">Findings</div>
            </div>
        </div>
        
        <div class="severity-grid">
            <div class="severity-card" style="background: #9b59b633;">
                <div class="count" style="color: #9b59b6;">{result.finding_count.get('critical', 0)}</div>
                <div>Critical</div>
            </div>
            <div class="severity-card" style="background: #e74c3c33;">
                <div class="count" style="color: #e74c3c;">{result.finding_count.get('high', 0)}</div>
                <div>High</div>
            </div>
            <div class="severity-card" style="background: #f39c1233;">
                <div class="count" style="color: #f39c12;">{result.finding_count.get('medium', 0)}</div>
                <div>Medium</div>
            </div>
            <div class="severity-card" style="background: #3498db33;">
                <div class="count" style="color: #3498db;">{result.finding_count.get('low', 0)}</div>
                <div>Low</div>
            </div>
            <div class="severity-card" style="background: #1abc9c33;">
                <div class="count" style="color: #1abc9c;">{result.finding_count.get('info', 0)}</div>
                <div>Info</div>
            </div>
        </div>
        
        <h2 style="margin-bottom: 1rem;">Findings</h2>
        {findings_html if findings_html else '<p style="color: #888;">No vulnerabilities found.</p>'}
        
        <div class="footer">
            <p>Generated by REVUEX v{REVUEX_VERSION}</p>
            <p style="margin-top: 0.5rem;">Bug Bounty Automation Framework</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)
        self.log_info(f"HTML report saved: {path}")
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL to ensure proper format"""
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        return url.rstrip("/")
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split("/")[0]
    
    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within the defined scope"""
        try:
            domain = self._extract_domain(url)
            for scope_item in self.scope:
                if scope_item in domain or domain.endswith(scope_item):
                    return True
                # Handle wildcards
                if scope_item.startswith("*."):
                    base_domain = scope_item[2:]
                    if domain == base_domain or domain.endswith(f".{base_domain}"):
                        return True
            return False
        except Exception:
            return False
    
    def _get_user_agent(self, rotate: bool = False) -> str:
        """Get User-Agent string, optionally rotating"""
        if rotate:
            with self._lock:
                self._user_agent_index = (self._user_agent_index + 1) % len(USER_AGENTS)
        return USER_AGENTS[self._user_agent_index]
    
    def build_url(self, path: str, params: Optional[Dict[str, str]] = None) -> str:
        """Build full URL from path and optional parameters"""
        url = urljoin(self.target, path)
        if params:
            from urllib.parse import urlencode
            url = f"{url}?{urlencode(params)}"
        return url
    
    # =========================================================================
    # LOGGING
    # =========================================================================
    
    def _setup_logging(self) -> None:
        """Configure logging for the scanner"""
        self.logger = logging.getLogger(f"revuex.{self.name}")
        
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
    
    def _colorize(self, text: str, color_code: str) -> str:
        """Apply ANSI color if colors are enabled"""
        if self.color:
            return f"{color_code}{text}\033[0m"
        return text
    
    def log_info(self, message: str) -> None:
        """Log info message"""
        if not self.quiet:
            prefix = self._colorize("[*]", "\033[94m")
            print(f"{prefix} {message}")
        self.logger.info(message)
    
    def log_success(self, message: str) -> None:
        """Log success message"""
        if not self.quiet:
            prefix = self._colorize("[+]", "\033[92m")
            print(f"{prefix} {message}")
        self.logger.info(message)
    
    def log_warning(self, message: str) -> None:
        """Log warning message"""
        if not self.quiet:
            prefix = self._colorize("[!]", "\033[93m")
            print(f"{prefix} {message}")
        self.logger.warning(message)
    
    def log_error(self, message: str) -> None:
        """Log error message"""
        prefix = self._colorize("[-]", "\033[91m")
        print(f"{prefix} {message}")
        self.logger.error(message)
    
    def log_debug(self, message: str) -> None:
        """Log debug message"""
        if self.verbose:
            prefix = self._colorize("[D]", "\033[90m")
            print(f"{prefix} {message}")
        self.logger.debug(message)
    
    def print_banner(self) -> None:
        """Print REVUEX banner"""
        if not self.quiet:
            banner = REVUEX_BANNER.format(version=REVUEX_VERSION)
            if self.color:
                print(f"\033[96m{banner}\033[0m")
            else:
                print(banner)
    
    # =========================================================================
    # LIFECYCLE METHODS
    # =========================================================================
    
    def pre_scan(self) -> bool:
        """
        Pre-scan hook for validation and setup.
        
        Returns:
            True if scan should proceed, False to abort
        """
        self._start_time = datetime.now(timezone.utc)
        self._status = ScanStatus.RUNNING
        
        self.print_banner()
        self.log_info(f"Starting {self.name} scan")
        self.log_info(f"Target: {self.target}")
        self.log_info(f"Scope: {', '.join(self.scope)}")
        
        if not self._validate_target():
            self.log_error("Target validation failed")
            self._status = ScanStatus.FAILED
            return False
        
        return True
    
    def post_scan(self, result: ScanResult = None) -> None:
        """Post-scan hook for cleanup and summary"""
        self._status = ScanStatus.COMPLETED
        
        if not self.quiet and result is not None:
            print()
            self.log_info("=" * 50)
            self.log_info("SCAN COMPLETE")
            self.log_info("=" * 50)
            if hasattr(result, 'duration_seconds') and result.duration_seconds is not None:
                self.log_info(f"Duration: {result.duration_seconds:.2f} seconds")
            if hasattr(result, 'total_requests'):
                self.log_info(f"Requests: {result.total_requests} total, {result.failed_requests} failed")
            if hasattr(result, 'findings'):
                self.log_info(f"Findings: {len(result.findings)} total")
                
                for severity in Severity:
                    count = result.finding_count.get(severity.value, 0)
                    if count > 0:
                        color = severity.color if self.color else ""
                        reset = "\033[0m" if self.color else ""
                        print(f"  {color}{severity.value.upper()}: {count}{reset}")
    
    def run(self) -> ScanResult:
        """
        Full scan execution with lifecycle management.
        
        This is the recommended entry point for running scans.
        Handles pre-scan validation, scan execution, error handling,
        and post-scan cleanup.
        
        Returns:
            ScanResult with all findings and statistics
        """
        try:
            if not self.pre_scan():
                return self.generate_result("Pre-scan validation failed")
            
            result = self.scan()
            self.post_scan(result)
            
            return result
            
        except KeyboardInterrupt:
            self.log_warning("Scan interrupted by user")
            self._status = ScanStatus.CANCELLED
            return self.generate_result("Scan cancelled by user")
            
        except Exception as e:
            self.log_error(f"Scan failed with error: {str(e)}")
            self._status = ScanStatus.FAILED
            if self.verbose:
                import traceback
                traceback.print_exc()
            return self.generate_result(str(e))
            
        finally:
            self.close_session()
    
    # =========================================================================
    # CONTEXT MANAGER SUPPORT
    # =========================================================================
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup"""
        self.close_session()
        return False


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_scanner_info() -> Dict[str, str]:
    """Get REVUEX scanner information"""
    return {
        "name": "REVUEX",
        "version": REVUEX_VERSION,
        "description": "Bug Bounty Automation Framework",
        "author": "REVUEX Team",
    }


def print_disclaimer() -> None:
    """Print legal disclaimer"""
    disclaimer = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                              LEGAL DISCLAIMER                                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This tool is designed for authorized security testing and bug bounty        ║
║  hunting ONLY. Users are responsible for ensuring they have proper           ║
║  authorization before testing any target.                                    ║
║                                                                              ║
║  Unauthorized access to computer systems is illegal under laws including:    ║
║  - Computer Fraud and Abuse Act (CFAA) - United States                      ║
║  - Computer Misuse Act - United Kingdom                                      ║
║  - Similar legislation in other jurisdictions                                ║
║                                                                              ║
║  By using this tool, you agree to:                                          ║
║  1. Only test systems you own or have explicit written permission to test   ║
║  2. Follow responsible disclosure practices                                  ║
║  3. Comply with all applicable bug bounty program rules                     ║
║  4. Not use this tool for malicious purposes                                ║
║                                                                              ║
║  THE AUTHORS ASSUME NO LIABILITY FOR MISUSE OF THIS SOFTWARE                ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    print(disclaimer)


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Core classes
    "BaseScanner",
    "Finding",
    "ScanResult",
    "RateLimiter",
    
    # Enums
    "Severity",
    "ScanStatus",
    "RequestMethod",
    
    # Constants
    "REVUEX_VERSION",
    "REVUEX_BANNER",
    "DEFAULT_CONFIG",
    "USER_AGENTS",
    
    # Utility functions
    "get_scanner_info",
    "print_disclaimer",
]
