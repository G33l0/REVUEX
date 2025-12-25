#!/usr/bin/env python3
"""
REVUEX - Safety Checks Module
=============================

Comprehensive safety validation for responsible security testing.
Ensures all scanning activities remain within authorized scope
and follow bug bounty program guidelines.

Features:
- Scope validation (domain, IP, URL patterns)
- Dangerous payload detection and filtering
- Rate limit enforcement
- Out-of-scope protection
- Private IP range detection
- Cloud metadata protection
- Sensitive endpoint detection

Author: REVUEX Team
License: MIT
"""

import re
import socket
import ipaddress
import logging
from typing import Optional, List, Dict, Set, Tuple, Union, Pattern
from urllib.parse import urlparse, urljoin, parse_qs
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import lru_cache
import tldextract


# =============================================================================
# CONSTANTS
# =============================================================================

# Private IP ranges (RFC 1918 + additional reserved ranges)
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-grade NAT
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmark testing
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
]

# IPv6 private ranges
PRIVATE_IPV6_RANGES = [
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("fc00::/7"),           # Unique local
    ipaddress.ip_network("fe80::/10"),          # Link-local
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

# Cloud metadata endpoints (should never be accessed in SSRF unless testing)
CLOUD_METADATA_ENDPOINTS = [
    # AWS
    "169.254.169.254",
    "fd00:ec2::254",
    "instance-data",
    "metadata.aws",
    
    # GCP
    "metadata.google.internal",
    "169.254.169.254",
    
    # Azure
    "169.254.169.254",
    "metadata.azure",
    
    # DigitalOcean
    "169.254.169.254",
    
    # Oracle Cloud
    "169.254.169.254",
    
    # Alibaba Cloud
    "100.100.100.200",
    
    # OpenStack
    "169.254.169.254",
]

# Dangerous ports that should be avoided
DANGEROUS_PORTS = {
    22,     # SSH
    23,     # Telnet
    25,     # SMTP
    53,     # DNS
    110,    # POP3
    143,    # IMAP
    445,    # SMB
    3306,   # MySQL
    3389,   # RDP
    5432,   # PostgreSQL
    5900,   # VNC
    6379,   # Redis
    27017,  # MongoDB
}

# Sensitive paths that may indicate critical infrastructure
SENSITIVE_PATHS = [
    "/admin",
    "/administrator",
    "/wp-admin",
    "/phpmyadmin",
    "/cpanel",
    "/webmail",
    "/.git",
    "/.svn",
    "/.env",
    "/config",
    "/backup",
    "/db",
    "/database",
    "/sql",
    "/api/internal",
    "/internal",
    "/private",
    "/secret",
    "/management",
    "/console",
    "/shell",
    "/terminal",
]

# Patterns that may indicate destructive payloads
DESTRUCTIVE_PATTERNS = [
    r"(?i)(drop|delete|truncate|alter)\s+(table|database|schema)",
    r"(?i)rm\s+-rf",
    r"(?i)format\s+c:",
    r"(?i)mkfs\.",
    r"(?i)dd\s+if=",
    r"(?i)>\s*/dev/[sh]d[a-z]",
    r"(?i)shutdown",
    r"(?i)reboot",
    r"(?i)init\s+0",
    r"(?i):(){ :\|:& };:",  # Fork bomb
]


# =============================================================================
# ENUMS & DATA CLASSES
# =============================================================================

class SafetyLevel(Enum):
    """Safety enforcement levels"""
    STRICT = auto()      # Maximum safety, block anything suspicious
    STANDARD = auto()    # Balanced safety for typical bug bounty
    PERMISSIVE = auto()  # Minimal restrictions (for authorized pentests)


class ValidationResult(Enum):
    """Result of a safety validation"""
    ALLOWED = auto()
    BLOCKED = auto()
    WARNING = auto()


@dataclass
class SafetyCheckResult:
    """Result of a safety check with details"""
    result: ValidationResult
    message: str
    details: Dict = field(default_factory=dict)
    
    @property
    def is_allowed(self) -> bool:
        return self.result == ValidationResult.ALLOWED
    
    @property
    def is_blocked(self) -> bool:
        return self.result == ValidationResult.BLOCKED
    
    def __bool__(self) -> bool:
        return self.is_allowed


@dataclass
class ScopeDefinition:
    """
    Defines the authorized testing scope.
    
    Supports:
    - Explicit domain inclusion/exclusion
    - Wildcard patterns (*.example.com)
    - IP ranges (CIDR notation)
    - URL path patterns
    - Port restrictions
    """
    # Included targets
    include_domains: List[str] = field(default_factory=list)
    include_ips: List[str] = field(default_factory=list)
    include_paths: List[str] = field(default_factory=list)
    
    # Excluded targets (higher priority than includes)
    exclude_domains: List[str] = field(default_factory=list)
    exclude_ips: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)
    
    # Port restrictions
    allowed_ports: Set[int] = field(default_factory=lambda: {80, 443, 8080, 8443})
    
    # Additional settings
    allow_subdomains: bool = True
    allow_private_ips: bool = False
    allow_cloud_metadata: bool = False
    
    def __post_init__(self):
        """Normalize scope entries"""
        self.include_domains = [d.lower().strip() for d in self.include_domains]
        self.exclude_domains = [d.lower().strip() for d in self.exclude_domains]


# =============================================================================
# SCOPE VALIDATOR
# =============================================================================

class ScopeValidator:
    """
    Validates targets against defined scope.
    
    Core component for ensuring all testing activities
    remain within authorized boundaries.
    
    Usage:
        scope = ScopeDefinition(
            include_domains=["example.com", "*.example.com"],
            exclude_domains=["admin.example.com"],
            allowed_ports={80, 443}
        )
        validator = ScopeValidator(scope)
        
        if validator.is_in_scope("https://api.example.com/users"):
            # Proceed with testing
            pass
    """
    
    def __init__(
        self,
        scope: Optional[ScopeDefinition] = None,
        safety_level: SafetyLevel = SafetyLevel.STANDARD
    ):
        self.scope = scope or ScopeDefinition()
        self.safety_level = safety_level
        self.logger = logging.getLogger("revuex.safety.scope")
        
        # Compile regex patterns for efficiency
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile domain patterns to regex for fast matching"""
        self._include_patterns: List[Pattern] = []
        self._exclude_patterns: List[Pattern] = []
        
        for domain in self.scope.include_domains:
            pattern = self._domain_to_regex(domain)
            self._include_patterns.append(re.compile(pattern, re.IGNORECASE))
        
        for domain in self.scope.exclude_domains:
            pattern = self._domain_to_regex(domain)
            self._exclude_patterns.append(re.compile(pattern, re.IGNORECASE))
    
    def _domain_to_regex(self, domain: str) -> str:
        """Convert domain pattern to regex"""
        # Escape special regex characters
        pattern = re.escape(domain)
        
        # Convert wildcards
        pattern = pattern.replace(r"\*", r"[a-zA-Z0-9-]+")
        
        # Handle subdomain wildcards
        if domain.startswith("*."):
            base = re.escape(domain[2:])
            pattern = rf"([a-zA-Z0-9-]+\.)*{base}"
        
        return f"^{pattern}$"
    
    @lru_cache(maxsize=1000)
    def _extract_domain(self, url: str) -> Tuple[str, str, int]:
        """
        Extract domain, path, and port from URL.
        Results are cached for performance.
        """
        try:
            parsed = urlparse(url)
            
            # Get domain
            domain = parsed.netloc.lower()
            
            # Extract port
            port = parsed.port
            if port is None:
                port = 443 if parsed.scheme == "https" else 80
            
            # Remove port from domain if present
            if ":" in domain:
                domain = domain.rsplit(":", 1)[0]
            
            # Get path
            path = parsed.path or "/"
            
            return domain, path, port
            
        except Exception as e:
            self.logger.warning(f"Failed to parse URL {url}: {e}")
            return "", "/", 80
    
    def is_in_scope(self, url: str) -> SafetyCheckResult:
        """
        Check if a URL is within the defined scope.
        
        Args:
            url: URL to validate
        
        Returns:
            SafetyCheckResult with validation details
        """
        if not url:
            return SafetyCheckResult(
                result=ValidationResult.BLOCKED,
                message="Empty URL provided"
            )
        
        # Normalize URL
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        
        domain, path, port = self._extract_domain(url)
        
        if not domain:
            return SafetyCheckResult(
                result=ValidationResult.BLOCKED,
                message="Could not extract domain from URL",
                details={"url": url}
            )
        
        # Check if it's an IP address
        is_ip = self._is_ip_address(domain)
        
        if is_ip:
            return self._validate_ip(domain, port, url)
        else:
            return self._validate_domain(domain, path, port, url)
    
    def _validate_domain(
        self,
        domain: str,
        path: str,
        port: int,
        original_url: str
    ) -> SafetyCheckResult:
        """Validate a domain-based URL"""
        
        # Check excluded domains first (higher priority)
        for pattern in self._exclude_patterns:
            if pattern.match(domain):
                return SafetyCheckResult(
                    result=ValidationResult.BLOCKED,
                    message=f"Domain {domain} is explicitly excluded from scope",
                    details={"domain": domain, "url": original_url}
                )
        
        # Check excluded paths
        for excluded_path in self.scope.exclude_paths:
            if path.startswith(excluded_path):
                return SafetyCheckResult(
                    result=ValidationResult.BLOCKED,
                    message=f"Path {path} is excluded from scope",
                    details={"path": path, "url": original_url}
                )
        
        # Check included domains
        domain_in_scope = False
        for pattern in self._include_patterns:
            if pattern.match(domain):
                domain_in_scope = True
                break
        
        # Check with subdomain handling
        if not domain_in_scope and self.scope.allow_subdomains:
            extracted = tldextract.extract(domain)
            base_domain = f"{extracted.domain}.{extracted.suffix}"
            
            for include_domain in self.scope.include_domains:
                # Remove wildcard prefix for comparison
                clean_include = include_domain.lstrip("*.")
                if base_domain == clean_include or domain.endswith(f".{clean_include}"):
                    domain_in_scope = True
                    break
        
        if not domain_in_scope and self._include_patterns:
            return SafetyCheckResult(
                result=ValidationResult.BLOCKED,
                message=f"Domain {domain} is not in scope",
                details={"domain": domain, "url": original_url}
            )
        
        # Check port restrictions
        if self.scope.allowed_ports and port not in self.scope.allowed_ports:
            return SafetyCheckResult(
                result=ValidationResult.BLOCKED,
                message=f"Port {port} is not allowed",
                details={"port": port, "allowed": list(self.scope.allowed_ports)}
            )
        
        # Check for sensitive paths in strict mode
        if self.safety_level == SafetyLevel.STRICT:
            for sensitive in SENSITIVE_PATHS:
                if path.lower().startswith(sensitive):
                    return SafetyCheckResult(
                        result=ValidationResult.WARNING,
                        message=f"Sensitive path detected: {path}",
                        details={"path": path, "url": original_url}
                    )
        
        return SafetyCheckResult(
            result=ValidationResult.ALLOWED,
            message="URL is within scope",
            details={"domain": domain, "path": path, "port": port}
        )
    
    def _validate_ip(
        self,
        ip_str: str,
        port: int,
        original_url: str
    ) -> SafetyCheckResult:
        """Validate an IP-based URL"""
        
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return SafetyCheckResult(
                result=ValidationResult.BLOCKED,
                message=f"Invalid IP address: {ip_str}",
                details={"ip": ip_str}
            )
        
        # Check for private IPs
        if not self.scope.allow_private_ips:
            if self._is_private_ip(ip):
                return SafetyCheckResult(
                    result=ValidationResult.BLOCKED,
                    message=f"Private IP addresses are not allowed: {ip_str}",
                    details={"ip": ip_str, "is_private": True}
                )
        
        # Check for cloud metadata IPs
        if not self.scope.allow_cloud_metadata:
            if ip_str in CLOUD_METADATA_ENDPOINTS:
                return SafetyCheckResult(
                    result=ValidationResult.BLOCKED,
                    message=f"Cloud metadata endpoint blocked: {ip_str}",
                    details={"ip": ip_str, "is_metadata": True}
                )
        
        # Check if IP is in allowed ranges
        ip_in_scope = False
        for ip_range in self.scope.include_ips:
            try:
                network = ipaddress.ip_network(ip_range, strict=False)
                if ip in network:
                    ip_in_scope = True
                    break
            except ValueError:
                # Single IP comparison
                if ip_str == ip_range:
                    ip_in_scope = True
                    break
        
        # Check excluded IPs
        for ip_range in self.scope.exclude_ips:
            try:
                network = ipaddress.ip_network(ip_range, strict=False)
                if ip in network:
                    return SafetyCheckResult(
                        result=ValidationResult.BLOCKED,
                        message=f"IP {ip_str} is explicitly excluded",
                        details={"ip": ip_str}
                    )
            except ValueError:
                if ip_str == ip_range:
                    return SafetyCheckResult(
                        result=ValidationResult.BLOCKED,
                        message=f"IP {ip_str} is explicitly excluded",
                        details={"ip": ip_str}
                    )
        
        if not ip_in_scope and self.scope.include_ips:
            return SafetyCheckResult(
                result=ValidationResult.BLOCKED,
                message=f"IP {ip_str} is not in scope",
                details={"ip": ip_str}
            )
        
        # Check port
        if self.scope.allowed_ports and port not in self.scope.allowed_ports:
            return SafetyCheckResult(
                result=ValidationResult.BLOCKED,
                message=f"Port {port} is not allowed",
                details={"port": port}
            )
        
        return SafetyCheckResult(
            result=ValidationResult.ALLOWED,
            message="IP is within scope",
            details={"ip": ip_str, "port": port}
        )
    
    def _is_ip_address(self, host: str) -> bool:
        """Check if host is an IP address"""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False
    
    def _is_private_ip(self, ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
        """Check if IP is in private range"""
        if isinstance(ip, ipaddress.IPv4Address):
            for network in PRIVATE_IP_RANGES:
                if ip in network:
                    return True
        else:
            for network in PRIVATE_IPV6_RANGES:
                if ip in network:
                    return True
        return False
    
    def add_to_scope(self, domain: str) -> None:
        """Dynamically add a domain to scope"""
        domain = domain.lower().strip()
        if domain not in self.scope.include_domains:
            self.scope.include_domains.append(domain)
            self._compile_patterns()
    
    def remove_from_scope(self, domain: str) -> None:
        """Remove a domain from scope"""
        domain = domain.lower().strip()
        if domain in self.scope.include_domains:
            self.scope.include_domains.remove(domain)
            self._compile_patterns()


# =============================================================================
# PAYLOAD SAFETY VALIDATOR
# =============================================================================

class PayloadValidator:
    """
    Validates payloads for safety before use.
    
    Ensures payloads are designed for detection, not exploitation.
    Blocks destructive or malicious payloads.
    """
    
    def __init__(self, safety_level: SafetyLevel = SafetyLevel.STANDARD):
        self.safety_level = safety_level
        self.logger = logging.getLogger("revuex.safety.payload")
        
        # Compile destructive patterns
        self._destructive_patterns = [
            re.compile(pattern) for pattern in DESTRUCTIVE_PATTERNS
        ]
    
    def validate_payload(self, payload: str) -> SafetyCheckResult:
        """
        Validate a payload for safety.
        
        Args:
            payload: Payload string to validate
        
        Returns:
            SafetyCheckResult indicating if payload is safe
        """
        if not payload:
            return SafetyCheckResult(
                result=ValidationResult.ALLOWED,
                message="Empty payload"
            )
        
        # Check for destructive patterns
        for pattern in self._destructive_patterns:
            if pattern.search(payload):
                return SafetyCheckResult(
                    result=ValidationResult.BLOCKED,
                    message="Destructive payload pattern detected",
                    details={"pattern": pattern.pattern, "payload": payload[:100]}
                )
        
        # Check for excessive length (potential DoS)
        if len(payload) > 10000:
            if self.safety_level == SafetyLevel.STRICT:
                return SafetyCheckResult(
                    result=ValidationResult.BLOCKED,
                    message="Payload exceeds maximum length",
                    details={"length": len(payload), "max": 10000}
                )
            else:
                return SafetyCheckResult(
                    result=ValidationResult.WARNING,
                    message="Payload is unusually long",
                    details={"length": len(payload)}
                )
        
        # Check for binary content
        try:
            payload.encode("utf-8")
        except UnicodeEncodeError:
            return SafetyCheckResult(
                result=ValidationResult.WARNING,
                message="Payload contains non-UTF-8 characters",
                details={"payload": repr(payload[:50])}
            )
        
        return SafetyCheckResult(
            result=ValidationResult.ALLOWED,
            message="Payload passed safety checks"
        )
    
    def validate_sqli_payload(self, payload: str) -> SafetyCheckResult:
        """Validate SQL injection payload specifically"""
        base_result = self.validate_payload(payload)
        if not base_result.is_allowed:
            return base_result
        
        # Block data modification statements
        dangerous_sql = [
            r"(?i)\b(DROP|DELETE|TRUNCATE|ALTER|CREATE|INSERT|UPDATE)\b",
            r"(?i)\bINTO\s+OUTFILE\b",
            r"(?i)\bLOAD_FILE\b",
            r"(?i)\bINTO\s+DUMPFILE\b",
        ]
        
        if self.safety_level in [SafetyLevel.STRICT, SafetyLevel.STANDARD]:
            for pattern in dangerous_sql:
                if re.search(pattern, payload):
                    return SafetyCheckResult(
                        result=ValidationResult.BLOCKED,
                        message="Data-modifying SQL statement detected",
                        details={"payload": payload[:100]}
                    )
        
        return SafetyCheckResult(
            result=ValidationResult.ALLOWED,
            message="SQLi payload is safe for testing"
        )
    
    def validate_command_payload(self, payload: str) -> SafetyCheckResult:
        """Validate command injection payload"""
        base_result = self.validate_payload(payload)
        if not base_result.is_allowed:
            return base_result
        
        # Block destructive commands
        dangerous_commands = [
            r"(?i)\brm\s+-[rf]",
            r"(?i)\bmkfs\b",
            r"(?i)\bdd\s+if=",
            r"(?i)\b(shutdown|reboot|halt|poweroff)\b",
            r"(?i)\bkill\s+-9\s+-1",
            r"(?i)\b(format|fdisk)\b",
            r"(?i)>\s*/dev/",
            r"(?i)\bchmod\s+777\s+/",
            r"(?i)\bchown.*\s+/",
        ]
        
        for pattern in dangerous_commands:
            if re.search(pattern, payload):
                return SafetyCheckResult(
                    result=ValidationResult.BLOCKED,
                    message="Destructive command pattern detected",
                    details={"payload": payload[:100]}
                )
        
        return SafetyCheckResult(
            result=ValidationResult.ALLOWED,
            message="Command payload is safe for testing"
        )
    
    def sanitize_payload(self, payload: str) -> str:
        """
        Attempt to sanitize a payload by removing dangerous elements.
        
        Note: This is a best-effort sanitization. Always prefer
        using pre-vetted safe payloads.
        """
        # Remove null bytes
        payload = payload.replace("\x00", "")
        
        # Limit length
        if len(payload) > 5000:
            payload = payload[:5000]
        
        return payload


# =============================================================================
# REQUEST SAFETY VALIDATOR
# =============================================================================

class RequestValidator:
    """
    Validates HTTP requests before sending.
    
    Ensures requests follow responsible testing guidelines.
    """
    
    def __init__(
        self,
        scope_validator: Optional[ScopeValidator] = None,
        payload_validator: Optional[PayloadValidator] = None,
        safety_level: SafetyLevel = SafetyLevel.STANDARD
    ):
        self.scope_validator = scope_validator
        self.payload_validator = payload_validator or PayloadValidator(safety_level)
        self.safety_level = safety_level
        self.logger = logging.getLogger("revuex.safety.request")
        
        # Track request counts for rate limiting awareness
        self._request_counts: Dict[str, int] = {}
    
    def validate_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        params: Optional[Dict[str, str]] = None
    ) -> SafetyCheckResult:
        """
        Comprehensive request validation.
        
        Args:
            url: Target URL
            method: HTTP method
            headers: Request headers
            body: Request body
            params: Query parameters
        
        Returns:
            SafetyCheckResult with validation outcome
        """
        # Validate URL/scope
        if self.scope_validator:
            scope_result = self.scope_validator.is_in_scope(url)
            if not scope_result.is_allowed:
                return scope_result
        
        # Validate method
        allowed_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        if method.upper() not in allowed_methods:
            return SafetyCheckResult(
                result=ValidationResult.BLOCKED,
                message=f"HTTP method {method} is not allowed",
                details={"method": method}
            )
        
        # Check for dangerous methods in strict mode
        if self.safety_level == SafetyLevel.STRICT:
            if method.upper() in {"DELETE", "PUT", "PATCH"}:
                return SafetyCheckResult(
                    result=ValidationResult.WARNING,
                    message=f"Data-modifying method {method} requires caution",
                    details={"method": method}
                )
        
        # Validate headers
        if headers:
            for key, value in headers.items():
                # Check for injection in headers
                if "\r" in key or "\n" in key or "\r" in value or "\n" in value:
                    return SafetyCheckResult(
                        result=ValidationResult.BLOCKED,
                        message="CRLF injection detected in headers",
                        details={"header": key}
                    )
        
        # Validate body/payload
        if body:
            payload_result = self.payload_validator.validate_payload(body)
            if not payload_result.is_allowed:
                return payload_result
        
        # Validate query parameters
        if params:
            for key, value in params.items():
                param_result = self.payload_validator.validate_payload(str(value))
                if not param_result.is_allowed:
                    param_result.details["parameter"] = key
                    return param_result
        
        return SafetyCheckResult(
            result=ValidationResult.ALLOWED,
            message="Request passed all safety checks"
        )
    
    def validate_batch(
        self,
        requests: List[Dict]
    ) -> Tuple[List[Dict], List[SafetyCheckResult]]:
        """
        Validate a batch of requests.
        
        Returns:
            Tuple of (valid_requests, blocked_results)
        """
        valid = []
        blocked = []
        
        for req in requests:
            result = self.validate_request(
                url=req.get("url", ""),
                method=req.get("method", "GET"),
                headers=req.get("headers"),
                body=req.get("body"),
                params=req.get("params")
            )
            
            if result.is_allowed:
                valid.append(req)
            else:
                blocked.append(result)
        
        return valid, blocked


# =============================================================================
# DNS REBINDING PROTECTION
# =============================================================================

class DNSRebindingProtector:
    """
    Protection against DNS rebinding attacks.
    
    Resolves domains and validates the resulting IPs
    to prevent DNS rebinding during SSRF testing.
    """
    
    def __init__(self, scope_validator: Optional[ScopeValidator] = None):
        self.scope_validator = scope_validator
        self.logger = logging.getLogger("revuex.safety.dns")
        self._resolution_cache: Dict[str, List[str]] = {}
    
    def resolve_and_validate(self, hostname: str) -> SafetyCheckResult:
        """
        Resolve hostname and validate resulting IPs.
        
        Args:
            hostname: Domain to resolve
        
        Returns:
            SafetyCheckResult with validation outcome
        """
        try:
            # Check cache first
            if hostname in self._resolution_cache:
                ips = self._resolution_cache[hostname]
            else:
                # Resolve hostname
                ips = []
                try:
                    results = socket.getaddrinfo(hostname, None)
                    ips = list(set(result[4][0] for result in results))
                    self._resolution_cache[hostname] = ips
                except socket.gaierror as e:
                    return SafetyCheckResult(
                        result=ValidationResult.WARNING,
                        message=f"DNS resolution failed: {e}",
                        details={"hostname": hostname}
                    )
            
            if not ips:
                return SafetyCheckResult(
                    result=ValidationResult.WARNING,
                    message="No IP addresses resolved",
                    details={"hostname": hostname}
                )
            
            # Validate each resolved IP
            for ip_str in ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    
                    # Check for private IPs
                    if isinstance(ip, ipaddress.IPv4Address):
                        for network in PRIVATE_IP_RANGES:
                            if ip in network:
                                return SafetyCheckResult(
                                    result=ValidationResult.BLOCKED,
                                    message=f"DNS resolves to private IP: {ip_str}",
                                    details={
                                        "hostname": hostname,
                                        "resolved_ip": ip_str,
                                        "is_private": True
                                    }
                                )
                    
                    # Check for cloud metadata
                    if ip_str in CLOUD_METADATA_ENDPOINTS:
                        return SafetyCheckResult(
                            result=ValidationResult.BLOCKED,
                            message=f"DNS resolves to cloud metadata IP: {ip_str}",
                            details={
                                "hostname": hostname,
                                "resolved_ip": ip_str,
                                "is_metadata": True
                            }
                        )
                        
                except ValueError:
                    continue
            
            return SafetyCheckResult(
                result=ValidationResult.ALLOWED,
                message="DNS resolution validated",
                details={"hostname": hostname, "resolved_ips": ips}
            )
            
        except Exception as e:
            self.logger.error(f"DNS validation error: {e}")
            return SafetyCheckResult(
                result=ValidationResult.WARNING,
                message=f"DNS validation error: {str(e)}",
                details={"hostname": hostname}
            )
    
    def clear_cache(self) -> None:
        """Clear DNS resolution cache"""
        self._resolution_cache.clear()


# =============================================================================
# SAFETY MANAGER (UNIFIED INTERFACE)
# =============================================================================

class SafetyManager:
    """
    Unified safety management for REVUEX scanners.
    
    Combines scope validation, payload checking, request validation,
    and DNS rebinding protection into a single interface.
    
    Usage:
        safety = SafetyManager(
            scope=ScopeDefinition(include_domains=["example.com"]),
            safety_level=SafetyLevel.STANDARD
        )
        
        # Validate before making request
        if safety.validate_request(url, method="POST", body=payload):
            # Proceed with request
            pass
    """
    
    def __init__(
        self,
        scope: Optional[ScopeDefinition] = None,
        safety_level: SafetyLevel = SafetyLevel.STANDARD
    ):
        self.safety_level = safety_level
        
        # Initialize validators
        self.scope_validator = ScopeValidator(scope, safety_level)
        self.payload_validator = PayloadValidator(safety_level)
        self.request_validator = RequestValidator(
            self.scope_validator,
            self.payload_validator,
            safety_level
        )
        self.dns_protector = DNSRebindingProtector(self.scope_validator)
        
        self.logger = logging.getLogger("revuex.safety")
    
    def validate_url(self, url: str) -> SafetyCheckResult:
        """Quick URL/scope validation"""
        return self.scope_validator.is_in_scope(url)
    
    def validate_payload(self, payload: str) -> SafetyCheckResult:
        """Quick payload validation"""
        return self.payload_validator.validate_payload(payload)
    
    def validate_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        params: Optional[Dict[str, str]] = None,
        check_dns: bool = False
    ) -> SafetyCheckResult:
        """
        Full request validation.
        
        Args:
            url: Target URL
            method: HTTP method
            headers: Request headers
            body: Request body
            params: Query parameters
            check_dns: Also validate DNS resolution
        
        Returns:
            SafetyCheckResult
        """
        # Basic request validation
        result = self.request_validator.validate_request(
            url, method, headers, body, params
        )
        
        if not result.is_allowed:
            return result
        
        # Optional DNS rebinding check
        if check_dns:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            hostname = parsed.netloc.split(":")[0]
            
            dns_result = self.dns_protector.resolve_and_validate(hostname)
            if not dns_result.is_allowed:
                return dns_result
        
        return result
    
    def is_safe(self, url: str) -> bool:
        """Simple boolean check if URL is safe to request"""
        return self.validate_url(url).is_allowed
    
    def add_to_scope(self, domain: str) -> None:
        """Add domain to scope"""
        self.scope_validator.add_to_scope(domain)
    
    def set_safety_level(self, level: SafetyLevel) -> None:
        """Change safety level"""
        self.safety_level = level
        self.scope_validator.safety_level = level
        self.payload_validator.safety_level = level
        self.request_validator.safety_level = level


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def is_private_ip(ip_string: str) -> bool:
    """Quick check if IP is private"""
    try:
        ip = ipaddress.ip_address(ip_string)
        if isinstance(ip, ipaddress.IPv4Address):
            for network in PRIVATE_IP_RANGES:
                if ip in network:
                    return True
        else:
            for network in PRIVATE_IPV6_RANGES:
                if ip in network:
                    return True
        return False
    except ValueError:
        return False


def is_cloud_metadata(host: str) -> bool:
    """Check if host is a cloud metadata endpoint"""
    return host.lower() in [ep.lower() for ep in CLOUD_METADATA_ENDPOINTS]


def extract_base_domain(url: str) -> str:
    """Extract base domain from URL"""
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}"


def create_default_scope(target: str, include_subdomains: bool = True) -> ScopeDefinition:
    """Create a default scope from a target URL/domain
    
    Args:
        target: Target URL or domain
        include_subdomains: Whether to include subdomains in scope (default: True)
    
    Returns:
        ScopeDefinition with default safe settings
    """
    # Extract base domain
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        domain = parsed.netloc
    else:
        domain = target
    
    # Remove port if present
    if ":" in domain:
        domain = domain.rsplit(":", 1)[0]
    
    # Get base domain
    extracted = tldextract.extract(domain)
    base = f"{extracted.domain}.{extracted.suffix}"
    
    # Build include_domains based on subdomain setting
    if include_subdomains:
        include_domains = [base, f"*.{base}"]
    else:
        include_domains = [base]
    
    return ScopeDefinition(
        include_domains=include_domains,
        allowed_ports={80, 443, 8080, 8443},
        allow_subdomains=include_subdomains,
        allow_private_ips=False,
        allow_cloud_metadata=False
    )


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Main classes
    "SafetyManager",
    "ScopeValidator",
    "PayloadValidator",
    "RequestValidator",
    "DNSRebindingProtector",
    
    # Data classes
    "ScopeDefinition",
    "SafetyCheckResult",
    
    # Enums
    "SafetyLevel",
    "ValidationResult",
    
    # Utility functions
    "is_private_ip",
    "is_cloud_metadata",
    "extract_base_domain",
    "create_default_scope",
    
    # Constants
    "PRIVATE_IP_RANGES",
    "CLOUD_METADATA_ENDPOINTS",
    "DANGEROUS_PORTS",
    "SENSITIVE_PATHS",
]
