#!/usr/bin/env python3
"""
REVUEX - Utilities Module
=========================

Common utility functions used across all REVUEX scanners.

Includes:
- URL manipulation and parsing
- Encoding/decoding utilities
- File operations
- Network helpers
- String manipulation
- Data extraction patterns
- Hashing and checksums
- Time utilities
- Color/formatting helpers

Author: REVUEX Team
License: MIT
"""

import os
import re
import sys
import json
import time
import random
import string
import hashlib
import base64
import binascii
import socket
import ipaddress
import mimetypes
from pathlib import Path
from typing import (
    Optional, List, Dict, Any, Union, Tuple,
    Iterator, Callable, Pattern, Set
)
from urllib.parse import (
    urlparse, urlunparse, urljoin, urlencode,
    parse_qs, parse_qsl, quote, unquote,
    quote_plus, unquote_plus
)
from datetime import datetime, timezone, timedelta
from functools import wraps, lru_cache
from contextlib import contextmanager
import html
import unicodedata

# Optional imports with fallbacks
try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

try:
    import chardet
    HAS_CHARDET = True
except ImportError:
    HAS_CHARDET = False


# =============================================================================
# CONSTANTS
# =============================================================================

# Common file extensions by type
EXTENSION_TYPES = {
    "script": [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
    "style": [".css", ".scss", ".sass", ".less"],
    "markup": [".html", ".htm", ".xhtml", ".xml", ".svg"],
    "data": [".json", ".yaml", ".yml", ".toml", ".csv", ".tsv"],
    "image": [".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svg"],
    "document": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"],
    "archive": [".zip", ".tar", ".gz", ".rar", ".7z", ".bz2"],
    "config": [".conf", ".cfg", ".ini", ".env", ".properties"],
    "code": [".py", ".rb", ".php", ".java", ".go", ".rs", ".c", ".cpp"],
}

# Regex patterns for common data extraction
PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ipv6": re.compile(r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"),
    "url": re.compile(r"https?://[^\s<>\"']+"),
    "domain": re.compile(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"),
    "phone": re.compile(r"[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}"),
    "credit_card": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"),
    "api_key": re.compile(r"(?i)(api[_-]?key|apikey|api_secret|access_token)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_-]{16,})"),
    "aws_key": re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
    "aws_secret": re.compile(r"(?i)aws_?(?:secret_?)?(?:access_?)?key[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9/+]{40})"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    "password": re.compile(r"(?i)(password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?([^\s\"']{4,})"),
    "bearer_token": re.compile(r"(?i)bearer\s+([a-zA-Z0-9_-]+\.?[a-zA-Z0-9_-]*\.?[a-zA-Z0-9_-]*)"),
    "base64": re.compile(r"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"),
    "uuid": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    "hash_md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "hash_sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "hash_sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "github_token": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,}"),
    "google_api": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
}

# HTTP status code categories
HTTP_STATUS = {
    "informational": range(100, 200),
    "success": range(200, 300),
    "redirect": range(300, 400),
    "client_error": range(400, 500),
    "server_error": range(500, 600),
}


# =============================================================================
# URL UTILITIES
# =============================================================================

def normalize_url(url: str, default_scheme: str = "https") -> str:
    """
    Normalize a URL to a consistent format.
    
    Args:
        url: URL to normalize
        default_scheme: Scheme to use if not present
    
    Returns:
        Normalized URL string
    """
    url = url.strip()
    
    # Add scheme if missing
    if not url.startswith(("http://", "https://", "//")):
        url = f"{default_scheme}://{url}"
    elif url.startswith("//"):
        url = f"{default_scheme}:{url}"
    
    # Parse and reconstruct
    parsed = urlparse(url)
    
    # Normalize components
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    
    # Remove default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]
    
    # Remove trailing slash from path (except root)
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    
    # Reconstruct
    normalized = urlunparse((
        scheme,
        netloc,
        path,
        parsed.params,
        parsed.query,
        ""  # Remove fragment
    ))
    
    return normalized


def parse_url(url: str) -> Dict[str, Any]:
    """
    Parse URL into components with additional metadata.
    
    Returns:
        Dictionary with URL components
    """
    parsed = urlparse(url)
    
    # Extract port
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    
    # Extract domain parts
    domain = parsed.netloc
    if ":" in domain:
        domain = domain.rsplit(":", 1)[0]
    
    # Parse query parameters
    params = parse_qs(parsed.query, keep_blank_values=True)
    
    # Get file extension if present
    path = parsed.path
    ext = ""
    if "." in path.split("/")[-1]:
        ext = "." + path.rsplit(".", 1)[-1].lower()
    
    result = {
        "original": url,
        "scheme": parsed.scheme,
        "domain": domain,
        "port": port,
        "path": path,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "params": params,
        "extension": ext,
        "is_https": parsed.scheme == "https",
    }
    
    # Add TLD extraction if available
    if HAS_TLDEXTRACT:
        extracted = tldextract.extract(url)
        result["subdomain"] = extracted.subdomain
        result["registered_domain"] = extracted.registered_domain
        result["tld"] = extracted.suffix
    
    return result


def build_url(
    base: str,
    path: str = "",
    params: Optional[Dict[str, Any]] = None,
    fragment: str = ""
) -> str:
    """
    Build a URL from components.
    
    Args:
        base: Base URL
        path: Path to append
        params: Query parameters
        fragment: URL fragment
    
    Returns:
        Constructed URL
    """
    # Join base and path
    url = urljoin(base, path)
    
    # Parse current URL
    parsed = urlparse(url)
    
    # Merge query parameters
    current_params = dict(parse_qsl(parsed.query))
    if params:
        current_params.update(params)
    
    # Build query string
    query = urlencode(current_params, doseq=True) if current_params else ""
    
    # Reconstruct
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        query,
        fragment
    ))


def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    domain = parsed.netloc
    if ":" in domain:
        domain = domain.rsplit(":", 1)[0]
    return domain.lower()


def extract_base_url(url: str) -> str:
    """Extract base URL (scheme + domain) from full URL"""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def get_url_depth(url: str) -> int:
    """Get the path depth of a URL"""
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    if not path:
        return 0
    return len(path.split("/"))


def extract_parameters(url: str) -> Dict[str, List[str]]:
    """Extract query parameters from URL"""
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def inject_parameter(url: str, param: str, value: str) -> str:
    """Inject or replace a parameter in URL"""
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    params[param] = value
    new_query = urlencode(params)
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))


def remove_parameter(url: str, param: str) -> str:
    """Remove a parameter from URL"""
    parsed = urlparse(url)
    params = [(k, v) for k, v in parse_qsl(parsed.query) if k != param]
    new_query = urlencode(params)
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))


def get_path_variants(url: str) -> List[str]:
    """Generate path traversal variants of a URL"""
    parsed = urlparse(url)
    path_parts = [p for p in parsed.path.split("/") if p]
    
    variants = []
    for i in range(len(path_parts)):
        partial_path = "/" + "/".join(path_parts[:i+1])
        variants.append(urlunparse((
            parsed.scheme,
            parsed.netloc,
            partial_path,
            "", "", ""
        )))
    
    return variants


def is_same_origin(url1: str, url2: str) -> bool:
    """Check if two URLs have the same origin"""
    p1 = urlparse(url1)
    p2 = urlparse(url2)
    
    port1 = p1.port or (443 if p1.scheme == "https" else 80)
    port2 = p2.port or (443 if p2.scheme == "https" else 80)
    
    return (
        p1.scheme == p2.scheme and
        p1.netloc.split(":")[0] == p2.netloc.split(":")[0] and
        port1 == port2
    )


# =============================================================================
# ENCODING UTILITIES
# =============================================================================

def url_encode(text: str, safe: str = "") -> str:
    """URL encode a string"""
    return quote(text, safe=safe)


def url_decode(text: str) -> str:
    """URL decode a string"""
    return unquote(text)


def double_url_encode(text: str) -> str:
    """Double URL encode a string"""
    return quote(quote(text, safe=""), safe="")


def base64_encode(data: Union[str, bytes]) -> str:
    """Base64 encode data"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("utf-8")


def base64_decode(data: str) -> bytes:
    """Base64 decode data"""
    # Add padding if needed
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    return base64.b64decode(data)


def base64_decode_safe(data: str) -> Optional[str]:
    """Safely decode base64, returning None on failure"""
    try:
        decoded = base64_decode(data)
        return decoded.decode("utf-8")
    except Exception:
        return None


def hex_encode(data: Union[str, bytes]) -> str:
    """Hex encode data"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return binascii.hexlify(data).decode("utf-8")


def hex_decode(data: str) -> bytes:
    """Hex decode data"""
    return binascii.unhexlify(data)


def html_encode(text: str) -> str:
    """HTML entity encode"""
    return html.escape(text)


def html_decode(text: str) -> str:
    """HTML entity decode"""
    return html.unescape(text)


def unicode_encode(text: str, form: str = "NFC") -> str:
    """Unicode normalize text"""
    return unicodedata.normalize(form, text)


def to_json(data: Any, pretty: bool = False) -> str:
    """Convert data to JSON string"""
    if pretty:
        return json.dumps(data, indent=2, default=str, ensure_ascii=False)
    return json.dumps(data, default=str, ensure_ascii=False)


def from_json(text: str) -> Any:
    """Parse JSON string"""
    return json.loads(text)


def safe_json_loads(text: str, default: Any = None) -> Any:
    """Safely parse JSON, returning default on failure"""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return default


# =============================================================================
# HASHING UTILITIES
# =============================================================================

def md5(data: Union[str, bytes]) -> str:
    """Calculate MD5 hash"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.md5(data).hexdigest()


def sha1(data: Union[str, bytes]) -> str:
    """Calculate SHA1 hash"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha1(data).hexdigest()


def sha256(data: Union[str, bytes]) -> str:
    """Calculate SHA256 hash"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha512(data: Union[str, bytes]) -> str:
    """Calculate SHA512 hash"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha512(data).hexdigest()


def hash_file(filepath: str, algorithm: str = "sha256") -> str:
    """Calculate hash of a file"""
    h = hashlib.new(algorithm)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_hash_id(data: str, length: int = 16) -> str:
    """Generate a short hash ID from data"""
    return sha256(data)[:length]


# =============================================================================
# STRING UTILITIES
# =============================================================================

def random_string(
    length: int = 16,
    charset: str = string.ascii_letters + string.digits
) -> str:
    """Generate a random string"""
    return "".join(random.choice(charset) for _ in range(length))


def random_hex(length: int = 16) -> str:
    """Generate a random hex string"""
    return "".join(random.choice("0123456789abcdef") for _ in range(length))


def random_email(domain: str = "example.com") -> str:
    """Generate a random email address"""
    username = random_string(8, string.ascii_lowercase)
    return f"{username}@{domain}"


def random_user_agent() -> str:
    """Generate a random user agent string"""
    from .base_scanner import USER_AGENTS
    return random.choice(USER_AGENTS)


def truncate(text: str, length: int = 100, suffix: str = "...") -> str:
    """Truncate text to specified length"""
    if len(text) <= length:
        return text
    return text[:length - len(suffix)] + suffix


def clean_string(text: str) -> str:
    """Clean and normalize a string"""
    # Remove null bytes
    text = text.replace("\x00", "")
    # Normalize whitespace
    text = " ".join(text.split())
    return text.strip()


def extract_between(text: str, start: str, end: str) -> List[str]:
    """Extract all substrings between start and end markers"""
    pattern = re.escape(start) + r"(.*?)" + re.escape(end)
    return re.findall(pattern, text, re.DOTALL)


def count_occurrences(text: str, substring: str, case_sensitive: bool = True) -> int:
    """Count occurrences of substring in text"""
    if not case_sensitive:
        text = text.lower()
        substring = substring.lower()
    return text.count(substring)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein edit distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def similarity_ratio(s1: str, s2: str) -> float:
    """Calculate similarity ratio between two strings (0.0 to 1.0)"""
    distance = levenshtein_distance(s1, s2)
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    return 1.0 - (distance / max_len)


# =============================================================================
# DATA EXTRACTION
# =============================================================================

def extract_emails(text: str) -> List[str]:
    """Extract email addresses from text"""
    return list(set(PATTERNS["email"].findall(text)))


def extract_urls(text: str) -> List[str]:
    """Extract URLs from text"""
    return list(set(PATTERNS["url"].findall(text)))


def extract_ips(text: str) -> List[str]:
    """Extract IP addresses from text"""
    ipv4 = PATTERNS["ipv4"].findall(text)
    ipv6 = PATTERNS["ipv6"].findall(text)
    return list(set(ipv4 + ipv6))


def extract_domains(text: str) -> List[str]:
    """Extract domain names from text"""
    domains = PATTERNS["domain"].findall(text)
    # Filter out common false positives
    filtered = [d for d in domains if not d.startswith(("0.", "1.", "2."))]
    return list(set(filtered))


def extract_jwts(text: str) -> List[str]:
    """Extract JWT tokens from text"""
    return list(set(PATTERNS["jwt"].findall(text)))


def extract_secrets(text: str) -> Dict[str, List[str]]:
    """
    Extract potential secrets from text.
    
    Returns:
        Dictionary mapping secret type to list of found secrets
    """
    secrets = {}
    
    secret_patterns = [
        ("api_key", PATTERNS["api_key"]),
        ("aws_key", PATTERNS["aws_key"]),
        ("aws_secret", PATTERNS["aws_secret"]),
        ("private_key", PATTERNS["private_key"]),
        ("password", PATTERNS["password"]),
        ("bearer_token", PATTERNS["bearer_token"]),
        ("jwt", PATTERNS["jwt"]),
        ("github_token", PATTERNS["github_token"]),
        ("slack_token", PATTERNS["slack_token"]),
        ("google_api", PATTERNS["google_api"]),
    ]
    
    for name, pattern in secret_patterns:
        matches = pattern.findall(text)
        if matches:
            # Handle tuple results from groups
            if matches and isinstance(matches[0], tuple):
                matches = [m[-1] for m in matches]  # Get last group
            secrets[name] = list(set(matches))
    
    return secrets


def extract_by_pattern(text: str, pattern: Union[str, Pattern]) -> List[str]:
    """Extract matches using custom pattern"""
    if isinstance(pattern, str):
        pattern = re.compile(pattern)
    return pattern.findall(text)


# =============================================================================
# FILE UTILITIES
# =============================================================================

def read_file(filepath: str, encoding: str = "utf-8") -> str:
    """Read file contents"""
    with open(filepath, "r", encoding=encoding) as f:
        return f.read()


def read_file_lines(filepath: str, encoding: str = "utf-8") -> List[str]:
    """Read file as list of lines"""
    with open(filepath, "r", encoding=encoding) as f:
        return [line.strip() for line in f if line.strip()]


def write_file(filepath: str, content: str, encoding: str = "utf-8") -> None:
    """Write content to file"""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", encoding=encoding) as f:
        f.write(content)


def append_file(filepath: str, content: str, encoding: str = "utf-8") -> None:
    """Append content to file"""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "a", encoding=encoding) as f:
        f.write(content)


def read_json_file(filepath: str) -> Any:
    """Read JSON file"""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json_file(filepath: str, data: Any, pretty: bool = True) -> None:
    """Write data to JSON file"""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        if pretty:
            json.dump(data, f, indent=2, default=str, ensure_ascii=False)
        else:
            json.dump(data, f, default=str, ensure_ascii=False)


def ensure_dir(dirpath: str) -> Path:
    """Ensure directory exists"""
    path = Path(dirpath)
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_file_extension(filepath: str) -> str:
    """Get file extension"""
    return Path(filepath).suffix.lower()


def get_file_size(filepath: str) -> int:
    """Get file size in bytes"""
    return Path(filepath).stat().st_size


def file_exists(filepath: str) -> bool:
    """Check if file exists"""
    return Path(filepath).is_file()


def get_mime_type(filepath: str) -> str:
    """Get MIME type of file"""
    mime_type, _ = mimetypes.guess_type(filepath)
    return mime_type or "application/octet-stream"


def detect_encoding(data: bytes) -> str:
    """Detect encoding of bytes data"""
    if HAS_CHARDET:
        result = chardet.detect(data)
        return result.get("encoding", "utf-8") or "utf-8"
    return "utf-8"


# =============================================================================
# NETWORK UTILITIES
# =============================================================================

def is_valid_ip(ip: str) -> bool:
    """Check if string is valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    """Check if string is valid CIDR notation"""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def expand_cidr(cidr: str) -> List[str]:
    """Expand CIDR to list of IPs (limited to /24 or smaller)"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.num_addresses > 256:
            raise ValueError("CIDR range too large (max /24)")
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def resolve_hostname(hostname: str) -> List[str]:
    """Resolve hostname to IP addresses"""
    try:
        results = socket.getaddrinfo(hostname, None)
        return list(set(result[4][0] for result in results))
    except socket.gaierror:
        return []


def reverse_dns(ip: str) -> Optional[str]:
    """Reverse DNS lookup"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if port is open on host"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error:
        return False


def get_http_status_category(status_code: int) -> str:
    """Get HTTP status code category"""
    for category, range_obj in HTTP_STATUS.items():
        if status_code in range_obj:
            return category
    return "unknown"


def is_success_status(status_code: int) -> bool:
    """Check if HTTP status indicates success"""
    return status_code in HTTP_STATUS["success"]


def is_redirect_status(status_code: int) -> bool:
    """Check if HTTP status indicates redirect"""
    return status_code in HTTP_STATUS["redirect"]


def is_error_status(status_code: int) -> bool:
    """Check if HTTP status indicates error"""
    return (
        status_code in HTTP_STATUS["client_error"] or
        status_code in HTTP_STATUS["server_error"]
    )


# =============================================================================
# TIME UTILITIES
# =============================================================================

def get_timestamp() -> str:
    """Get current ISO timestamp"""
    return datetime.now(timezone.utc).isoformat()


def get_timestamp_formatted(fmt: str = "%Y%m%d_%H%M%S") -> str:
    """Get formatted timestamp"""
    return datetime.now().strftime(fmt)


def parse_timestamp(timestamp: str) -> datetime:
    """Parse ISO timestamp"""
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def time_ago(seconds: float) -> str:
    """Convert seconds to human-readable time ago"""
    if seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hours"
    else:
        return f"{int(seconds / 86400)} days"


def format_duration(seconds: float) -> str:
    """Format duration in human-readable format"""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"
    else:
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return f"{hours}h {minutes}m"


@contextmanager
def timer():
    """Context manager for timing code blocks"""
    start = time.time()
    yield lambda: time.time() - start


def sleep_with_jitter(base_delay: float, jitter: float = 0.3) -> None:
    """Sleep with random jitter to avoid detection patterns"""
    actual_delay = base_delay * (1 + random.uniform(-jitter, jitter))
    time.sleep(max(0, actual_delay))


# =============================================================================
# COLOR/FORMATTING UTILITIES
# =============================================================================

class Colors:
    """ANSI color codes for terminal output"""
    
    # Reset
    RESET = "\033[0m"
    
    # Regular colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Bright colors
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    
    # Styles
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"
    
    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY output)"""
        for attr in dir(cls):
            if attr.isupper() and not attr.startswith("_"):
                setattr(cls, attr, "")


def colorize(text: str, color: str, bold: bool = False) -> str:
    """Apply color to text"""
    style = Colors.BOLD if bold else ""
    return f"{style}{color}{text}{Colors.RESET}"


def print_colored(text: str, color: str, bold: bool = False, **kwargs) -> None:
    """Print colored text"""
    print(colorize(text, color, bold), **kwargs)


def print_success(message: str) -> None:
    """Print success message"""
    print(f"{Colors.GREEN}[+] {message}{Colors.RESET}")


def print_error(message: str) -> None:
    """Print error message"""
    print(f"{Colors.RED}[-] {message}{Colors.RESET}")


def print_warning(message: str) -> None:
    """Print warning message"""
    print(f"{Colors.YELLOW}[!] {message}{Colors.RESET}")


def print_info(message: str) -> None:
    """Print info message"""
    print(f"{Colors.BLUE}[*] {message}{Colors.RESET}")


def print_debug(message: str) -> None:
    """Print debug message"""
    print(f"{Colors.BRIGHT_BLACK}[D] {message}{Colors.RESET}")


# Disable colors if not TTY
if not sys.stdout.isatty():
    Colors.disable()


# =============================================================================
# DECORATORS
# =============================================================================

def retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: Tuple = (Exception,)
) -> Callable:
    """Decorator for retrying failed functions"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            current_delay = delay
            
            while attempt < max_attempts:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    attempt += 1
                    if attempt >= max_attempts:
                        raise
                    time.sleep(current_delay)
                    current_delay *= backoff
            
            return None
        return wrapper
    return decorator


def memoize(func: Callable) -> Callable:
    """Simple memoization decorator"""
    cache = {}
    
    @wraps(func)
    def wrapper(*args):
        if args not in cache:
            cache[args] = func(*args)
        return cache[args]
    
    wrapper.cache = cache
    wrapper.clear_cache = lambda: cache.clear()
    return wrapper


def timed(func: Callable) -> Callable:
    """Decorator to time function execution"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        print(f"{func.__name__} took {format_duration(elapsed)}")
        return result
    return wrapper


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # URL utilities
    "normalize_url",
    "parse_url",
    "build_url",
    "extract_domain",
    "extract_base_url",
    "get_url_depth",
    "extract_parameters",
    "inject_parameter",
    "remove_parameter",
    "get_path_variants",
    "is_same_origin",
    
    # Encoding utilities
    "url_encode",
    "url_decode",
    "double_url_encode",
    "base64_encode",
    "base64_decode",
    "base64_decode_safe",
    "hex_encode",
    "hex_decode",
    "html_encode",
    "html_decode",
    "unicode_encode",
    "to_json",
    "from_json",
    "safe_json_loads",
    
    # Hashing utilities
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "hash_file",
    "generate_hash_id",
    
    # String utilities
    "random_string",
    "random_hex",
    "random_email",
    "random_user_agent",
    "truncate",
    "clean_string",
    "extract_between",
    "count_occurrences",
    "levenshtein_distance",
    "similarity_ratio",
    
    # Data extraction
    "extract_emails",
    "extract_urls",
    "extract_ips",
    "extract_domains",
    "extract_jwts",
    "extract_secrets",
    "extract_by_pattern",
    "PATTERNS",
    
    # File utilities
    "read_file",
    "read_file_lines",
    "write_file",
    "append_file",
    "read_json_file",
    "write_json_file",
    "ensure_dir",
    "get_file_extension",
    "get_file_size",
    "file_exists",
    "get_mime_type",
    "detect_encoding",
    
    # Network utilities
    "is_valid_ip",
    "is_valid_cidr",
    "expand_cidr",
    "resolve_hostname",
    "reverse_dns",
    "is_port_open",
    "get_http_status_category",
    "is_success_status",
    "is_redirect_status",
    "is_error_status",
    
    # Time utilities
    "get_timestamp",
    "get_timestamp_formatted",
    "parse_timestamp",
    "time_ago",
    "format_duration",
    "timer",
    "sleep_with_jitter",
    
    # Color/formatting
    "Colors",
    "colorize",
    "print_colored",
    "print_success",
    "print_error",
    "print_warning",
    "print_info",
    "print_debug",
    
    # Decorators
    "retry",
    "memoize",
    "timed",
    
    # Constants
    "EXTENSION_TYPES",
    "HTTP_STATUS",
]