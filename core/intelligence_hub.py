#!/usr/bin/env python3
"""
REVUEX - Intelligence Hub Module
================================

Cross-tool intelligence sharing system for bug bounty automation.

The Intelligence Hub enables REVUEX scanners to share discovered data,
reducing redundant requests and improving detection capabilities.

Features:
- Endpoint discovery sharing
- Parameter intelligence
- Technology fingerprint database
- Credential/token tracking
- Finding correlation
- Session state management
- Persistent storage (SQLite)
- In-memory caching for performance
- Cross-scanner communication
- Historical data analysis

Author: REVUEX Team
License: MIT
"""

import os
import json
import sqlite3
import hashlib
import threading
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Set, Tuple, Union
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from collections import defaultdict
from contextlib import contextmanager
import re

# Optional imports
try:
    from urllib.parse import urlparse, urljoin, parse_qs
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False


# =============================================================================
# CONSTANTS
# =============================================================================

DEFAULT_DB_PATH = "intelligence.db"
DEFAULT_CACHE_TTL = 3600  # 1 hour
MAX_CACHE_SIZE = 10000

# Intelligence categories
INTEL_CATEGORIES = [
    "endpoint",
    "parameter",
    "technology",
    "credential",
    "finding",
    "header",
    "cookie",
    "form",
    "api",
    "subdomain",
    "email",
    "secret",
]

# Parameter types for classification
PARAM_TYPES = {
    "id": ["id", "uid", "user_id", "userid", "account", "acc"],
    "auth": ["token", "auth", "key", "api_key", "apikey", "secret", "password", "pwd"],
    "file": ["file", "path", "filename", "document", "doc", "upload", "download"],
    "url": ["url", "uri", "link", "redirect", "next", "return", "callback", "goto"],
    "search": ["q", "query", "search", "keyword", "term", "s"],
    "page": ["page", "p", "offset", "limit", "start", "count", "size"],
    "sort": ["sort", "order", "orderby", "sortby", "dir", "direction"],
    "filter": ["filter", "category", "type", "status", "tag"],
    "data": ["data", "json", "xml", "payload", "body", "content"],
    "debug": ["debug", "test", "dev", "verbose", "trace"],
}

# Technology signatures for fingerprinting
TECH_SIGNATURES = {
    "php": {
        "headers": ["x-powered-by: php"],
        "cookies": ["phpsessid"],
        "extensions": [".php", ".php3", ".php4", ".php5", ".phtml"],
        "patterns": [r"\.php\?", r"php error", r"<?php"],
    },
    "asp.net": {
        "headers": ["x-powered-by: asp.net", "x-aspnet-version"],
        "cookies": ["asp.net_sessionid", "aspxauth"],
        "extensions": [".aspx", ".ashx", ".asmx", ".axd"],
        "patterns": [r"__viewstate", r"__eventvalidation"],
    },
    "java": {
        "headers": ["x-powered-by: servlet", "x-powered-by: jsp"],
        "cookies": ["jsessionid"],
        "extensions": [".jsp", ".jsf", ".do", ".action"],
        "patterns": [r"java\.lang\.", r"struts", r"spring"],
    },
    "python": {
        "headers": ["x-powered-by: python", "server: gunicorn", "server: uvicorn"],
        "cookies": ["session"],
        "extensions": [".py"],
        "patterns": [r"django", r"flask", r"fastapi", r"traceback"],
    },
    "nodejs": {
        "headers": ["x-powered-by: express"],
        "cookies": ["connect.sid"],
        "extensions": [".js"],
        "patterns": [r"node", r"express", r"npm"],
    },
    "ruby": {
        "headers": ["x-powered-by: phusion passenger", "server: puma"],
        "cookies": ["_session_id"],
        "extensions": [".rb", ".erb"],
        "patterns": [r"rails", r"sinatra", r"ruby"],
    },
    "nginx": {
        "headers": ["server: nginx"],
        "patterns": [r"nginx"],
    },
    "apache": {
        "headers": ["server: apache"],
        "patterns": [r"apache", r"mod_"],
    },
    "iis": {
        "headers": ["server: microsoft-iis"],
        "patterns": [r"iis", r"microsoft"],
    },
    "cloudflare": {
        "headers": ["server: cloudflare", "cf-ray"],
        "cookies": ["__cfduid", "__cf_bm"],
    },
    "aws": {
        "headers": ["x-amz-", "x-amzn-"],
        "patterns": [r"amazonaws\.com", r"aws", r"s3\."],
    },
    "wordpress": {
        "patterns": [r"wp-content", r"wp-includes", r"wp-admin", r"wordpress"],
        "cookies": ["wordpress_"],
    },
    "drupal": {
        "headers": ["x-drupal-"],
        "cookies": ["drupal"],
        "patterns": [r"drupal", r"sites/default"],
    },
    "joomla": {
        "patterns": [r"joomla", r"/administrator/", r"com_content"],
    },
}


# =============================================================================
# DATA CLASSES
# =============================================================================

class IntelType(Enum):
    """Intelligence data types"""
    ENDPOINT = auto()
    PARAMETER = auto()
    TECHNOLOGY = auto()
    CREDENTIAL = auto()
    FINDING = auto()
    HEADER = auto()
    COOKIE = auto()
    FORM = auto()
    API = auto()
    SUBDOMAIN = auto()
    EMAIL = auto()
    SECRET = auto()


@dataclass
class Endpoint:
    """Discovered endpoint"""
    url: str
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    parameters: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    discovered_by: str = ""
    timestamp: str = ""
    response_hash: str = ""
    is_authenticated: bool = False
    is_api: bool = False
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.response_hash and self.url:
            self.response_hash = hashlib.md5(f"{self.url}{self.method}".encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Parameter:
    """Discovered parameter with context"""
    name: str
    value: str = ""
    param_type: str = "unknown"  # id, auth, file, url, search, etc.
    location: str = "query"  # query, body, header, cookie, path
    endpoint: str = ""
    is_reflected: bool = False
    is_stored: bool = False
    encoding: str = ""
    discovered_by: str = ""
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if self.param_type == "unknown":
            self.param_type = self._classify_param()
    
    def _classify_param(self) -> str:
        """Auto-classify parameter type based on name"""
        name_lower = self.name.lower()
        for ptype, keywords in PARAM_TYPES.items():
            if any(kw in name_lower for kw in keywords):
                return ptype
        return "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Technology:
    """Detected technology/framework"""
    name: str
    version: str = ""
    category: str = ""  # server, framework, cms, cdn, etc.
    confidence: float = 1.0
    evidence: List[str] = field(default_factory=list)
    cpe: str = ""  # Common Platform Enumeration
    discovered_by: str = ""
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Credential:
    """Discovered credential/token"""
    cred_type: str  # api_key, jwt, password, token, etc.
    value: str
    context: str = ""  # Where it was found
    is_valid: bool = False
    is_expired: bool = False
    scope: str = ""
    discovered_by: str = ""
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
    
    @property
    def masked_value(self) -> str:
        """Return masked credential for safe logging"""
        if len(self.value) <= 8:
            return "*" * len(self.value)
        return self.value[:4] + "*" * (len(self.value) - 8) + self.value[-4:]
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["masked_value"] = self.masked_value
        return data


@dataclass
class IntelQuery:
    """Query parameters for intelligence retrieval"""
    intel_type: Optional[IntelType] = None
    domain: str = ""
    scanner: str = ""
    since: Optional[datetime] = None
    limit: int = 100
    include_expired: bool = False


# =============================================================================
# INTELLIGENCE HUB CLASS
# =============================================================================

class IntelligenceHub:
    """
    Central intelligence sharing system for REVUEX scanners.
    
    Enables cross-tool communication and data sharing to:
    - Reduce redundant HTTP requests
    - Share discovered endpoints and parameters
    - Track technology fingerprints
    - Correlate findings across scanners
    - Maintain persistent knowledge base
    
    Usage:
        hub = IntelligenceHub(db_path="intel.db")
        
        # Add discovered endpoint
        hub.add_endpoint(Endpoint(
            url="https://example.com/api/users",
            method="GET",
            discovered_by="subdomain_hunter"
        ))
        
        # Query endpoints for a domain
        endpoints = hub.get_endpoints(domain="example.com")
        
        # Add parameter intelligence
        hub.add_parameter(Parameter(
            name="user_id",
            param_type="id",
            endpoint="https://example.com/api/users"
        ))
        
        # Get interesting parameters for IDOR testing
        idor_params = hub.get_parameters(param_type="id")
    """
    
    def __init__(
        self,
        db_path: Optional[str] = None,
        in_memory: bool = False,
        cache_ttl: int = DEFAULT_CACHE_TTL,
        auto_save: bool = True
    ):
        """
        Initialize the Intelligence Hub.
        
        Args:
            db_path: Path to SQLite database (None for default)
            in_memory: Use in-memory database only
            cache_ttl: Cache time-to-live in seconds
            auto_save: Automatically persist changes
        """
        self.db_path = ":memory:" if in_memory else (db_path or DEFAULT_DB_PATH)
        self.cache_ttl = cache_ttl
        self.auto_save = auto_save
        
        # In-memory caches
        self._endpoint_cache: Dict[str, Endpoint] = {}
        self._parameter_cache: Dict[str, Parameter] = {}
        self._technology_cache: Dict[str, Technology] = {}
        self._credential_cache: Dict[str, Credential] = {}
        
        # Domain-based indexes for fast lookup
        self._domain_endpoints: Dict[str, Set[str]] = defaultdict(set)
        self._domain_params: Dict[str, Set[str]] = defaultdict(set)
        self._domain_techs: Dict[str, Set[str]] = defaultdict(set)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Statistics
        self._stats = {
            "endpoints_added": 0,
            "parameters_added": 0,
            "technologies_added": 0,
            "credentials_added": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "db_queries": 0,
        }
        
        # Initialize database
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize SQLite database schema"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Endpoints table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS endpoints (
                    id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    method TEXT DEFAULT 'GET',
                    status_code INTEGER,
                    content_type TEXT,
                    content_length INTEGER,
                    parameters TEXT,
                    headers TEXT,
                    technologies TEXT,
                    discovered_by TEXT,
                    timestamp TEXT,
                    response_hash TEXT,
                    is_authenticated INTEGER DEFAULT 0,
                    is_api INTEGER DEFAULT 0,
                    domain TEXT,
                    UNIQUE(url, method)
                )
            """)
            
            # Parameters table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS parameters (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    value TEXT,
                    param_type TEXT,
                    location TEXT,
                    endpoint TEXT,
                    is_reflected INTEGER DEFAULT 0,
                    is_stored INTEGER DEFAULT 0,
                    encoding TEXT,
                    discovered_by TEXT,
                    timestamp TEXT,
                    domain TEXT,
                    UNIQUE(name, endpoint, location)
                )
            """)
            
            # Technologies table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS technologies (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    version TEXT,
                    category TEXT,
                    confidence REAL,
                    evidence TEXT,
                    cpe TEXT,
                    discovered_by TEXT,
                    timestamp TEXT,
                    domain TEXT,
                    UNIQUE(name, domain)
                )
            """)
            
            # Credentials table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id TEXT PRIMARY KEY,
                    cred_type TEXT NOT NULL,
                    value_hash TEXT NOT NULL,
                    context TEXT,
                    is_valid INTEGER DEFAULT 0,
                    is_expired INTEGER DEFAULT 0,
                    scope TEXT,
                    discovered_by TEXT,
                    timestamp TEXT,
                    domain TEXT
                )
            """)
            
            # Findings correlation table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS finding_correlations (
                    id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL,
                    related_finding_id TEXT NOT NULL,
                    correlation_type TEXT,
                    confidence REAL,
                    timestamp TEXT
                )
            """)
            
            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_domain ON endpoints(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_discovered ON endpoints(discovered_by)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_parameters_type ON parameters(param_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_parameters_domain ON parameters(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_technologies_domain ON technologies(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_technologies_name ON technologies(name)")
            
            conn.commit()
    
    @contextmanager
    def _get_connection(self):
        """Get database connection with context management"""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return ""
    
    def _generate_id(self, *args) -> str:
        """Generate unique ID from arguments"""
        data = "|".join(str(arg) for arg in args)
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    # =========================================================================
    # ENDPOINT MANAGEMENT
    # =========================================================================
    
    def add_endpoint(self, endpoint: Endpoint) -> bool:
        """
        Add discovered endpoint to intelligence hub.
        
        Args:
            endpoint: Endpoint object to add
        
        Returns:
            True if added (new), False if already exists
        """
        with self._lock:
            endpoint_id = self._generate_id(endpoint.url, endpoint.method)
            
            # Check cache first
            if endpoint_id in self._endpoint_cache:
                self._stats["cache_hits"] += 1
                return False
            
            domain = self._extract_domain(endpoint.url)
            
            # Add to cache
            self._endpoint_cache[endpoint_id] = endpoint
            self._domain_endpoints[domain].add(endpoint_id)
            
            # Persist to database
            if self.auto_save:
                self._save_endpoint(endpoint, endpoint_id, domain)
            
            self._stats["endpoints_added"] += 1
            return True
    
    def _save_endpoint(self, endpoint: Endpoint, endpoint_id: str, domain: str) -> None:
        """Save endpoint to database"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO endpoints 
                    (id, url, method, status_code, content_type, content_length,
                     parameters, headers, technologies, discovered_by, timestamp,
                     response_hash, is_authenticated, is_api, domain)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    endpoint_id,
                    endpoint.url,
                    endpoint.method,
                    endpoint.status_code,
                    endpoint.content_type,
                    endpoint.content_length,
                    json.dumps(endpoint.parameters),
                    json.dumps(endpoint.headers),
                    json.dumps(endpoint.technologies),
                    endpoint.discovered_by,
                    endpoint.timestamp,
                    endpoint.response_hash,
                    1 if endpoint.is_authenticated else 0,
                    1 if endpoint.is_api else 0,
                    domain
                ))
                conn.commit()
            except sqlite3.IntegrityError:
                pass  # Already exists
    
    def get_endpoints(
        self,
        domain: str = "",
        method: str = "",
        discovered_by: str = "",
        is_api: Optional[bool] = None,
        limit: int = 100
    ) -> List[Endpoint]:
        """
        Query endpoints from intelligence hub.
        
        Args:
            domain: Filter by domain
            method: Filter by HTTP method
            discovered_by: Filter by scanner
            is_api: Filter API endpoints
            limit: Maximum results
        
        Returns:
            List of matching endpoints
        """
        with self._lock:
            # Check cache first for domain queries
            if domain and domain in self._domain_endpoints:
                self._stats["cache_hits"] += 1
                endpoint_ids = self._domain_endpoints[domain]
                results = [
                    self._endpoint_cache[eid]
                    for eid in endpoint_ids
                    if eid in self._endpoint_cache
                ]
                
                # Apply filters
                if method:
                    results = [e for e in results if e.method == method]
                if discovered_by:
                    results = [e for e in results if e.discovered_by == discovered_by]
                if is_api is not None:
                    results = [e for e in results if e.is_api == is_api]
                
                return results[:limit]
            
            # Query database
            self._stats["cache_misses"] += 1
            self._stats["db_queries"] += 1
            
            query = "SELECT * FROM endpoints WHERE 1=1"
            params = []
            
            if domain:
                query += " AND domain = ?"
                params.append(domain)
            if method:
                query += " AND method = ?"
                params.append(method)
            if discovered_by:
                query += " AND discovered_by = ?"
                params.append(discovered_by)
            if is_api is not None:
                query += " AND is_api = ?"
                params.append(1 if is_api else 0)
            
            query += f" ORDER BY timestamp DESC LIMIT {limit}"
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                rows = cursor.fetchall()
            
            endpoints = []
            for row in rows:
                endpoint = Endpoint(
                    url=row["url"],
                    method=row["method"],
                    status_code=row["status_code"] or 0,
                    content_type=row["content_type"] or "",
                    content_length=row["content_length"] or 0,
                    parameters=json.loads(row["parameters"] or "[]"),
                    headers=json.loads(row["headers"] or "{}"),
                    technologies=json.loads(row["technologies"] or "[]"),
                    discovered_by=row["discovered_by"] or "",
                    timestamp=row["timestamp"] or "",
                    response_hash=row["response_hash"] or "",
                    is_authenticated=bool(row["is_authenticated"]),
                    is_api=bool(row["is_api"]),
                )
                endpoints.append(endpoint)
                
                # Update cache
                self._endpoint_cache[row["id"]] = endpoint
                self._domain_endpoints[domain].add(row["id"])
            
            return endpoints
    
    def endpoint_exists(self, url: str, method: str = "GET") -> bool:
        """Check if endpoint already discovered"""
        endpoint_id = self._generate_id(url, method)
        
        with self._lock:
            if endpoint_id in self._endpoint_cache:
                return True
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT 1 FROM endpoints WHERE id = ?",
                    (endpoint_id,)
                )
                return cursor.fetchone() is not None
    
    # =========================================================================
    # PARAMETER MANAGEMENT
    # =========================================================================
    
    def add_parameter(self, parameter: Parameter) -> bool:
        """Add discovered parameter to intelligence hub"""
        with self._lock:
            param_id = self._generate_id(
                parameter.name, parameter.endpoint, parameter.location
            )
            
            if param_id in self._parameter_cache:
                self._stats["cache_hits"] += 1
                return False
            
            domain = self._extract_domain(parameter.endpoint)
            
            self._parameter_cache[param_id] = parameter
            self._domain_params[domain].add(param_id)
            
            if self.auto_save:
                self._save_parameter(parameter, param_id, domain)
            
            self._stats["parameters_added"] += 1
            return True
    
    def _save_parameter(self, parameter: Parameter, param_id: str, domain: str) -> None:
        """Save parameter to database"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO parameters
                    (id, name, value, param_type, location, endpoint,
                     is_reflected, is_stored, encoding, discovered_by, timestamp, domain)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    param_id,
                    parameter.name,
                    parameter.value,
                    parameter.param_type,
                    parameter.location,
                    parameter.endpoint,
                    1 if parameter.is_reflected else 0,
                    1 if parameter.is_stored else 0,
                    parameter.encoding,
                    parameter.discovered_by,
                    parameter.timestamp,
                    domain
                ))
                conn.commit()
            except sqlite3.IntegrityError:
                pass
    
    def get_parameters(
        self,
        domain: str = "",
        param_type: str = "",
        location: str = "",
        is_reflected: Optional[bool] = None,
        limit: int = 100
    ) -> List[Parameter]:
        """Query parameters from intelligence hub"""
        with self._lock:
            # Check cache for domain queries
            if domain and domain in self._domain_params:
                self._stats["cache_hits"] += 1
                param_ids = self._domain_params[domain]
                results = [
                    self._parameter_cache[pid]
                    for pid in param_ids
                    if pid in self._parameter_cache
                ]
                
                if param_type:
                    results = [p for p in results if p.param_type == param_type]
                if location:
                    results = [p for p in results if p.location == location]
                if is_reflected is not None:
                    results = [p for p in results if p.is_reflected == is_reflected]
                
                return results[:limit]
            
            # Query database
            self._stats["cache_misses"] += 1
            self._stats["db_queries"] += 1
            
            query = "SELECT * FROM parameters WHERE 1=1"
            params = []
            
            if domain:
                query += " AND domain = ?"
                params.append(domain)
            if param_type:
                query += " AND param_type = ?"
                params.append(param_type)
            if location:
                query += " AND location = ?"
                params.append(location)
            if is_reflected is not None:
                query += " AND is_reflected = ?"
                params.append(1 if is_reflected else 0)
            
            query += f" LIMIT {limit}"
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                rows = cursor.fetchall()
            
            parameters = []
            for row in rows:
                param = Parameter(
                    name=row["name"],
                    value=row["value"] or "",
                    param_type=row["param_type"] or "unknown",
                    location=row["location"] or "query",
                    endpoint=row["endpoint"] or "",
                    is_reflected=bool(row["is_reflected"]),
                    is_stored=bool(row["is_stored"]),
                    encoding=row["encoding"] or "",
                    discovered_by=row["discovered_by"] or "",
                    timestamp=row["timestamp"] or "",
                )
                parameters.append(param)
            
            return parameters
    
    def get_interesting_parameters(self, domain: str = "") -> Dict[str, List[Parameter]]:
        """
        Get parameters organized by vulnerability potential.
        
        Returns dict with keys: 'idor', 'ssrf', 'sqli', 'xss', 'lfi'
        """
        all_params = self.get_parameters(domain=domain, limit=500)
        
        interesting = {
            "idor": [],    # ID parameters for IDOR testing
            "ssrf": [],    # URL parameters for SSRF testing
            "sqli": [],    # Potential SQL injection points
            "xss": [],     # Reflected parameters for XSS
            "lfi": [],     # File path parameters for LFI
            "auth": [],    # Authentication parameters
        }
        
        for param in all_params:
            if param.param_type == "id":
                interesting["idor"].append(param)
            elif param.param_type == "url":
                interesting["ssrf"].append(param)
            elif param.param_type == "file":
                interesting["lfi"].append(param)
            elif param.param_type == "auth":
                interesting["auth"].append(param)
            
            if param.is_reflected:
                interesting["xss"].append(param)
            
            # SQL injection candidates
            if param.param_type in ["id", "search", "filter", "sort"]:
                interesting["sqli"].append(param)
        
        return interesting
    
    # =========================================================================
    # TECHNOLOGY MANAGEMENT
    # =========================================================================
    
    def add_technology(self, technology: Technology) -> bool:
        """Add detected technology to intelligence hub"""
        with self._lock:
            tech_id = self._generate_id(technology.name)
            
            if tech_id in self._technology_cache:
                # Update if higher confidence
                existing = self._technology_cache[tech_id]
                if technology.confidence > existing.confidence:
                    self._technology_cache[tech_id] = technology
                    if self.auto_save:
                        self._save_technology(technology, tech_id, "")
                return False
            
            self._technology_cache[tech_id] = technology
            
            if self.auto_save:
                self._save_technology(technology, tech_id, "")
            
            self._stats["technologies_added"] += 1
            return True
    
    def _save_technology(self, technology: Technology, tech_id: str, domain: str) -> None:
        """Save technology to database"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO technologies
                    (id, name, version, category, confidence, evidence, cpe,
                     discovered_by, timestamp, domain)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    tech_id,
                    technology.name,
                    technology.version,
                    technology.category,
                    technology.confidence,
                    json.dumps(technology.evidence),
                    technology.cpe,
                    technology.discovered_by,
                    technology.timestamp,
                    domain
                ))
                conn.commit()
            except sqlite3.IntegrityError:
                pass
    
    def get_technologies(self, domain: str = "", category: str = "") -> List[Technology]:
        """Query technologies from intelligence hub"""
        query = "SELECT * FROM technologies WHERE 1=1"
        params = []
        
        if domain:
            query += " AND domain = ?"
            params.append(domain)
        if category:
            query += " AND category = ?"
            params.append(category)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
        
        technologies = []
        for row in rows:
            tech = Technology(
                name=row["name"],
                version=row["version"] or "",
                category=row["category"] or "",
                confidence=row["confidence"] or 1.0,
                evidence=json.loads(row["evidence"] or "[]"),
                cpe=row["cpe"] or "",
                discovered_by=row["discovered_by"] or "",
                timestamp=row["timestamp"] or "",
            )
            technologies.append(tech)
        
        return technologies
    
    def fingerprint_from_response(
        self,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        body: str,
        url: str
    ) -> List[Technology]:
        """
        Auto-detect technologies from HTTP response.
        
        Args:
            headers: Response headers
            cookies: Response cookies
            body: Response body
            url: Request URL
        
        Returns:
            List of detected technologies
        """
        detected = []
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        cookies_lower = {k.lower(): v for k, v in cookies.items()}
        body_lower = body.lower()
        url_lower = url.lower()
        
        for tech_name, signatures in TECH_SIGNATURES.items():
            confidence = 0.0
            evidence = []
            
            # Check headers
            for header_sig in signatures.get("headers", []):
                header_key = header_sig.split(":")[0].strip()
                if header_key in headers_lower:
                    if ":" in header_sig:
                        expected_value = header_sig.split(":", 1)[1].strip()
                        if expected_value in headers_lower[header_key]:
                            confidence += 0.4
                            evidence.append(f"Header: {header_sig}")
                    else:
                        confidence += 0.3
                        evidence.append(f"Header: {header_key}")
            
            # Check cookies
            for cookie_sig in signatures.get("cookies", []):
                if cookie_sig.lower() in cookies_lower:
                    confidence += 0.3
                    evidence.append(f"Cookie: {cookie_sig}")
            
            # Check extensions
            for ext in signatures.get("extensions", []):
                if ext in url_lower:
                    confidence += 0.2
                    evidence.append(f"Extension: {ext}")
            
            # Check patterns
            for pattern in signatures.get("patterns", []):
                if re.search(pattern, body_lower) or re.search(pattern, url_lower):
                    confidence += 0.2
                    evidence.append(f"Pattern: {pattern}")
            
            if confidence > 0:
                tech = Technology(
                    name=tech_name,
                    confidence=min(confidence, 1.0),
                    evidence=evidence,
                    discovered_by="fingerprinter",
                )
                detected.append(tech)
                self.add_technology(tech)
        
        return detected
    
    # =========================================================================
    # CREDENTIAL MANAGEMENT
    # =========================================================================
    
    def add_credential(self, credential: Credential) -> bool:
        """Add discovered credential to intelligence hub"""
        with self._lock:
            value_hash = hashlib.sha256(credential.value.encode()).hexdigest()
            cred_id = self._generate_id(credential.cred_type, value_hash)
            
            if cred_id in self._credential_cache:
                return False
            
            self._credential_cache[cred_id] = credential
            
            if self.auto_save:
                self._save_credential(credential, cred_id, value_hash)
            
            self._stats["credentials_added"] += 1
            return True
    
    def _save_credential(self, credential: Credential, cred_id: str, value_hash: str) -> None:
        """Save credential to database (only stores hash, not actual value)"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO credentials
                    (id, cred_type, value_hash, context, is_valid, is_expired,
                     scope, discovered_by, timestamp, domain)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cred_id,
                    credential.cred_type,
                    value_hash,
                    credential.context,
                    1 if credential.is_valid else 0,
                    1 if credential.is_expired else 0,
                    credential.scope,
                    credential.discovered_by,
                    credential.timestamp,
                    ""
                ))
                conn.commit()
            except sqlite3.IntegrityError:
                pass
    
    # =========================================================================
    # STATISTICS & UTILITIES
    # =========================================================================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get intelligence hub statistics"""
        with self._lock:
            stats = self._stats.copy()
            stats["cache_size"] = {
                "endpoints": len(self._endpoint_cache),
                "parameters": len(self._parameter_cache),
                "technologies": len(self._technology_cache),
                "credentials": len(self._credential_cache),
            }
            
            # Get database counts
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT COUNT(*) FROM endpoints")
                stats["db_endpoints"] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM parameters")
                stats["db_parameters"] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM technologies")
                stats["db_technologies"] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(DISTINCT domain) FROM endpoints")
                stats["unique_domains"] = cursor.fetchone()[0]
            
            return stats
    
    def get_domain_summary(self, domain: str) -> Dict[str, Any]:
        """Get intelligence summary for a domain"""
        endpoints = self.get_endpoints(domain=domain, limit=1000)
        parameters = self.get_parameters(domain=domain, limit=1000)
        technologies = self.get_technologies(domain=domain)
        interesting = self.get_interesting_parameters(domain=domain)
        
        return {
            "domain": domain,
            "endpoints_count": len(endpoints),
            "parameters_count": len(parameters),
            "technologies": [t.name for t in technologies],
            "api_endpoints": len([e for e in endpoints if e.is_api]),
            "authenticated_endpoints": len([e for e in endpoints if e.is_authenticated]),
            "interesting_params": {
                k: len(v) for k, v in interesting.items()
            },
            "unique_params": len(set(p.name for p in parameters)),
        }
    
    def clear_cache(self) -> None:
        """Clear in-memory caches"""
        with self._lock:
            self._endpoint_cache.clear()
            self._parameter_cache.clear()
            self._technology_cache.clear()
            self._credential_cache.clear()
            self._domain_endpoints.clear()
            self._domain_params.clear()
            self._domain_techs.clear()
    
    def export_json(self, filepath: str, domain: str = "") -> None:
        """Export intelligence data to JSON"""
        data = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "statistics": self.get_statistics(),
            "endpoints": [e.to_dict() for e in self.get_endpoints(domain=domain, limit=10000)],
            "parameters": [p.to_dict() for p in self.get_parameters(domain=domain, limit=10000)],
            "technologies": [t.to_dict() for t in self.get_technologies(domain=domain)],
        }
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    
    def import_json(self, filepath: str) -> int:
        """Import intelligence data from JSON"""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        imported = 0
        
        for ep_data in data.get("endpoints", []):
            endpoint = Endpoint(**ep_data)
            if self.add_endpoint(endpoint):
                imported += 1
        
        for param_data in data.get("parameters", []):
            param = Parameter(**param_data)
            if self.add_parameter(param):
                imported += 1
        
        for tech_data in data.get("technologies", []):
            tech = Technology(**tech_data)
            if self.add_technology(tech):
                imported += 1
        
        return imported
    
    def close(self) -> None:
        """Close the intelligence hub and cleanup resources"""
        self.clear_cache()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

# Global hub instance for easy access
_global_hub: Optional[IntelligenceHub] = None


def get_hub(db_path: Optional[str] = None) -> IntelligenceHub:
    """
    Get or create global intelligence hub instance.
    
    Args:
        db_path: Database path (only used on first call)
    
    Returns:
        IntelligenceHub instance
    """
    global _global_hub
    
    if _global_hub is None:
        _global_hub = IntelligenceHub(db_path=db_path)
    
    return _global_hub


def share_endpoint(url: str, method: str = "GET", discovered_by: str = "") -> bool:
    """Quick function to share discovered endpoint"""
    hub = get_hub()
    return hub.add_endpoint(Endpoint(
        url=url,
        method=method,
        discovered_by=discovered_by
    ))


def share_parameter(name: str, endpoint: str, param_type: str = "", discovered_by: str = "") -> bool:
    """Quick function to share discovered parameter"""
    hub = get_hub()
    return hub.add_parameter(Parameter(
        name=name,
        endpoint=endpoint,
        param_type=param_type,
        discovered_by=discovered_by
    ))


def get_known_endpoints(domain: str) -> List[Endpoint]:
    """Quick function to get known endpoints for domain"""
    hub = get_hub()
    return hub.get_endpoints(domain=domain)


def get_attack_surface(domain: str) -> Dict[str, Any]:
    """Get attack surface summary for domain"""
    hub = get_hub()
    return hub.get_domain_summary(domain)


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Main class
    "IntelligenceHub",
    
    # Data classes
    "Endpoint",
    "Parameter",
    "Technology",
    "Credential",
    "IntelType",
    "IntelQuery",
    
    # Convenience functions
    "get_hub",
    "share_endpoint",
    "share_parameter",
    "get_known_endpoints",
    "get_attack_surface",
    
    # Constants
    "INTEL_CATEGORIES",
    "PARAM_TYPES",
    "TECH_SIGNATURES",
]
