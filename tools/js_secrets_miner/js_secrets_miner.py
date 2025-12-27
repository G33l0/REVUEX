#!/usr/bin/env python3
"""
REVUEX JS-Secrets-Miner GOLD v4.0
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
SCANNER_VERSION = "4.0.0"

BANNER = r"""
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
JS-Secrets-Miner GOLD v4.0 - A Client-Side Trust Leak Intelligence
[Enhanced False Positive Filtering]
"""

# Confidence threshold for high-value findings
CONFIDENCE_THRESHOLD = 70

# =============================================================================
# FALSE POSITIVE EXCLUSION PATTERNS (ENHANCED v2.2)
# =============================================================================

# Variable names that indicate UI/translation/config (NOT secrets)
FALSE_POSITIVE_VAR_PATTERNS = [
    r'(?i)^(label|title|description|placeholder|hint|message|text|caption)$',
    r'(?i)^(header|footer|column|row|cell|table|field)_',
    r'(?i)_(label|title|description|placeholder|hint|message|text|name|header)$',
    r'(?i)^(TABLE_|HEADER_|COLUMN_|ROW_|FIELD_|FORM_|INPUT_|BUTTON_|LABEL_)',
    r'(?i)^(SUGGESTION_|TRANSLATION_|I18N_|LOCALE_|MSG_|TXT_|STR_)',
    r'(?i)(DISPLAY|VISIBLE|HIDDEN|ENABLED|DISABLED|READONLY)$',
    r'(?i)^(className|classList|style|css|id|name|type|role|aria)',
    r'(?i)^(onClick|onChange|onSubmit|onLoad|onError|handler|callback)',
    r'(?i)^(width|height|size|margin|padding|border|color|background)',
    r'(?i)^(route|path|url|link|href|src|redirect)$',
    r'(?i)^(status|state|mode|phase|step|stage|version)$',
    # NEW: Exclude step/flow/reducer names that contain keywords
    r'(?i)(Step|Steps|Stage|Phase|Flow|Reducer|Action|Event|Handler)$',
    r'(?i)^(Branded|Signup|SignUp|Login|Register|Checkout|Payment)',
    r'(?i)_(STEP|STEPS|STAGE|PHASE|FLOW|EVENT|ACTION|NAME|TYPE|ID)$',
    r'(?i)^[A-Z][a-z]+[A-Z][a-z]+(Step|Phase|Stage|Event)$',  # CamelCase steps
    # NEW: LocalStorage/SessionStorage key names
    r'(?i)LOCAL_STORAGE_KEY$',
    r'(?i)SESSION_STORAGE_KEY$',
    r'(?i)STORAGE_KEY$',
    r'(?i)^(DARK_MODE|THEME|LANG|LOCALE|USER_PREF)',
    # NEW: Polling/interval config
    r'(?i)(INTERVAL|TIMEOUT|DELAY|RETRIES|RETRY|POLLING)$',
    r'(?i)^(MAX_|MIN_|DEFAULT_)',
    # NEW: URL/HTTP config
    r'(?i)^(HTTP|HTTPS|WS|WSS)_PREFIX$',
    r'(?i)^(API_|BASE_|ROOT_)?(URL|URI|ENDPOINT|HOST|DOMAIN)$',
]

# Value patterns that are clearly NOT secrets
FALSE_POSITIVE_VALUE_PATTERNS = [
    r'(?i)^(true|false|null|undefined|none|n\/a)$',
    r'(?i)^(yes|no|on|off|enabled|disabled)$',
    r'(?i)^(loading|pending|success|error|failed|complete)$',
    r'(?i)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$',
    r'(?i)^(application\/json|text\/html|text\/plain|multipart)',
    r'^[0-9]+$',  # Pure numbers
    r'^[0-9]+\.[0-9]+\.[0-9]+$',  # Version numbers
    r'^#[a-fA-F0-9]{3,8}$',  # CSS colors
    r'^(rgb|rgba|hsl|hsla)\(',  # CSS colors
    r'^\d+px$|^\d+em$|^\d+rem$|^\d+%$',  # CSS units
    r'^(https?:\/\/|\/\/|\/)[^\s]*\.(jpg|jpeg|png|gif|svg|ico|webp)',  # Image URLs
    r'^(https?:\/\/|\/\/|\/)[^\s]*\.(css|js|woff|ttf|eot)',  # Asset URLs
    r'(?i)^(select|insert|update|delete|from|where|and|or)[\s_]',  # SQL fragments
    r'^[\w\s]{50,}$',  # Long text with spaces (likely human readable text)
    # NEW: Common localStorage key values
    r'(?i)^is[A-Z][a-zA-Z]+$',  # isDarkMode, isLoggedIn, etc.
    r'(?i)^(darkMode|lightMode|theme|language|locale|lang)$',
    r'(?i)^[a-z]+_[a-z]+_[a-z]+$',  # snake_case_names (usually config)
    # NEW: Camel case identifiers that are NOT secrets
    r'^[a-z]+[A-Z][a-zA-Z]+$',  # camelCaseNames without numbers
    # NEW: Simple short strings that can't be secrets
    r'^[a-zA-Z]{1,12}$',  # Short alpha-only strings
    r'^[a-z]{2}$',  # Language codes (en, es, de, etc.)
    r'^[A-Z]{2}$',  # Country codes (US, ES, GB, etc.)
]

# Known safe values that should NEVER be flagged
KNOWN_SAFE_VALUES = {
    # Fetch/HTTP config
    "same-origin", "include", "omit", "cors", "no-cors", "navigate",
    "default", "no-store", "reload", "no-cache", "force-cache", "only-if-cached",
    "follow", "error", "manual",
    "json", "text", "blob", "arraybuffer", "document",
    # HTTP methods
    "get", "post", "put", "delete", "patch", "head", "options",
    # Common config values
    "true", "false", "null", "undefined", "none", "auto",
    # Theme/UI values
    "dark", "light", "system", "auto",
    "isDarkMode", "isLightMode", "darkMode", "lightMode",
    # Common localStorage key names
    "theme", "language", "locale", "lang", "token", "user", "auth",
    # URL prefixes
    "http://", "https://", "ws://", "wss://", "//",
}

# Context patterns that indicate false positives (surrounding code)
FALSE_POSITIVE_CONTEXT_PATTERNS = [
    r'label\s*:\s*["\']',
    r'description\s*:\s*["\']',
    r'placeholder\s*:\s*["\']',
    r'title\s*:\s*["\']',
    r'message\s*:\s*["\']',
    r'text\s*:\s*["\']',
    r'tooltip\s*:\s*["\']',
    r'hint\s*:\s*["\']',
    r'i18n\s*[\[\(]',
    r't\s*\(\s*["\']',  # i18n translation function
    r'translate\s*\(',
    r'formatMessage\s*\(',
    r'\.innerHTML\s*=',
    r'\.textContent\s*=',
    r'\.innerText\s*=',
    r'console\.(log|warn|error|info)',
    r'throw\s+new\s+Error',
    # NEW: Redux/state management
    r'makeReducer\s*\(',
    r'createSlice\s*\(',
    r'createAction\s*\(',
    r'dispatch\s*\(',
    # NEW: Step/flow definitions
    r'Step\s*:\s*["\']',
    r'step\s*:\s*["\']',
    r'phase\s*:\s*["\']',
    r'stage\s*:\s*["\']',
]

# Minimum entropy for a real secret (increased from 4.0 to 4.5)
MIN_SECRET_ENTROPY = 4.5

# Minimum length for high-confidence secrets
MIN_SECRET_LENGTH = 20

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

# =============================================================================
# FALSE POSITIVE EXCLUSION PATTERNS (NEW)
# =============================================================================

# Variable names that are UI/translation keys, NOT secrets
FALSE_POSITIVE_VAR_PATTERNS = [
    r"^(LABEL|TITLE|HEADER|DESCRIPTION|PLACEHOLDER|HINT|MESSAGE|TEXT|BTN|BUTTON)_",
    r"^(TABLE_HEADER|TABLE_FIELD|COLUMN|ROW|CELL)_",
    r"^(SUGGESTION|RECOMMEND|SEARCH|FILTER|SORT)_",
    r"^(ERROR|WARNING|INFO|SUCCESS|ALERT)_",
    r"^(TOOLTIP|MODAL|DIALOG|POPUP|NOTIFICATION)_",
    r"^(NAV|MENU|TAB|SIDEBAR|FOOTER|HEADER)_",
    r"^(FORM|INPUT|SELECT|CHECKBOX|RADIO)_",
    r"^(I18N|LANG|LOCALE|TRANSLATION|TRANS)_",
    r"_(LABEL|TITLE|TEXT|MESSAGE|DESCRIPTION|PLACEHOLDER)$",
    r"_(HEADER|COLUMN|FIELD|NAME|HINT)$",
]

# Values that look like translation keys or UI strings, NOT secrets
FALSE_POSITIVE_VALUE_PATTERNS = [
    r"^(TABLE_|LABEL_|HEADER_|TITLE_|BTN_|BUTTON_|NAV_|MENU_)",
    r"^(SUGGESTION_|DESCRIPTION_|PLACEHOLDER_|TOOLTIP_|ERROR_|WARNING_)",
    r"^(FORM_|INPUT_|SELECT_|MODAL_|DIALOG_|NOTIFICATION_)",
    r"^[A-Z][A-Z0-9_]{5,}$",  # ALL_CAPS_CONSTANT (likely translation key)
    r"^(Click|Submit|Cancel|Save|Delete|Edit|View|Add|Remove|Update)\s",  # UI button text
    r"^(Please|Enter|Select|Choose|Provide|Confirm)\s",  # UI instruction text
    r"^\d+(\.\d+)?$",  # Pure numbers
    r"^(true|false|null|undefined)$",  # JS primitives
    r"^(https?://|mailto:|tel:)",  # URLs (handled separately)
    r"^#[0-9a-fA-F]{3,8}$",  # Color codes
    r"^\d{1,2}px$|^\d{1,3}%$|^\d{1,2}rem$",  # CSS units
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
# FALSE POSITIVE FILTER (ENHANCED - v2.2)
# =============================================================================

class FalsePositiveFilter:
    """
    Advanced false positive detection to eliminate UI labels, 
    translations, and configuration values from secret detection.
    """
    
    def __init__(self):
        # Compile regex patterns for performance
        self.var_patterns = [re.compile(p) for p in FALSE_POSITIVE_VAR_PATTERNS]
        self.value_patterns = [re.compile(p) for p in FALSE_POSITIVE_VALUE_PATTERNS]
        self.context_patterns = [re.compile(p) for p in FALSE_POSITIVE_CONTEXT_PATTERNS]
    
    def is_false_positive(self, var: str, value: str, context: str = "") -> tuple:
        """
        Check if a variable/value pair is likely a false positive.
        
        Returns:
            tuple: (is_false_positive: bool, reason: str)
        """
        # Check 1: Known safe values (exact match)
        if value.lower() in KNOWN_SAFE_VALUES or value in KNOWN_SAFE_VALUES:
            return True, f"Value is a known safe configuration: {value}"
        
        # Check 2: Variable name patterns (UI/config indicators)
        for pattern in self.var_patterns:
            if pattern.search(var):
                return True, f"Variable name matches UI/config pattern: {var}"
        
        # Check 3: Value patterns (non-secret formats)
        for pattern in self.value_patterns:
            if pattern.match(value):
                return True, f"Value matches non-secret pattern: {value[:30]}"
        
        # Check 4: Context patterns (surrounding code indicates config/UI)
        if context:
            for pattern in self.context_patterns:
                if pattern.search(context):
                    return True, f"Context indicates UI/config usage"
        
        # Check 5: Human-readable text detection
        if self._is_human_readable(value):
            return True, "Value appears to be human-readable text"
        
        # Check 6: Entropy check - low entropy = not random = not a secret
        entropy = calculate_entropy(value)
        if entropy < MIN_SECRET_ENTROPY and len(value) < 40:
            return True, f"Low entropy ({entropy:.2f}) - not random enough for secret"
        
        # Check 7: Length check - too short to be a real secret
        if len(value) < MIN_SECRET_LENGTH:
            # Exception: known API key prefixes
            has_known_prefix = any(value.startswith(prefix) for prefix in THIRD_PARTY_HINTS.keys())
            if not has_known_prefix:
                return True, f"Value too short ({len(value)} chars) to be a secret"
        
        # Check 8: Repeated patterns
        if self._has_repeated_pattern(value):
            return True, "Value contains repeated patterns"
        
        # Check 9: ALL_CAPS_SNAKE_CASE constants (likely enum/config names)
        if re.match(r'^[A-Z][A-Z0-9_]{5,}$', value) and '_' in value:
            return True, "Value appears to be a constant name, not a secret"
        
        return False, ""
    
    def _is_human_readable(self, value: str) -> bool:
        """Check if value appears to be human-readable text."""
        # Contains multiple spaces
        if value.count(' ') >= 2:
            return True
        
        # Contains common English words
        common_words = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 
                       'can', 'has', 'her', 'was', 'one', 'our', 'out', 'with',
                       'please', 'enter', 'select', 'click', 'submit', 'cancel',
                       'error', 'success', 'failed', 'invalid', 'required']
        value_lower = value.lower()
        word_count = sum(1 for word in common_words if word in value_lower)
        if word_count >= 2:
            return True
        
        # Mostly lowercase letters with spaces (sentence-like)
        if re.match(r'^[a-z][a-z\s]{10,}$', value.lower()):
            lowercase_ratio = sum(1 for c in value if c.islower()) / len(value)
            if lowercase_ratio > 0.8:
                return True
        
        return False
    
    def _has_repeated_pattern(self, value: str) -> bool:
        """Check for repeated character patterns."""
        if len(value) < 8:
            return False
        
        # Check for repeating sequences
        for pattern_len in range(2, len(value) // 3 + 1):
            pattern = value[:pattern_len]
            if pattern * (len(value) // pattern_len) == value[:pattern_len * (len(value) // pattern_len)]:
                if len(value) // pattern_len >= 3:
                    return True
        
        # Check for too many repeated characters
        char_counts = {}
        for c in value:
            char_counts[c] = char_counts.get(c, 0) + 1
        
        max_repeat = max(char_counts.values())
        if max_repeat / len(value) > 0.5:
            return True
        
        return False
    
    def get_confidence_penalty(self, var: str, value: str) -> int:
        """
        Calculate confidence penalty based on false positive indicators.
        
        Returns:
            int: Negative score adjustment (0 to -50)
        """
        penalty = 0
        
        # Variable name contains UI-related terms
        ui_terms = ['label', 'title', 'text', 'message', 'description', 'header', 
                   'placeholder', 'hint', 'caption', 'display', 'column', 'row']
        var_lower = var.lower()
        for term in ui_terms:
            if term in var_lower:
                penalty -= 15
                break
        
        # Value looks like a constant/enum name
        if re.match(r'^[A-Z][A-Z0-9_]+$', value):
            penalty -= 20
        
        # Value is too short for a real secret
        if len(value) < MIN_SECRET_LENGTH:
            penalty -= 10
        
        # Low entropy
        entropy = calculate_entropy(value)
        if entropy < MIN_SECRET_ENTROPY:
            penalty -= int((MIN_SECRET_ENTROPY - entropy) * 10)
        
        return max(penalty, -50)


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
# SECRET HEURISTIC ENGINE (Enhanced v2.0)
# =============================================================================

class SecretHeuristicEngine:
    """Analyze potential secrets using heuristics with false positive filtering."""
    
    def __init__(self):
        self.fp_filter = FalsePositiveFilter()
    
    def analyze(self, var: str, value: str, context: str = "") -> Dict:
        """Analyze a variable and value for secret indicators."""
        signals = []
        
        # FIRST: Check for false positives
        is_fp, fp_reason = self.fp_filter.is_false_positive(var, value, context)
        if is_fp:
            return {
                "signals": [],
                "provider": "",
                "entropy": calculate_entropy(value),
                "is_false_positive": True,
                "fp_reason": fp_reason,
                "confidence_penalty": -100,  # Exclude completely
            }
        
        # Check for keyword match
        var_lower = var.lower()
        if any(k in var_lower for k in SECRET_KEYWORDS):
            signals.append("keyword")
        
        # Check entropy (increased threshold)
        ent = calculate_entropy(value)
        if ent > MIN_SECRET_ENTROPY:
            signals.append("entropy")
        
        # Check length
        if len(value) >= MIN_SECRET_LENGTH:
            signals.append("length")
        
        # Check for hex-like patterns
        if re.match(r'^[a-fA-F0-9]{16,}$', value):
            signals.append("hex_pattern")
        
        # Check for base64-like patterns (but not ALL_CAPS constants)
        if re.match(r'^[A-Za-z0-9+/=]{20,}$', value) and not re.match(r'^[A-Z0-9_]+$', value):
            signals.append("base64_pattern")
        
        # Check for third-party provider
        provider = ""
        for prefix, name in THIRD_PARTY_HINTS.items():
            if value.startswith(prefix):
                provider = name
                signals.append("third_party")
                break
        
        # Calculate confidence penalty for borderline cases
        confidence_penalty = self.fp_filter.get_confidence_penalty(var, value)
        
        return {
            "signals": signals,
            "provider": provider,
            "entropy": ent,
            "is_false_positive": False,
            "fp_reason": "",
            "confidence_penalty": confidence_penalty,
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
# CONFIDENCE SCORER (Enhanced v2.0)
# =============================================================================

class ConfidenceScorer:
    """Score secrets by confidence level with false positive penalty."""
    
    def score(self, meta: Dict) -> int:
        """Calculate confidence score (0-100) with false positive penalty."""
        
        # If marked as false positive, return 0
        if meta.get("is_false_positive"):
            return 0
        
        score = 0
        
        # Entropy signal (increased weight for high entropy)
        if "entropy" in meta.get("signals", []):
            entropy_val = meta.get("entropy", 0)
            if entropy_val > 5.0:
                score += 35  # Very high entropy = likely real secret
            elif entropy_val > 4.5:
                score += 30
            else:
                score += 25
        
        # Keyword signal
        if "keyword" in meta.get("signals", []):
            score += 25
        
        # Third-party detection (strong indicator)
        if "third_party" in meta.get("signals", []):
            score += 25  # Increased from 15
        
        # Pattern detection (hex, base64)
        if "hex_pattern" in meta.get("signals", []) or "base64_pattern" in meta.get("signals", []):
            score += 10
        
        # Length signal
        if "length" in meta.get("signals", []):
            score += 5
        
        # Second-order usage (used in API calls)
        if meta.get("second_order"):
            score += 20
        
        # High impact
        impact = meta.get("impact", ImpactLevel.INFO)
        if impact in (ImpactLevel.HIGH, ImpactLevel.CRITICAL):
            score += 20
        elif impact == ImpactLevel.MEDIUM:
            score += 10
        
        # Apply false positive confidence penalty
        penalty = meta.get("confidence_penalty", 0)
        score += penalty
        
        return max(0, min(score, 100))


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
        super().__init__(
            name="JSSecretsMiner",
            description="JavaScript secrets and API key extraction",
            target=target,
            **kwargs
        )
        
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
            self._request_count += 1
            
            js_data = self.fetcher.get(js_url)
            if not js_data:
                continue
            
            self.logger.debug(f"Analyzing: {js_url}")
            
            # Extract assignments
            assignments = self.parser.extract_assignments(js_data["body"])
            
            for assign in assignments:
                # Get surrounding context for better analysis
                value_idx = js_data["body"].find(assign["value"])
                context_start = max(0, value_idx - 200)
                context_end = min(len(js_data["body"]), value_idx + len(assign["value"]) + 200)
                surrounding_context = js_data["body"][context_start:context_end] if value_idx >= 0 else ""
                
                # Analyze with heuristics (now includes false positive detection)
                heuristics = self.heuristic.analyze(assign["var"], assign["value"], surrounding_context)
                
                # Skip if marked as false positive
                if heuristics.get("is_false_positive"):
                    self.logger.debug(f"Skipping false positive: {assign['var']} - {heuristics.get('fp_reason', '')}")
                    continue
                
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
                
                # Calculate confidence (includes penalty)
                meta = {
                    "signals": heuristics["signals"],
                    "second_order": is_second_order,
                    "impact": impact,
                    "entropy": heuristics.get("entropy", 0),
                    "confidence_penalty": heuristics.get("confidence_penalty", 0),
                    "is_false_positive": False,
                }
                confidence = self.scorer.score(meta)
                
                # Skip low confidence results (likely false positives)
                if confidence < 40:
                    self.logger.debug(f"Skipping low confidence ({confidence}%): {assign['var']}")
                    continue
                
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
        if result and hasattr(result, "duration_seconds") and result.duration_seconds:
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
            "scan_id": getattr(result, "scan_id", "unknown") if result else "unknown",
            "duration": getattr(result, "duration_seconds", 0) if result else 0,
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
