#!/usr/bin/env python3
"""
REVUEX File Upload GOLD v4.0
============================
Research-Grade File Upload Validation Scanner (10/10 GOLD)

Core Techniques:
- Upload Policy Extraction
- Structural Integrity File Mutation
- MIME / Extension / Content Mismatch Detection
- Server Normalization Analysis
- Second-Order Marker Correlation
- Confidence-Weighted Findings

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import os
import re
import json
import time
import hashlib
import mimetypes
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.base_scanner import BaseScanner, Finding, ScanResult, Severity, ScanStatus
from core.utils import print_success, print_error, print_warning, print_info

SCANNER_NAME = "File Upload Scanner GOLD"
SCANNER_VERSION = "4.0.0"

BANNER = r"""
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

File Upload GOLD — Upload Policy Validation Scanner
"""

CONFIDENCE_THRESHOLD = 80
SAFE_MARKER_PREFIX = "REVUEX_UPLOAD"
SAFE_TEXT_CONTENT = b"REVUEX SAFE FILE\nNO EXECUTION\nTEST MARKER\n"

MAGIC_BYTES = {
    "png": b"\x89PNG\r\n\x1a\n", "jpg": b"\xff\xd8\xff\xe0", "jpeg": b"\xff\xd8\xff\xe0",
    "gif": b"GIF89a", "pdf": b"%PDF-1.4", "zip": b"PK\x03\x04", "bmp": b"BM",
    "doc": b"\xd0\xcf\x11\xe0", "docx": b"PK\x03\x04",
}

DANGEROUS_EXTENSIONS = [
    "php", "php3", "php4", "php5", "phtml", "phar",
    "asp", "aspx", "asa", "ashx", "asmx",
    "jsp", "jspx", "cgi", "pl", "py", "rb", "sh",
    "exe", "dll", "bat", "cmd", "ps1", "vbs",
    "htaccess", "config", "svg", "xml", "html", "htm",
]

COMMON_ALLOWED = ["jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "txt"]

MIME_TYPES = {
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
    "gif": "image/gif", "pdf": "application/pdf", "txt": "text/plain",
    "html": "text/html", "php": "application/x-php", "svg": "image/svg+xml",
}

@dataclass
class UploadCheckResult:
    check_name: str
    description: str
    severity: Severity
    confidence_score: int
    evidence: Dict[str, Any]
    technique: str
    is_vulnerable: bool

class FileMutationEngine:
    @staticmethod
    def generate_baseline(ext: str) -> Dict[str, Any]:
        magic = MAGIC_BYTES.get(ext, b"")
        content = magic + SAFE_TEXT_CONTENT
        mime = MIME_TYPES.get(ext, mimetypes.types_map.get(f".{ext}", "application/octet-stream"))
        return {"filename": f"baseline_test.{ext}", "content": content, "mime": mime, "extension": ext}
    
    @staticmethod
    def generate_contradiction(ext: str) -> Dict[str, Any]:
        marker = f"{SAFE_MARKER_PREFIX}_{hashlib.md5(ext.encode()).hexdigest()[:8]}"
        content = SAFE_TEXT_CONTENT + marker.encode()
        fake_ext = "txt" if ext != "txt" else "jpg"
        fake_mime = MIME_TYPES.get(fake_ext, "text/plain")
        return {"filename": f"contradiction_test.{ext}", "content": content, "mime": fake_mime, "extension": ext, "marker": marker}
    
    @staticmethod
    def generate_double_extension(base_ext: str, dangerous_ext: str) -> Dict[str, Any]:
        marker = f"{SAFE_MARKER_PREFIX}_DBL_{hashlib.md5(f'{base_ext}{dangerous_ext}'.encode()).hexdigest()[:6]}"
        magic = MAGIC_BYTES.get(base_ext, b"")
        content = magic + SAFE_TEXT_CONTENT + marker.encode()
        return {"filename": f"test.{dangerous_ext}.{base_ext}", "content": content, "mime": MIME_TYPES.get(base_ext, "application/octet-stream"), "extension": base_ext, "marker": marker, "technique": "double_extension"}
    
    @staticmethod
    def generate_null_byte(base_ext: str, dangerous_ext: str) -> Dict[str, Any]:
        marker = f"{SAFE_MARKER_PREFIX}_NULL_{hashlib.md5(f'{base_ext}{dangerous_ext}'.encode()).hexdigest()[:6]}"
        magic = MAGIC_BYTES.get(base_ext, b"")
        content = magic + SAFE_TEXT_CONTENT + marker.encode()
        return {"filename": f"test.{dangerous_ext}%00.{base_ext}", "content": content, "mime": MIME_TYPES.get(base_ext, "application/octet-stream"), "extension": base_ext, "marker": marker, "technique": "null_byte"}
    
    @staticmethod
    def generate_case_variation(ext: str) -> Dict[str, Any]:
        marker = f"{SAFE_MARKER_PREFIX}_CASE_{hashlib.md5(ext.encode()).hexdigest()[:6]}"
        content = SAFE_TEXT_CONTENT + marker.encode()
        varied_ext = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(ext))
        return {"filename": f"test.{varied_ext}", "content": content, "mime": MIME_TYPES.get(ext.lower(), "application/octet-stream"), "extension": varied_ext, "marker": marker, "technique": "case_variation"}
    
    @staticmethod
    def generate_path_traversal() -> Dict[str, Any]:
        marker = f"{SAFE_MARKER_PREFIX}_PATH_{hashlib.md5(b'traversal').hexdigest()[:6]}"
        content = SAFE_TEXT_CONTENT + marker.encode()
        return {"filename": "../../../tmp/test.txt", "content": content, "mime": "text/plain", "extension": "txt", "marker": marker, "technique": "path_traversal"}
    
    @staticmethod
    def generate_special_chars() -> List[Dict[str, Any]]:
        files = []
        for name in ["test;.jpg", "test|.jpg", "test`.jpg", "test$.jpg", "test&.jpg"]:
            marker = f"{SAFE_MARKER_PREFIX}_SPEC_{hashlib.md5(name.encode()).hexdigest()[:6]}"
            files.append({"filename": name, "content": MAGIC_BYTES.get("jpg", b"") + SAFE_TEXT_CONTENT + marker.encode(), "mime": "image/jpeg", "marker": marker, "technique": "special_chars"})
        return files
    
    @staticmethod
    def generate_polyglot(ext: str) -> Dict[str, Any]:
        marker = f"{SAFE_MARKER_PREFIX}_POLY_{hashlib.md5(ext.encode()).hexdigest()[:6]}"
        magic = MAGIC_BYTES.get("gif", b"GIF89a")
        content = magic + b"\x00" * 10 + SAFE_TEXT_CONTENT + marker.encode()
        return {"filename": f"polyglot.{ext}", "content": content, "mime": MIME_TYPES.get(ext, "application/octet-stream"), "extension": ext, "marker": marker, "technique": "polyglot"}
    
    @staticmethod
    def generate_mime_mismatch(ext: str) -> Dict[str, Any]:
        marker = f"{SAFE_MARKER_PREFIX}_MIME_{hashlib.md5(ext.encode()).hexdigest()[:6]}"
        magic = MAGIC_BYTES.get(ext, b"")
        content = magic + SAFE_TEXT_CONTENT + marker.encode()
        wrong_mime = "application/x-php" if ext != "php" else "image/jpeg"
        return {"filename": f"mimemismatch.{ext}", "content": content, "mime": wrong_mime, "extension": ext, "marker": marker, "technique": "mime_mismatch"}
    
    @staticmethod
    def generate_content_type_bypass(ext: str) -> Dict[str, Any]:
        marker = f"{SAFE_MARKER_PREFIX}_CT_{hashlib.md5(ext.encode()).hexdigest()[:6]}"
        content = SAFE_TEXT_CONTENT + marker.encode()
        return {"filename": f"ctbypass.{ext}", "content": content, "mime": "image/jpeg", "extension": ext, "marker": marker, "technique": "content_type_bypass"}
    
    @staticmethod
    def generate_htaccess() -> Dict[str, Any]:
        marker = f"{SAFE_MARKER_PREFIX}_HTACCESS_{hashlib.md5(b'htaccess').hexdigest()[:6]}"
        content = b"# REVUEX Test\n# " + marker.encode() + b"\n"
        return {"filename": ".htaccess", "content": content, "mime": "text/plain", "extension": "htaccess", "marker": marker, "technique": "htaccess"}
    
    @staticmethod
    def generate_svg_xss() -> Dict[str, Any]:
        marker = f"{SAFE_MARKER_PREFIX}_SVG_{hashlib.md5(b'svg').hexdigest()[:6]}"
        content = f'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><text>{marker}</text></svg>'.encode()
        return {"filename": "test.svg", "content": content, "mime": "image/svg+xml", "extension": "svg", "marker": marker, "technique": "svg_upload"}

class FileUploadScanner(BaseScanner):
    def __init__(self, target: str, upload_field: str = "file", allowed_extensions: Optional[List[str]] = None, test_dangerous: bool = True, custom_headers: Optional[Dict[str, str]] = None, confidence_threshold: int = CONFIDENCE_THRESHOLD, **kwargs):
        super().__init__(
            name="FileUploadScanner",
            description="File upload vulnerability scanner",
            target=target,
            **kwargs
        )
        self.upload_field = upload_field
        self.allowed_extensions = allowed_extensions or COMMON_ALLOWED
        self.test_dangerous = test_dangerous
        self.custom_headers = custom_headers or {}
        self.confidence_threshold = confidence_threshold
        self.policy: Dict[str, Any] = {}
        self.baseline_responses: Dict[str, Any] = {}
        self.check_results: List[UploadCheckResult] = []
        self.total_confidence: int = 0
        self.markers_found: List[str] = []
        self.scanner_name = SCANNER_NAME
        self.scanner_version = SCANNER_VERSION
    
    def _validate_target(self) -> bool:
        try:
            parsed = urlparse(self.target)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            response = self.session.get(base_url, timeout=self.timeout)
            return response.status_code < 500
        except Exception:
            return False
    
    def scan(self) -> None:
        self.logger.info(f"Starting File Upload GOLD scan on {self.target}")
        self._extract_policy()
        self._test_baseline_uploads()
        self._test_extension_contradictions()
        if self.test_dangerous:
            self._test_double_extension()
            self._test_null_byte()
            self._test_case_variation()
            self._test_content_type_bypass()
            self._test_htaccess()
        self._test_mime_mismatch()
        self._test_path_traversal()
        self._test_polyglot()
        self._test_special_chars()
        self._test_svg()
        self._check_second_order()
        self.logger.info(f"File Upload scan complete. Found {len(self.findings)} issue(s)")
    
    def _upload_file(self, file_obj: Dict[str, Any]) -> Optional[Any]:
        self.rate_limiter.acquire()
        self._request_count += 1
        files = {self.upload_field: (file_obj["filename"], file_obj["content"], file_obj["mime"])}
        try:
            response = self.session.post(self.target, files=files, headers=self.custom_headers, timeout=self.timeout)
            time.sleep(self.delay)
            return response
        except Exception as e:
            self.logger.debug(f"Upload error: {e}")
            return None
    
    def _extract_policy(self) -> None:
        self.policy = {"allowed_extensions": self.allowed_extensions, "max_size": None, "inferred": True}
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            accept_match = re.search(r'accept=["\']([^"\']+)["\']', response.text)
            if accept_match:
                extensions = re.findall(r'\.(\w+)', accept_match.group(1))
                if extensions:
                    self.policy["allowed_extensions"] = extensions
                    self.policy["inferred"] = False
        except Exception:
            pass
        print_info(f"Upload policy: {self.policy}")
    
    def _test_baseline_uploads(self) -> None:
        for ext in self.policy["allowed_extensions"][:5]:
            baseline = FileMutationEngine.generate_baseline(ext)
            response = self._upload_file(baseline)
            if response:
                self.baseline_responses[ext] = {"status": response.status_code, "text": response.text[:1000], "accepted": response.status_code < 400}
                if response.status_code < 400:
                    self.logger.info(f"Baseline .{ext} accepted (HTTP {response.status_code})")
    
    def _test_extension_contradictions(self) -> None:
        for ext in self.policy["allowed_extensions"][:3]:
            baseline = FileMutationEngine.generate_baseline(ext)
            contradiction = FileMutationEngine.generate_contradiction(ext)
            r_base = self._upload_file(baseline)
            r_contra = self._upload_file(contradiction)
            if not r_base or not r_contra:
                continue
            confidence = 0
            if r_base.status_code < 400: confidence += 20
            if r_contra.status_code < 400: confidence += 40
            if r_base.status_code == r_contra.status_code: confidence += 20
            if confidence >= self.confidence_threshold:
                self._add_check_result("Extension/Content Mismatch Accepted", f"Server accepts .{ext} with mismatched MIME type", Severity.HIGH, confidence, {"baseline_status": r_base.status_code, "contradiction_status": r_contra.status_code, "marker": contradiction.get("marker")}, "contradiction", True)
                if contradiction.get("marker"): self.markers_found.append(contradiction["marker"])
    
    def _test_double_extension(self) -> None:
        allowed_ext = self.policy["allowed_extensions"][0] if self.policy["allowed_extensions"] else "jpg"
        for dangerous_ext in ["php", "asp"][:2]:
            file_obj = FileMutationEngine.generate_double_extension(allowed_ext, dangerous_ext)
            response = self._upload_file(file_obj)
            if response and response.status_code < 400:
                self._add_check_result("Double Extension Bypass", f"Server accepts .{dangerous_ext}.{allowed_ext}", Severity.CRITICAL, 85, {"filename": file_obj["filename"], "status": response.status_code, "marker": file_obj.get("marker")}, "double_extension", True)
                if file_obj.get("marker"): self.markers_found.append(file_obj["marker"])
    
    def _test_null_byte(self) -> None:
        allowed_ext = self.policy["allowed_extensions"][0] if self.policy["allowed_extensions"] else "jpg"
        file_obj = FileMutationEngine.generate_null_byte(allowed_ext, "php")
        response = self._upload_file(file_obj)
        if response and response.status_code < 400:
            self._add_check_result("Null Byte Injection Bypass", "Server accepts filename with null byte", Severity.CRITICAL, 90, {"filename": file_obj["filename"], "status": response.status_code, "marker": file_obj.get("marker")}, "null_byte", True)
            if file_obj.get("marker"): self.markers_found.append(file_obj["marker"])
    
    def _test_case_variation(self) -> None:
        for ext in ["php", "Php", "pHp", "PHP"]:
            file_obj = FileMutationEngine.generate_case_variation(ext)
            response = self._upload_file(file_obj)
            if response and response.status_code < 400:
                self._add_check_result("Case Variation Bypass", f"Server accepts case-varied: {file_obj['extension']}", Severity.HIGH, 75, {"extension": file_obj["extension"], "status": response.status_code}, "case_variation", True)
                break
    
    def _test_mime_mismatch(self) -> None:
        for ext in self.policy["allowed_extensions"][:2]:
            file_obj = FileMutationEngine.generate_mime_mismatch(ext)
            response = self._upload_file(file_obj)
            if response and response.status_code < 400:
                self._add_check_result("MIME Type Mismatch Accepted", f"Server accepts .{ext} with wrong MIME", Severity.MEDIUM, 70, {"extension": ext, "sent_mime": file_obj["mime"], "status": response.status_code}, "mime_mismatch", True)
                if file_obj.get("marker"): self.markers_found.append(file_obj["marker"])
    
    def _test_content_type_bypass(self) -> None:
        for ext in ["php", "html", "svg"]:
            file_obj = FileMutationEngine.generate_content_type_bypass(ext)
            response = self._upload_file(file_obj)
            if response and response.status_code < 400:
                self._add_check_result("Content-Type Bypass", f"Server accepts .{ext} with image/jpeg", Severity.HIGH, 80, {"extension": ext, "status": response.status_code}, "content_type_bypass", True)
                if file_obj.get("marker"): self.markers_found.append(file_obj["marker"])
    
    def _test_path_traversal(self) -> None:
        file_obj = FileMutationEngine.generate_path_traversal()
        response = self._upload_file(file_obj)
        if response and response.status_code < 400:
            self._add_check_result("Path Traversal in Filename", "Server accepts path traversal chars", Severity.CRITICAL, 85, {"filename": file_obj["filename"], "status": response.status_code}, "path_traversal", True)
            if file_obj.get("marker"): self.markers_found.append(file_obj["marker"])
    
    def _test_polyglot(self) -> None:
        for ext in ["php", "html"]:
            file_obj = FileMutationEngine.generate_polyglot(ext)
            response = self._upload_file(file_obj)
            if response and response.status_code < 400:
                self._add_check_result("Polyglot File Accepted", f"Server accepts polyglot with .{ext}", Severity.HIGH, 75, {"extension": ext, "status": response.status_code}, "polyglot", True)
                if file_obj.get("marker"): self.markers_found.append(file_obj["marker"])
    
    def _test_special_chars(self) -> None:
        files = FileMutationEngine.generate_special_chars()
        for file_obj in files[:3]:
            response = self._upload_file(file_obj)
            if response and response.status_code < 400:
                self._add_check_result("Special Characters in Filename", f"Server accepts: {file_obj['filename']}", Severity.MEDIUM, 65, {"filename": file_obj["filename"], "status": response.status_code}, "special_chars", True)
                if file_obj.get("marker"): self.markers_found.append(file_obj["marker"])
                break
    
    def _test_htaccess(self) -> None:
        file_obj = FileMutationEngine.generate_htaccess()
        response = self._upload_file(file_obj)
        if response and response.status_code < 400:
            self._add_check_result(".htaccess Upload Accepted", "Server accepts .htaccess upload", Severity.CRITICAL, 95, {"filename": file_obj["filename"], "status": response.status_code}, "htaccess", True)
            if file_obj.get("marker"): self.markers_found.append(file_obj["marker"])
    
    def _test_svg(self) -> None:
        file_obj = FileMutationEngine.generate_svg_xss()
        response = self._upload_file(file_obj)
        if response and response.status_code < 400:
            self._add_check_result("SVG Upload Accepted", "Server accepts SVG (XSS vector)", Severity.MEDIUM, 70, {"filename": file_obj["filename"], "status": response.status_code}, "svg_upload", True)
            if file_obj.get("marker"): self.markers_found.append(file_obj["marker"])
    
    def _check_second_order(self) -> None:
        if not self.markers_found: return
        for ext, resp_data in self.baseline_responses.items():
            for marker in self.markers_found:
                if marker in resp_data.get("text", ""):
                    for result in self.check_results:
                        if result.evidence.get("marker") == marker:
                            result.confidence_score += 10
                            print_warning(f"Second-order marker observed: {marker}")
    
    def _add_check_result(self, check_name: str, description: str, severity: Severity, confidence_score: int, evidence: Dict[str, Any], technique: str, is_vulnerable: bool) -> None:
        result = UploadCheckResult(check_name=check_name, description=description, severity=severity, confidence_score=confidence_score, evidence=evidence, technique=technique, is_vulnerable=is_vulnerable)
        self.check_results.append(result)
        self.total_confidence += confidence_score
        self._create_finding(result)
        print_success(f"{check_name} (+{confidence_score})")
    
    def _create_finding(self, result: UploadCheckResult) -> None:
        finding = Finding(
            id=self._generate_finding_id(result.check_name), title=result.check_name, severity=result.severity,
            description=result.description, url=self.target, parameter=self.upload_field, method="POST",
            payload=result.evidence.get("filename", "N/A"), evidence=json.dumps(result.evidence, indent=2),
            impact=self._get_impact(result), remediation=self._get_remediation(result),
            vulnerability_type="file_upload", confidence="high" if result.confidence_score >= 80 else "medium",
        )
        self.add_finding(finding)
    
    def _get_impact(self, result: UploadCheckResult) -> str:
        if result.severity == Severity.CRITICAL:
            return "CRITICAL: File upload bypass enables RCE, web shell deployment, server compromise"
        elif result.severity == Severity.HIGH:
            return "HIGH: Upload weakness enables stored XSS, SSRF via SVG/XML, potential code execution"
        return "MEDIUM: Upload issue may enable further attacks, indicates weak validation"
    
    def _get_remediation(self, result: UploadCheckResult) -> str:
        remediations = {
            "double_extension": "Validate ONLY final extension, use allowlist, strip multiple extensions",
            "null_byte": "Sanitize filename, remove null bytes, generate new server-side filename",
            "path_traversal": "Generate new filename server-side, never use user-supplied path",
            "mime_mismatch": "Verify Content-Type matches extension, check magic bytes",
            "content_type_bypass": "Don't trust Content-Type alone, verify actual content",
            "htaccess": "Block .htaccess uploads, use allowlist, store outside webroot",
            "svg_upload": "Sanitize SVG content, strip scripts, serve with CSP headers",
        }
        return remediations.get(result.technique, "Implement strict validation, use allowlist, verify magic bytes, generate new filenames server-side")
    
    def _generate_finding_id(self, context: str) -> str:
        data = f"{self.target}:{context}:{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="revuex-file-upload", description="REVUEX File Upload GOLD Scanner")
    parser.add_argument("-t", "--target", required=True, help="Upload endpoint URL")
    parser.add_argument("-f", "--field", default="file", help="Upload field name")
    parser.add_argument("--extensions", help="Comma-separated allowed extensions")
    parser.add_argument("--no-dangerous", action="store_true", help="Skip dangerous extension tests")
    parser.add_argument("--headers", help="Custom headers JSON file")
    parser.add_argument("--threshold", type=int, default=CONFIDENCE_THRESHOLD, help="Confidence threshold")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--delay", type=float, default=0.5, help="Request delay")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    return parser

def main() -> int:
    parser = create_parser()
    args = parser.parse_args()
    extensions = [e.strip() for e in args.extensions.split(",")] if args.extensions else None
    custom_headers = {}
    if args.headers:
        try:
            with open(args.headers) as f: custom_headers = json.load(f)
        except: pass
    if not args.quiet:
        print(BANNER)
        print(f"[+] Target: {args.target}")
        print(f"[+] Upload field: {args.field}\n")
    scanner = FileUploadScanner(target=args.target, upload_field=args.field, allowed_extensions=extensions, test_dangerous=not args.no_dangerous, custom_headers=custom_headers, confidence_threshold=args.threshold, delay=args.delay, timeout=args.timeout, verbose=args.verbose)
    result = scanner.run()
    if not args.quiet:
        print(f"\n{'='*60}\nSCAN COMPLETE\n{'='*60}")
        if result and hasattr(result, 'findings'):
            print(f"Issues Found: {len(result.findings)}")
        print(f"Total Confidence: {scanner.total_confidence}")
    if args.output and result:
        output_data = {"scanner": SCANNER_NAME, "version": SCANNER_VERSION, "target": args.target, "findings": [{"id": f.id, "title": f.title, "severity": f.severity.value} for f in getattr(result, "findings", [])]}
        with open(args.output, "w") as f: json.dump(output_data, f, indent=2)
        if not args.quiet: print(f"\nResults saved to: {args.output}")
    return 1 if result and getattr(result, "findings", []) else 0

if __name__ == "__main__":
    sys.exit(main())
