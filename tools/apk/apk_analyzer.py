#!/usr/bin/env python3
"""
REVUEX APK Analyzer GOLD v1.0
=============================
Research-Grade Android APK Security Analyzer (10/10 GOLD)

Detection Philosophy:
- No exploitation
- No dynamic hooking
- Invariant violation proof
- Confidence-based findings
- Bug bounty defensible

Core Techniques:
- APK Decompilation (apktool)
- AndroidManifest.xml Analysis
- Smali Code Analysis
- Hardcoded Secret Detection
- Weak Cryptography Detection
- WebView Security Analysis
- Network Security Config Analysis
- Certificate Pinning Detection
- Root Detection Bypass Analysis

Author: REVUEX Team
License: MIT (Private Research Use)
"""

import os
import re
import json
import shutil
import subprocess
import hashlib
import zipfile
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.base_scanner import BaseScanner, Finding, ScanResult, Severity, ScanStatus
from core.utils import print_success, print_error, print_warning, print_info


# =============================================================================
# CONSTANTS
# =============================================================================

SCANNER_NAME = "APK Analyzer GOLD"
SCANNER_VERSION = "1.0.0"

BANNER = r"""
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

APK Analyzer GOLD — Android Security Analysis
"""

CONFIDENCE_THRESHOLD = 75

# Secret detection patterns
SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key\s*[=:]\s*["\']?)([a-zA-Z0-9_\-]{16,})', "API Key"),
    (r'(?i)(secret[_-]?key\s*[=:]\s*["\']?)([a-zA-Z0-9_\-]{16,})', "Secret Key"),
    (r'(?i)(password\s*[=:]\s*["\']?)([^\s"\']{8,})', "Hardcoded Password"),
    (r'(?i)(token\s*[=:]\s*["\']?)([a-zA-Z0-9_\-\.]{20,})', "Access Token"),
    (r'(?i)(aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']?)([A-Z0-9]{20})', "AWS Access Key"),
    (r'(?i)(aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?)([a-zA-Z0-9/+=]{40})', "AWS Secret Key"),
    (r'(?i)(firebase[_-]?api[_-]?key\s*[=:]\s*["\']?)([a-zA-Z0-9_\-]{30,})', "Firebase API Key"),
    (r'(?i)(google[_-]?api[_-]?key\s*[=:]\s*["\']?)([a-zA-Z0-9_\-]{30,})', "Google API Key"),
    (r'AIza[0-9A-Za-z_-]{35}', "Google API Key (Pattern)"),
    (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', "Firebase Cloud Messaging"),
    (r'(?i)(private[_-]?key\s*[=:]\s*["\']?)([a-zA-Z0-9/+=]{20,})', "Private Key"),
    (r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----', "PEM Private Key"),
    (r'(?i)(client[_-]?secret\s*[=:]\s*["\']?)([a-zA-Z0-9_\-]{16,})', "OAuth Client Secret"),
]

# Weak crypto patterns
WEAK_CRYPTO_PATTERNS = [
    (r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']', "MD5 Hash"),
    (r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']', "SHA1 Hash"),
    (r'(?i)DES(?!ede)', "DES Encryption"),
    (r'(?i)RC4', "RC4 Encryption"),
    (r'ECB', "ECB Mode"),
    (r'NoPadding', "No Padding"),
    (r'(?i)Math\.random\(\)', "Insecure Random"),
    (r'SecureRandom\.getInstance\s*\(\s*["\']SHA1PRNG["\']', "Weak PRNG"),
]

# URL/Endpoint patterns
URL_PATTERNS = [
    (r'https?://[^\s"\'<>]+', "HTTP URL"),
    (r'(?i)(base[_-]?url\s*[=:]\s*["\']?)(https?://[^\s"\']+)', "Base URL"),
    (r'(?i)(endpoint\s*[=:]\s*["\']?)(https?://[^\s"\']+)', "API Endpoint"),
]


# =============================================================================
# APK CHECK RESULT DATACLASS
# =============================================================================

@dataclass
class APKCheckResult:
    """Result of a single APK check."""
    check_name: str
    description: str
    severity: Severity
    confidence_score: int
    evidence: Dict[str, Any]
    is_vulnerable: bool


# =============================================================================
# APK ANALYZER GOLD CLASS
# =============================================================================

class APKAnalyzer(BaseScanner):
    """
    GOLD-tier APK Security Analyzer.
    
    Methodology:
    1. Decompile APK using apktool
    2. Analyze AndroidManifest.xml
    3. Scan smali code for secrets
    4. Detect weak cryptography
    5. Analyze WebView security
    6. Check network security config
    7. Report with confidence scoring
    """
    
    def __init__(
        self,
        apk_path: str,
        output_dir: Optional[str] = None,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
        **kwargs
    ):
        """
        Initialize APK Analyzer.
        
        Args:
            apk_path: Path to APK file
            output_dir: Output directory for decompiled files
            confidence_threshold: Minimum confidence for findings
        """
        # APK Analyzer doesn't need a target URL
        super().__init__(target="file://" + apk_path, **kwargs)
        
        self.apk_path = apk_path
        self.output_dir = output_dir or "apk_decoded"
        self.confidence_threshold = confidence_threshold
        
        # State tracking
        self.check_results: List[APKCheckResult] = []
        self.total_confidence: int = 0
        self.apk_info: Dict[str, Any] = {}
        self.found_secrets: Set[str] = set()
        self.found_urls: Set[str] = set()
        
        # Scanner info
        self.scanner_name = SCANNER_NAME
        self.scanner_version = SCANNER_VERSION
    
    def _validate_target(self) -> bool:
        """Validate APK file exists."""
        return os.path.exists(self.apk_path)
    
    def scan(self) -> None:
        """Execute the GOLD APK scan."""
        self.logger.info(f"Starting APK Analyzer GOLD scan")
        self.logger.info(f"APK: {self.apk_path}")
        
        # Phase 1: Extract APK info
        self.logger.info("Phase 1: Extracting APK information...")
        self._extract_apk_info()
        
        # Phase 2: Decompile APK
        self.logger.info("Phase 2: Decompiling APK...")
        if not self._decompile():
            self.logger.error("Decompilation failed - aborting")
            return
        
        # Phase 3: Analyze manifest
        self.logger.info("Phase 3: Analyzing AndroidManifest.xml...")
        self._analyze_manifest()
        
        # Phase 4: Analyze network security config
        self.logger.info("Phase 4: Analyzing network security config...")
        self._analyze_network_security()
        
        # Phase 5: Scan for secrets
        self.logger.info("Phase 5: Scanning for hardcoded secrets...")
        self._scan_for_secrets()
        
        # Phase 6: Detect weak crypto
        self.logger.info("Phase 6: Detecting weak cryptography...")
        self._detect_weak_crypto()
        
        # Phase 7: Analyze WebView security
        self.logger.info("Phase 7: Analyzing WebView security...")
        self._analyze_webview()
        
        # Phase 8: Check certificate pinning
        self.logger.info("Phase 8: Checking certificate pinning...")
        self._check_cert_pinning()
        
        # Phase 9: Check root detection
        self.logger.info("Phase 9: Checking root detection...")
        self._check_root_detection()
        
        # Phase 10: Extract URLs
        self.logger.info("Phase 10: Extracting URLs and endpoints...")
        self._extract_urls()
        
        self.logger.info(f"APK scan complete. Found {len(self.findings)} issue(s)")
    
    # =========================================================================
    # APK INFO EXTRACTION
    # =========================================================================
    
    def _extract_apk_info(self) -> None:
        """Extract basic APK information."""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                self.apk_info["files"] = len(apk.namelist())
                self.apk_info["size"] = os.path.getsize(self.apk_path)
                
                # Check for common files
                self.apk_info["has_native"] = any("lib/" in n for n in apk.namelist())
                self.apk_info["has_assets"] = any("assets/" in n for n in apk.namelist())
            
            # Calculate hash
            with open(self.apk_path, 'rb') as f:
                self.apk_info["sha256"] = hashlib.sha256(f.read()).hexdigest()
            
            print_info(f"APK Size: {self.apk_info['size']} bytes")
            print_info(f"APK SHA256: {self.apk_info['sha256'][:16]}...")
            
        except Exception as e:
            self.logger.debug(f"APK info extraction error: {e}")
    
    # =========================================================================
    # DECOMPILATION
    # =========================================================================
    
    def _decompile(self) -> bool:
        """Decompile APK using apktool."""
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        
        try:
            result = subprocess.run(
                ["apktool", "d", "-f", self.apk_path, "-o", self.output_dir],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300
            )
            
            if result.returncode == 0:
                print_info(f"Decompiled to: {self.output_dir}")
                return True
            else:
                print_warning(f"apktool error: {result.stderr.decode()[:200]}")
                return False
                
        except FileNotFoundError:
            print_error("apktool not found. Please install apktool.")
            return False
        except subprocess.TimeoutExpired:
            print_error("Decompilation timed out")
            return False
        except Exception as e:
            print_error(f"Decompilation failed: {e}")
            return False
    
    # =========================================================================
    # MANIFEST ANALYSIS
    # =========================================================================
    
    def _analyze_manifest(self) -> None:
        """Analyze AndroidManifest.xml."""
        manifest_path = os.path.join(self.output_dir, "AndroidManifest.xml")
        
        if not os.path.exists(manifest_path):
            print_warning("AndroidManifest.xml not found")
            return
        
        with open(manifest_path, "r", errors="ignore") as f:
            manifest = f.read()
        
        # Debuggable build
        if 'android:debuggable="true"' in manifest:
            self._add_check_result(
                "Debuggable Production APK",
                "Application has debuggable flag enabled in production",
                Severity.CRITICAL,
                95,
                {"manifest": "android:debuggable=true"},
                True
            )
        
        # Backup allowed
        if 'android:allowBackup="true"' in manifest or 'android:allowBackup' not in manifest:
            self._add_check_result(
                "Application Backup Allowed",
                "Application data can be backed up (default: true)",
                Severity.MEDIUM,
                80,
                {"manifest": "android:allowBackup=true (or not set)"},
                True
            )
        
        # Exported components
        exported_activities = re.findall(r'<activity[^>]*android:exported="true"[^>]*>', manifest)
        exported_services = re.findall(r'<service[^>]*android:exported="true"[^>]*>', manifest)
        exported_receivers = re.findall(r'<receiver[^>]*android:exported="true"[^>]*>', manifest)
        exported_providers = re.findall(r'<provider[^>]*android:exported="true"[^>]*>', manifest)
        
        total_exported = len(exported_activities) + len(exported_services) + len(exported_receivers) + len(exported_providers)
        
        if total_exported > 0:
            self._add_check_result(
                "Exported Android Components",
                f"Found {total_exported} exported components that may be accessible by other apps",
                Severity.HIGH,
                80,
                {
                    "activities": len(exported_activities),
                    "services": len(exported_services),
                    "receivers": len(exported_receivers),
                    "providers": len(exported_providers)
                },
                True
            )
        
        # Cleartext traffic
        if 'android:usesCleartextTraffic="true"' in manifest:
            self._add_check_result(
                "Cleartext Traffic Enabled",
                "Application allows cleartext HTTP traffic",
                Severity.HIGH,
                90,
                {"manifest": "android:usesCleartextTraffic=true"},
                True
            )
        
        # Dangerous permissions
        dangerous_perms = [
            "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG",
            "READ_CALENDAR", "WRITE_CALENDAR", "CAMERA", "RECORD_AUDIO",
            "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "READ_PHONE_STATE",
            "CALL_PHONE", "READ_SMS", "SEND_SMS", "RECEIVE_SMS"
        ]
        
        found_dangerous = [p for p in dangerous_perms if p in manifest]
        if found_dangerous:
            print_info(f"Dangerous permissions: {', '.join(found_dangerous[:5])}...")
    
    # =========================================================================
    # NETWORK SECURITY CONFIG
    # =========================================================================
    
    def _analyze_network_security(self) -> None:
        """Analyze network_security_config.xml."""
        config_path = os.path.join(self.output_dir, "res", "xml", "network_security_config.xml")
        
        if not os.path.exists(config_path):
            # Check alternative locations
            for root, dirs, files in os.walk(self.output_dir):
                if "network_security_config.xml" in files:
                    config_path = os.path.join(root, "network_security_config.xml")
                    break
            else:
                return
        
        with open(config_path, "r", errors="ignore") as f:
            config = f.read()
        
        # Cleartext permitted
        if 'cleartextTrafficPermitted="true"' in config:
            self._add_check_result(
                "Cleartext Traffic Permitted in Network Config",
                "Network security config allows cleartext traffic",
                Severity.HIGH,
                85,
                {"file": config_path},
                True
            )
        
        # Trust user certificates
        if '<trust-anchors>' in config and 'user' in config.lower():
            self._add_check_result(
                "User Certificates Trusted",
                "Application trusts user-installed certificates",
                Severity.MEDIUM,
                80,
                {"file": config_path},
                True
            )
    
    # =========================================================================
    # SECRET SCANNING
    # =========================================================================
    
    def _scan_for_secrets(self) -> None:
        """Scan source files for hardcoded secrets."""
        secret_files = []
        
        for root, _, files in os.walk(self.output_dir):
            for filename in files:
                if not filename.endswith((".smali", ".xml", ".json", ".properties")):
                    continue
                
                filepath = os.path.join(root, filename)
                
                try:
                    with open(filepath, "r", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
                
                for pattern, secret_type in SECRET_PATTERNS:
                    matches = re.findall(pattern, content)
                    if matches:
                        # Deduplicate
                        match_str = str(matches[0]) if matches else ""
                        if match_str not in self.found_secrets:
                            self.found_secrets.add(match_str)
                            secret_files.append({
                                "file": filepath.replace(self.output_dir + "/", ""),
                                "type": secret_type,
                                "sample": match_str[:50] + "..." if len(match_str) > 50 else match_str
                            })
        
        if secret_files:
            # Group by type
            by_type = {}
            for s in secret_files:
                by_type.setdefault(s["type"], []).append(s)
            
            for secret_type, items in by_type.items():
                self._add_check_result(
                    f"Hardcoded {secret_type}",
                    f"Found {len(items)} potential hardcoded {secret_type.lower()}(s)",
                    Severity.HIGH,
                    80,
                    {"count": len(items), "files": [i["file"] for i in items[:5]]},
                    True
                )
    
    # =========================================================================
    # WEAK CRYPTO DETECTION
    # =========================================================================
    
    def _detect_weak_crypto(self) -> None:
        """Detect weak cryptographic implementations."""
        weak_crypto_found = {}
        
        for root, _, files in os.walk(self.output_dir):
            for filename in files:
                if not filename.endswith(".smali"):
                    continue
                
                filepath = os.path.join(root, filename)
                
                try:
                    with open(filepath, "r", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
                
                for pattern, crypto_type in WEAK_CRYPTO_PATTERNS:
                    if re.search(pattern, content):
                        weak_crypto_found.setdefault(crypto_type, []).append(
                            filepath.replace(self.output_dir + "/", "")
                        )
        
        for crypto_type, files in weak_crypto_found.items():
            self._add_check_result(
                f"Weak Cryptography: {crypto_type}",
                f"Found usage of weak {crypto_type} in {len(files)} file(s)",
                Severity.MEDIUM,
                75,
                {"type": crypto_type, "files": files[:5]},
                True
            )
    
    # =========================================================================
    # WEBVIEW ANALYSIS
    # =========================================================================
    
    def _analyze_webview(self) -> None:
        """Analyze WebView security."""
        webview_issues = {
            "addJavascriptInterface": [],
            "setJavaScriptEnabled": [],
            "setAllowFileAccess": [],
            "setAllowUniversalAccessFromFileURLs": []
        }
        
        for root, _, files in os.walk(self.output_dir):
            for filename in files:
                if not filename.endswith(".smali"):
                    continue
                
                filepath = os.path.join(root, filename)
                
                try:
                    with open(filepath, "r", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
                
                for method in webview_issues.keys():
                    if method in content:
                        webview_issues[method].append(
                            filepath.replace(self.output_dir + "/", "")
                        )
        
        # JavaScript Interface (high risk)
        if webview_issues["addJavascriptInterface"]:
            self._add_check_result(
                "WebView JavaScript Interface Exposed",
                "WebView exposes JavaScript interface (potential RCE on older Android)",
                Severity.HIGH,
                85,
                {"files": webview_issues["addJavascriptInterface"][:5]},
                True
            )
        
        # File access from WebView
        if webview_issues["setAllowUniversalAccessFromFileURLs"]:
            self._add_check_result(
                "WebView Universal File Access",
                "WebView allows universal file access from file URLs",
                Severity.HIGH,
                80,
                {"files": webview_issues["setAllowUniversalAccessFromFileURLs"][:5]},
                True
            )
    
    # =========================================================================
    # CERTIFICATE PINNING
    # =========================================================================
    
    def _check_cert_pinning(self) -> None:
        """Check for certificate pinning implementation."""
        pinning_indicators = [
            "CertificatePinner",
            "X509TrustManager",
            "SSLPinningVerifier",
            "TrustManagerFactory",
            "sha256/"
        ]
        
        pinning_found = False
        
        for root, _, files in os.walk(self.output_dir):
            for filename in files:
                if not filename.endswith((".smali", ".xml")):
                    continue
                
                filepath = os.path.join(root, filename)
                
                try:
                    with open(filepath, "r", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
                
                for indicator in pinning_indicators:
                    if indicator in content:
                        pinning_found = True
                        break
            
            if pinning_found:
                break
        
        if not pinning_found:
            self._add_check_result(
                "No Certificate Pinning Detected",
                "Application does not appear to implement certificate pinning",
                Severity.MEDIUM,
                70,
                {"note": "MITM attacks may be easier"},
                True
            )
    
    # =========================================================================
    # ROOT DETECTION
    # =========================================================================
    
    def _check_root_detection(self) -> None:
        """Check for root detection implementation."""
        root_indicators = [
            "isRooted",
            "RootBeer",
            "checkRoot",
            "/system/app/Superuser.apk",
            "/system/xbin/su",
            "com.noshufou.android.su",
            "com.koushikdutta.superuser",
            "eu.chainfire.supersu"
        ]
        
        root_detection_found = False
        
        for root, _, files in os.walk(self.output_dir):
            for filename in files:
                if not filename.endswith(".smali"):
                    continue
                
                filepath = os.path.join(root, filename)
                
                try:
                    with open(filepath, "r", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
                
                for indicator in root_indicators:
                    if indicator in content:
                        root_detection_found = True
                        break
            
            if root_detection_found:
                break
        
        if root_detection_found:
            print_info("Root detection mechanisms found")
    
    # =========================================================================
    # URL EXTRACTION
    # =========================================================================
    
    def _extract_urls(self) -> None:
        """Extract URLs and API endpoints."""
        for root, _, files in os.walk(self.output_dir):
            for filename in files:
                if not filename.endswith((".smali", ".xml", ".json")):
                    continue
                
                filepath = os.path.join(root, filename)
                
                try:
                    with open(filepath, "r", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
                
                # Extract URLs
                urls = re.findall(r'https?://[^\s"\'<>]+', content)
                for url in urls:
                    # Clean URL
                    url = url.rstrip('.,;:)')
                    if len(url) > 10 and url not in self.found_urls:
                        self.found_urls.add(url)
        
        if self.found_urls:
            print_info(f"Extracted {len(self.found_urls)} unique URLs")
    
    # =========================================================================
    # RESULT HANDLING
    # =========================================================================
    
    def _add_check_result(self, check_name: str, description: str, severity: Severity, confidence_score: int, evidence: Dict[str, Any], is_vulnerable: bool) -> None:
        """Add a check result and create finding."""
        result = APKCheckResult(
            check_name=check_name,
            description=description,
            severity=severity,
            confidence_score=confidence_score,
            evidence=evidence,
            is_vulnerable=is_vulnerable
        )
        self.check_results.append(result)
        self.total_confidence += confidence_score
        self._create_finding(result)
        print_success(f"{check_name} (+{confidence_score})")
    
    def _create_finding(self, result: APKCheckResult) -> None:
        """Create finding from check result."""
        finding = Finding(
            id=self._generate_finding_id(result.check_name),
            title=result.check_name,
            severity=result.severity,
            description=result.description,
            url=f"file://{self.apk_path}",
            parameter="APK",
            method="STATIC",
            payload="N/A",
            evidence=json.dumps(result.evidence, indent=2),
            impact=self._get_impact(result),
            remediation=self._get_remediation(result),
            vulnerability_type="mobile_security",
            confidence="high" if result.confidence_score >= 80 else "medium",
        )
        self.add_finding(finding)
    
    def _get_impact(self, result: APKCheckResult) -> str:
        """Get impact description."""
        if result.severity == Severity.CRITICAL:
            return "CRITICAL: Debuggable APK allows runtime manipulation and data extraction"
        elif result.severity == Severity.HIGH:
            return "HIGH: Security weakness enables data exposure or component abuse"
        return "MEDIUM: Security misconfiguration that should be addressed"
    
    def _get_remediation(self, result: APKCheckResult) -> str:
        """Get remediation based on check type."""
        remediations = {
            "debuggable": "1. Set android:debuggable=false\n2. Use release build configuration\n3. Enable ProGuard/R8",
            "backup": "1. Set android:allowBackup=false\n2. Encrypt sensitive local data",
            "exported": "1. Set android:exported=false for internal components\n2. Add permission requirements\n3. Validate caller identity",
            "cleartext": "1. Use HTTPS everywhere\n2. Set android:usesCleartextTraffic=false\n3. Implement network security config",
            "secret": "1. Remove hardcoded secrets\n2. Use Android Keystore\n3. Fetch secrets from secure backend",
            "crypto": "1. Use SHA-256 or higher\n2. Use AES-GCM encryption\n3. Use SecureRandom properly",
            "webview": "1. Remove addJavascriptInterface on SDK < 17\n2. Disable file access\n3. Validate loaded URLs",
            "pinning": "1. Implement certificate pinning\n2. Use OkHttp CertificatePinner\n3. Add backup pins",
        }
        for key, remediation in remediations.items():
            if key.lower() in result.check_name.lower():
                return remediation
        return "1. Follow Android security best practices\n2. Review OWASP Mobile guidelines\n3. Perform security code review"
    
    def _generate_finding_id(self, context: str) -> str:
        """Generate unique finding ID."""
        data = f"{self.apk_path}:{context}:{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(prog="revuex-apk", description="REVUEX APK Analyzer GOLD - Android Security Scanner")
    parser.add_argument("-a", "--apk", required=True, help="Path to APK file")
    parser.add_argument("--output-dir", help="Output directory for decompiled files")
    parser.add_argument("--threshold", type=int, default=CONFIDENCE_THRESHOLD, help=f"Confidence threshold (default: {CONFIDENCE_THRESHOLD})")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    return parser


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not os.path.exists(args.apk):
        print_error(f"APK file not found: {args.apk}")
        return 1
    
    if not args.quiet:
        print(BANNER)
        print(f"[+] APK: {args.apk}")
        print()
    
    analyzer = APKAnalyzer(
        apk_path=args.apk,
        output_dir=args.output_dir,
        confidence_threshold=args.threshold,
        verbose=args.verbose,
    )
    
    result = analyzer.run()
    
    if not args.quiet:
        print(f"\n{'='*60}")
        print("SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"APK: {args.apk}")
        print(f"Duration: {result.duration_seconds:.2f}s")
        print(f"Issues Found: {len(result.findings)}")
        print(f"Total Confidence: {analyzer.total_confidence}")
        print(f"URLs Extracted: {len(analyzer.found_urls)}")
        print(f"Secrets Found: {len(analyzer.found_secrets)}")
    
    if args.output:
        output_data = {
            "scanner": SCANNER_NAME,
            "version": SCANNER_VERSION,
            "apk": args.apk,
            "apk_info": analyzer.apk_info,
            "urls_extracted": list(analyzer.found_urls)[:50],
            "findings": [{"id": f.id, "title": f.title, "severity": f.severity.value} for f in result.findings]
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        if not args.quiet:
            print(f"\nResults saved to: {args.output}")
    
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
