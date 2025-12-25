#!/usr/bin/env python3
"""
REVUEX - Bug Bounty Automation Framework
=========================================

Master orchestrator for coordinating all REVUEX security scanners.

This is the main entry point for running comprehensive vulnerability
assessments against authorized targets.

Features:
- Unified CLI interface for all 20 scanners
- Intelligent scan orchestration
- Cross-tool intelligence sharing
- Professional HTML/JSON/Markdown reports
- Rate limiting and safety controls
- Resume interrupted scans
- Configurable scan profiles

Usage:
    python revuex_suite.py --help
    python revuex_suite.py scan -t https://example.com
    python revuex_suite.py scan -t example.com --profile aggressive
    python revuex_suite.py recon -t example.com
    python revuex_suite.py report -i results.json

Author: REVUEX Team
License: MIT
Website: https://revuex.io

⚠️  LEGAL DISCLAIMER:
This tool is intended for authorized security testing only.
Only use on systems you have explicit permission to test.
Unauthorized access to computer systems is illegal.
"""

import os
import sys
import json
import signal
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import time

# Ensure core module is importable
sys.path.insert(0, str(Path(__file__).parent))

# Core imports
from core.base_scanner import (
    BaseScanner,
    Finding,
    ScanResult,
    Severity,
    ScanStatus,
    REVUEX_VERSION,
    REVUEX_BANNER,
    DEFAULT_CONFIG,
)
from core.safety_checks import (
    SafetyManager,
    ScopeDefinition,
    ScopeValidator,
    SafetyLevel,
    create_default_scope,
)
from core.utils import (
    normalize_url,
    extract_domain,
    ensure_dir,
    write_json_file,
    read_json_file,
    get_timestamp,
    format_duration,
    Colors,
    print_success,
    print_error,
    print_warning,
    print_info,
)
from core.logger import (
    RevuexLogger,
    get_logger,
    configure_logging,
)
from core.report_generator import (
    ReportGenerator,
    ReportMetadata,
    FindingReport,
    ScanStatistics,
    create_report,
)
from core.intelligence_hub import (
    IntelligenceHub,
    get_hub,
    Endpoint,
    Parameter,
    Technology,
)


# =============================================================================
# CONSTANTS
# =============================================================================

SUITE_VERSION = REVUEX_VERSION

# Scan profiles with pre-configured settings
SCAN_PROFILES = {
    "stealth": {
        "description": "Minimal footprint, slow and careful",
        "delay": 5.0,
        "rate_limit": 10,
        "threads": 1,
        "timeout": 15,
        "retries": 1,
        "tools": ["subdomain_hunter", "tech_fingerprinter", "js_secrets_miner"],
    },
    "standard": {
        "description": "Balanced speed and coverage",
        "delay": 1.0,
        "rate_limit": 30,
        "threads": 3,
        "timeout": 10,
        "retries": 2,
        "tools": "all",
    },
    "aggressive": {
        "description": "Fast and comprehensive (use with caution)",
        "delay": 0.2,
        "rate_limit": 100,
        "threads": 10,
        "timeout": 5,
        "retries": 1,
        "tools": "all",
    },
    "recon": {
        "description": "Reconnaissance only - no active exploitation",
        "delay": 2.0,
        "rate_limit": 20,
        "threads": 3,
        "timeout": 10,
        "retries": 2,
        "tools": ["subdomain_hunter", "tech_fingerprinter", "js_secrets_miner"],
    },
    "injection": {
        "description": "Focus on injection vulnerabilities",
        "delay": 1.0,
        "rate_limit": 30,
        "threads": 3,
        "timeout": 10,
        "retries": 2,
        "tools": ["ssrf", "sqli", "xss", "ssti", "xxe"],
    },
    "access": {
        "description": "Focus on access control issues",
        "delay": 1.0,
        "rate_limit": 30,
        "threads": 3,
        "timeout": 10,
        "retries": 2,
        "tools": ["idor", "cors", "csrf", "jwt_scanner", "session"],
    },
}

# Tool categories for organization
TOOL_CATEGORIES = {
    "recon": {
        "subdomain_hunter": "Subdomain enumeration and discovery",
        "tech_fingerprinter": "Technology stack detection",
        "js_secrets_miner": "JavaScript secrets and API key extraction",
    },
    "injection": {
        "ssrf": "Server-Side Request Forgery",
        "sqli": "SQL Injection",
        "xss": "Cross-Site Scripting",
        "ssti": "Server-Side Template Injection",
        "xxe": "XML External Entity Injection",
    },
    "access_control": {
        "idor": "Insecure Direct Object Reference",
        "cors": "CORS Misconfiguration",
        "csrf": "Cross-Site Request Forgery",
    },
    "authentication": {
        "jwt": "JWT Vulnerability Scanner",
        "session": "Session Management Analyzer",
    },
    "business_logic": {
        "business_logic": "Business Logic Flaw Scanner",
        "race_condition": "Race Condition Tester",
        "price_manipulation": "Price Manipulation Scanner",
    },
    "other": {
        "file_upload": "File Upload Vulnerability Scanner",
        "graphql": "GraphQL Introspection and Security",
        "dependency": "Dependency Vulnerability Checker",
        "apk_analyzer": "Android APK Security Analyzer",
    },
}

# All available tools flattened
ALL_TOOLS = []
for category_tools in TOOL_CATEGORIES.values():
    ALL_TOOLS.extend(category_tools.keys())


# =============================================================================
# DATA CLASSES
# =============================================================================

class ScanPhase(Enum):
    """Scan execution phases"""
    INIT = auto()
    RECON = auto()
    DISCOVERY = auto()
    SCANNING = auto()
    EXPLOITATION = auto()
    REPORTING = auto()
    COMPLETE = auto()


@dataclass
class ScanConfig:
    """Scan configuration"""
    target: str
    output_dir: str = "scans"
    profile: str = "standard"
    tools: List[str] = field(default_factory=list)
    exclude_tools: List[str] = field(default_factory=list)
    
    # Request settings
    delay: float = 1.0
    rate_limit: int = 30
    threads: int = 3
    timeout: int = 10
    retries: int = 2
    
    # Authentication
    cookies: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    auth_token: str = ""
    
    # Proxy
    proxy: str = ""
    
    # Scope
    scope_file: str = ""
    include_subdomains: bool = True
    
    # Output
    output_format: List[str] = field(default_factory=lambda: ["html", "json"])
    verbose: bool = False
    quiet: bool = False
    
    # Advanced
    resume: bool = False
    resume_file: str = ""
    dry_run: bool = False
    
    # Interactive mode
    interactive: bool = True  # Prompt for missing scanner params
    non_interactive: bool = False  # Skip all prompts (for CI/CD)
    
    # Scanner-specific parameters
    scanner_params: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # IDOR-specific (convenience)
    token_a: str = ""
    token_b: str = ""
    
    def __post_init__(self):
        # Normalize target
        if not self.target.startswith(("http://", "https://")):
            self.target = f"https://{self.target}"
        
        # Apply profile settings
        if self.profile in SCAN_PROFILES:
            profile = SCAN_PROFILES[self.profile]
            if not self.tools:
                tools_setting = profile.get("tools", "all")
                if tools_setting == "all":
                    self.tools = ALL_TOOLS.copy()
                else:
                    self.tools = tools_setting.copy()
            
            # Apply profile defaults if not explicitly set
            self.delay = self.delay or profile.get("delay", 1.0)
            self.rate_limit = self.rate_limit or profile.get("rate_limit", 30)
            self.threads = self.threads or profile.get("threads", 3)
            self.timeout = self.timeout or profile.get("timeout", 10)
        
        # Remove excluded tools
        if self.exclude_tools:
            self.tools = [t for t in self.tools if t not in self.exclude_tools]
        
        # Store IDOR tokens in scanner_params if provided via CLI
        if self.token_a or self.token_b:
            if "idor" not in self.scanner_params:
                self.scanner_params["idor"] = {}
            if self.token_a:
                self.scanner_params["idor"]["token_a"] = self.token_a
            if self.token_b:
                self.scanner_params["idor"]["token_b"] = self.token_b
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanState:
    """Scan state for resume capability"""
    scan_id: str
    config: Dict[str, Any]
    phase: str = "INIT"
    completed_tools: List[str] = field(default_factory=list)
    pending_tools: List[str] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    start_time: str = ""
    last_update: str = ""
    
    def save(self, filepath: str) -> None:
        """Save state to file"""
        self.last_update = datetime.now(timezone.utc).isoformat()
        write_json_file(filepath, asdict(self))
    
    @classmethod
    def load(cls, filepath: str) -> "ScanState":
        """Load state from file"""
        data = read_json_file(filepath)
        return cls(**data)


# =============================================================================
# REVUEX SUITE CLASS
# =============================================================================

class RevuexSuite:
    """
    Master orchestrator for REVUEX security scanning framework.
    
    Coordinates all scanners, manages intelligence sharing,
    and generates comprehensive reports.
    """
    
    def __init__(self, config: ScanConfig):
        """
        Initialize the REVUEX suite.
        
        Args:
            config: Scan configuration
        """
        self.config = config
        self.scan_id = self._generate_scan_id()
        self.start_time = datetime.now(timezone.utc)
        
        # Setup output directory
        self.output_dir = Path(config.output_dir) / self.scan_id
        ensure_dir(str(self.output_dir))
        
        # Initialize logger
        self.logger = get_logger(
            name="revuex",
            log_dir=str(self.output_dir / "logs"),
            verbose=config.verbose,
        )
        
        # Initialize intelligence hub
        self.intel_hub = IntelligenceHub(
            db_path=str(self.output_dir / "intelligence.db")
        )
        
        # Initialize safety manager
        self.safety = SafetyManager(level=SafetyLevel.STANDARD)
        if config.scope_file:
            self._load_scope(config.scope_file)
        else:
            self._create_default_scope()
        
        # Scan state
        self.phase = ScanPhase.INIT
        self.findings: List[Finding] = []
        self.statistics = ScanStatistics()
        self.errors: List[str] = []
        
        # Scanner instances (lazy loaded)
        self._scanners: Dict[str, BaseScanner] = {}
        
        # Thread control
        self._shutdown_event = threading.Event()
        self._lock = threading.Lock()
        
        # Resume state
        self.state: Optional[ScanState] = None
        if config.resume and config.resume_file:
            self._load_resume_state(config.resume_file)
    
    def _generate_scan_id(self) -> str:
        """Generate unique scan ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = extract_domain(self.config.target) or "scan"
        domain = domain.replace(".", "_").replace(":", "_")
        return f"{domain}_{timestamp}"
    
    def _create_default_scope(self) -> None:
        """Create default scope from target"""
        domain = extract_domain(self.config.target)
        scope = create_default_scope(
            domain,
            include_subdomains=self.config.include_subdomains
        )
        self.safety.scope_validator = ScopeValidator(scope)
    
    def _load_scope(self, filepath: str) -> None:
        """Load scope from file"""
        try:
            import yaml
            with open(filepath, "r") as f:
                scope_data = yaml.safe_load(f)
            
            scope = ScopeDefinition(**scope_data)
            self.safety.scope_validator = ScopeValidator(scope)
            self.logger.info(f"Loaded scope from {filepath}")
        except Exception as e:
            self.logger.warning(f"Failed to load scope file: {e}")
            self._create_default_scope()
    
    def _load_resume_state(self, filepath: str) -> None:
        """Load resume state from file"""
        try:
            self.state = ScanState.load(filepath)
            self.logger.info(f"Resuming scan from {filepath}")
            self.logger.info(f"Completed tools: {self.state.completed_tools}")
        except Exception as e:
            self.logger.warning(f"Failed to load resume state: {e}")
    
    def _save_state(self) -> None:
        """Save current scan state"""
        if self.state is None:
            self.state = ScanState(
                scan_id=self.scan_id,
                config=self.config.to_dict(),
                start_time=self.start_time.isoformat(),
            )
        
        self.state.phase = self.phase.name
        self.state.findings = [asdict(f) for f in self.findings]
        self.state.errors = self.errors
        
        state_file = self.output_dir / "scan_state.json"
        self.state.save(str(state_file))
    
    def _get_scanner(self, tool_name: str) -> Optional[BaseScanner]:
        """
        Get or create scanner instance with interactive prompts for required params.
        
        Args:
            tool_name: Name of the tool
        
        Returns:
            Scanner instance or None if not available
        """
        if tool_name in self._scanners:
            return self._scanners[tool_name]
        
        try:
            # Dynamic import of scanner
            module_path = f"tools.{tool_name}"
            scanner_class_name = self._tool_to_class_name(tool_name)
            
            module = __import__(module_path, fromlist=[scanner_class_name])
            scanner_class = getattr(module, scanner_class_name)
            
            # Get scanner-specific parameters
            extra_params = self._get_scanner_params(tool_name, scanner_class_name)
            
            # If scanner requires params that weren't provided and user chose to skip
            if extra_params is None:
                self.logger.info(f"Skipping {tool_name} (missing required configuration)")
                return None
            
            # Build base parameters - handle different parameter names
            base_params = {
                "delay": self.config.delay,
                "timeout": self.config.timeout,
                "verbose": self.config.verbose,
            }
            
            # Add proxy if set
            if self.config.proxy:
                base_params["proxy"] = self.config.proxy
            
            # Handle scanners with different primary parameter names
            scanner_param_mapping = {
                # tool_name: (param_name, value)
                "subdomain_hunter": ("domain", self._extract_domain(self.config.target)),
                "apk_analyzer": ("apk_path", extra_params.pop("apk_path", "")),
                "jwt": ("token", extra_params.pop("jwt_token", "") or extra_params.pop("token", "")),
            }
            
            if tool_name in scanner_param_mapping:
                param_name, param_value = scanner_param_mapping[tool_name]
                if not param_value and tool_name in ["apk_analyzer"]:
                    self.logger.info(f"Skipping {tool_name} (missing required: {param_name})")
                    return None
                base_params[param_name] = param_value
                # JWT analyzer also needs target
                if tool_name == "jwt":
                    base_params["target"] = self.config.target
            else:
                # Standard scanner with target parameter
                base_params["target"] = self.config.target
            
            # Merge extra params
            base_params.update(extra_params)
            
            # Create scanner
            scanner = scanner_class(**base_params)
            
            # Set cookies/headers if provided and scanner has session
            if hasattr(scanner, 'session'):
                if self.config.cookies:
                    scanner.session.headers["Cookie"] = self.config.cookies
                if self.config.headers:
                    scanner.session.headers.update(self.config.headers)
                if self.config.auth_token:
                    scanner.session.headers["Authorization"] = f"Bearer {self.config.auth_token}"
            
            self._scanners[tool_name] = scanner
            return scanner
            
        except ImportError as e:
            self.logger.debug(f"Scanner {tool_name} not yet implemented: {e}")
            return None
        except TypeError as e:
            # Handle missing required arguments
            self.logger.warning(f"Scanner {tool_name} requires additional configuration: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to load scanner {tool_name}: {e}")
            return None
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        from urllib.parse import urlparse
        if url.startswith(("http://", "https://")):
            parsed = urlparse(url)
            return parsed.netloc
        return url
    
    def _get_scanner_params(self, tool_name: str, class_name: str) -> Optional[Dict[str, Any]]:
        """
        Get scanner-specific parameters, prompting interactively if needed.
        
        Args:
            tool_name: Name of the tool
            class_name: Scanner class name
        
        Returns:
            Dict of extra parameters or None to skip scanner
        """
        params = {}
        
        # Define scanner-specific requirements
        scanner_requirements = {
            "idor": {
                "description": "IDOR Scanner requires two different account tokens for cross-account testing",
                "params": [
                    {"name": "token_a", "prompt": "Enter Token A (Account A/Owner) [Bearer xxx]", "required": False},
                    {"name": "token_b", "prompt": "Enter Token B (Account B/Attacker) [Bearer xxx]", "required": False},
                ],
                "skip_message": "IDOR scanner will be skipped (no cross-account testing)"
            },
            "jwt": {
                "description": "JWT Scanner analyzes JWT tokens for vulnerabilities",
                "params": [
                    {"name": "token", "prompt": "Enter JWT token to analyze (or press Enter to scan for tokens)", "required": False},
                ],
                "skip_message": "JWT scanner will scan responses for tokens automatically"
            },
            "apk_analyzer": {
                "description": "APK Analyzer requires an APK file path",
                "params": [
                    {"name": "apk_path", "prompt": "Enter path to APK file", "required": True},
                ],
                "skip_message": "APK Analyzer will be skipped (no APK file provided)"
            },
            "file_upload": {
                "description": "File Upload Scanner tests file upload endpoints",
                "params": [
                    {"name": "upload_endpoint", "prompt": "Enter upload endpoint URL (or Enter to auto-detect)", "required": False},
                ],
                "skip_message": "File Upload scanner will auto-detect upload forms"
            },
        }
        
        # Check if this scanner has special requirements
        if tool_name not in scanner_requirements:
            return params  # No special requirements
        
        req = scanner_requirements[tool_name]
        
        # Check if we already have params from config
        config_params = getattr(self.config, 'scanner_params', {}).get(tool_name, {})
        if config_params:
            return config_params
        
        # Interactive mode - prompt for params
        if self.config.interactive and not self.config.non_interactive:
            print(f"\n{'='*60}")
            print(f"  {class_name} Configuration")
            print(f"{'='*60}")
            print(f"  {req['description']}")
            print()
            
            has_required = True
            for param in req["params"]:
                try:
                    value = input(f"  {param['prompt']}: ").strip()
                    if value:
                        params[param["name"]] = value
                    elif param["required"]:
                        has_required = False
                        print(f"  [!] {param['name']} is required")
                except (EOFError, KeyboardInterrupt):
                    print("\n  [!] Input cancelled")
                    return None
            
            if not has_required:
                skip = input(f"\n  Skip this scanner? (Y/n): ").strip().lower()
                if skip != 'n':
                    print(f"  {req['skip_message']}")
                    return None
            
            print()
        
        return params
    
    def _tool_to_class_name(self, tool_name: str) -> str:
        """Convert tool name to class name"""
        # Direct mapping for all tools (tool_name -> ClassName)
        direct_mapping = {
            # Recon
            "subdomain_hunter": "SubdomainHunter",
            "tech_fingerprinter": "TechFingerprinter",
            "js_secrets_miner": "JSSecretsMiner",
            # Injection
            "ssrf": "SSRFScanner",
            "sqli": "SQLiScanner",
            "xss": "XSSScanner",
            "ssti": "SSTIScanner",
            "xxe": "XXEScanner",
            # Access Control
            "idor": "IDORScanner",
            "cors": "CORSScanner",
            "csrf": "CSRFScanner",
            # Authentication
            "jwt": "JWTAnalyzer",
            "session": "SessionScanner",
            # Business Logic
            "business_logic": "BusinessLogicScanner",
            "race_condition": "RaceConditionScanner",
            "price_manipulation": "PriceManipulationScanner",
            # Other
            "file_upload": "FileUploadScanner",
            "graphql": "GraphQLScanner",
            "dependency": "DependencyScanner",
            "apk_analyzer": "APKAnalyzer",
        }
        
        if tool_name in direct_mapping:
            return direct_mapping[tool_name]
        
        # Fallback: convert tool_name to CamelCase + Scanner
        parts = tool_name.split("_")
        class_name = "".join(p.capitalize() for p in parts) + "Scanner"
        return class_name
    
    # =========================================================================
    # SCAN EXECUTION
    # =========================================================================
    
    def run(self) -> ScanResult:
        """
        Execute the full scan.
        
        Returns:
            ScanResult with all findings
        """
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        try:
            self._print_banner()
            self._print_config()
            
            if self.config.dry_run:
                self._dry_run()
                return self._create_result()
            
            # Execute scan phases
            self._phase_init()
            self._phase_recon()
            self._phase_scanning()
            self._phase_reporting()
            
            self.phase = ScanPhase.COMPLETE
            self._save_state()
            
            return self._create_result()
            
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            self._save_state()
            return self._create_result()
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            self.errors.append(str(e))
            self._save_state()
            raise
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.warning(f"Received signal {signum}, shutting down...")
        self._shutdown_event.set()
        self._save_state()
    
    def _print_banner(self) -> None:
        """Print REVUEX banner"""
        if not self.config.quiet:
            print(REVUEX_BANNER)
            print()
    
    def _print_config(self) -> None:
        """Print scan configuration"""
        if self.config.quiet:
            return
        
        print_info(f"Scan ID: {self.scan_id}")
        print_info(f"Target: {self.config.target}")
        print_info(f"Profile: {self.config.profile}")
        print_info(f"Tools: {len(self.config.tools)} enabled")
        print_info(f"Output: {self.output_dir}")
        print()
        
        if self.config.verbose:
            print_info("Configuration:")
            print(f"  Delay: {self.config.delay}s")
            print(f"  Rate Limit: {self.config.rate_limit} req/min")
            print(f"  Threads: {self.config.threads}")
            print(f"  Timeout: {self.config.timeout}s")
            print()
    
    def _dry_run(self) -> None:
        """Show what would be done without executing"""
        print_warning("DRY RUN - No actual requests will be made")
        print()
        print_info("Tools that would be executed:")
        
        for category, tools in TOOL_CATEGORIES.items():
            category_tools = [t for t in self.config.tools if t in tools]
            if category_tools:
                print(f"\n  [{category.upper()}]")
                for tool in category_tools:
                    desc = tools.get(tool, "")
                    status = "✓" if self._get_scanner(tool) else "○"
                    print(f"    {status} {tool}: {desc}")
        
        print()
        print_info("Scan would be saved to: " + str(self.output_dir))
    
    def _phase_init(self) -> None:
        """Initialize scan"""
        self.phase = ScanPhase.INIT
        self.logger.info("Initializing scan...")
        
        # Validate target is in scope
        validation = self.safety.validate_request(
            url=self.config.target,
            method="GET"
        )
        
        if not validation.is_safe:
            raise ValueError(f"Target not in scope: {validation.reason}")
        
        # Create output directories
        ensure_dir(str(self.output_dir / "logs"))
        ensure_dir(str(self.output_dir / "evidence"))
        ensure_dir(str(self.output_dir / "reports"))
        
        self.logger.success("Initialization complete")
    
    def _phase_recon(self) -> None:
        """Execute reconnaissance phase"""
        self.phase = ScanPhase.RECON
        self.logger.info("Starting reconnaissance phase...")
        
        recon_tools = ["subdomain_hunter", "tech_fingerprinter", "js_secrets_miner"]
        tools_to_run = [t for t in recon_tools if t in self.config.tools]
        
        if self.state and self.state.completed_tools:
            tools_to_run = [t for t in tools_to_run if t not in self.state.completed_tools]
        
        self._run_tools(tools_to_run)
        self.logger.success("Reconnaissance phase complete")
    
    def _phase_scanning(self) -> None:
        """Execute main scanning phase"""
        self.phase = ScanPhase.SCANNING
        self.logger.info("Starting vulnerability scanning phase...")
        
        # All tools except recon
        recon_tools = {"subdomain_hunter", "tech_fingerprinter", "js_secrets_miner"}
        scan_tools = [t for t in self.config.tools if t not in recon_tools]
        
        if self.state and self.state.completed_tools:
            scan_tools = [t for t in scan_tools if t not in self.state.completed_tools]
        
        self._run_tools(scan_tools)
        self.logger.success("Scanning phase complete")
    
    def _phase_reporting(self) -> None:
        """Generate reports"""
        self.phase = ScanPhase.REPORTING
        self.logger.info("Generating reports...")
        
        # Update statistics
        self.statistics.critical_count = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        self.statistics.high_count = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        self.statistics.medium_count = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        self.statistics.low_count = sum(1 for f in self.findings if f.severity == Severity.LOW)
        self.statistics.info_count = sum(1 for f in self.findings if f.severity == Severity.INFO)
        
        end_time = datetime.now(timezone.utc)
        self.statistics.duration_seconds = (end_time - self.start_time).total_seconds()
        
        # Create report generator
        metadata = ReportMetadata(
            title="REVUEX Security Assessment Report",
            target=self.config.target,
            target_domain=extract_domain(self.config.target),
            scan_id=self.scan_id,
            scan_date=self.start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        )
        
        generator = ReportGenerator(
            metadata=metadata,
            output_dir=str(self.output_dir / "reports")
        )
        
        # Convert findings to report format
        for finding in self.findings:
            report_finding = FindingReport(
                id=finding.id,
                title=finding.title,
                severity=finding.severity.value,
                description=finding.description,
                url=finding.url,
                parameter=finding.parameter,
                payload=finding.payload,
                evidence=finding.evidence,
                impact=finding.impact,
                remediation=finding.remediation,
                vulnerability_type=finding.vulnerability_type,
            )
            generator.add_finding(report_finding)
        
        generator.set_statistics(self.statistics)
        
        # Generate reports
        report_paths = generator.generate_all(
            base_name=f"revuex_{self.scan_id}",
            formats=self.config.output_format
        )
        
        self.logger.success("Reports generated:")
        for fmt, path in report_paths.items():
            self.logger.info(f"  {fmt.upper()}: {path}")
        
        # Print summary
        self._print_summary()
    
    def _run_tools(self, tools: List[str]) -> None:
        """
        Run multiple tools with thread pool.
        
        Args:
            tools: List of tool names to run
        """
        if not tools:
            return
        
        if self.config.threads == 1:
            # Sequential execution
            for tool in tools:
                if self._shutdown_event.is_set():
                    break
                self._run_single_tool(tool)
        else:
            # Parallel execution
            with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                futures = {
                    executor.submit(self._run_single_tool, tool): tool
                    for tool in tools
                }
                
                for future in as_completed(futures):
                    if self._shutdown_event.is_set():
                        break
                    
                    tool = futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.error(f"Tool {tool} failed: {e}")
                        self.errors.append(f"{tool}: {e}")
    
    def _run_single_tool(self, tool_name: str) -> None:
        """
        Run a single tool.
        
        Args:
            tool_name: Name of the tool to run
        """
        self.logger.info(f"Running {tool_name}...")
        
        scanner = self._get_scanner(tool_name)
        if scanner is None:
            self.logger.warning(f"Scanner {tool_name} not available")
            return
        
        try:
            # Run the scanner
            result = scanner.run()
            
            # Collect findings
            with self._lock:
                self.findings.extend(result.findings)
                self.statistics.total_requests += result.total_requests
                self.statistics.endpoints_tested += result.endpoints_tested
                
                # Mark as completed
                if self.state:
                    self.state.completed_tools.append(tool_name)
            
            # Share intelligence
            self._share_intelligence(tool_name, result)
            
            # Log results
            finding_count = len(result.findings)
            if finding_count > 0:
                self.logger.success(f"{tool_name}: Found {finding_count} issue(s)")
            else:
                self.logger.info(f"{tool_name}: No issues found")
            
        except Exception as e:
            self.logger.error(f"{tool_name} error: {e}")
            self.errors.append(f"{tool_name}: {e}")
    
    def _share_intelligence(self, tool_name: str, result: ScanResult) -> None:
        """Share scan results with intelligence hub"""
        # Share discovered endpoints
        for finding in result.findings:
            if finding.url:
                self.intel_hub.add_endpoint(Endpoint(
                    url=finding.url,
                    method=finding.method if hasattr(finding, "method") else "GET",
                    discovered_by=tool_name,
                ))
            
            if finding.parameter:
                self.intel_hub.add_parameter(Parameter(
                    name=finding.parameter,
                    endpoint=finding.url,
                    discovered_by=tool_name,
                ))
    
    def _create_result(self) -> ScanResult:
        """Create final scan result"""
        end_time = datetime.now(timezone.utc)
        duration = (end_time - self.start_time).total_seconds()
        
        return ScanResult(
            target=self.config.target,
            scan_id=self.scan_id,
            status=ScanStatus.COMPLETED if not self.errors else ScanStatus.PARTIAL,
            findings=self.findings,
            start_time=self.start_time.isoformat(),
            end_time=end_time.isoformat(),
            duration_seconds=duration,
            total_requests=self.statistics.total_requests,
            endpoints_tested=self.statistics.endpoints_tested,
            errors=self.errors,
        )
    
    def _print_summary(self) -> None:
        """Print scan summary"""
        if self.config.quiet:
            return
        
        print()
        print("=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)
        print()
        
        duration = format_duration(self.statistics.duration_seconds)
        print(f"  Target:     {self.config.target}")
        print(f"  Duration:   {duration}")
        print(f"  Requests:   {self.statistics.total_requests}")
        print()
        
        # Findings by severity
        print("  Findings:")
        if self.statistics.critical_count:
            print(f"    {Colors.RED}Critical: {self.statistics.critical_count}{Colors.RESET}")
        if self.statistics.high_count:
            print(f"    {Colors.RED}High:     {self.statistics.high_count}{Colors.RESET}")
        if self.statistics.medium_count:
            print(f"    {Colors.YELLOW}Medium:   {self.statistics.medium_count}{Colors.RESET}")
        if self.statistics.low_count:
            print(f"    {Colors.BLUE}Low:      {self.statistics.low_count}{Colors.RESET}")
        if self.statistics.info_count:
            print(f"    {Colors.CYAN}Info:     {self.statistics.info_count}{Colors.RESET}")
        
        total = self.statistics.total_findings
        if total == 0:
            print(f"    {Colors.GREEN}No vulnerabilities found{Colors.RESET}")
        
        print()
        print(f"  Output: {self.output_dir}")
        print("=" * 60)


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        prog="revuex",
        description="REVUEX - Bug Bounty Automation Framework",
        epilog="Documentation: https://docs.revuex.io",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"REVUEX v{SUITE_VERSION}"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # -------------------------------------------------------------------------
    # SCAN command
    # -------------------------------------------------------------------------
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run vulnerability scan",
        description="Execute comprehensive vulnerability scan against target"
    )
    
    scan_parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target URL or domain"
    )
    
    scan_parser.add_argument(
        "-o", "--output",
        default="scans",
        help="Output directory (default: scans)"
    )
    
    scan_parser.add_argument(
        "-p", "--profile",
        choices=list(SCAN_PROFILES.keys()),
        default="standard",
        help="Scan profile (default: standard)"
    )
    
    scan_parser.add_argument(
        "--tools",
        nargs="+",
        choices=ALL_TOOLS,
        help="Specific tools to run"
    )
    
    scan_parser.add_argument(
        "--exclude",
        nargs="+",
        choices=ALL_TOOLS,
        help="Tools to exclude"
    )
    
    scan_parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay between requests in seconds (default: 1.0)"
    )
    
    scan_parser.add_argument(
        "--rate-limit",
        type=int,
        default=30,
        help="Maximum requests per minute (default: 30)"
    )
    
    scan_parser.add_argument(
        "--threads",
        type=int,
        default=3,
        help="Number of concurrent threads (default: 3)"
    )
    
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    scan_parser.add_argument(
        "--proxy",
        help="HTTP proxy (e.g., http://127.0.0.1:8080)"
    )
    
    scan_parser.add_argument(
        "--cookies",
        help="Cookies string"
    )
    
    scan_parser.add_argument(
        "--header",
        action="append",
        dest="headers",
        help="Custom header (can be used multiple times)"
    )
    
    scan_parser.add_argument(
        "--auth",
        help="Bearer token for authentication"
    )
    
    # IDOR-specific authentication
    scan_parser.add_argument(
        "--token-a",
        help="IDOR: Token for Account A (owner account)"
    )
    
    scan_parser.add_argument(
        "--token-b",
        help="IDOR: Token for Account B (attacker account)"
    )
    
    # Interactive mode controls
    scan_parser.add_argument(
        "--interactive",
        action="store_true",
        default=True,
        help="Enable interactive prompts for scanner configuration (default: enabled)"
    )
    
    scan_parser.add_argument(
        "--non-interactive", "--no-prompt",
        action="store_true",
        dest="non_interactive",
        help="Disable all interactive prompts (for CI/CD pipelines)"
    )
    
    scan_parser.add_argument(
        "--scope",
        help="Scope definition file (YAML)"
    )
    
    scan_parser.add_argument(
        "--format",
        nargs="+",
        choices=["html", "json", "md", "txt"],
        default=["html", "json"],
        help="Report formats (default: html json)"
    )
    
    scan_parser.add_argument(
        "--resume",
        help="Resume from state file"
    )
    
    scan_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without executing"
    )
    
    scan_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    
    scan_parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress banner and non-essential output"
    )
    
    # -------------------------------------------------------------------------
    # RECON command
    # -------------------------------------------------------------------------
    recon_parser = subparsers.add_parser(
        "recon",
        help="Run reconnaissance only",
        description="Execute reconnaissance phase without active scanning"
    )
    
    recon_parser.add_argument("-t", "--target", required=True, help="Target domain")
    recon_parser.add_argument("-o", "--output", default="scans", help="Output directory")
    recon_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    recon_parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    # -------------------------------------------------------------------------
    # LIST command
    # -------------------------------------------------------------------------
    list_parser = subparsers.add_parser(
        "list",
        help="List available tools",
        description="Show all available security testing tools"
    )
    
    list_parser.add_argument(
        "--category",
        choices=list(TOOL_CATEGORIES.keys()),
        help="Filter by category"
    )
    
    # -------------------------------------------------------------------------
    # PROFILES command
    # -------------------------------------------------------------------------
    subparsers.add_parser(
        "profiles",
        help="Show available scan profiles",
        description="Display all available scan profiles and their settings"
    )
    
    # -------------------------------------------------------------------------
    # REPORT command
    # -------------------------------------------------------------------------
    report_parser = subparsers.add_parser(
        "report",
        help="Generate report from results",
        description="Generate report from existing scan results"
    )
    
    report_parser.add_argument("-i", "--input", required=True, help="Input JSON file")
    report_parser.add_argument("-o", "--output", help="Output file path")
    report_parser.add_argument(
        "--format",
        choices=["html", "json", "md", "txt"],
        default="html",
        help="Report format"
    )
    
    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute scan command"""
    # Parse headers
    headers = {}
    if args.headers:
        for h in args.headers:
            if ":" in h:
                key, value = h.split(":", 1)
                headers[key.strip()] = value.strip()
    
    # Create config
    config = ScanConfig(
        target=args.target,
        output_dir=args.output,
        profile=args.profile,
        tools=args.tools or [],
        exclude_tools=args.exclude or [],
        delay=args.delay,
        rate_limit=args.rate_limit,
        threads=args.threads,
        timeout=args.timeout,
        proxy=args.proxy or "",
        cookies=args.cookies or "",
        headers=headers,
        auth_token=args.auth or "",
        scope_file=args.scope or "",
        output_format=args.format,
        verbose=args.verbose,
        quiet=args.quiet,
        resume=bool(args.resume),
        resume_file=args.resume or "",
        dry_run=args.dry_run,
        interactive=getattr(args, 'interactive', True),
        non_interactive=getattr(args, 'non_interactive', False),
        token_a=getattr(args, 'token_a', "") or "",
        token_b=getattr(args, 'token_b', "") or "",
    )
    
    # Create and run suite
    suite = RevuexSuite(config)
    result = suite.run()
    
    # Return exit code based on findings
    if result.status == ScanStatus.ERROR:
        return 2
    elif len(result.findings) > 0:
        return 1
    return 0


def cmd_recon(args: argparse.Namespace) -> int:
    """Execute recon command"""
    config = ScanConfig(
        target=args.target,
        output_dir=args.output,
        profile="recon",
        verbose=args.verbose,
        quiet=args.quiet,
    )
    
    suite = RevuexSuite(config)
    result = suite.run()
    
    return 0 if result.status == ScanStatus.COMPLETED else 1


def cmd_list(args: argparse.Namespace) -> int:
    """List available tools"""
    print()
    print("REVUEX Security Tools")
    print("=" * 60)
    
    for category, tools in TOOL_CATEGORIES.items():
        if args.category and args.category != category:
            continue
        
        print(f"\n[{category.upper()}]")
        for tool, description in tools.items():
            print(f"  {tool:25} {description}")
    
    print()
    return 0


def cmd_profiles(args: argparse.Namespace) -> int:
    """Show available profiles"""
    print()
    print("REVUEX Scan Profiles")
    print("=" * 60)
    
    for name, profile in SCAN_PROFILES.items():
        print(f"\n{Colors.CYAN}{name}{Colors.RESET}")
        print(f"  Description: {profile['description']}")
        print(f"  Delay:       {profile['delay']}s")
        print(f"  Rate Limit:  {profile['rate_limit']} req/min")
        print(f"  Threads:     {profile['threads']}")
        tools = profile['tools']
        if tools == "all":
            print(f"  Tools:       All ({len(ALL_TOOLS)} tools)")
        else:
            print(f"  Tools:       {', '.join(tools)}")
    
    print()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Generate report from results"""
    input_path = Path(args.input)
    if not input_path.exists():
        print_error(f"Input file not found: {args.input}")
        return 1
    
    try:
        data = read_json_file(str(input_path))
        findings = data.get("findings", [])
        target = data.get("target", "Unknown")
        scan_id = data.get("scan_id", "")
        
        output_paths = create_report(
            findings=findings,
            target=target,
            scan_id=scan_id,
            formats=[args.format]
        )
        
        print_success(f"Report generated: {output_paths.get(args.format)}")
        return 0
        
    except Exception as e:
        print_error(f"Failed to generate report: {e}")
        return 1


def main() -> int:
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if args.command is None:
        # Print banner and help
        print(REVUEX_BANNER)
        parser.print_help()
        return 0
    
    # Route to command handler
    commands = {
        "scan": cmd_scan,
        "recon": cmd_recon,
        "list": cmd_list,
        "profiles": cmd_profiles,
        "report": cmd_report,
    }
    
    handler = commands.get(args.command)
    if handler:
        return handler(args)
    
    parser.print_help()
    return 0


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    sys.exit(main())
