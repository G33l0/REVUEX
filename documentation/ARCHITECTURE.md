# REVUEX Architecture

## Overview

REVUEX is a modular bug bounty automation framework built on the GOLD (Ground-truth Observational Lightweight Detection) philosophy.

```
┌─────────────────────────────────────────────────────────────┐
│                    REVUEX SUITE                             │
├─────────────────────────────────────────────────────────────┤
│  revuex_suite.py (Master Orchestrator)                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   RECON     │  │  INJECTION  │  │   ACCESS    │         │
│  │  Scanners   │  │  Scanners   │  │  CONTROL    │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  BUSINESS   │  │    API      │  │   MOBILE    │         │
│  │   LOGIC     │  │  Scanners   │  │  Analysis   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                    CORE LIBRARY                             │
│  ┌──────────────┬──────────────┬──────────────┐            │
│  │ BaseScanner  │ SafetyChecks │   Logger     │            │
│  ├──────────────┼──────────────┼──────────────┤            │
│  │ Intelligence │   Report     │    Utils     │            │
│  │     Hub      │  Generator   │              │            │
│  └──────────────┴──────────────┴──────────────┘            │
├─────────────────────────────────────────────────────────────┤
│                   PAYLOAD LIBRARY                           │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
revuex-vul-suite/
├── revuex_suite.py          # Master orchestrator
├── setup.py                 # Package installation
├── requirements.txt         # Dependencies
│
├── core/                    # Shared core library
│   ├── __init__.py
│   ├── base_scanner.py      # BaseScanner class
│   ├── safety_checks.py     # Safety validation
│   ├── logger.py            # Logging system
│   ├── intelligence_hub.py  # Cross-tool intelligence
│   ├── report_generator.py  # Report generation
│   └── utils.py             # Utility functions
│
├── tools/                   # 20 Security scanners
│   ├── __init__.py          # Scanner registry
│   ├── ssrf/
│   ├── sqli/
│   ├── xss/
│   └── [17 more...]
│
├── payloads/                # Payload collections
│   ├── ssrf/
│   ├── sqli/
│   └── [18 more...]
│
└── documentation/           # Documentation
```

## Core Components

### BaseScanner

All scanners inherit from `BaseScanner`:

```python
class BaseScanner:
    """Base class for all REVUEX scanners."""
    
    def __init__(self, target, **kwargs):
        self.target = target
        self.session = requests.Session()
        self.findings = []
        self.rate_limiter = RateLimiter()
        self.logger = Logger()
    
    def run(self) -> ScanResult:
        """Execute the scan."""
        self._validate_target()
        self.scan()
        return self._build_result()
    
    def scan(self):
        """Override in subclass."""
        raise NotImplementedError
    
    def add_finding(self, finding: Finding):
        """Add a finding to results."""
        self.findings.append(finding)
```

### Finding Class

```python
@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    description: str
    url: str
    parameter: str
    method: str
    payload: str
    evidence: str
    impact: str
    remediation: str
    vulnerability_type: str
    confidence: str
```

### ScanResult Class

```python
@dataclass
class ScanResult:
    scanner_name: str
    target: str
    status: ScanStatus
    findings: List[Finding]
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    request_count: int
```

## Scanner Categories

### Reconnaissance (3 tools)
| Tool | Purpose |
|------|---------|
| SubdomainHunter | Passive subdomain enumeration |
| TechFingerprinter | Technology stack detection |
| JSSecretsMiner | JavaScript secret extraction |

### Injection (5 tools)
| Tool | Purpose |
|------|---------|
| SSRFScanner | Server-Side Request Forgery |
| SQLiScanner | SQL Injection |
| XSSScanner | Cross-Site Scripting |
| SSTIScanner | Server-Side Template Injection |
| XXEScanner | XML External Entity |

### Access Control (5 tools)
| Tool | Purpose |
|------|---------|
| IDORScanner | Insecure Direct Object Reference |
| CORSScanner | CORS misconfiguration |
| CSRFScanner | Cross-Site Request Forgery |
| SessionScanner | Session management |
| JWTAnalyzer | JWT vulnerabilities |

### Business Logic (3 tools)
| Tool | Purpose |
|------|---------|
| BusinessLogicScanner | Workflow flaws |
| PriceManipulationScanner | E-commerce manipulation |
| RaceConditionScanner | Concurrency issues |

### Other (4 tools)
| Tool | Purpose |
|------|---------|
| FileUploadScanner | File upload vulnerabilities |
| GraphQLScanner | GraphQL security |
| APKAnalyzer | Android APK analysis |
| DependencyScanner | Vulnerable libraries |

## GOLD Philosophy

### Core Principles

1. **Zero Exploitation**
   - Detection only, no harmful payloads
   - No file exfiltration or data theft
   - No callback abuse or network exploitation

2. **Differential Analysis**
   - Compare baseline vs test responses
   - Identify deviations indicating vulnerabilities
   - Reduce false positives through correlation

3. **Confidence Scoring**
   - Each signal contributes to confidence score
   - Threshold-based findings (typically 75-80%)
   - Multiple signals required for high confidence

4. **Bug Bounty Ready**
   - Professional report generation
   - Evidence collection for reproducibility
   - Remediation guidance included

## Data Flow

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│  Target  │────▶│ Scanner  │────▶│ Findings │
└──────────┘     └──────────┘     └──────────┘
                      │
                      ▼
              ┌──────────────┐
              │   Payloads   │
              └──────────────┘
                      │
                      ▼
              ┌──────────────┐
              │   Analysis   │
              │  • Baseline  │
              │  • Probe     │
              │  • Compare   │
              └──────────────┘
                      │
                      ▼
              ┌──────────────┐
              │  Confidence  │
              │   Scoring    │
              └──────────────┘
                      │
                      ▼
              ┌──────────────┐
              │    Report    │
              └──────────────┘
```

## Intelligence Hub

Cross-tool intelligence sharing:

```python
class IntelligenceHub:
    """Share intelligence between scanners."""
    
    def share_finding(self, scanner, finding):
        """Share finding with other scanners."""
        pass
    
    def get_related(self, vulnerability_type):
        """Get related findings."""
        pass
    
    def correlate(self):
        """Correlate findings across scanners."""
        pass
```

## Extensibility

### Adding a New Scanner

1. Create scanner directory in `tools/`
2. Implement scanner inheriting from `BaseScanner`
3. Create `__init__.py`, `__main__.py`, `README.md`
4. Add payloads to `payloads/`
5. Register in `tools/__init__.py`

### Scanner Template

```python
from core.base_scanner import BaseScanner, Finding, Severity

class NewScanner(BaseScanner):
    def __init__(self, target, **kwargs):
        super().__init__(target=target, **kwargs)
        self.scanner_name = "New Scanner GOLD"
    
    def scan(self):
        # 1. Capture baseline
        baseline = self._capture_baseline()
        
        # 2. Run tests
        for test in self.tests:
            result = self._run_test(test)
            
            # 3. Calculate confidence
            confidence = self._calculate_confidence(result, baseline)
            
            # 4. Add finding if threshold met
            if confidence >= self.threshold:
                self.add_finding(Finding(...))
```

## Security Considerations

- Rate limiting prevents overwhelming targets
- Safety checks validate payloads before sending
- No storage of sensitive target data
- Findings sanitized before export
- Legal disclaimer required before use
