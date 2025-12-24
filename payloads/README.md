# REVUEX Payload Library

Curated payload collections for all 20 GOLD scanners.

## Overview

Each scanner has a dedicated payload directory containing JSON files with detection patterns, test cases, and configuration.

## Structure

```
payloads/
├── README.md                    ← This file
├── ssrf/
│   └── payloads.json           ← SSRF detection payloads
├── sqli/
│   └── payloads.json           ← SQL injection patterns
├── xss/
│   └── payloads.json           ← XSS payloads by context
├── ssti/
│   └── payloads.json           ← Template injection patterns
├── xxe/
│   └── payloads.json           ← XXE detection payloads
├── cors/
│   └── payloads.json           ← CORS test origins
├── csrf/
│   └── payloads.json           ← CSRF detection patterns
├── idor/
│   └── payloads.json           ← IDOR test patterns
├── jwt/
│   └── payloads.json           ← JWT attack patterns
├── graphql/
│   └── payloads.json           ← GraphQL queries
├── session/
│   └── payloads.json           ← Session test patterns
├── file_upload/
│   └── payloads.json           ← File upload bypasses
├── business_logic/
│   └── payloads.json           ← Business logic tests
├── price_manipulation/
│   └── payloads.json           ← Price manipulation tests
├── race_condition/
│   └── payloads.json           ← Race condition configs
├── dependency/
│   └── payloads.json           ← Vulnerable library patterns
├── apk_analyzer/
│   └── payloads.json           ← APK analysis patterns
├── subdomain_hunter/
│   └── payloads.json           ← Subdomain sources
├── tech_fingerprinter/
│   └── payloads.json           ← Technology signatures
└── js_secrets_miner/
    └── payloads.json           ← Secret regex patterns
```

## Payload Categories

### Injection Payloads

| Scanner | Payloads | Description |
|---------|----------|-------------|
| **SSRF** | Internal IPs, cloud metadata, bypasses | Non-exploitative SSRF detection |
| **SQLi** | Error-based, blind, time-based | SQL injection fingerprinting |
| **XSS** | HTML, attribute, JS contexts | Context-aware XSS detection |
| **SSTI** | Jinja2, Twig, FreeMarker, etc. | Template engine probes |
| **XXE** | Safe entities, DOCTYPE tests | Non-destructive XXE detection |

### Access Control Payloads

| Scanner | Payloads | Description |
|---------|----------|-------------|
| **CORS** | External origins, bypasses | Origin reflection tests |
| **CSRF** | Token patterns, origin checks | CSRF protection analysis |
| **IDOR** | ID patterns, UUID formats | Object reference tests |
| **JWT** | Algorithm confusion, claims | JWT vulnerability patterns |
| **Session** | Cookie attributes, fixation | Session security tests |

### Business Logic Payloads

| Scanner | Payloads | Description |
|---------|----------|-------------|
| **Business Logic** | Workflow bypasses | State machine tests |
| **Price Manipulation** | Negative, zero, overflow | Price/quantity tests |
| **Race Condition** | Concurrency patterns | Atomicity tests |

### Reconnaissance Payloads

| Scanner | Payloads | Description |
|---------|----------|-------------|
| **Subdomain** | CT logs, DNS sources | Subdomain enumeration |
| **Tech Fingerprinter** | Headers, scripts, patterns | Technology signatures |
| **JS Secrets** | API keys, tokens, credentials | Secret patterns |
| **Dependency** | Library fingerprints, CVEs | Vulnerable library detection |

## Payload Format

All payloads use JSON format:

```json
{
  "metadata": {
    "name": "Scanner Name Payloads",
    "version": "1.0.0",
    "description": "Description of payload collection",
    "author": "REVUEX Team"
  },
  "payloads": {
    "category1": [...],
    "category2": [...]
  },
  "patterns": {
    "detection": [...],
    "indicators": [...]
  }
}
```

## Usage

### Loading Payloads

```python
import json
from pathlib import Path

def load_payloads(scanner_name: str) -> dict:
    payload_file = Path(f"payloads/{scanner_name}/payloads.json")
    with open(payload_file) as f:
        return json.load(f)

# Example
ssrf_payloads = load_payloads("ssrf")
print(ssrf_payloads["internal_payloads"]["localhost"])
```

### Custom Payloads

Add custom payloads by extending the JSON files:

```json
{
  "custom_payloads": {
    "my_payload_1": "value1",
    "my_payload_2": "value2"
  }
}
```

## GOLD Philosophy

All payloads follow GOLD principles:

1. **Non-Exploitative** - Detection only, no harmful payloads
2. **Safe Testing** - No file access, no callbacks
3. **Differential Analysis** - Compare baseline vs test
4. **Confidence-Based** - Multiple signals for high confidence

## Key Payload Files

### SSRF (ssrf/payloads.json)

```json
{
  "internal_payloads": {
    "localhost": ["http://127.0.0.1", "http://localhost"],
    "ipv6": ["http://[::1]"],
    "alternative": ["http://0.0.0.0", "http://127.1"]
  },
  "cloud_metadata": {
    "aws": "http://169.254.169.254/latest/meta-data/",
    "gcp": "http://metadata.google.internal/",
    "azure": "http://169.254.169.254/metadata/instance"
  }
}
```

### XSS (xss/payloads.json)

```json
{
  "contexts": {
    "html": ["<script>alert(1)</script>"],
    "attribute": ["\" onmouseover=\"alert(1)"],
    "javascript": ["';alert(1);//"]
  }
}
```

### SSTI (ssti/payloads.json)

```json
{
  "probes": {
    "jinja2": ["{{7*7}}", "{{config}}"],
    "twig": ["{{7*7}}", "{{_self}}"],
    "freemarker": ["${7*7}", "${.now}"]
  }
}
```

## Contributing

To add new payloads:

1. Edit the relevant `payloads.json` file
2. Follow the existing format
3. Ensure payloads are non-exploitative
4. Test with the scanner
5. Submit a pull request

## Legal Disclaimer

These payloads are for authorized security testing only. Always obtain proper authorization before testing.

---

**REVUEX** - Professional Bug Bounty Automation Framework
