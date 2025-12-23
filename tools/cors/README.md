# REVUEX CORS Scanner GOLD

High-confidence CORS misconfiguration scanner for detecting origin reflection, wildcard issues, and credential exposure.

## Overview

Comprehensive CORS testing with subdomain bypasses, null origin, and regex bypass patterns. No exploitation required.

## GOLD Principles

- **No exploitation** - Detection only
- **Origin reflection** - Arbitrary origin testing
- **Credential exposure** - ACAC header analysis
- **Bypass patterns** - Subdomain, regex, protocol
- **Confidence scoring** - Threshold-based findings

## Features

| Technique | Description | Severity |
|-----------|-------------|----------|
| **Wildcard + Credentials** | `*` with `credentials: true` | CRITICAL |
| **Origin Reflection + Credentials** | Reflects any origin + credentials | CRITICAL |
| **Origin Reflection** | Reflects arbitrary origin | HIGH |
| **Null Origin** | Accepts `null` origin | HIGH |
| **Subdomain Bypass** | evil.target.com accepted | HIGH |
| **Regex Bypass** | target.com.evil.com accepted | HIGH |
| **Protocol Downgrade** | HTTPS to HTTP accepted | MEDIUM |
| **Preflight Misconfiguration** | OPTIONS allows dangerous methods | MEDIUM |

## Usage

### CLI

```bash
# Basic scan
python -m tools.cors -t https://example.com/api/user

# With custom origins
python -m tools.cors -t https://example.com/api -o https://mytest.com

# With headers
python -m tools.cors -t https://example.com/api -H "Authorization: Bearer token"

# Output to JSON
python -m tools.cors -t https://example.com/api --output cors_report.json
```

### Python API

```python
from tools.cors import CORSScanner

scanner = CORSScanner(
    target="https://example.com/api/user",
    custom_origins=["https://mytest.com"]
)
result = scanner.run()

print(f"Baseline ACAO: {scanner.baseline_response.get('acao')}")
print(f"Issues found: {len(result.findings)}")
```

## Test Origins

### External Origins
```
https://evil.com
https://attacker.example
https://malicious.site
http://evil.com
null
```

### Subdomain Bypasses
```
https://evil.{domain}
https://{domain}.evil.com
https://{domain}evil.com
https://evil{domain}
```

### Regex Bypasses
```
https://{domain}.attacker.com
https://attacker.com.{domain}
https://{domain}%60.evil.com
https://{domain}%0d.evil.com
```

## Confidence Scoring

| Factor | Score |
|--------|-------|
| ACAO header present | +30 |
| Origin reflected exactly | +30 |
| Wildcard with credentials | +40 |
| Credentials allowed | +30 |
| Cross-origin accepted | +20 |

**Threshold: 80** (High Confidence)

## CORS Headers Analyzed

| Header | Description |
|--------|-------------|
| `Access-Control-Allow-Origin` | Allowed origins |
| `Access-Control-Allow-Credentials` | Cookie/auth inclusion |
| `Access-Control-Allow-Methods` | Allowed HTTP methods |
| `Access-Control-Allow-Headers` | Allowed request headers |

## Legal Disclaimer

For authorized security testing only.

## Author

REVUEX Team - Bug Bounty Automation Framework
