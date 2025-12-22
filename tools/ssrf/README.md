# REVUEX SSRF Scanner GOLD v4.0

High-confidence SSRF scanner with embedded Scope Intelligence Engine (SIE) for automatic endpoint and parameter discovery.

## Overview

Automatic endpoint discovery with differential response analysis. No external collaborator dependency required.

## GOLD Principles

- **No exploitation** - Detection only
- **No collaborator** - Self-contained analysis
- **Automatic discovery** - SIE finds endpoints
- **Differential analysis** - Response comparison
- **Confidence scoring** - Threshold-based findings

## Features

### Scope Intelligence Engine (SIE)

| Source | What it Finds |
|--------|---------------|
| **HTML Forms** | action URLs + input parameters |
| **JavaScript** | fetch(), axios, XMLHttpRequest |
| **Inline JS** | API endpoints, URL assignments |
| **Links** | /api/, callback, redirect URLs |
| **Common Paths** | /proxy, /fetch, /redirect |

### SSRF Tests

| Technique | Description | Severity |
|-----------|-------------|----------|
| **Internal IPs** | 127.0.0.1, localhost, 0.0.0.0 | HIGH |
| **Cloud Metadata** | AWS, GCP, Azure, DigitalOcean | CRITICAL |
| **URL Parser Bypass** | @, #, unicode, hex encoding | HIGH |
| **Header-based** | X-Forwarded-For, Host injection | HIGH |
| **Protocol Handlers** | file://, gopher://, dict:// | HIGH |

## Usage

### CLI

```bash
# Basic scan (auto-discovery)
python -m tools.ssrf -t https://example.com

# With custom endpoint
python -m tools.ssrf -t https://example.com -e /api/proxy

# With custom parameters
python -m tools.ssrf -t https://example.com -p webhook_url -p callback

# Skip discovery (test target directly)
python -m tools.ssrf -t https://example.com/api/fetch --skip-discovery

# With headers
python -m tools.ssrf -t https://example.com -H "Authorization: Bearer token"

# Output to JSON
python -m tools.ssrf -t https://example.com -o ssrf_report.json
```

### Python API

```python
from tools.ssrf import SSRFScanner

scanner = SSRFScanner(
    target="https://example.com",
    custom_endpoints=["/api/proxy", "/api/fetch"],
    custom_params=["webhook_url", "callback"]
)
result = scanner.run()

print(f"Endpoints discovered: {len(scanner.discovered_endpoints)}")
print(f"Issues found: {len(result.findings)}")
```

## Confidence Scoring

| Factor | Score |
|--------|-------|
| SIE Discovery | +30 |
| Non-error response | +20 |
| SSRF indicator in response | +30 |
| Response differs from baseline | +10-20 |
| Cloud metadata content | +30 |

**Threshold: 80** (High Confidence)

## Internal Payloads

```
http://127.0.0.1
http://localhost
http://[::1]
http://0.0.0.0
http://127.1
http://2130706433 (decimal)
http://0x7f.0.0.1 (hex)
```

## Cloud Metadata Endpoints

| Cloud | Endpoint |
|-------|----------|
| AWS | http://169.254.169.254/latest/meta-data/ |
| GCP | http://metadata.google.internal/computeMetadata/v1/ |
| Azure | http://169.254.169.254/metadata/instance |
| DigitalOcean | http://169.254.169.254/metadata/v1/ |

## URL Parser Bypasses

```
http://127.0.0.1#@example.com
http://example.com@127.0.0.1
http://127.0.0.1%23@example.com
http://127。0。0。1 (full-width dots)
```

## Legal Disclaimer

For authorized security testing only.

## Author

REVUEX Team - Bug Bounty Automation Framework
