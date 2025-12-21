# REVUEX Subdomain Hunter GOLD

Research-Grade Subdomain Intelligence Engine for Bug Bounty Hunters.

## Overview

High-confidence subdomain discovery with zero noise. This tool uses passive and semi-passive techniques to find subdomains while classifying ownership and identifying takeover risks.

## Features

|Technique                   |Description                                         |
|----------------------------|----------------------------------------------------|
|**CT Log Mining**           |Certificate Transparency via crt.sh                 |
|**HTML/JS Extraction**      |Parse URLs from webpage content                     |
|**Multi-Source Correlation**|Higher confidence when found in multiple sources    |
|**DNS Resolution**          |Verify subdomain resolves                           |
|**Ownership Classification**|OWNED / THIRD_PARTY / DANGLING                      |
|**Takeover Detection**      |Identify dangling DNS pointing to claimable services|
|**Service Fingerprinting**  |Detect sensitive services (admin, dev, api)         |
|**Second-Order Discovery**  |Find subdomains from discovered subdomains          |
|**Trust Boundary Analysis** |CORS wildcards, cookie scope issues                 |
|**Confidence Scoring**      |0-100 score based on multiple factors               |

## Usage

### CLI

```bash
# Basic scan
python -m tools.subdomain_hunter -d example.com

# With lower threshold
python -m tools.subdomain_hunter -d example.com --threshold 50

# Verbose with output
python -m tools.subdomain_hunter -d example.com -v -o results.json
```

### Python API

```python
from tools.subdomain_hunter import SubdomainHunter

hunter = SubdomainHunter(
    domain="example.com",
    confidence_threshold=70
)
result = hunter.run()

for finding in result.findings:
    print(f"[{finding.severity.value}] {finding.title}")
```

## Ownership Classification

|Type           |Description                                           |
|---------------|------------------------------------------------------|
|**OWNED**      |Subdomain resolves to target infrastructure           |
|**THIRD_PARTY**|Subdomain uses external service (GitHub, Heroku, etc.)|
|**DANGLING**   |DNS record exists but doesn’t resolve = TAKEOVER RISK |

## Takeover Detection

Detects potential takeovers for:

- GitHub Pages
- Heroku
- AWS S3
- Azure
- Netlify
- Vercel
- And 15+ more services

## Legal Disclaimer

This tool is for authorized security testing only.

## Author

REVUEX Team - Bug Bounty Automation Framework
