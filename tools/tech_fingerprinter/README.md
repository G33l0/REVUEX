# REVUEX Tech Fingerprinter GOLD

High-Confidence Technology Stack Detection via Invariants & Correlation.

## Overview

Passive-only technology fingerprinting using invariant analysis. No fuzzing, no payloads - just intelligent correlation and confidence scoring.

## Design Philosophy

- **Passive only** - No active probing or fuzzing
- **No payloads** - Zero attack traffic
- **Correlation > Banners** - Multiple signals for confidence
- **Triager-defensible** - Confidence scoring

## Features

|Technique                |Description                     |
|-------------------------|--------------------------------|
|**Header Analysis**      |Server, X-Powered-By detection  |
|**Cookie Fingerprinting**|Session cookie name patterns    |
|**Asset Patterns**       |JS/CSS path fingerprints        |
|**Error Schemas**        |JSON error structure analysis   |
|**Meta Tags**            |Generator meta tag extraction   |
|**TLS Analysis**         |SSL version, cipher, certificate|
|**WAF/CDN Detection**    |Signature header detection      |
|**X-Powered-By**         |Language/framework extraction   |
|**Confidence Scoring**   |0-100 per technology            |
|**Intelligence Export**  |JSON for other GOLD tools       |

## Usage

### CLI

```bash
# Basic scan
python -m tools.tech_fingerprinter -t https://example.com

# With custom threshold
python -m tools.tech_fingerprinter -t https://example.com --threshold 50

# Output to JSON
python -m tools.tech_fingerprinter -t https://example.com -o report.json
```

### Python API

```python
from tools.tech_fingerprinter import TechFingerprinter

scanner = TechFingerprinter(target="https://example.com")
result = scanner.run()

# Get intelligence for other tools
intel = scanner.get_intel()
print(intel["frameworks"])
print(intel["infrastructure"])
```

## Detected Technologies

### Frameworks

- Django, Flask, Rails, Laravel, Express
- Spring, ASP.NET, Phoenix, Play
- Next.js, Nuxt, React, Vue, Angular
- Gatsby, Svelte

### Infrastructure

- Nginx, Apache, IIS, Tomcat
- Gunicorn, Uvicorn, Kestrel, Jetty
- Varnish, Envoy, Caddy

### WAF/CDN

- Cloudflare, Akamai, Fastly
- CloudFront, Incapsula, Sucuri
- StackPath, Azure CDN

### CMS

- WordPress, Drupal, Joomla
- Ghost, Shopify, Magento
- Wix, Squarespace

## Confidence Scoring

|Signal        |Score|
|--------------|-----|
|Meta Generator|+30  |
|Cookie Pattern|+25  |
|WAF Header    |+25  |
|Asset Pattern |+20  |
|Error Schema  |+20  |
|X-Powered-By  |+20  |
|Server Header |+15  |
|TLS Info      |+10  |

**Threshold: 70** (CONFIRMED)

## Intelligence Export

```json
{
  "frameworks": {
    "django": 45,
    "react": 20
  },
  "infrastructure": {
    "nginx": 15,
    "TLSv1.3": 10
  },
  "waf_cdn": {
    "cloudflare": 35
  }
}
```

## Integration with Other Tools

```python
from tools.tech_fingerprinter import TechFingerprinter
from tools.sqli import SQLiScanner

# First, fingerprint
fp = TechFingerprinter(target="https://example.com")
fp.run()
intel = fp.get_intel()

# Use intel to customize SQLi scanner
if "django" in intel["frameworks"]:
    # Django-specific SQLi techniques
    pass
```

## Legal Disclaimer

This tool performs passive analysis only. For authorized security testing.

## Author

REVUEX Team - Bug Bounty Automation Framework