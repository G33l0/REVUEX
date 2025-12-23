# REVUEX Dependency Scanner GOLD

High-confidence dependency and component risk analyzer for detecting vulnerable JavaScript libraries.

## Overview

Automated detection of vulnerable frontend libraries with version fingerprinting, CVE correlation, and confidence-based findings.

## GOLD Principles

- **No exploitation** - Detection only
- **Version fingerprinting** - URL and content analysis
- **CVE correlation** - Known vulnerability matching
- **Confidence scoring** - Threshold-based findings
- **CDN support** - cdnjs, jsdelivr, unpkg

## Features

| Library | Risk | Severity |
|---------|------|----------|
| **jQuery** | XSS / Prototype Pollution | HIGH |
| **Angular 1.x** | Template Injection / Sandbox Escape | CRITICAL |
| **Lodash** | Prototype Pollution | HIGH |
| **Moment.js** | ReDoS / Path Traversal | MEDIUM |
| **Bootstrap** | XSS | MEDIUM |
| **Vue.js** | XSS / Template Injection | HIGH |
| **Handlebars** | Prototype Pollution / RCE | CRITICAL |
| **DOMPurify** | XSS Bypass | HIGH |
| **Axios** | SSRF / Header Injection | HIGH |
| **Underscore** | Arbitrary Code Execution | CRITICAL |
| **Marked** | ReDoS / XSS | HIGH |
| **Highlight.js** | ReDoS | MEDIUM |

## Usage

### CLI

```bash
# Basic scan
python -m tools.dependency -t https://example.com

# Deep scan (fetch script contents)
python -m tools.dependency -t https://example.com --deep

# With headers
python -m tools.dependency -t https://example.com -H "Cookie: session=abc"

# Output to JSON
python -m tools.dependency -t https://example.com -o dependency_report.json
```

### Python API

```python
from tools.dependency import DependencyScanner

scanner = DependencyScanner(
    target="https://example.com",
    deep_scan=True
)
result = scanner.run()

print(f"Libraries found: {scanner.discovered_libraries}")
print(f"Vulnerable: {len(result.findings)}")
```

## Detection Methods

### 1. URL Analysis
Extracts library/version from script URLs:
```
/jquery-3.4.1.min.js
/libs/lodash/4.17.15/lodash.min.js
npm/moment@2.29.0
```

### 2. CDN Patterns
Supports major CDNs:
- cdnjs.cloudflare.com
- jsdelivr.net
- unpkg.com
- googleapis.com

### 3. Inline Script Fingerprinting
Detects library usage in inline scripts:
```javascript
jQuery.fn.init
angular.module
new Vue({})
React.createElement
```

### 4. Deep Scan
Fetches script contents to find version comments:
```javascript
/*! jQuery v3.4.1 */
* @version 4.17.15
```

## Confidence Scoring

| Factor | Score |
|--------|-------|
| Library detected | +25 |
| Version extracted | +25 |
| Vulnerable version range | +30 |
| Security-sensitive class | +20 |

**Threshold: 75** (High Confidence)

## CVE Coverage

The scanner tracks CVEs for each library:
- jQuery: CVE-2020-11022, CVE-2020-11023
- Lodash: CVE-2021-23337, CVE-2020-8203
- Angular: CVE-2020-7676
- Handlebars: CVE-2021-23369, CVE-2019-19919
- And many more...

## Legal Disclaimer

For authorized security testing only.

## Author

REVUEX Team - Bug Bounty Automation Framework
