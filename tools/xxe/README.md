# REVUEX XXE Scanner GOLD

Enterprise-grade non-exploitational XXE vulnerability validator with multi-engine correlation.

## Overview

Zero-destructive XXE detection using 9 validation engines. No file exfiltration, no callback abuse, evidence-backed confidence scoring.

## GOLD Principles

- **Zero-destructive** - No harmful payloads
- **No file exfiltration** - Safe entity tests only
- **No callback abuse** - No external connections
- **Multi-engine correlation** - 9 detection engines
- **Confidence scoring** - Threshold-based findings

## Validation Engines

| Engine | Description | Score |
|--------|-------------|-------|
| **Parser Fingerprinting** | Detect XML parser type | +15 |
| **Safe Entity Acceptance** | Test internal entity expansion | +30 |
| **Blind Timing** | Detect processing delays | +20 |
| **Content-Type Mismatch** | XML parsed with wrong CT | +15 |
| **Schema Relaxation** | DTD error surface visible | +15 |
| **Header Correlation** | XXE indicators in headers | +10 |
| **Parameter Entity** | % entity processing | +20 |
| **Error-Based** | Entity error messages | +20 |
| **DOCTYPE Processing** | DOCTYPE affects response | +15 |

## Usage

### CLI

```bash
# Basic scan
python -m tools.xxe -u https://example.com/api/xml

# With custom headers
python -m tools.xxe -u https://example.com/api -H "Authorization: Bearer token"

# Custom XML payload
python -m tools.xxe -u https://example.com/api --xml custom.xml

# Output to JSON
python -m tools.xxe -u https://example.com/api -o xxe_report.json
```

### Python API

```python
from tools.xxe import XXEScanner

scanner = XXEScanner(target="https://example.com/api/xml")
result = scanner.run()

print(f"Parser detected: {scanner.detected_parser}")
print(f"Confidence: {scanner.total_confidence}%")
print(f"Signals: {scanner.reasons}")
```

## Safe Test Payloads

### Safe Entity Test
```xml
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY harmless "REVUEX_XXE_SAFE_TEST">
]>
<root>&harmless;</root>
```

### DOCTYPE Test
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ELEMENT root (#PCDATA)>
]>
<root>test</root>
```

## Confidence Scoring

| Threshold | Status |
|-----------|--------|
| 0-49 | LOW - Minimal indicators |
| 50-74 | MEDIUM - Some signals present |
| 75-100 | HIGH - XXE capability confirmed |

**Default Threshold: 75**

## Parser Fingerprints Detected

- libxml (PHP, Python)
- Xerces (Java)
- Expat (Python, Perl)
- Dom4j (Java)
- Saxon (Java)
- Woodstox (Java)
- MSXML (Windows)

## What This Scanner Does NOT Do

- ❌ Read /etc/passwd or sensitive files
- ❌ Make external HTTP callbacks
- ❌ Perform Billion Laughs DoS
- ❌ Exploit blind XXE with OOB
- ❌ Access internal network resources

## Legal Disclaimer

For authorized security testing only. This scanner is designed for responsible vulnerability disclosure.

## Author

REVUEX Team (G33L0) - Bug Bounty Automation Framework
