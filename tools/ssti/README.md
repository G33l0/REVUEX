# REVUEX SSTI Scanner GOLD

High-confidence Server-Side Template Injection capability detector with multi-engine support.

## Overview

Zero-exploitation SSTI detection using multi-signal correlation: syntax artifacts, error fingerprinting, header analysis, and safe math probes.

## GOLD Principles

- **Zero exploitation** - Capability identification only
- **Multi-signal correlation** - Multiple detection methods
- **No payload execution** - Safe probes only
- **Confidence scoring** - Threshold-based findings
- **13 engine support** - Comprehensive coverage

## Supported Template Engines

| Engine | Language | Risk Level |
|--------|----------|------------|
| **Jinja2** | Python | CRITICAL |
| **Twig** | PHP | CRITICAL |
| **FreeMarker** | Java | CRITICAL |
| **Velocity** | Java | CRITICAL |
| **Pebble** | Java | CRITICAL |
| **Thymeleaf** | Java/Spring | CRITICAL |
| **Smarty** | PHP | CRITICAL |
| **Mako** | Python | CRITICAL |
| **ERB** | Ruby | CRITICAL |
| **EJS** | JavaScript | CRITICAL |
| **Nunjucks** | JavaScript | CRITICAL |
| **Handlebars** | JavaScript | HIGH |
| **Mustache** | Multi | HIGH |

## Usage

### CLI

```bash
# Basic scan
python -m tools.ssti -t https://example.com/page?name=test

# With custom parameters
python -m tools.ssti -t https://example.com -p template -p content

# Skip parameter probing
python -m tools.ssti -t https://example.com --no-probe

# With headers
python -m tools.ssti -t https://example.com -H "Cookie: session=abc"

# Output to JSON
python -m tools.ssti -t https://example.com -o ssti_report.json
```

### Python API

```python
from tools.ssti import SSTIScanner

scanner = SSTIScanner(
    target="https://example.com/page?name=test",
    custom_params=["template", "view"]
)
result = scanner.run()

print(f"Engines detected: {scanner.detected_engines}")
print(f"Issues found: {len(result.findings)}")
```

## Detection Methods

### 1. Syntax Artifact Analysis
Detects template syntax patterns in response:
```
{{...}}     - Jinja2, Twig, Pebble, Nunjucks
${...}      - FreeMarker, Velocity, Thymeleaf
<%...%>     - ERB, EJS, Mako
{...}       - Smarty
```

### 2. Error Fingerprinting
Detects engine-specific error messages:
```
jinja2.exceptions.UndefinedError
Twig\Error\RuntimeError
freemarker.core.InvalidReferenceException
VelocityException
```

### 3. Header Analysis
Detects framework fingerprints:
```
X-Powered-By: Flask
X-Powered-By: PHP
Server: Apache/Tomcat
```

### 4. Math Probe Evaluation
Safe arithmetic tests:
```
{{7*7}} → 49    (Jinja2, Twig, Pebble)
${7*7} → 49     (FreeMarker, Thymeleaf)
<%=7*7%> → 49   (ERB, EJS)
{7*7} → 49      (Smarty)
```

## Confidence Scoring

| Signal | Score |
|--------|-------|
| Template syntax detected | +25 |
| Engine-specific error | +30 |
| Framework header | +20 |
| Reflection marker | +20 |
| Math evaluation | +40 |
| Security relevance | +10 |

**Threshold: 75** (High Confidence)

## Safe Probes

All probes are non-exploitative:
- Simple arithmetic: `7*7`, `7+7`
- Variable access: `{{self}}`, `${.now}`
- No system commands
- No file access
- No code execution

## Legal Disclaimer

For authorized security testing only.

## Author

REVUEX Team - Bug Bounty Automation Framework
