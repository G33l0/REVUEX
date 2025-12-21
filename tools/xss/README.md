# REVUEX XSS Scanner GOLD

Research-Grade Cross-Site Scripting detection engine for Bug Bounty Professionals.

## Overview

This scanner detects multiple types of XSS vulnerabilities using advanced techniques that go beyond simple pattern matching.

## Features

| Technique | Description |
|-----------|-------------|
| **Context-Aware Reflection** | Detects reflection context (HTML, JS, attribute) and sends context-specific payloads |
| **DOM-XSS Analysis** | Static + runtime correlation, source-to-sink flow detection |
| **Stored XSS** | Second-order XSS via persistent marker tracking |
| **Blind Header XSS** | Injection via User-Agent, Referer, X-Forwarded-For |
| **CSP Analysis** | Detects missing/weak Content Security Policy |
| **JS Sink Parsing** | ESPrima-style static analysis for dangerous assignments |
| **Framework Detection** | React, Vue, Angular sink detection (dangerouslySetInnerHTML, v-html, etc.) |
| **Method Confusion** | Tests GET, POST, PUT, PATCH for WAF bypass |
| **JSON Mutation** | Recursive deep injection into JSON bodies |

## Usage

### CLI

```bash
# Basic scan
python -m tools.xss -t "https://example.com/search?q=test"

# With JSON body
python -m tools.xss -t "https://example.com/api" --json '{"query":"test"}'

# Full options
python -m tools.xss -t TARGET \
    --json '{"data":"test"}' \
    --callback "https://your-callback.com" \
    --no-stored \
    --delay 1.0 \
    -v
```

### Python API

```python
from tools.xss import XSSScanner

scanner = XSSScanner(
    target="https://example.com/search?q=test",
    json_body={"query": "test"},
    test_stored=True,
    test_dom=True
)
result = scanner.run()

for finding in result.findings:
    print(f"[{finding.severity.value}] {finding.title}")
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --target` | Target URL | Required |
| `--json` | JSON body for POST | {} |
| `--callback` | Blind XSS callback URL | None |
| `--no-methods` | Skip method confusion | False |
| `--no-stored` | Skip stored XSS | False |
| `--no-headers` | Skip blind header XSS | False |
| `--no-dom` | Skip DOM XSS | False |
| `-o, --output` | Output file (JSON) | None |
| `-v, --verbose` | Verbose output | False |

## Detection Contexts

The scanner automatically detects and exploits these contexts:

- **HTML Text** - `<div>INJECTION</div>`
- **HTML Attribute** - `<input value="INJECTION">`
- **JavaScript String** - `var x = "INJECTION";`
- **JavaScript Template** - `` `${INJECTION}` ``
- **URL Parameter** - `<a href="INJECTION">`
- **CSS Value** - `<style>INJECTION</style>`

## CVSS & CWE

- **CWE-79**: Cross-site Scripting (XSS)
- **OWASP**: A03:2021 - Injection
- **CVSS**: 6.1-9.6 depending on type

## Legal Disclaimer

This tool is for authorized security testing only.

## Author

REVUEX Team - Bug Bounty Automation Framework
