# REVUEX APK Analyzer GOLD

Research-grade Android APK security analyzer for detecting misconfigurations, hardcoded secrets, and security weaknesses.

## Overview

Static analysis of Android applications without exploitation or dynamic hooking. Bug bounty defensible methodology.

## GOLD Principles

- **No exploitation** - Static analysis only
- **No dynamic hooking** - No runtime manipulation
- **Invariant proof** - Configuration validation
- **Confidence scoring** - Threshold-based findings
- **Bug bounty ready** - Defensible evidence

## Prerequisites

- **apktool** - APK decompilation tool

```bash
# Ubuntu/Debian
sudo apt install apktool

# macOS
brew install apktool

# Manual
# Download from https://ibotpeaches.github.io/Apktool/
```

## Features

| Technique | Description | Severity |
|-----------|-------------|----------|
| **Debuggable APK** | Debug flag enabled in production | CRITICAL |
| **Hardcoded Secrets** | API keys, tokens, passwords | HIGH |
| **Exported Components** | Accessible activities/services | HIGH |
| **Cleartext Traffic** | HTTP allowed | HIGH |
| **WebView JS Interface** | JavaScript bridge exposed | HIGH |
| **Weak Cryptography** | MD5, SHA1, DES, RC4 | MEDIUM |
| **Backup Allowed** | App data extractable | MEDIUM |
| **No Cert Pinning** | MITM susceptible | MEDIUM |

## Usage

### CLI

```bash
# Basic scan
python -m tools.apk_analyzer -a app.apk

# Custom output directory
python -m tools.apk_analyzer -a app.apk --output-dir ./decoded

# Output to JSON
python -m tools.apk_analyzer -a app.apk -o report.json

# Verbose mode
python -m tools.apk_analyzer -a app.apk -v
```

### Python API

```python
from tools.apk_analyzer import APKAnalyzer

analyzer = APKAnalyzer(apk_path="app.apk")
result = analyzer.run()

print(f"Issues found: {len(result.findings)}")
print(f"URLs extracted: {len(analyzer.found_urls)}")
print(f"Secrets found: {len(analyzer.found_secrets)}")
```

## Analysis Phases

1. **APK Info Extraction** - Size, hash, structure
2. **Decompilation** - apktool decode
3. **Manifest Analysis** - Permissions, flags, components
4. **Network Security** - network_security_config.xml
5. **Secret Scanning** - Regex pattern matching
6. **Weak Crypto Detection** - Insecure algorithms
7. **WebView Analysis** - JavaScript interfaces
8. **Cert Pinning Check** - SSL/TLS validation
9. **Root Detection Check** - Anti-tampering
10. **URL Extraction** - API endpoints

## Secret Patterns Detected

| Pattern | Example |
|---------|---------|
| API Keys | `api_key=ABC123...` |
| AWS Keys | `AKIA...` |
| Firebase | `AIza...` |
| Private Keys | `-----BEGIN PRIVATE KEY-----` |
| OAuth Secrets | `client_secret=...` |
| Passwords | `password=...` |

## Confidence Scoring

| Check | Score |
|-------|-------|
| Debuggable APK | +95 |
| Cleartext Traffic | +90 |
| WebView JS Interface | +85 |
| Exported Components | +80 |
| Hardcoded Secrets | +80 |
| Backup Allowed | +80 |
| Weak Crypto | +75 |
| No Cert Pinning | +70 |

**Threshold: 75** (High Confidence)

## Output

The scanner extracts:
- Security findings with evidence
- All HTTP/HTTPS URLs found
- Potential hardcoded secrets
- APK metadata (hash, size, structure)

## Legal Disclaimer

For authorized security testing only. Only analyze APKs you have permission to test.

## Author

REVUEX Team - Bug Bounty Automation Framework
