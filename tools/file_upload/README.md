# REVUEX File Upload Scanner GOLD

Research-grade file upload validation scanner using structural contradiction and differential analysis. Zero exploitation, zero weaponization.

## Overview

Detects file upload vulnerabilities through policy enforcement failures using safe, non-exploitative testing.

## GOLD Principles

- **No execution** - Safe marker content only
- **No weaponization** - No actual exploits
- **Structural contradiction** - Mismatched content/extension
- **Differential analysis** - Compare baseline vs probe
- **Second-order confirmation** - Marker correlation

## Features

| Technique | Description | Severity |
|-----------|-------------|----------|
| **Double Extension** | test.php.jpg bypass | CRITICAL |
| **Null Byte** | test.php%00.jpg injection | CRITICAL |
| **.htaccess** | Config file upload | CRITICAL |
| **Path Traversal** | ../../../tmp/test.txt | CRITICAL |
| **Content-Type Bypass** | Wrong MIME acceptance | HIGH |
| **Case Variation** | .pHp, .PhP bypasses | HIGH |
| **Polyglot** | Valid as multiple types | HIGH |
| **MIME Mismatch** | Extension/type conflict | MEDIUM |
| **SVG Upload** | XSS vector via SVG | MEDIUM |
| **Special Chars** | test;.jpg, test|.jpg | MEDIUM |

## Usage

### CLI

```bash
# Basic scan
python -m tools.file_upload -t https://example.com/upload

# Specify upload field name
python -m tools.file_upload -t https://example.com/upload -f file_input

# Test specific extensions
python -m tools.file_upload -t https://example.com/upload --extensions jpg,png,pdf

# Skip dangerous tests
python -m tools.file_upload -t https://example.com/upload --no-dangerous

# Output to JSON
python -m tools.file_upload -t https://example.com/upload -o report.json
```

### Python API

```python
from tools.file_upload import FileUploadScanner

scanner = FileUploadScanner(
    target="https://example.com/upload",
    upload_field="file",
    allowed_extensions=["jpg", "png", "pdf"],
    test_dangerous=True
)
result = scanner.run()

print(f"Found {len(result.findings)} issues")
print(f"Total Confidence: {scanner.total_confidence}")
```

## Confidence Scoring

| Check | Score |
|-------|-------|
| .htaccess Upload | +95 |
| Null Byte Injection | +90 |
| Double Extension | +85 |
| Path Traversal | +85 |
| Content-Type Bypass | +80 |
| Case Variation | +75 |
| Polyglot File | +75 |
| MIME Mismatch | +70 |
| SVG Upload | +70 |
| Special Characters | +65 |

**Threshold: 80** (High Confidence)

## Test File Types

The scanner generates safe test files with:
- Valid magic bytes (PNG, JPG, GIF, PDF, etc.)
- Safe text content (no executable code)
- Unique markers for tracking

## Legal Disclaimer

For authorized security testing only. Does not execute any uploaded files.

## Author

REVUEX Team - Bug Bounty Automation Framework
