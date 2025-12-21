# REVUEX JWT Analyzer GOLD

High-Confidence JWT Vulnerability Detection without Exploitation.

## Overview

Zero-exploitation JWT analysis using pure invariant and trust analysis. No token forgery, no brute-force, no privilege abuse - just high-confidence vulnerability detection.

## Design Philosophy

- **Zero token forgery** - Never create malicious tokens
- **Zero brute-force** - No key guessing
- **Zero privilege abuse** - No exploitation attempts
- **Pure analysis** - Structural and trust inspection only

## Features

|Technique                |Description                             |
|-------------------------|----------------------------------------|
|**Algorithm Integrity**  |Detect RS*/HS* confusion, none algorithm|
|**Algorithm Confusion**  |RSA to HMAC downgrade detection         |
|**Optional Claim Trust** |Missing aud, iss, exp, nbf validation   |
|**Authorization Binding**|Weak identity binding in claims         |
|**Privilege Escalation** |Admin/role claims in token              |
|**JWKS Trust**           |jku/x5u header injection vectors        |
|**Key ID Injection**     |Path traversal, SQL injection in kid    |
|**Second-Order Trust**   |Async flow trust issues                 |
|**Token Expiration**     |Excessive lifetime, expired acceptance  |
|**Confidence Scoring**   |0-100 aggregate score                   |

## Usage

### CLI

```bash
# Basic analysis
python -m tools.jwt -t https://api.example.com --jwt "eyJhbGciOiJSUzI1NiIs..."

# With custom threshold
python -m tools.jwt -t https://api.example.com --jwt "eyJ..." --threshold 50 -v

# Output to JSON
python -m tools.jwt -t https://api.example.com --jwt "eyJ..." -o report.json
```

### Python API

```python
from tools.jwt import JWTAnalyzer

analyzer = JWTAnalyzer(
    target="https://api.example.com",
    token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
)
result = analyzer.run()

print(f"Confidence Score: {analyzer.total_confidence}")
for finding in result.findings:
    print(f"[{finding.severity.value}] {finding.title}")
```

## Vulnerability Classes

|Class                   |Severity|Description                      |
|------------------------|--------|---------------------------------|
|**Algorithm None**      |CRITICAL|No signature verification        |
|**Algorithm Confusion** |CRITICAL|RS256 → HS256 key confusion      |
|**JWKS Injection (jku)**|CRITICAL|Client-controlled key endpoint   |
|**X5U Injection**       |CRITICAL|Client-controlled certificate URL|
|**Missing kid**         |HIGH    |Static/implicit key verification |
|**Missing exp**         |HIGH    |Token never expires              |
|**Weak Auth Binding**   |HIGH    |Identity from JWT claims         |
|**Admin Flag**          |HIGH    |Privilege escalation vector      |
|**Missing aud/iss**     |MEDIUM  |No audience/issuer validation    |
|**Role Claims**         |MEDIUM  |Modifiable role information      |

## Confidence Scoring

|Check                        |Score|
|-----------------------------|-----|
|Algorithm None               |+35  |
|Algorithm Integrity Violation|+30  |
|JWKS Injection (jku)         |+25  |
|X5U Header Injection         |+25  |
|Key ID Injection             |+20  |
|Missing Expiration           |+20  |
|Weak Auth Binding            |+20  |
|Missing kid                  |+15  |
|Admin Flag                   |+15  |
|Missing aud/iss              |+15  |
|Second-Order Trust           |+10  |

**Threshold: 70** (High Confidence)

## Legal Disclaimer

This tool is for authorized security testing only. It performs passive analysis without exploitation.

## Author

REVUEX Team - Bug Bounty Automation Framework