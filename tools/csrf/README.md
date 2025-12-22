# REVUEX CSRF Scanner GOLD

Research-grade CSRF validation scanner for detecting token bypass, origin enforcement failures, and method confusion vulnerabilities.

## Overview

Zero-exploitation CSRF testing using differential request validation. No victim simulation, no actual exploitation.

## GOLD Principles

- **No exploitation** - Differential analysis only
- **No victim simulation** - Self-request testing
- **Token validation** - Presence, requirement, binding
- **Origin enforcement** - Header validation checks
- **Method confusion** - HTTP method bypass detection

## Features

|Technique                 |Description                   |Severity|
|--------------------------|------------------------------|--------|
|**Token Removal**         |Request succeeds without token|CRITICAL|
|**Token Modification**    |Invalid token accepted        |CRITICAL|
|**Cross-Origin Accepted** |Different Origin header works |HIGH    |
|**Null Origin Bypass**    |null Origin accepted          |HIGH    |
|**Method Confusion**      |POST accepts GET              |HIGH    |
|**No CSRF Token**         |Endpoint lacks protection     |HIGH    |
|**Empty Token Bypass**    |Empty token accepted          |HIGH    |
|**Origin Not Validated**  |Missing Origin works          |MEDIUM  |
|**Content-Type Confusion**|Different CT accepted         |MEDIUM  |
|**SameSite=None**         |Weak cookie protection        |MEDIUM  |
|**Double Submit Cookie**  |Attackable pattern            |MEDIUM  |

## Usage

### CLI

```bash
# Basic scan
python -m tools.csrf -t https://example.com -a /api/transfer

# Specify HTTP method
python -m tools.csrf -t https://example.com -a /api/settings --method PUT

# With request data
python -m tools.csrf -t https://example.com -a /api/password \
    --data '{"new_password":"test123"}'

# Output to JSON
python -m tools.csrf -t https://example.com -a /api/transfer -o csrf_report.json
```

### Python API

```python
from tools.csrf import CSRFScanner

scanner = CSRFScanner(
    target="https://example.com",
    action_path="/api/transfer",
    method="POST",
    action_data={"amount": "100", "to": "attacker"}
)
result = scanner.run()

print(f"CSRF tokens found: {list(scanner.csrf_tokens.keys())}")
print(f"Issues found: {len(result.findings)}")
```

## Confidence Scoring

|Check                  |Score|
|-----------------------|-----|
|Token Removal Bypass   |+90  |
|Token Validation Bypass|+90  |
|Cross-Origin Accepted  |+85  |
|Method Confusion       |+85  |
|No CSRF Token          |+85  |
|Null Origin Bypass     |+80  |
|Origin Not Validated   |+75  |
|Content-Type Confusion |+70  |
|SameSite=None          |+70  |
|Double Submit Cookie   |+65  |

**Threshold: 80** (High Confidence)

## Legal Disclaimer

For authorized security testing only. Does not perform actual CSRF attacks.

## Author

REVUEX Team - Bug Bounty Automation Framework