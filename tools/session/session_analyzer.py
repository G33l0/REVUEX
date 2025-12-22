# REVUEX Session Scanner GOLD

Research-grade session management scanner for detecting session fixation, invalidation failures, token weaknesses, and cookie misconfigurations.

## Overview

Zero-exploitation session testing using state-transition validation and passive entropy analysis. No hijacking, no replay, no brute force.

## GOLD Principles

- **No hijacking** - No session theft
- **No replay** - No token reuse attacks
- **No brute force** - Passive analysis only
- **State validation** - Compare auth transitions
- **Entropy analysis** - Token strength assessment

## Features

|Technique               |Description                     |Severity|
|------------------------|--------------------------------|--------|
|**Session Fixation**    |Token not rotated on login      |CRITICAL|
|**Logout Invalidation** |Token persists after logout     |HIGH    |
|**Cookie Attributes**   |Missing Secure/HttpOnly/SameSite|HIGH    |
|**Header/Cookie Desync**|Conflicting session sources     |HIGH    |
|**Token Predictability**|Sequential/similar tokens       |HIGH    |
|**Low Entropy**         |Weak token randomness           |MEDIUM  |
|**Short Token**         |Insufficient token length       |MEDIUM  |
|**Session Lifetime**    |Excessive max-age               |MEDIUM  |

## Usage

### CLI

```bash
# Basic scan (unauthenticated only)
python -m tools.session -t https://example.com

# With login endpoint
python -m tools.session -t https://example.com --login-path /api/login

# With login and logout
python -m tools.session -t https://example.com --login-path /login --logout-path /logout

# With login credentials
python -m tools.session -t https://example.com --login-path /login \
    --login-data '{"username":"test","password":"test123"}'

# Output to JSON
python -m tools.session -t https://example.com -o session_report.json
```

### Python API

```python
from tools.session import SessionScanner

scanner = SessionScanner(
    target="https://example.com",
    login_path="/api/login",
    logout_path="/api/logout",
    login_data={"username": "test", "password": "test123"}
)
result = scanner.run()

print(f"States captured: {list(scanner.states.keys())}")
print(f"Issues found: {len(result.findings)}")
```

## State Capture

The scanner captures three states:

|State        |Description           |
|-------------|----------------------|
|`unauth`     |Before authentication |
|`auth`       |After successful login|
|`post_logout`|After logout          |

## Token Extraction

Tokens are extracted from:

- Cookies (session, sid, token, auth, etc.)
- Response headers
- JSON response body
- Set-Cookie headers

## Confidence Scoring

|Check               |Score|
|--------------------|-----|
|Session Fixation    |+90  |
|Logout Invalidation |+85  |
|Cookie Attributes   |+80  |
|Token Predictability|+80  |
|Header/Cookie Desync|+75  |
|Low Entropy         |+75  |
|Short Token         |+70  |
|Excessive Lifetime  |+70  |

**Threshold: 80** (High Confidence)

## Cookie Attribute Checks

|Attribute |Purpose                |
|----------|-----------------------|
|`Secure`  |HTTPS-only transmission|
|`HttpOnly`|Prevents XSS access    |
|`SameSite`|CSRF protection        |

## Entropy Requirements

- Minimum entropy: **3.5 bits per character**
- Minimum token length: **16 characters**
- Recommended: **128+ bits of entropy**

## Legal Disclaimer

For authorized security testing only. Does not perform session hijacking or replay attacks.

## Author

REVUEX Team - Bug Bounty Automation Framework