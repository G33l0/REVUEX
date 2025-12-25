# REVUEX IDOR Scanner GOLD v1.1

Research-Grade IDOR Detection with Dual-Account + Blind/Second-Order Testing.

## Overview

This scanner uses the **dual-account methodology** to eliminate false positives in IDOR testing:

1. **Account A (Owner)** - Has legitimate access to a resource
2. **Account B (Attacker)** - Should NOT have access to Account A's resource
3. **Compare** - If Account B sees Account A's data = IDOR confirmed

This approach provides **HIGH confidence** findings because we know for certain that Account A owns the resource.

## Features

| Technique | Description |
|-----------|-------------|
| **Dual-Account Verification** | Eliminates false positives through ownership confirmation |
| **JSON Structural Diffing** | Compares response structure to detect authorization leaks |
| **Sensitive Field Detection** | Identifies high-impact data exposure (email, SSN, tokens) |
| **Blind IDOR via Headers** | Injects object ID via X-User-Id, X-Account-Id headers |
| **Second-Order IDOR** | Detects deferred authorization bypass |
| **Multi-Method Testing** | Tests GET, POST, PUT, DELETE, PATCH |
| **ID Enumeration** | Tests adjacent IDs for mass data access |
| **ID Pattern Detection** | Recognizes numeric, UUID, MongoDB ObjectId patterns |

## Phases

```
Phase 1: Direct A/B Authorization Diff
        → Account A accesses resource (baseline)
        → Account B attempts same access
        → Compare responses structurally

Phase 2: Blind / Second-Order IDOR
        → Inject object ID via headers as Account A
        → Wait for deferred processing
        → Check if Account B sees correlated data

Phase 3: ID Enumeration (optional)
        → Test adjacent IDs (122, 124, etc.)
        → Detect mass data access potential
```

## Usage

### CLI

```bash
# Basic direct IDOR test
python -m tools.idor -t "https://api.example.com/orders/123" \
    --token-a "Bearer owner_jwt_token" \
    --token-b "Bearer attacker_jwt_token"

# Provide IDOR tokens directly via CLI
python revuex_suite.py scan -t https://target.com \
    --token-a "Bearer user1_token" \
    --token-b "Bearer user2_token"

# Disable all prompts (for CI/CD)
python revuex_suite.py scan -t https://target.com --non-interactive

# Or use --no-prompt
python revuex_suite.py scan -t https://target.com --no-prompt

# With blind/second-order IDOR testing
python -m tools.idor -t "https://api.example.com/orders/123" \
    --token-a "Bearer AAA" \
    --token-b "Bearer BBB" \
    --object-id "123"

# Custom blind headers
python -m tools.idor -t "https://api.example.com/v1/orders/123" \
    --token-a "Bearer AAA" \
    --token-b "Bearer BBB" \
    --object-id "123" \
    --blind-headers X-User-Id X-Account-Id X-Actor-Id

# With ID enumeration
python -m tools.idor -t "https://api.example.com/users/456/profile" \
    --token-a "session_cookie_a" \
    --token-b "session_cookie_b" \
    --enum

# Full options
python -m tools.idor -t TARGET \
    --token-a "Bearer xxx" \
    --token-b "Bearer yyy" \
    --object-id "123" \
    --threshold 0.85 \
    --json '{"action":"view"}' \
    -o results.json \
    -v
```

### Python API

```python
from tools.idor import IDORScanner

scanner = IDORScanner(
    target="https://api.example.com/orders/123",
    token_a="Bearer owner_token",
    token_b="Bearer attacker_token",
    test_methods=True,
    test_enumeration=True
)
result = scanner.run()

for finding in result.findings:
    print(f"[{finding.severity.value}] {finding.title}")
    print(f"  Evidence: {finding.evidence}")
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --target` | Target URL with object ID | Required |
| `--token-a` | Authorization for Account A (owner) | Required |
| `--token-b` | Authorization for Account B (attacker) | Required |
| `--object-id` | Object ID for blind IDOR testing | Auto-detect |
| `--blind-headers` | Headers for blind IDOR injection | 20+ default headers |
| `--no-methods` | Only test GET method | False |
| `--no-blind` | Skip blind/second-order testing | False |
| `--enum` | Test ID enumeration | False |
| `--threshold` | Similarity threshold | 0.90 |
| `--json` | JSON body for POST/PUT | {} |
| `-o, --output` | Output file (JSON) | None |
| `-v, --verbose` | Verbose output | False |

## Methodology

```
┌─────────────────────────────────────────────────────────┐
│                    IDOR Testing Flow                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. Account A (Owner) requests /api/orders/123          │
│     → Response: { "id": 123, "user": "alice", ... }     │
│     → Status: 200 OK                                    │
│                                                         │
│  2. Account B (Attacker) requests /api/orders/123       │
│     → Response: ???                                     │
│                                                         │
│  3. Analysis:                                           │
│     ├─ Status B = 401/403/404 → Authorization OK ✓      │
│     ├─ Status B = 200 + Different Data → Likely OK     │
│     └─ Status B = 200 + Same Data → IDOR CONFIRMED! ✗   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Sensitive Fields Detection

The scanner identifies exposure of:

- **Identity**: email, username, user_id, account_id
- **Authentication**: password, token, api_key, secret
- **Personal**: SSN, phone, address, date_of_birth
- **Financial**: credit_card, bank_account, balance
- **Authorization**: role, permissions, is_admin

## CVSS & CWE

- **CWE-639**: Authorization Bypass Through User-Controlled Key
- **OWASP**: A01:2021 - Broken Access Control
- **CVSS**: 6.5-9.1 depending on data sensitivity

## Legal Disclaimer

This tool is for authorized security testing only.

## Author

REVUEX Team - Bug Bounty Automation Framework
