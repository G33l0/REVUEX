# REVUEX Race Condition Scanner GOLD

Research-grade race condition and concurrency scanner for detecting atomicity violations, idempotency failures, and TOCTOU bugs.

## Overview

Deterministic concurrency validation without exploitation or brute-force. Bug bounty defensible methodology.

## GOLD Principles

- **No exploitation** - Detection only
- **No brute-force** - Controlled concurrency
- **Deterministic** - Reproducible results
- **Atomicity proof** - Differential analysis
- **Idempotency check** - Response variance

## Features

| Technique | Description | Severity |
|-----------|-------------|----------|
| **Missing Atomicity** | Multiple concurrent accepts | CRITICAL |
| **Idempotency Violation** | Different responses | HIGH |
| **Atomicity Failure** | Mixed success/failure | HIGH |
| **Response Variance** | Inconsistent state | HIGH |
| **Time Window Analysis** | Locking behavior | INFO |

## Usage

### CLI

```bash
# Basic scan
python -m tools.race_condition -u https://example.com/api/transfer -X POST

# With request data
python -m tools.race_condition -u https://example.com/api/apply-coupon \
    -X POST -d '{"coupon": "DISCOUNT50"}'

# Custom thread count
python -m tools.race_condition -u https://example.com/api/vote \
    -X POST -t 10

# With headers
python -m tools.race_condition -u https://example.com/api/transfer \
    -X POST -H "Authorization: Bearer token123" \
    -d '{"amount": "100", "to": "user2"}'

# Output to JSON
python -m tools.race_condition -u https://example.com/api/transfer -o race_report.json
```

### Python API

```python
from tools.race_condition import RaceConditionScanner

scanner = RaceConditionScanner(
    target="https://example.com/api/transfer",
    method="POST",
    request_data={"amount": "100", "to": "user2"},
    custom_headers={"Authorization": "Bearer token123"},
    thread_count=5
)
result = scanner.run()

print(f"Concurrent responses: {len(scanner.concurrent_responses)}")
print(f"Issues found: {len(result.findings)}")
```

## Methodology

1. **Baseline Capture** - Single request for comparison
2. **Concurrent Fire** - Multiple simultaneous requests
3. **Response Analysis** - Compare status codes, lengths, hashes
4. **Idempotency Check** - Verify identical responses
5. **Atomicity Check** - Detect mixed success/failure

## Confidence Scoring

| Indicator | Score |
|-----------|-------|
| Base confidence | +40 |
| Multiple successes | +30 |
| Response variance | +20 |
| All requests succeeded | +15 |
| Mixed success/failure | +80 (atomicity) |

**Threshold: 85** (High Confidence)

## Common Targets

| Target Type | Example Endpoint |
|-------------|------------------|
| Fund Transfer | `/api/transfer` |
| Coupon Redemption | `/api/apply-coupon` |
| Voting | `/api/vote` |
| Inventory Checkout | `/api/checkout` |
| Points Redemption | `/api/redeem` |
| Account Upgrade | `/api/upgrade` |

## Detection Indicators

- Multiple 200 OK responses
- Different response bodies
- Varying response lengths
- Mixed status codes
- Database constraint errors

## Legal Disclaimer

For authorized security testing only. Test with minimal impact.

## Author

REVUEX Team - Bug Bounty Automation Framework
