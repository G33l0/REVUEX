# REVUEX Business Logic Scanner GOLD

High-Confidence Business Logic Vulnerability Detection without Exploitation.

## Overview

Zero-exploitation business logic testing using invariant-based detection. No fraud, no checkout completion, no privilege abuse - just differential behavior analysis.

## Design Philosophy

- **No fraud** - Never complete transactions
- **No checkout** - Never process payments
- **No privilege abuse** - Never escalate access
- **Differential proof** - Compare baseline vs probe behavior

## Features

|Technique                |Description                              |
|-------------------------|-----------------------------------------|
|**Workflow State**       |Detect out-of-order state transitions    |
|**Price/Quantity Trust** |Detect client-side value trust           |
|**Idempotency**          |Detect missing replay protection         |
|**Role/Capability Drift**|Detect role vs operation mismatch        |
|**Temporal Logic**       |Detect time-based rule violations        |
|**Quantity Manipulation**|Detect negative/zero/excessive quantities|
|**Coupon Abuse**         |Detect coupon reuse/stacking             |
|**Second-Order Trust**   |Detect async trust propagation           |
|**Similarity Scoring**   |Compare response differential            |
|**Confidence Scoring**   |Aggregate vulnerability confidence       |

## Usage

### CLI

```bash
# Basic scan
python -m tools.business_logic -t https://api.example.com --baseline baseline.json --probes probes.json

# With custom headers
python -m tools.business_logic -t https://api.example.com --baseline baseline.json --probes probes.json --headers headers.json

# Output to JSON
python -m tools.business_logic -t https://api.example.com --baseline baseline.json --probes probes.json -o report.json
```

### Python API

```python
from tools.business_logic import BusinessLogicScanner

scanner = BusinessLogicScanner(
    target="https://api.example.com",
    baseline={
        "method": "POST",
        "path": "/api/checkout",
        "json": {"item_id": 1, "quantity": 1, "price": 100}
    },
    probes=[
        {
            "category": "pricing",
            "method": "POST",
            "path": "/api/checkout",
            "json": {"item_id": 1, "quantity": 1, "price": 0}
        },
        {
            "category": "workflow",
            "method": "POST",
            "path": "/api/complete",
            "json": {"order_id": 123}
        }
    ]
)
result = scanner.run()

print(f"Confidence Score: {scanner.total_confidence}")
```

## Baseline Format

```json
{
    "method": "POST",
    "path": "/api/checkout",
    "json": {
        "item_id": 1,
        "quantity": 1,
        "price": 99.99
    }
}
```

## Probes Format

```json
[
    {
        "category": "pricing",
        "method": "POST",
        "path": "/api/checkout",
        "json": {"item_id": 1, "quantity": 1, "price": 0}
    },
    {
        "category": "quantity",
        "method": "POST",
        "path": "/api/checkout",
        "json": {"item_id": 1, "quantity": -1}
    },
    {
        "category": "workflow",
        "method": "POST",
        "path": "/api/order/complete",
        "json": {"order_id": 123}
    },
    {
        "category": "temporal",
        "method": "POST",
        "path": "/api/promo/apply",
        "json": {"code": "EXPIRED2023"}
    }
]
```

## Probe Categories

|Category     |Description                   |
|-------------|------------------------------|
|`workflow`   |Out-of-order state transitions|
|`pricing`    |Price manipulation probes     |
|`quantity`   |Quantity manipulation probes  |
|`capability` |Role/permission testing       |
|`temporal`   |Time-based rule testing       |
|`coupon`     |Coupon/discount abuse         |
|`idempotency`|Replay attack testing         |
|`currency`   |Currency confusion testing    |

## Confidence Scoring

|Check                  |Score|
|-----------------------|-----|
|Workflow State Failure |+25  |
|Price/Quantity Trust   |+20  |
|Temporal Rule Violation|+20  |
|Quantity Manipulation  |+20  |
|Missing Idempotency    |+15  |
|Role/Capability Drift  |+15  |
|Coupon Abuse Vector    |+15  |
|Second-Order Trust     |+10  |

**Threshold: 70** (High Confidence)

## Legal Disclaimer

This tool is for authorized security testing only. It performs non-exploitative analysis.

## Author

REVUEX Team - Bug Bounty Automation Framework