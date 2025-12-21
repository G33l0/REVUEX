# REVUEX Price Manipulation Scanner GOLD

Unified detection of pricing, coupon, subscription, and trial abuse via server-side trust invariant violations.

## Overview

Zero-exploitation monetary manipulation testing using invariant-based detection. No fraud, no checkout completion, no brute force - just differential behavior analysis.

## GOLD Principles

- **No exploitation** - Never complete transactions
- **No checkout** - Never process payments
- **No brute force** - Targeted probing only
- **Differential proof** - Compare baseline vs probe behavior
- **High-confidence** - Minimum 80% threshold

## Features

|Technique                 |Description                      |
|--------------------------|---------------------------------|
|**Price Invariant**       |Client-side price trust detection|
|**Quantity Invariant**    |Total recalculation failure      |
|**Coupon Invariant**      |Reuse and validation bypass      |
|**Subscription Invariant**|Client-declared state trust      |
|**Trial Invariant**       |Trial abuse detection            |
|**Currency Invariant**    |Currency confusion attacks       |
|**Negative Invariant**    |Negative value acceptance        |
|**Second-Order Trust**    |Async monetary trust             |
|**Similarity Scoring**    |Response differential analysis   |
|**Confidence Scoring**    |Aggregate vulnerability score    |

## Usage

### CLI

```bash
# Basic scan
python -m tools.price_manipulation -t https://api.example.com --baseline baseline.json --probes probes.json

# With custom headers (e.g., auth token)
python -m tools.price_manipulation -t https://api.example.com --baseline baseline.json --probes probes.json --headers headers.json

# Output to JSON
python -m tools.price_manipulation -t https://api.example.com --baseline baseline.json --probes probes.json -o report.json

# Using example payloads
python -m tools.price_manipulation -t https://api.example.com \
    --baseline payloads/price_manipulation/baseline_example.json \
    --probes payloads/price_manipulation/probes.json
```

### Python API

```python
from tools.price_manipulation import PriceManipulationScanner

scanner = PriceManipulationScanner(
    target="https://api.example.com",
    baseline={
        "method": "POST",
        "path": "/checkout/preview",
        "json": {"item_id": 1, "quantity": 1, "price": 99.99}
    },
    probes=[
        {"category": "price", "method": "POST", "path": "/checkout/preview", 
         "json": {"item_id": 1, "price": 0}},
        {"category": "quantity", "method": "POST", "path": "/checkout/preview",
         "json": {"item_id": 1, "qty": 100, "total": 1}},
    ]
)
result = scanner.run()

print(f"Confidence Score: {scanner.total_confidence}")
```

## Baseline Format

```json
{
    "method": "POST",
    "path": "/checkout/preview",
    "json": {
        "item_id": 1,
        "quantity": 1,
        "price": 99.99,
        "currency": "USD"
    }
}
```

## Probes Format

See `payloads/price_manipulation/probes.json` for full examples.

```json
[
    {
        "category": "price",
        "method": "POST",
        "path": "/checkout/preview",
        "json": {"item_id": 1, "price": 0}
    },
    {
        "category": "negative",
        "method": "POST",
        "path": "/checkout/preview",
        "json": {"item_id": 1, "qty": -1}
    },
    {
        "category": "coupon",
        "method": "POST",
        "path": "/checkout/preview",
        "json": {"coupon": "FREE100"}
    }
]
```

## Probe Categories

|Category      |Description                     |
|--------------|--------------------------------|
|`price`       |Zero/reduced price manipulation |
|`quantity`    |Quantity/total mismatch         |
|`negative`    |Negative values                 |
|`coupon`      |Coupon reuse/abuse              |
|`subscription`|Subscription state manipulation |
|`trial`       |Trial period abuse              |
|`currency`    |Currency confusion              |
|`discount`    |Discount percentage manipulation|

## Confidence Scoring

|Check                         |Score|
|------------------------------|-----|
|Client-Side Price Trust       |+30  |
|Subscription State Trust      |+25  |
|Negative Value Acceptance     |+25  |
|Quantity Recalculation Failure|+20  |
|Coupon Reuse Violation        |+20  |
|Currency Confusion            |+20  |
|Trial Abuse                   |+15  |
|Second-Order Trust            |+10  |

**Threshold: 80** (High Confidence)

## Vulnerability Classes

|Class                 |Severity|Impact                    |
|----------------------|--------|--------------------------|
|**Price Trust**       |CRITICAL|Purchase items for $0     |
|**Subscription Trust**|CRITICAL|Free premium access       |
|**Negative Values**   |CRITICAL|Credit/refund fraud       |
|**Coupon Reuse**      |CRITICAL|Unlimited discounts       |
|**Quantity Failure**  |HIGH    |Bulk items at single price|
|**Currency Confusion**|HIGH    |Pay in weak currency      |
|**Trial Abuse**       |HIGH    |Unlimited trial periods   |

## Legal Disclaimer

This tool is for authorized security testing only. It performs non-exploitative analysis without completing transactions.

## Author

REVUEX Team - Bug Bounty Automation Framework