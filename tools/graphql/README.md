# REVUEX GraphQL Scanner GOLD

Research-grade GraphQL security scanner for detecting introspection exposure, query depth issues, method confusion, and batching attacks.

## Overview

Zero-exploitation GraphQL testing using schema and runtime invariant validation. No brute-force, no exploitation.

## GOLD Principles

- **No exploitation** - Validation only
- **No brute-force** - Passive analysis
- **Schema validation** - Introspection testing
- **Runtime checks** - Depth/complexity limits
- **Confidence scoring** - Threshold-based findings

## Features

| Technique | Description | Severity |
|-----------|-------------|----------|
| **Introspection Enabled** | Full schema exposed | CRITICAL |
| **GET Method Accepted** | CSRF risk | HIGH |
| **Query Depth Not Limited** | DoS risk | HIGH |
| **Nested Depth Not Limited** | DoS risk | HIGH |
| **Content-Type Confusion** | Non-JSON accepted | MEDIUM |
| **Verbose Error Disclosure** | Stack traces exposed | MEDIUM |
| **Query Batching Allowed** | Brute-force risk | MEDIUM |
| **Field Suggestions Enabled** | Enumeration risk | MEDIUM |
| **Alias Abuse Possible** | Rate limit bypass | MEDIUM |

## Usage

### CLI

```bash
# Basic scan
python -m tools.graphql -e https://example.com/graphql

# With custom headers
python -m tools.graphql -e https://example.com/graphql \
    -H "Authorization: Bearer token123"

# Multiple headers
python -m tools.graphql -e https://example.com/graphql \
    -H "Authorization: Bearer token" \
    -H "X-API-Key: key123"

# Output to JSON
python -m tools.graphql -e https://example.com/graphql -o graphql_report.json
```

### Python API

```python
from tools.graphql import GraphQLScanner

scanner = GraphQLScanner(
    target="https://example.com/graphql",
    custom_headers={"Authorization": "Bearer token123"}
)
result = scanner.run()

print(f"Schema exposed: {scanner.schema_data is not None}")
print(f"Issues found: {len(result.findings)}")
```

## Test Queries

| Query | Purpose |
|-------|---------|
| `{ __typename }` | Baseline |
| `{ __schema { types { name } } }` | Introspection |
| `{ __typename { __typename { ... } } }` | Depth testing |
| `{ nonExistentField }` | Error disclosure |
| `[{query1}, {query2}]` | Batching |
| `{ user { passwor } }` | Field suggestions |
| `{ a1: __typename a2: __typename ... }` | Alias abuse |

## Confidence Scoring

| Check | Score |
|-------|-------|
| Introspection Enabled | +50 (schema) + 10 (status) |
| GET Method Accepted | +40 (works) + 10 (status) |
| Query Depth Not Limited | +50 |
| Nested Depth Not Limited | +85 |
| Content-Type Confusion | +40 + 10 |
| Verbose Errors | +50 |
| Batching Allowed | +50 |
| Field Suggestions | +50 |
| Alias Abuse | +50 |

**Threshold: 80** (High Confidence)

## Legal Disclaimer

For authorized security testing only.

## Author

REVUEX Team - Bug Bounty Automation Framework
