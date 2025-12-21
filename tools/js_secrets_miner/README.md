# REVUEX JS Secrets Miner GOLD

Research-Grade JavaScript Secret & Trust-Leak Discovery Engine for Bug Bounty Hunters.

## Overview

High-confidence secret discovery in client-side JavaScript with zero noise. This tool uses structural parsing, entropy analysis, and contextual validation to find real security-relevant secrets.

## Features

|Technique                   |Description                                                  |
|----------------------------|-------------------------------------------------------------|
|**JS File Discovery**       |Script src, inline references, common paths                  |
|**Esprima-Style Parsing**   |Structural extraction of variable assignments                |
|**Secret Heuristics**       |Keyword matching, entropy analysis, length checks            |
|**Third-Party Detection**   |AWS, Stripe, Google, GitHub, Slack, OpenAI, etc.             |
|**Contextual Validation**   |Classify as SERVER_SECRET_LEAK, THIRD_PARTY_KEY, CLIENT_TOKEN|
|**Second-Order Correlation**|Detect secrets used in fetch/axios/XHR sinks                 |
|**Impact Classification**   |CRITICAL, HIGH, MEDIUM, LOW based on context                 |
|**Confidence Scoring**      |0-100 score based on multiple factors                        |

## Usage

### CLI

```bash
# Basic scan
python -m tools.js_secrets_miner -t https://example.com

# With lower threshold
python -m tools.js_secrets_miner -t https://example.com --threshold 50

# Verbose with output
python -m tools.js_secrets_miner -t https://example.com -v -o secrets.json
```

### Python API

```python
from tools.js_secrets_miner import JSSecretsMiner

miner = JSSecretsMiner(
    target="https://example.com",
    confidence_threshold=70
)
result = miner.run()

for finding in result.findings:
    print(f"[{finding.severity.value}] {finding.title}")
```

## Secret Categories

|Category              |Description                                   |
|----------------------|----------------------------------------------|
|**SERVER_SECRET_LEAK**|Backend secrets exposed in frontend (CRITICAL)|
|**THIRD_PARTY_KEY**   |AWS, Stripe, Google API keys                  |
|**CLIENT_TOKEN**      |Frontend tokens with limited scope            |
|**PUBLIC_CONFIG**     |Non-sensitive configuration values            |

## Detected Providers

- AWS (AKIA, ASIA)
- Stripe (sk_live, pk_live)
- Google (AIza)
- GitHub (ghp_, gho_)
- Slack (xoxb, xoxp)
- OpenAI (sk-)
- SendGrid (SG.)
- Twilio (AC, SK)
- Shopify (shpat_)
- GitLab (glpat-)
- And 20+ more…

## Second-Order Detection

Detects if secrets are actively used in:

- `fetch()` calls
- `axios` requests
- `XMLHttpRequest`
- `Authorization` headers
- `WebSocket` connections

## Legal Disclaimer

This tool is for authorized security testing only.

## Author

REVUEX Team - Bug Bounty Automation Framework