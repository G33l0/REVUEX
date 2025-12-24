# REVUEX Usage Guide

## Quick Start

### Full Suite Scan
```bash
python revuex_suite.py -t https://example.com --all
```

### Individual Tool
```bash
python -m tools.ssrf -t https://example.com/api
python -m tools.sqli -u "https://example.com/search?q=test"
python -m tools.xss -t https://example.com/page
```

## Command Line Interface

### Master Orchestrator

```bash
python revuex_suite.py [OPTIONS]

Options:
  -t, --target URL        Target URL (required)
  --all                   Run all scanners
  --recon                 Run reconnaissance tools only
  --injection             Run injection scanners only
  --access-control        Run access control scanners only
  -o, --output DIR        Output directory (default: ./scans)
  -v, --verbose           Verbose output
  -q, --quiet             Quiet mode
  --delay FLOAT           Request delay (default: 0.5)
  --timeout INT           Request timeout (default: 10)
```

### Individual Scanners

Each scanner supports common options:

```bash
python -m tools.<scanner> [OPTIONS]

Common Options:
  -t, --target URL        Target URL
  -u, --url URL           Alternative target flag
  -H, --header KEY:VALUE  Custom HTTP header
  -o, --output FILE       Output file (JSON)
  --threshold INT         Confidence threshold
  --delay FLOAT           Request delay
  --timeout INT           Request timeout
  -v, --verbose           Verbose output
  -q, --quiet             Quiet mode
```

## Python API

### Import Scanners

```python
# Import specific scanner
from tools.ssrf import SSRFScanner
from tools.sqli import SQLiScanner

# Import all scanners
from tools import *

# Get scanner by name
from tools import get_scanner
scanner_class = get_scanner("ssrf")
```

### Basic Usage

```python
from tools.ssrf import SSRFScanner

# Initialize scanner
scanner = SSRFScanner(
    target="https://example.com/api",
    delay=0.5,
    timeout=10,
    verbose=True
)

# Run scan
result = scanner.run()

# Access findings
print(f"Found {len(result.findings)} issues")
for finding in result.findings:
    print(f"- {finding.title}: {finding.severity}")
```

### Advanced Configuration

```python
from tools.idor import IDORScanner

scanner = IDORScanner(
    target="https://example.com/api/user",
    auth_headers={
        "Authorization": "Bearer user1_token"
    },
    victim_headers={
        "Authorization": "Bearer user2_token"
    },
    test_ids=["1", "2", "100", "admin"],
    confidence_threshold=80
)

result = scanner.run()
```

### Batch Scanning

```python
from tools import get_scanner

targets = [
    "https://example1.com",
    "https://example2.com",
    "https://example3.com"
]

scanners = ["ssrf", "sqli", "xss", "cors"]

for target in targets:
    for scanner_name in scanners:
        scanner_class = get_scanner(scanner_name)
        scanner = scanner_class(target=target)
        result = scanner.run()
        
        if result.findings:
            print(f"[!] {target} - {scanner_name}: {len(result.findings)} findings")
```

## Output Formats

### JSON Output
```bash
python -m tools.ssrf -t https://example.com -o results.json
```

### HTML Report
```bash
python revuex_suite.py -t https://example.com --all --format html
```

### Markdown Report
```bash
python revuex_suite.py -t https://example.com --all --format markdown
```

## Scanner Categories

### Reconnaissance
```bash
python -m tools.subdomain_hunter -d example.com
python -m tools.tech_fingerprinter -t https://example.com
python -m tools.js_secrets -t https://example.com
```

### Injection Testing
```bash
python -m tools.ssrf -t https://example.com/api
python -m tools.sqli -u "https://example.com/search?q=test"
python -m tools.xss -t https://example.com/page
python -m tools.ssti -t https://example.com/template
python -m tools.xxe -u https://example.com/api/xml
```

### Access Control
```bash
python -m tools.idor -t https://example.com/api/user/1
python -m tools.cors -t https://example.com/api
python -m tools.csrf -t https://example.com/form
python -m tools.session -t https://example.com
python -m tools.jwt -t "eyJhbGciOiJIUzI1NiIs..."
```

### Business Logic
```bash
python -m tools.business_logic -t https://example.com/checkout
python -m tools.price_manipulation -t https://example.com/cart
python -m tools.race_condition -u https://example.com/transfer
```

### API & Mobile
```bash
python -m tools.graphql -t https://example.com/graphql
python -m tools.apk_analyzer -a app.apk
python -m tools.dependency -t https://example.com
```

## Best Practices

1. **Always get authorization** before testing
2. **Start with reconnaissance** to understand the target
3. **Use appropriate delays** to avoid rate limiting
4. **Review findings manually** before reporting
5. **Document your methodology** for reproducibility

## Next Steps

- See [Tool Documentation](tools/) for detailed scanner guides
- Check [Examples](examples/) for real-world workflows
- Read [Architecture](ARCHITECTURE.md) to understand the system
