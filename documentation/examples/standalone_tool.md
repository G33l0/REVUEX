# Standalone Tool Examples

Using individual REVUEX scanners independently.

## SSRF Scanner

```bash
# CLI
python -m tools.ssrf -t https://example.com/api/proxy

# With custom parameters
python -m tools.ssrf -t https://example.com/api -p url -p target -p fetch
```

```python
# Python
from tools.ssrf import SSRFScanner

scanner = SSRFScanner(
    target="https://example.com/api/proxy",
    skip_discovery=False,
    confidence_threshold=80
)
result = scanner.run()

for finding in result.findings:
    print(f"[{finding.severity.value}] {finding.title}")
    print(f"  Parameter: {finding.parameter}")
    print(f"  Payload: {finding.payload}")
```

## SQLi Scanner

```bash
# CLI
python -m tools.sqli -u "https://example.com/search?q=test&id=1"

# Specific parameters
python -m tools.sqli -u "https://example.com/api" -p id -p user_id
```

```python
# Python
from tools.sqli import SQLiScanner

scanner = SQLiScanner(
    target="https://example.com/search?q=test",
    test_params=["q", "id"],
    delay=0.5
)
result = scanner.run()
```

## XSS Scanner

```bash
# CLI
python -m tools.xss -t "https://example.com/search?q=test"
```

```python
# Python
from tools.xss import XSSScanner

scanner = XSSScanner(
    target="https://example.com/search",
    contexts=["html", "attribute", "javascript"]
)
result = scanner.run()
```

## CORS Scanner

```bash
# CLI
python -m tools.cors -t https://example.com/api/user

# With custom origins
python -m tools.cors -t https://example.com/api -o https://evil.com
```

```python
# Python
from tools.cors import CORSScanner

scanner = CORSScanner(
    target="https://example.com/api/user",
    custom_origins=["https://evil.com", "https://attacker.site"]
)
result = scanner.run()

print(f"Baseline ACAO: {scanner.baseline_response.get('acao')}")
```

## IDOR Scanner

```bash
# CLI with two accounts
python -m tools.idor -t https://example.com/api/user/1 \
    -H "Authorization: Bearer user1_token" \
    --victim-header "Authorization: Bearer user2_token"
```

```python
# Python
from tools.idor import IDORScanner

scanner = IDORScanner(
    target="https://example.com/api/user/1",
    auth_headers={"Authorization": "Bearer attacker_token"},
    victim_headers={"Authorization": "Bearer victim_token"},
    test_ids=["1", "2", "100", "999", "admin"]
)
result = scanner.run()
```

## XXE Scanner

```bash
# CLI
python -m tools.xxe -u https://example.com/api/xml
```

```python
# Python
from tools.xxe import XXEScanner

scanner = XXEScanner(
    target="https://example.com/api/xml",
    custom_headers={"Content-Type": "application/xml"}
)
result = scanner.run()

print(f"Parser detected: {scanner.detected_parser}")
print(f"Confidence: {scanner.total_confidence}%")
```

## SSTI Scanner

```bash
# CLI
python -m tools.ssti -t "https://example.com/render?template=test"

# With custom parameters
python -m tools.ssti -t https://example.com/page -p name -p content
```

```python
# Python
from tools.ssti import SSTIScanner

scanner = SSTIScanner(
    target="https://example.com/render?template=test",
    custom_params=["template", "view", "page"],
    test_params=True
)
result = scanner.run()

for engine, score in scanner.detected_engines.items():
    print(f"  {engine}: {score}%")
```

## JWT Analyzer

```bash
# CLI
python -m tools.jwt -t "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

```python
# Python
from tools.jwt import JWTAnalyzer

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

scanner = JWTAnalyzer(target=token)
result = scanner.run()
```

## GraphQL Scanner

```bash
# CLI
python -m tools.graphql -t https://example.com/graphql
```

```python
# Python
from tools.graphql import GraphQLScanner

scanner = GraphQLScanner(
    target="https://example.com/graphql",
    max_depth=10,
    test_introspection=True
)
result = scanner.run()
```

## Race Condition Scanner

```bash
# CLI
python -m tools.race_condition -u https://example.com/api/transfer \
    -X POST -d '{"amount": 100}' -t 5
```

```python
# Python
from tools.race_condition import RaceConditionScanner

scanner = RaceConditionScanner(
    target="https://example.com/api/transfer",
    method="POST",
    data={"amount": 100, "to": "attacker"},
    threads=5,
    window=0.05
)
result = scanner.run()
```

## Dependency Scanner

```bash
# CLI
python -m tools.dependency -t https://example.com

# Deep scan
python -m tools.dependency -t https://example.com --deep
```

```python
# Python
from tools.dependency import DependencyScanner

scanner = DependencyScanner(
    target="https://example.com",
    deep_scan=True
)
result = scanner.run()

print(f"Libraries found: {scanner.discovered_libraries}")
```

## APK Analyzer

```bash
# CLI
python -m tools.apk_analyzer -a /path/to/app.apk
```

```python
# Python
from tools.apk_analyzer import APKAnalyzer

scanner = APKAnalyzer(
    apk_path="/path/to/app.apk",
    output_dir="/path/to/output"
)
result = scanner.run()
```

## Common Patterns

### With Custom Headers

```python
scanner = SomeScanner(
    target="https://example.com",
    custom_headers={
        "Authorization": "Bearer token",
        "Cookie": "session=abc123",
        "X-Custom": "value"
    }
)
```

### With Output File

```bash
python -m tools.ssrf -t https://example.com -o results.json
```

### With Verbose Mode

```bash
python -m tools.ssrf -t https://example.com -v
```

### With Custom Threshold

```python
scanner = SomeScanner(
    target="https://example.com",
    confidence_threshold=90  # Higher threshold = fewer findings
)
```
