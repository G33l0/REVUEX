# REVUEX SQLi Scanner

Advanced SQL Injection vulnerability scanner with multiple detection techniques.

## Overview

SQL Injection (SQLi) is a code injection technique that exploits security vulnerabilities in an application's database layer. This scanner detects various types of SQLi vulnerabilities.

## Features

- **Multi-DBMS Detection**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite
- **Multiple Techniques**: Error-based, Boolean-based, Time-based, UNION-based
- **WAF Bypass**: Case variations, comment injection, encoding tricks
- **Smart Detection**: Prioritizes SQLi-prone parameters (id, user, search, etc.)

## Usage

### CLI

```bash
# Basic scan
python -m tools.sqli -t "https://example.com/search?q=test"

# Thorough scan
python -m tools.sqli -t "https://example.com/user?id=1" --level 2

# Target specific DBMS
python -m tools.sqli -t "https://example.com/api?item=123" --dbms mysql -v
```

### Python API

```python
from tools.sqli import SQLiScanner

scanner = SQLiScanner(target="https://example.com/search?q=test")
result = scanner.run()

for finding in result.findings:
    print(f"[{finding.severity.value}] {finding.title}")
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --target` | Target URL with parameters | Required |
| `--level` | Scan intensity (1-3) | 1 |
| `--dbms` | Target DBMS | Auto-detect |
| `--time-delay` | Time-based delay (seconds) | 5 |
| `--all-params` | Test all parameters | False |
| `--no-waf-bypass` | Skip WAF bypass tests | False |
| `-o, --output` | Output file (JSON) | None |
| `-v, --verbose` | Verbose output | False |

## Detection Techniques

1. **Error-Based**: Triggers SQL errors to confirm injection
2. **Boolean-Based Blind**: Compares true/false condition responses
3. **Time-Based Blind**: Uses SLEEP/WAITFOR to confirm injection
4. **UNION-Based**: Extracts data via UNION SELECT

## CVSS & CWE

- **CWE-89**: SQL Injection
- **OWASP**: A03:2021 - Injection
- **CVSS**: 8.6-9.8 (Critical)

## Legal Disclaimer

This tool is for authorized security testing only. Unauthorized access is illegal.

## Author

REVUEX Team - Bug Bounty Automation Framework
