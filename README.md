# REVUEX

<div align="center">

```
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
```

**Professional Bug Bounty Automation Framework**

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Installation](#installation) •
[Quick Start](#quick-start) •
[Tools](#tools) •
[Documentation](#documentation) •
[Contributing](#contributing)

</div>

---

## 🎯 What is REVUEX?

REVUEX is a comprehensive bug bounty automation framework designed by security researchers, for security researchers. It combines 20 specialized security scanners into a unified toolkit that generates **bug bounty-ready reports** with professional documentation, evidence collection, and remediation guidance.

### Why REVUEX?

- **🔥 Real-World Focus** — Tools designed to find actual vulnerabilities, not theoretical ones
- **📋 Bounty-Ready Reports** — HTML/JSON/Markdown reports ready for submission
- **🛡️ Safety First** — Rate limiting, scope validation, and responsible testing practices
- **🔧 Modular Design** — Use tools standalone or as an integrated suite
- **🧠 Intelligence Sharing** — Findings from one tool inform others automatically
- **⚡ Efficient** — Parallel scanning with configurable concurrency

---

## 📦 Installation

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- Git

### Quick Install

```bash
# Clone the repository
git clone https://github.com/G33l0/revuex.git
cd revuex

# Install dependencies
pip install -r requirements.txt

# Verify installation
python revuex_suite.py --version
```

### Development Install

```bash
# Clone and install in development mode
git clone https://github.com/G33l0/revuex.git
cd revuex

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install with development dependencies
pip install -e ".[dev]"
```

### Docker Install (Coming Soon)

```bash
docker pull revuex/revuex:latest
docker run -it revuex/revuex --help
```

---

## 🚀 Quick Start

### Full Suite Scan

Run all applicable scanners against a target:

```bash
python revuex_suite.py -t https://target.com
```

### Single Tool Usage

Each tool works independently:

```bash
# Subdomain enumeration
python -m tools.subdomain_hunter -t target.com

# SSRF scanning
python -m tools.ssrf -t https://target.com/api/fetch?url=

# SQL injection testing
python -m tools.sqli -t https://target.com/search?q=test

# Full list of options
python -m tools.ssrf --help
```

### Library Usage

Import REVUEX tools into your own scripts:

```python
from revuex.core import Severity
from revuex.tools.ssrf import SSRFScanner

# Initialize scanner
scanner = SSRFScanner(
    target="https://target.com/api/fetch",
    parameter="url",
    delay=1.0,
    timeout=10
)

# Run scan
result = scanner.run()

# Process findings
for finding in result.findings:
    if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
        print(f"[!] {finding.title}: {finding.url}")

# Export report
scanner.save_results(result, formats=["html", "json"])
```

---

## 🛠️ Tools

REVUEX includes 20 specialized security scanners:

### Reconnaissance

| Tool | Description | Status |
|------|-------------|--------|
| **Subdomain Hunter** | Multi-source subdomain enumeration with validation | ✅ Ready |
| **Tech Fingerprinter** | Technology stack identification and version detection | ✅ Ready |
| **JS Secrets Miner** | Extract secrets, API keys, and endpoints from JavaScript | ✅ Ready |

### Injection Vulnerabilities

| Tool | Description | Status |
|------|-------------|--------|
| **SQLi Scanner** | Advanced SQL injection with WAF bypass techniques | ✅ Ready |
| **XSS Scanner** | Context-aware XSS detection with DOM analysis | ✅ Ready |
| **SSTI Scanner** | Server-Side Template Injection across 15+ engines | ✅ Ready |
| **XXE Scanner** | XML External Entity injection testing | ✅ Ready |

### Access Control

| Tool | Description | Status |
|------|-------------|--------|
| **IDOR Tester** | Two-account methodology for access control testing | ✅ Ready |
| **CORS Scanner** | Cross-Origin Resource Sharing misconfiguration | ✅ Ready |
| **CSRF Tester** | Cross-Site Request Forgery detection | ✅ Ready |

### Server-Side Vulnerabilities

| Tool | Description | Status |
|------|-------------|--------|
| **SSRF Scanner** | Server-Side Request Forgery with cloud metadata checks | ✅ Ready |
| **File Upload Tester** | Unrestricted file upload vulnerability testing | ✅ Ready |

### Authentication & Session

| Tool | Description | Status |
|------|-------------|--------|
| **Session Analyzer** | Session management and fixation testing | ✅ Ready |
| **JWT Analyzer** | JSON Web Token security analysis | ✅ Ready |

### Business Logic

| Tool | Description | Status |
|------|-------------|--------|
| **Business Logic Abuser** | Workflow and business logic flaw detection | ✅ Ready |
| **Race Condition Tester** | TOCTOU and race condition vulnerability testing | ✅ Ready |
| **Price Manipulation** | E-commerce and payment logic testing | ✅ Ready |

### API & Mobile

| Tool | Description | Status |
|------|-------------|--------|
| **GraphQL Introspector** | GraphQL schema analysis and vulnerability testing | ✅ Ready |
| **APK Analyzer** | Android application security analysis | ✅ Ready |

### Supply Chain

| Tool | Description | Status |
|------|-------------|--------|
| **Dependency Checker** | Known vulnerability detection in dependencies | ✅ Ready |

---

## 📊 Sample Output

### Terminal Output

```
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
        Bug Bounty Automation Framework v1.0.0

[*] Starting SSRF Scanner scan
[*] Target: https://target.com/api/fetch
[*] Scope: target.com
[+] [CRITICAL] AWS Metadata SSRF @ https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/
[+] [HIGH] Internal Network Access @ https://target.com/api/fetch?url=http://192.168.1.1/
[*] ==================================================
[*] SCAN COMPLETE
[*] ==================================================
[*] Duration: 45.32 seconds
[*] Requests: 127 total, 3 failed
[*] Findings: 2 total
  CRITICAL: 1
  HIGH: 1
[*] HTML report saved: scans/ssrf_scanner_target.com_20250115_143022.html
```

### Report Formats

REVUEX generates reports in multiple formats:

- **HTML** — Professional, styled reports for client delivery
- **JSON** — Machine-readable for integration with other tools
- **Markdown** — Easy to include in bug bounty submissions
- **TXT** — Plain text for quick review

---

## ⚙️ Configuration

### Command Line Options

All tools support common options:

```bash
python -m tools.ssrf \
    -t https://target.com \          # Target URL
    --timeout 10 \                    # Request timeout (seconds)
    --delay 1.0 \                     # Delay between requests
    --rate-limit 30 \                 # Requests per minute
    --proxy http://127.0.0.1:8080 \   # Proxy (Burp/ZAP)
    --headers "Authorization: Bearer token" \  # Custom headers
    --cookies "session=abc123" \      # Cookies
    --output-dir ./reports \          # Output directory
    --formats json,html,md \          # Report formats
    --verbose                         # Verbose output
```

### Configuration File

Create a `revuex.yaml` for persistent configuration:

```yaml
# revuex.yaml
global:
  timeout: 10
  delay: 1.0
  rate_limit: 30
  verify_ssl: false
  output_dir: ./scans
  formats:
    - html
    - json

proxy:
  enabled: false
  url: http://127.0.0.1:8080

headers:
  User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"

# Tool-specific overrides
tools:
  ssrf:
    check_cloud_metadata: true
    internal_ranges:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
  
  sqli:
    techniques:
      - boolean
      - time
      - error
      - union
```

### Environment Variables

```bash
export REVUEX_PROXY="http://127.0.0.1:8080"
export REVUEX_TIMEOUT=10
export REVUEX_RATE_LIMIT=30
export REVUEX_OUTPUT_DIR="./scans"
```

---

## 📁 Project Structure

```
revuex/
├── revuex_suite.py          # Master orchestrator
├── core/                     # Shared core library
│   ├── base_scanner.py       # Abstract base class
│   ├── safety_checks.py      # Validation & safety
│   ├── intelligence_hub.py   # Cross-tool intelligence
│   ├── report_generator.py   # Report generation
│   └── utils.py              # Utilities
├── tools/                    # 20 Security scanners
│   ├── subdomain_hunter/
│   ├── ssrf/
│   ├── sqli/
│   └── ...
├── payloads/                 # Payload libraries
├── documentation/            # Detailed docs
└── scans/                    # Output directory
```

---

## 🔒 Responsible Use

### Legal Disclaimer

> ⚠️ **IMPORTANT**: REVUEX is designed for **authorized security testing only**.
> 
> Before using this tool, ensure you have:
> 1. **Written authorization** from the target owner, OR
> 2. Are testing within a **legitimate bug bounty program** scope
> 
> Unauthorized access to computer systems is illegal under:
> - Computer Fraud and Abuse Act (CFAA) — United States
> - Computer Misuse Act — United Kingdom
> - Similar legislation in other jurisdictions
> 
> **The authors assume no liability for misuse of this software.**

### Built-in Safety Features

REVUEX includes multiple safety mechanisms:

- **Scope Validation** — Requests are validated against defined scope
- **Rate Limiting** — Token bucket algorithm prevents target overload
- **Safe Payloads** — Payloads designed for detection, not exploitation
- **Request Delays** — Configurable delays between requests
- **Audit Logging** — All requests logged for accountability

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Installation Guide](documentation/INSTALLATION.md) | Detailed installation instructions |
| [Usage Guide](documentation/USAGE.md) | Comprehensive usage documentation |
| [Architecture](documentation/ARCHITECTURE.md) | Technical architecture overview |
| [API Reference](documentation/API_REFERENCE.md) | Programmatic API documentation |
| [Contributing](documentation/CONTRIBUTING.md) | Contribution guidelines |
| [Troubleshooting](documentation/TROUBLESHOOTING.md) | Common issues and solutions |

### Tool Documentation

Each tool has dedicated documentation in its README.md. See `tools/`:

- [SSRF Scanner](tools/ssrf.md)
- [SQLi Scanner](tools/sqli.md)
- [IDOR Tester](tools/idor.md)
- [Full list...](tools/)

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](documentation/CONTRIBUTING.md) for guidelines.

### Ways to Contribute

- 🐛 Report bugs and issues
- 💡 Suggest new features or tools
- 📝 Improve documentation
- 🔧 Submit pull requests
- 🧪 Add test cases
- 📦 Create payload libraries

### Development Setup

```bash
# Fork and clone
git clone https://github.com/yourusername/revuex.git
cd revuex

# Create feature branch
git checkout -b feature/my-feature

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Submit PR
```

---

## 📈 Roadmap

### v1.1.0 (Planned)
- [ ] Docker containerization
- [ ] Web UI dashboard
- [ ] Scheduled scanning
- [ ] Slack/Discord notifications

### v1.2.0 (Planned)
- [ ] API vulnerability scanner
- [ ] OAuth/OIDC tester
- [ ] WebSocket scanner
- [ ] Cloud misconfiguration checks

### v2.0.0 (Future)
- [ ] Machine learning-based detection
- [ ] Custom plugin system
- [ ] Distributed scanning
- [ ] Integration with popular platforms

---

## 💬 Community

- **Issues**: [GitHub Issues](https://github.com/yourusername/revuex/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/revuex/discussions)
- **Twitter**: [@revuex_security](https://twitter.com/revuex_security)
- **Discord**: [Join our server](https://discord.gg/revuex)

---

## 📜 License

REVUEX is released under the [MIT License](LICENSE).

```
MIT License

Copyright (c) 2025 REVUEX Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<div align="center">

**Built with ❤️ by security researchers, for security researchers**

[⬆ Back to Top](#revuex)

</div>
