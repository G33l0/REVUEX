# Library Usage Examples

Integrating REVUEX into your Python projects.

## Basic Integration

```python
#!/usr/bin/env python3
"""Basic REVUEX library integration."""

from tools import get_scanner, list_scanners, print_scanner_table

# List all available scanners
print_scanner_table()

# Get scanner by name
SSRFScanner = get_scanner("ssrf")

# Create and run scanner
scanner = SSRFScanner(target="https://example.com/api")
result = scanner.run()

# Process results
print(f"Status: {result.status}")
print(f"Findings: {len(result.findings)}")
```

## Batch Scanning

```python
#!/usr/bin/env python3
"""Scan multiple targets with multiple scanners."""

from tools import get_scanner

targets = [
    "https://target1.com",
    "https://target2.com",
    "https://target3.com"
]

scanners = ["ssrf", "cors", "sqli", "xss"]

results = {}

for target in targets:
    results[target] = {}
    
    for scanner_name in scanners:
        scanner_class = get_scanner(scanner_name)
        scanner = scanner_class(target=target, delay=1.0)
        result = scanner.run()
        
        results[target][scanner_name] = {
            "findings": len(result.findings),
            "duration": result.duration_seconds
        }
        
        if result.findings:
            print(f"[!] {target} - {scanner_name}: {len(result.findings)} findings")

# Summary
print("\n" + "="*60)
print("BATCH SCAN SUMMARY")
print("="*60)

for target, scanner_results in results.items():
    total = sum(r["findings"] for r in scanner_results.values())
    print(f"\n{target}: {total} total findings")
    for scanner, data in scanner_results.items():
        if data["findings"] > 0:
            print(f"  - {scanner}: {data['findings']}")
```

## Custom Workflow

```python
#!/usr/bin/env python3
"""Custom reconnaissance and exploitation workflow."""

from tools import (
    TechFingerprinter,
    JSSecretsMiner,
    SSRFScanner,
    SQLiScanner,
    CORSScanner
)

def recon_phase(target: str) -> dict:
    """Run reconnaissance scanners."""
    results = {"technologies": [], "secrets": []}
    
    # Technology fingerprinting
    tech = TechFingerprinter(target=target)
    tech_result = tech.run()
    results["technologies"] = [f.title for f in tech_result.findings]
    
    # JS secrets mining
    secrets = JSSecretsMiner(target=target)
    secrets_result = secrets.run()
    results["secrets"] = [f.payload for f in secrets_result.findings]
    
    return results

def vuln_phase(target: str, recon_data: dict) -> list:
    """Run vulnerability scanners based on recon data."""
    findings = []
    
    # Always run CORS check
    cors = CORSScanner(target=target)
    cors_result = cors.run()
    findings.extend(cors_result.findings)
    
    # Run SSRF if API detected
    if any("api" in t.lower() for t in recon_data["technologies"]):
        ssrf = SSRFScanner(target=target)
        ssrf_result = ssrf.run()
        findings.extend(ssrf_result.findings)
    
    # Run SQLi if database detected
    db_techs = ["mysql", "postgresql", "mongodb", "sql"]
    if any(db in t.lower() for t in recon_data["technologies"] for db in db_techs):
        sqli = SQLiScanner(target=target)
        sqli_result = sqli.run()
        findings.extend(sqli_result.findings)
    
    return findings

def main(target: str):
    print(f"[*] Starting custom workflow: {target}\n")
    
    # Phase 1: Recon
    print("[Phase 1] Reconnaissance")
    recon_data = recon_phase(target)
    print(f"  Technologies: {len(recon_data['technologies'])}")
    print(f"  Secrets: {len(recon_data['secrets'])}")
    
    # Phase 2: Vulnerability scanning
    print("\n[Phase 2] Vulnerability Scanning")
    findings = vuln_phase(target, recon_data)
    print(f"  Findings: {len(findings)}")
    
    # Report
    print("\n[Results]")
    for finding in findings:
        print(f"  [{finding.severity.value}] {finding.title}")
    
    return findings

if __name__ == "__main__":
    main("https://example.com")
```

## Async Scanning

```python
#!/usr/bin/env python3
"""Asynchronous scanning with concurrent.futures."""

import concurrent.futures
from tools import get_scanner

def run_scanner(scanner_name: str, target: str) -> dict:
    """Run a single scanner and return results."""
    scanner_class = get_scanner(scanner_name)
    scanner = scanner_class(target=target, delay=0.5)
    result = scanner.run()
    
    return {
        "scanner": scanner_name,
        "target": target,
        "findings": len(result.findings),
        "duration": result.duration_seconds,
        "details": [
            {"title": f.title, "severity": f.severity.value}
            for f in result.findings
        ]
    }

def parallel_scan(target: str, scanners: list, max_workers: int = 3):
    """Run multiple scanners in parallel."""
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(run_scanner, scanner, target): scanner
            for scanner in scanners
        }
        
        for future in concurrent.futures.as_completed(futures):
            scanner_name = futures[future]
            try:
                result = future.result()
                results.append(result)
                print(f"[+] {scanner_name}: {result['findings']} findings")
            except Exception as e:
                print(f"[-] {scanner_name}: Error - {e}")
    
    return results

if __name__ == "__main__":
    target = "https://example.com"
    scanners = ["cors", "ssrf", "sqli", "xss", "ssti"]
    
    print(f"[*] Parallel scan: {target}")
    print(f"[*] Scanners: {', '.join(scanners)}\n")
    
    results = parallel_scan(target, scanners, max_workers=3)
    
    # Summary
    total_findings = sum(r["findings"] for r in results)
    total_duration = sum(r["duration"] for r in results)
    
    print(f"\n{'='*50}")
    print(f"Total findings: {total_findings}")
    print(f"Total duration: {total_duration:.2f}s")
```

## Custom Reporter

```python
#!/usr/bin/env python3
"""Custom report generation."""

import json
from datetime import datetime
from tools import SSRFScanner, SQLiScanner, XSSScanner

class CustomReporter:
    def __init__(self):
        self.findings = []
        self.scan_info = {
            "started": datetime.now().isoformat(),
            "scanners_run": []
        }
    
    def add_results(self, scanner_name: str, result):
        self.scan_info["scanners_run"].append(scanner_name)
        self.findings.extend(result.findings)
    
    def generate_report(self, output_file: str):
        report = {
            "scan_info": self.scan_info,
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": self._count_by_severity()
            },
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "url": f.url,
                    "description": f.description,
                    "remediation": f.remediation
                }
                for f in self.findings
            ]
        }
        
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def _count_by_severity(self):
        counts = {}
        for f in self.findings:
            sev = f.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts

# Usage
reporter = CustomReporter()

target = "https://example.com"

# Run scanners
for scanner_class in [SSRFScanner, SQLiScanner, XSSScanner]:
    scanner = scanner_class(target=target)
    result = scanner.run()
    reporter.add_results(scanner.__class__.__name__, result)

# Generate report
report = reporter.generate_report("custom_report.json")
print(f"Report generated: {report['summary']}")
```

## Integration with Other Tools

```python
#!/usr/bin/env python3
"""Integration with external tools."""

import subprocess
import json
from tools import SSRFScanner

def run_nmap(target: str) -> list:
    """Run nmap and return open ports."""
    # Extract domain from URL
    from urllib.parse import urlparse
    domain = urlparse(target).netloc
    
    try:
        result = subprocess.run(
            ["nmap", "-p-", "--open", "-oG", "-", domain],
            capture_output=True, text=True, timeout=300
        )
        # Parse output for open ports
        ports = []
        for line in result.stdout.split("\n"):
            if "Ports:" in line:
                port_section = line.split("Ports:")[1]
                for port_info in port_section.split(","):
                    if "/open/" in port_info:
                        port = port_info.split("/")[0].strip()
                        ports.append(port)
        return ports
    except Exception as e:
        print(f"Nmap error: {e}")
        return []

def enhanced_scan(target: str):
    """Combine nmap with REVUEX scanning."""
    
    # 1. Port scan
    print("[*] Running port scan...")
    ports = run_nmap(target)
    print(f"    Open ports: {ports}")
    
    # 2. Run REVUEX on discovered services
    findings = []
    
    for port in ports:
        if port in ["80", "443", "8080", "8443"]:
            protocol = "https" if port in ["443", "8443"] else "http"
            url = f"{protocol}://{target}:{port}"
            
            print(f"[*] Scanning {url}...")
            scanner = SSRFScanner(target=url)
            result = scanner.run()
            findings.extend(result.findings)
    
    return findings

if __name__ == "__main__":
    findings = enhanced_scan("example.com")
    print(f"\nTotal findings: {len(findings)}")
```

## Flask Web Interface

```python
#!/usr/bin/env python3
"""Simple Flask web interface for REVUEX."""

from flask import Flask, request, jsonify
from tools import get_scanner, SCANNER_INFO

app = Flask(__name__)

@app.route("/scanners", methods=["GET"])
def list_scanners():
    """List available scanners."""
    return jsonify(SCANNER_INFO)

@app.route("/scan", methods=["POST"])
def run_scan():
    """Run a scan."""
    data = request.json
    
    target = data.get("target")
    scanner_name = data.get("scanner", "ssrf")
    
    if not target:
        return jsonify({"error": "target required"}), 400
    
    scanner_class = get_scanner(scanner_name)
    if not scanner_class:
        return jsonify({"error": f"unknown scanner: {scanner_name}"}), 400
    
    scanner = scanner_class(target=target)
    result = scanner.run()
    
    return jsonify({
        "target": target,
        "scanner": scanner_name,
        "status": result.status.value,
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "url": f.url
            }
            for f in result.findings
        ]
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)
```

Usage:
```bash
# List scanners
curl http://localhost:5000/scanners

# Run scan
curl -X POST http://localhost:5000/scan \
    -H "Content-Type: application/json" \
    -d '{"target": "https://example.com", "scanner": "ssrf"}'
```
