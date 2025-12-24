# Full Scan Example

Complete target scanning using REVUEX suite.

## Command Line

```bash
# Run all scanners
python revuex_suite.py -t https://example.com --all

# Run with custom output
python revuex_suite.py -t https://example.com --all -o ./reports/

# Run with verbose output
python revuex_suite.py -t https://example.com --all -v
```

## Python Script

```python
#!/usr/bin/env python3
"""
Full Scan Example
=================
Run all REVUEX scanners against a target.
"""

from tools import (
    SubdomainHunter,
    TechFingerprinter,
    JSSecretsMiner,
    SSRFScanner,
    SQLiScanner,
    IDORScanner,
    XSSScanner,
    CORSScanner,
    CSRFScanner,
    SSTIScanner,
    XXEScanner,
    GraphQLScanner,
    DependencyScanner
)
from core.report_generator import ReportGenerator

def full_scan(target: str):
    """Run comprehensive scan against target."""
    
    print(f"[*] Starting full scan: {target}")
    all_findings = []
    
    # Phase 1: Reconnaissance
    print("\n[Phase 1] Reconnaissance")
    
    # Subdomain enumeration (if domain provided)
    if not target.startswith("http"):
        hunter = SubdomainHunter(target=target)
        result = hunter.run()
        print(f"  Subdomains found: {len(result.findings)}")
    
    # Technology fingerprinting
    fingerprinter = TechFingerprinter(target=target)
    result = fingerprinter.run()
    all_findings.extend(result.findings)
    print(f"  Technologies detected: {len(result.findings)}")
    
    # JS secrets mining
    secrets_miner = JSSecretsMiner(target=target)
    result = secrets_miner.run()
    all_findings.extend(result.findings)
    print(f"  Secrets found: {len(result.findings)}")
    
    # Phase 2: Injection Testing
    print("\n[Phase 2] Injection Testing")
    
    scanners = [
        ("SSRF", SSRFScanner),
        ("SQLi", SQLiScanner),
        ("XSS", XSSScanner),
        ("SSTI", SSTIScanner),
    ]
    
    for name, scanner_class in scanners:
        try:
            scanner = scanner_class(target=target, delay=0.5)
            result = scanner.run()
            all_findings.extend(result.findings)
            print(f"  {name}: {len(result.findings)} findings")
        except Exception as e:
            print(f"  {name}: Error - {e}")
    
    # Phase 3: Access Control
    print("\n[Phase 3] Access Control Testing")
    
    access_scanners = [
        ("CORS", CORSScanner),
        ("CSRF", CSRFScanner),
    ]
    
    for name, scanner_class in access_scanners:
        try:
            scanner = scanner_class(target=target)
            result = scanner.run()
            all_findings.extend(result.findings)
            print(f"  {name}: {len(result.findings)} findings")
        except Exception as e:
            print(f"  {name}: Error - {e}")
    
    # Phase 4: API Testing
    print("\n[Phase 4] API Testing")
    
    graphql = GraphQLScanner(target=f"{target}/graphql")
    result = graphql.run()
    all_findings.extend(result.findings)
    print(f"  GraphQL: {len(result.findings)} findings")
    
    # Phase 5: Dependency Check
    print("\n[Phase 5] Dependency Analysis")
    
    deps = DependencyScanner(target=target)
    result = deps.run()
    all_findings.extend(result.findings)
    print(f"  Vulnerable dependencies: {len(result.findings)}")
    
    # Generate Report
    print("\n[*] Generating report...")
    
    if all_findings:
        generator = ReportGenerator(all_findings)
        generator.generate_html("full_scan_report.html")
        generator.generate_json("full_scan_report.json")
        print(f"[+] Report saved: full_scan_report.html")
    
    # Summary
    print(f"\n{'='*50}")
    print("SCAN COMPLETE")
    print(f"{'='*50}")
    print(f"Target: {target}")
    print(f"Total Findings: {len(all_findings)}")
    
    # Severity breakdown
    severity_counts = {}
    for f in all_findings:
        sev = f.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    for sev, count in sorted(severity_counts.items()):
        print(f"  {sev}: {count}")
    
    return all_findings


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python full_scan.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    findings = full_scan(target)
```

## Expected Output

```
[*] Starting full scan: https://example.com

[Phase 1] Reconnaissance
  Technologies detected: 5
  Secrets found: 2

[Phase 2] Injection Testing
  SSRF: 0 findings
  SQLi: 1 findings
  XSS: 0 findings
  SSTI: 0 findings

[Phase 3] Access Control Testing
  CORS: 1 findings
  CSRF: 0 findings

[Phase 4] API Testing
  GraphQL: 2 findings

[Phase 5] Dependency Analysis
  Vulnerable dependencies: 3

[*] Generating report...
[+] Report saved: full_scan_report.html

==================================================
SCAN COMPLETE
==================================================
Target: https://example.com
Total Findings: 9
  critical: 1
  high: 3
  medium: 4
  info: 1
```
