# Custom Workflow Examples

Building specialized scanning pipelines with REVUEX.

## Bug Bounty Workflow

```python
#!/usr/bin/env python3
"""
Bug Bounty Workflow
===================
Optimized workflow for bug bounty hunting.
"""

from tools import (
    SubdomainHunter,
    TechFingerprinter,
    JSSecretsMiner,
    SSRFScanner,
    IDORScanner,
    CORSScanner,
    GraphQLScanner
)

class BugBountyWorkflow:
    def __init__(self, domain: str, scope: list = None):
        self.domain = domain
        self.scope = scope or [domain]
        self.findings = []
        self.recon_data = {}
    
    def run(self):
        """Execute full bug bounty workflow."""
        print(f"[*] Bug Bounty Workflow: {self.domain}\n")
        
        # Step 1: Subdomain enumeration
        self.enumerate_subdomains()
        
        # Step 2: Technology fingerprinting
        self.fingerprint_technologies()
        
        # Step 3: Secret mining
        self.mine_secrets()
        
        # Step 4: High-value vulnerability checks
        self.check_high_value_vulns()
        
        return self.findings
    
    def enumerate_subdomains(self):
        print("[Phase 1] Subdomain Enumeration")
        hunter = SubdomainHunter(target=self.domain)
        result = hunter.run()
        subdomains = [f.url for f in result.findings]
        self.recon_data["subdomains"] = subdomains
        print(f"  Found {len(subdomains)} subdomains")
    
    def fingerprint_technologies(self):
        print("\n[Phase 2] Technology Fingerprinting")
        targets = self.recon_data.get("subdomains", [f"https://{self.domain}"])
        for target in targets[:10]:
            fingerprinter = TechFingerprinter(target=target)
            result = fingerprinter.run()
            if result.findings:
                print(f"  {target}: {len(result.findings)} technologies")
    
    def mine_secrets(self):
        print("\n[Phase 3] Secret Mining")
        targets = self.recon_data.get("subdomains", [f"https://{self.domain}"])
        for target in targets[:5]:
            miner = JSSecretsMiner(target=target)
            result = miner.run()
            if result.findings:
                self.findings.extend(result.findings)
                print(f"  {target}: {len(result.findings)} secrets!")
    
    def check_high_value_vulns(self):
        print("\n[Phase 4] High-Value Vulnerability Checks")
        targets = self.recon_data.get("subdomains", [f"https://{self.domain}"])
        
        for target in targets[:5]:
            # CORS
            cors = CORSScanner(target=target)
            self.findings.extend(cors.run().findings)
            
            # SSRF
            ssrf = SSRFScanner(target=target)
            self.findings.extend(ssrf.run().findings)
            
            # GraphQL
            graphql = GraphQLScanner(target=f"{target}/graphql")
            self.findings.extend(graphql.run().findings)


if __name__ == "__main__":
    workflow = BugBountyWorkflow(domain="example.com")
    findings = workflow.run()
    print(f"\nTotal findings: {len(findings)}")
```

## CI/CD Security Pipeline

```python
#!/usr/bin/env python3
"""
CI/CD Security Pipeline
=======================
Integrate REVUEX into CI/CD pipeline.
"""

import sys
import json
from tools import SSRFScanner, SQLiScanner, XSSScanner, CORSScanner, DependencyScanner

def run_security_scan(target: str, fail_on_high: bool = True) -> int:
    """
    Run security scan and return exit code.
    
    Returns:
        0 = No critical/high findings
        1 = Critical/high findings found
        2 = Scan error
    """
    findings = []
    
    scanners = [
        ("SSRF", SSRFScanner),
        ("SQLi", SQLiScanner),
        ("XSS", XSSScanner),
        ("CORS", CORSScanner),
        ("Dependencies", DependencyScanner),
    ]
    
    print(f"🔍 Security Scan: {target}\n")
    
    for name, scanner_class in scanners:
        try:
            print(f"  Running {name}...", end=" ")
            scanner = scanner_class(target=target, delay=0.2)
            result = scanner.run()
            findings.extend(result.findings)
            print(f"✓ ({len(result.findings)} findings)")
        except Exception as e:
            print(f"✗ Error: {e}")
    
    # Categorize findings
    critical = [f for f in findings if f.severity.value == "critical"]
    high = [f for f in findings if f.severity.value == "high"]
    medium = [f for f in findings if f.severity.value == "medium"]
    
    # Output results
    print(f"\n{'='*50}")
    print("SECURITY SCAN RESULTS")
    print(f"{'='*50}")
    print(f"Critical: {len(critical)}")
    print(f"High:     {len(high)}")
    print(f"Medium:   {len(medium)}")
    print(f"Total:    {len(findings)}")
    
    # Save results
    with open("security-scan-results.json", "w") as f:
        json.dump({
            "target": target,
            "summary": {
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "total": len(findings)
            },
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "url": f.url,
                    "description": f.description
                }
                for f in findings
            ]
        }, f, indent=2)
    
    # Determine exit code
    if fail_on_high and (critical or high):
        print("\n❌ FAILED: Critical/High vulnerabilities found!")
        return 1
    
    print("\n✅ PASSED: No critical/high vulnerabilities")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cicd_scan.py <target_url>")
        sys.exit(2)
    
    target = sys.argv[1]
    exit_code = run_security_scan(target)
    sys.exit(exit_code)
```

### GitHub Actions Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install REVUEX
        run: |
          pip install -r requirements.txt
          pip install -e .
      
      - name: Run Security Scan
        run: |
          python scripts/cicd_scan.py ${{ secrets.STAGING_URL }}
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-scan-results
          path: security-scan-results.json
```

## API Security Workflow

```python
#!/usr/bin/env python3
"""
API Security Testing Workflow
"""

from tools import SSRFScanner, SQLiScanner, IDORScanner, CORSScanner, JWTAnalyzer

class APISecurityWorkflow:
    def __init__(self, base_url: str, auth_token: str = None):
        self.base_url = base_url.rstrip("/")
        self.auth_headers = {}
        if auth_token:
            self.auth_headers["Authorization"] = f"Bearer {auth_token}"
        self.findings = []
        self.endpoints = []
    
    def add_endpoint(self, path: str, method: str = "GET", params: dict = None):
        self.endpoints.append({
            "path": path,
            "method": method,
            "params": params or {},
            "url": f"{self.base_url}{path}"
        })
    
    def run(self):
        print(f"[*] API Security Workflow: {self.base_url}\n")
        
        # Test JWT
        if "Authorization" in self.auth_headers:
            token = self.auth_headers["Authorization"].replace("Bearer ", "")
            jwt = JWTAnalyzer(target=token)
            self.findings.extend(jwt.run().findings)
        
        # Test CORS
        for endpoint in self.endpoints:
            cors = CORSScanner(target=endpoint["url"], custom_headers=self.auth_headers)
            self.findings.extend(cors.run().findings)
        
        # Test each endpoint
        for endpoint in self.endpoints:
            ssrf = SSRFScanner(target=endpoint["url"], custom_headers=self.auth_headers)
            self.findings.extend(ssrf.run().findings)
        
        return self.findings


# Usage
workflow = APISecurityWorkflow(
    base_url="https://api.example.com/v1",
    auth_token="eyJhbGciOiJIUzI1NiIs..."
)
workflow.add_endpoint("/users", params={"id": "1"})
workflow.add_endpoint("/orders", params={"order_id": "123"})
findings = workflow.run()
```

## E-Commerce Workflow

```python
#!/usr/bin/env python3
"""
E-Commerce Security Workflow
"""

from tools import PriceManipulationScanner, RaceConditionScanner, IDORScanner, CSRFScanner

class ECommerceWorkflow:
    def __init__(self, base_url: str, session_cookie: str):
        self.base_url = base_url
        self.auth_headers = {"Cookie": f"session={session_cookie}"}
        self.findings = []
    
    def run(self):
        print(f"[*] E-Commerce Workflow: {self.base_url}\n")
        
        # Price manipulation
        print("[*] Testing Price Manipulation")
        for endpoint in ["/api/cart", "/api/checkout"]:
            scanner = PriceManipulationScanner(
                target=f"{self.base_url}{endpoint}",
                custom_headers=self.auth_headers
            )
            self.findings.extend(scanner.run().findings)
        
        # Race conditions (coupon abuse)
        print("[*] Testing Race Conditions")
        race = RaceConditionScanner(
            target=f"{self.base_url}/api/redeem-coupon",
            method="POST",
            threads=5,
            custom_headers=self.auth_headers
        )
        self.findings.extend(race.run().findings)
        
        # Order IDOR
        print("[*] Testing Order IDOR")
        idor = IDORScanner(
            target=f"{self.base_url}/api/orders/1",
            auth_headers=self.auth_headers,
            test_ids=["1", "2", "100"]
        )
        self.findings.extend(idor.run().findings)
        
        return self.findings


# Usage
workflow = ECommerceWorkflow(
    base_url="https://shop.example.com",
    session_cookie="abc123xyz"
)
findings = workflow.run()
```

## Scheduled Monitoring

```python
#!/usr/bin/env python3
"""
Scheduled Security Monitoring
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from tools import CORSScanner, SSRFScanner, DependencyScanner

class SecurityMonitor:
    def __init__(self, targets: list, state_file: str = "monitor_state.json"):
        self.targets = targets
        self.state_file = Path(state_file)
        self.previous_state = self._load_state()
        self.current_findings = []
    
    def _load_state(self) -> dict:
        if self.state_file.exists():
            with open(self.state_file) as f:
                return json.load(f)
        return {"findings": {}, "last_scan": None}
    
    def _save_state(self):
        state = {
            "findings": {
                self._finding_hash(f): f.title
                for f in self.current_findings
            },
            "last_scan": datetime.now().isoformat()
        }
        with open(self.state_file, "w") as f:
            json.dump(state, f, indent=2)
    
    def _finding_hash(self, finding) -> str:
        data = f"{finding.title}:{finding.url}"
        return hashlib.md5(data.encode()).hexdigest()
    
    def run(self):
        print(f"[*] Security Monitor - {datetime.now().isoformat()}")
        
        for target in self.targets:
            print(f"[*] Scanning: {target}")
            for scanner_class in [CORSScanner, SSRFScanner, DependencyScanner]:
                try:
                    scanner = scanner_class(target=target, delay=1.0)
                    self.current_findings.extend(scanner.run().findings)
                except Exception as e:
                    print(f"    Error: {e}")
        
        # Find new findings
        previous_hashes = set(self.previous_state.get("findings", {}).keys())
        new_findings = [
            f for f in self.current_findings
            if self._finding_hash(f) not in previous_hashes
        ]
        
        if new_findings:
            print(f"\n[!] NEW FINDINGS: {len(new_findings)}")
            for f in new_findings:
                print(f"  [{f.severity.value}] {f.title}")
        else:
            print("\n[+] No new findings")
        
        self._save_state()


if __name__ == "__main__":
    monitor = SecurityMonitor(targets=[
        "https://app.example.com",
        "https://api.example.com"
    ])
    monitor.run()
```

### Cron Setup

```bash
# Run every 6 hours
0 */6 * * * cd /path/to/revuex && python scripts/monitor.py >> /var/log/revuex.log 2>&1
```
