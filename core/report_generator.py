#!/usr/bin/env python3
"""
REVUEX - Report Generator Module
================================

Professional bug bounty report generator.

Features:
- Multiple output formats (HTML, JSON, Markdown, TXT)
- Executive summary for non-technical stakeholders
- Technical evidence with request/response pairs
- Proof-of-concept code generation
- CVSS scoring integration
- Remediation guidance
- Compliance mapping (OWASP, CWE, CVE)

Author: REVUEX Team
License: MIT
"""

import json
import hashlib
import html
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict
from string import Template


# =============================================================================
# CONSTANTS
# =============================================================================

REVUEX_VERSION = "1.0.0"

SEVERITY_COLORS = {
    "critical": "#9b59b6",
    "high": "#e74c3c",
    "medium": "#f39c12",
    "low": "#3498db",
    "info": "#1abc9c",
}

OWASP_TOP_10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

VULN_CLASSIFICATION = {
    "ssrf": {"owasp": "A10", "cwe": "CWE-918", "name": "Server-Side Request Forgery"},
    "sqli": {"owasp": "A03", "cwe": "CWE-89", "name": "SQL Injection"},
    "xss": {"owasp": "A03", "cwe": "CWE-79", "name": "Cross-Site Scripting"},
    "idor": {"owasp": "A01", "cwe": "CWE-639", "name": "Insecure Direct Object Reference"},
    "xxe": {"owasp": "A03", "cwe": "CWE-611", "name": "XML External Entity"},
    "csrf": {"owasp": "A01", "cwe": "CWE-352", "name": "Cross-Site Request Forgery"},
    "cors": {"owasp": "A05", "cwe": "CWE-942", "name": "CORS Misconfiguration"},
    "ssti": {"owasp": "A03", "cwe": "CWE-1336", "name": "Server-Side Template Injection"},
    "rce": {"owasp": "A03", "cwe": "CWE-94", "name": "Remote Code Execution"},
    "lfi": {"owasp": "A01", "cwe": "CWE-98", "name": "Local File Inclusion"},
    "jwt": {"owasp": "A07", "cwe": "CWE-287", "name": "JWT Vulnerability"},
    "file_upload": {"owasp": "A04", "cwe": "CWE-434", "name": "Unrestricted File Upload"},
    "race_condition": {"owasp": "A04", "cwe": "CWE-362", "name": "Race Condition"},
    "business_logic": {"owasp": "A04", "cwe": "CWE-840", "name": "Business Logic Error"},
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ReportMetadata:
    """Report metadata and configuration"""
    title: str = "Security Assessment Report"
    subtitle: str = ""
    author: str = "REVUEX Security Scanner"
    target: str = ""
    target_domain: str = ""
    scan_id: str = ""
    scan_date: str = ""
    report_date: str = ""
    version: str = REVUEX_VERSION
    confidentiality: str = "CONFIDENTIAL"
    custom_css: str = ""
    
    def __post_init__(self):
        if not self.report_date:
            self.report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class FindingReport:
    """Structured finding for reports"""
    id: str
    title: str
    severity: str
    description: str
    
    url: str = ""
    parameter: str = ""
    method: str = "GET"
    
    payload: str = ""
    request: str = ""
    response: str = ""
    evidence: str = ""
    
    vulnerability_type: str = ""
    cwe_id: str = ""
    owasp_category: str = ""
    cvss_score: float = 0.0
    
    impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    confidence: str = "high"
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        
        if self.vulnerability_type and not self.cwe_id:
            classification = VULN_CLASSIFICATION.get(self.vulnerability_type.lower(), {})
            if classification:
                self.cwe_id = classification.get("cwe", "")
                self.owasp_category = classification.get("owasp", "")
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanStatistics:
    """Scan statistics for reports"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    duration_seconds: float = 0.0
    endpoints_tested: int = 0
    parameters_tested: int = 0
    payloads_tested: int = 0
    
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    @property
    def total_findings(self) -> int:
        return self.critical_count + self.high_count + self.medium_count + self.low_count + self.info_count
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["total_findings"] = self.total_findings
        return data


# =============================================================================
# REPORT GENERATOR CLASS
# =============================================================================

class ReportGenerator:
    """
    Professional bug bounty report generator.
    
    Usage:
        generator = ReportGenerator(
            metadata=ReportMetadata(title="Security Assessment", target="https://example.com")
        )
        generator.add_finding(FindingReport(...))
        generator.generate_html("report.html")
    """
    
    def __init__(
        self,
        metadata: Optional[ReportMetadata] = None,
        output_dir: str = "scans"
    ):
        self.metadata = metadata or ReportMetadata()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.findings: List[FindingReport] = []
        self.statistics: Optional[ScanStatistics] = None
    
    def add_finding(self, finding: FindingReport) -> None:
        """Add a finding to the report"""
        self.findings.append(finding)
        self._update_statistics()
    
    def add_findings(self, findings: List[FindingReport]) -> None:
        """Add multiple findings"""
        self.findings.extend(findings)
        self._update_statistics()
    
    def set_statistics(self, stats: ScanStatistics) -> None:
        """Set scan statistics"""
        self.statistics = stats
    
    def _update_statistics(self) -> None:
        """Update statistics based on current findings"""
        if self.statistics is None:
            self.statistics = ScanStatistics()
        
        self.statistics.critical_count = sum(1 for f in self.findings if f.severity.lower() == "critical")
        self.statistics.high_count = sum(1 for f in self.findings if f.severity.lower() == "high")
        self.statistics.medium_count = sum(1 for f in self.findings if f.severity.lower() == "medium")
        self.statistics.low_count = sum(1 for f in self.findings if f.severity.lower() == "low")
        self.statistics.info_count = sum(1 for f in self.findings if f.severity.lower() == "info")
    
    def _get_overall_risk(self) -> tuple:
        """Calculate overall risk level"""
        if self.statistics.critical_count > 0:
            return "critical", "CRITICAL"
        elif self.statistics.high_count > 0:
            return "high", "HIGH"
        elif self.statistics.medium_count > 0:
            return "medium", "MEDIUM"
        elif self.statistics.low_count > 0:
            return "low", "LOW"
        return "info", "INFO"
    
    def _get_risk_summary(self) -> str:
        """Generate risk summary text"""
        risk_level, _ = self._get_overall_risk()
        summaries = {
            "critical": "Critical vulnerabilities require immediate attention. System compromise is possible.",
            "high": "High severity vulnerabilities pose significant risk. Prioritize remediation.",
            "medium": "Medium severity issues should be addressed in the near term.",
            "low": "Low severity findings should be addressed as part of regular maintenance.",
            "info": "Only informational findings. Reasonable security posture observed.",
        }
        return summaries.get(risk_level, "Security assessment completed.")
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{seconds:.2f}s"
        elif seconds < 3600:
            return f"{int(seconds/60)}m {int(seconds%60)}s"
        return f"{int(seconds/3600)}h {int((seconds%3600)/60)}m"
    
    # =========================================================================
    # HTML GENERATION
    # =========================================================================
    
    def generate_html(self, filepath: Optional[str] = None) -> str:
        """Generate HTML report"""
        if self.statistics is None:
            self._update_statistics()
        
        overall_risk, overall_risk_label = self._get_overall_risk()
        findings_html = self._generate_findings_html()
        
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(self.metadata.title)}</title>
    <style>
        :root {{
            --bg-primary: #0a0a0a; --bg-secondary: #1a1a2e; --bg-card: #16213e;
            --text-primary: #e0e0e0; --text-secondary: #a0a0a0;
            --accent: #00d4ff; --border: #333;
            --critical: #9b59b6; --high: #e74c3c; --medium: #f39c12; --low: #3498db; --info: #1abc9c;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg-primary); color: var(--text-primary); line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        .header {{ background: linear-gradient(135deg, var(--bg-secondary), var(--bg-card)); padding: 3rem 2rem; border-radius: 12px; margin-bottom: 2rem; border: 1px solid var(--border); text-align: center; }}
        .header h1 {{ font-size: 2.5rem; background: linear-gradient(90deg, var(--accent), #7b2cbf); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .header .meta {{ display: flex; justify-content: center; gap: 2rem; flex-wrap: wrap; color: var(--text-secondary); margin-top: 1rem; }}
        .confidential {{ background: var(--high); color: white; padding: 0.25rem 1rem; border-radius: 4px; font-weight: bold; font-size: 0.8rem; margin-top: 1rem; display: inline-block; }}
        .section {{ background: var(--bg-secondary); border-radius: 12px; padding: 2rem; margin-bottom: 2rem; border: 1px solid var(--border); }}
        .section-title {{ font-size: 1.5rem; color: var(--accent); margin-bottom: 1.5rem; border-bottom: 2px solid var(--border); padding-bottom: 0.5rem; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
        .summary-card {{ background: var(--bg-card); padding: 1.5rem; border-radius: 8px; text-align: center; border: 1px solid var(--border); }}
        .summary-card .value {{ font-size: 2.5rem; font-weight: bold; }}
        .summary-card .label {{ color: var(--text-secondary); }}
        .summary-card.critical .value {{ color: var(--critical); }}
        .summary-card.high .value {{ color: var(--high); }}
        .summary-card.medium .value {{ color: var(--medium); }}
        .summary-card.low .value {{ color: var(--low); }}
        .summary-card.info .value {{ color: var(--info); }}
        .risk-box {{ display: flex; align-items: center; gap: 1rem; padding: 1.5rem; background: var(--bg-card); border-radius: 8px; margin: 1.5rem 0; }}
        .risk-gauge {{ width: 80px; height: 80px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; color: white; }}
        .risk-gauge.critical {{ background: var(--critical); }}
        .risk-gauge.high {{ background: var(--high); }}
        .risk-gauge.medium {{ background: var(--medium); }}
        .risk-gauge.low {{ background: var(--low); }}
        .risk-gauge.info {{ background: var(--info); }}
        .finding {{ background: var(--bg-card); border-radius: 8px; margin-bottom: 1.5rem; border: 1px solid var(--border); overflow: hidden; }}
        .finding-header {{ padding: 1rem 1.5rem; background: rgba(0,0,0,0.2); display: flex; align-items: center; gap: 1rem; border-bottom: 1px solid var(--border); }}
        .severity-badge {{ padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; color: white; }}
        .severity-badge.critical {{ background: var(--critical); }}
        .severity-badge.high {{ background: var(--high); }}
        .severity-badge.medium {{ background: var(--medium); }}
        .severity-badge.low {{ background: var(--low); }}
        .severity-badge.info {{ background: var(--info); }}
        .finding-title {{ font-weight: 600; }}
        .finding-id {{ margin-left: auto; color: var(--text-secondary); font-family: monospace; }}
        .finding-body {{ padding: 1.5rem; }}
        .finding-meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; padding: 1rem; background: rgba(0,0,0,0.2); border-radius: 4px; }}
        .finding-meta-item .label {{ color: var(--text-secondary); font-size: 0.8rem; }}
        .finding-meta-item .value {{ font-family: monospace; word-break: break-all; }}
        .finding-section {{ margin-bottom: 1.5rem; }}
        .finding-section h4 {{ color: var(--accent); margin-bottom: 0.75rem; }}
        .code-block {{ background: #0d0d0d; border: 1px solid var(--border); border-radius: 4px; padding: 1rem; font-family: monospace; font-size: 0.85rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
        .evidence-box {{ background: rgba(0,212,255,0.1); border: 1px solid var(--accent); border-radius: 4px; padding: 1rem; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background: var(--bg-card); color: var(--accent); }}
        .references {{ list-style: none; }}
        .references li {{ padding: 0.5rem 0; border-bottom: 1px solid var(--border); }}
        .references a {{ color: var(--accent); text-decoration: none; }}
        .footer {{ text-align: center; padding: 2rem; color: var(--text-secondary); border-top: 1px solid var(--border); margin-top: 2rem; }}
        .disclaimer {{ background: rgba(231,76,60,0.1); border: 1px solid var(--high); padding: 1rem; border-radius: 8px; margin-bottom: 2rem; }}
        .disclaimer strong {{ color: var(--high); }}
        @media print {{ body {{ background: white; color: black; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{html.escape(self.metadata.title)}</h1>
            <div class="meta">
                <span><strong>Target:</strong> {html.escape(self.metadata.target)}</span>
                <span><strong>Date:</strong> {html.escape(self.metadata.report_date)}</span>
                <span><strong>Scan ID:</strong> {html.escape(self.metadata.scan_id)}</span>
            </div>
            <span class="confidential">{html.escape(self.metadata.confidentiality)}</span>
        </div>
        
        <div class="disclaimer">
            <strong>â ï¸ Legal Disclaimer:</strong> This report is for authorized security testing only. Unauthorized access is illegal.
        </div>
        
        <div class="section">
            <h2 class="section-title">Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card critical"><div class="value">{self.statistics.critical_count}</div><div class="label">Critical</div></div>
                <div class="summary-card high"><div class="value">{self.statistics.high_count}</div><div class="label">High</div></div>
                <div class="summary-card medium"><div class="value">{self.statistics.medium_count}</div><div class="label">Medium</div></div>
                <div class="summary-card low"><div class="value">{self.statistics.low_count}</div><div class="label">Low</div></div>
                <div class="summary-card info"><div class="value">{self.statistics.info_count}</div><div class="label">Info</div></div>
            </div>
            <div class="risk-box">
                <div class="risk-gauge {overall_risk}">{overall_risk_label}</div>
                <div><h3>Overall Risk</h3><p>{self._get_risk_summary()}</p></div>
            </div>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Total Requests</td><td>{self.statistics.total_requests}</td></tr>
                <tr><td>Duration</td><td>{self._format_duration(self.statistics.duration_seconds)}</td></tr>
                <tr><td>Total Findings</td><td>{self.statistics.total_findings}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2 class="section-title">Detailed Findings</h2>
            {findings_html}
        </div>
        
        <div class="footer">
            <p>Generated by <strong>REVUEX</strong> v{REVUEX_VERSION}</p>
        </div>
    </div>
</body>
</html>'''
        
        if filepath:
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)
        
        return html_content
    
    def _generate_findings_html(self) -> str:
        """Generate HTML for all findings"""
        if not self.findings:
            return '<p style="color: var(--text-secondary);">No vulnerabilities identified.</p>'
        
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(self.findings, key=lambda f: severity_order.get(f.severity.lower(), 5))
        
        findings_html = []
        for finding in sorted_findings:
            payload_section = f'<div class="finding-section"><h4>Payload</h4><div class="code-block">{html.escape(finding.payload)}</div></div>' if finding.payload else ""
            evidence_section = f'<div class="finding-section"><h4>Evidence</h4><div class="evidence-box"><div class="code-block">{html.escape(finding.evidence[:1000])}</div></div></div>' if finding.evidence else ""
            refs_html = "".join(f'<li><a href="{r}" target="_blank">{r}</a></li>' for r in finding.references)
            references_section = f'<div class="finding-section"><h4>References</h4><ul class="references">{refs_html}</ul></div>' if finding.references else ""
            
            findings_html.append(f'''<div class="finding">
    <div class="finding-header">
        <span class="severity-badge {finding.severity.lower()}">{finding.severity.upper()}</span>
        <span class="finding-title">{html.escape(finding.title)}</span>
        <span class="finding-id">#{finding.id}</span>
    </div>
    <div class="finding-body">
        <div class="finding-meta">
            <div class="finding-meta-item"><span class="label">URL</span><span class="value">{html.escape(finding.url)}</span></div>
            <div class="finding-meta-item"><span class="label">Parameter</span><span class="value">{html.escape(finding.parameter or 'N/A')}</span></div>
            <div class="finding-meta-item"><span class="label">Method</span><span class="value">{finding.method}</span></div>
            <div class="finding-meta-item"><span class="label">CWE</span><span class="value">{finding.cwe_id or 'N/A'}</span></div>
        </div>
        <div class="finding-section"><h4>Description</h4><p>{html.escape(finding.description)}</p></div>
        {payload_section}
        {evidence_section}
        <div class="finding-section"><h4>Impact</h4><p>{html.escape(finding.impact or 'See description.')}</p></div>
        <div class="finding-section"><h4>Remediation</h4><p>{html.escape(finding.remediation or 'Consult security best practices.')}</p></div>
        {references_section}
    </div>
</div>''')
        
        return "\n".join(findings_html)
    
    # =========================================================================
    # JSON GENERATION
    # =========================================================================
    
    def generate_json(self, filepath: Optional[str] = None) -> str:
        """Generate JSON report"""
        if self.statistics is None:
            self._update_statistics()
        
        report_data = {
            "metadata": asdict(self.metadata),
            "statistics": self.statistics.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "total_findings": len(self.findings),
                "overall_risk": self._get_overall_risk()[0],
            }
        }
        
        json_content = json.dumps(report_data, indent=2, default=str)
        
        if filepath:
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(json_content)
        
        return json_content
    
    # =========================================================================
    # MARKDOWN GENERATION
    # =========================================================================
    
    def generate_markdown(self, filepath: Optional[str] = None) -> str:
        """Generate Markdown report"""
        if self.statistics is None:
            self._update_statistics()
        
        overall_risk, overall_risk_label = self._get_overall_risk()
        
        lines = [
            f"# {self.metadata.title}",
            f"\n**Target:** {self.metadata.target}  ",
            f"**Scan ID:** {self.metadata.scan_id}  ",
            f"**Date:** {self.metadata.report_date}",
            "\n---\n",
            "## Executive Summary\n",
            "| Severity | Count |",
            "|----------|-------|",
            f"| Critical | {self.statistics.critical_count} |",
            f"| High | {self.statistics.high_count} |",
            f"| Medium | {self.statistics.medium_count} |",
            f"| Low | {self.statistics.low_count} |",
            f"| Info | {self.statistics.info_count} |",
            f"\n**Overall Risk:** {overall_risk_label}\n",
            "\n---\n",
            "## Findings\n",
        ]
        
        if not self.findings:
            lines.append("*No vulnerabilities identified.*\n")
        else:
            for i, f in enumerate(self.findings, 1):
                lines.extend([
                    f"### {i}. {f.title}",
                    f"\n**Severity:** {f.severity.upper()}  ",
                    f"**URL:** `{f.url}`  ",
                    f"**Parameter:** `{f.parameter or 'N/A'}`  ",
                    f"**CWE:** {f.cwe_id or 'N/A'}\n",
                    f"#### Description\n{f.description}\n",
                ])
                if f.payload:
                    lines.extend(["#### Payload", f"```\n{f.payload}\n```\n"])
                if f.evidence:
                    lines.extend(["#### Evidence", f"```\n{f.evidence[:500]}\n```\n"])
                lines.extend([
                    f"#### Impact\n{f.impact or 'See description.'}\n",
                    f"#### Remediation\n{f.remediation or 'Consult security best practices.'}\n",
                    "---\n",
                ])
        
        lines.append(f"\n*Generated by REVUEX v{REVUEX_VERSION}*")
        md_content = "\n".join(lines)
        
        if filepath:
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(md_content)
        
        return md_content
    
    # =========================================================================
    # BATCH GENERATION
    # =========================================================================
    
    def generate_all(self, base_name: Optional[str] = None, formats: List[str] = ["html", "json", "md"]) -> Dict[str, str]:
        """Generate reports in multiple formats"""
        if base_name is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = self.metadata.target_domain or "report"
            base_name = f"revuex_{domain}_{timestamp}"
        
        output_paths = {}
        for fmt in formats:
            filepath = self.output_dir / f"{base_name}.{fmt}"
            if fmt == "html":
                self.generate_html(filepath)
            elif fmt == "json":
                self.generate_json(filepath)
            elif fmt == "md":
                self.generate_markdown(filepath)
            output_paths[fmt] = str(filepath)
        
        return output_paths


# =============================================================================
# CONVENIENCE FUNCTION
# =============================================================================

def create_report(findings: List[Dict], target: str, scan_id: str = "", output_dir: str = "scans", formats: List[str] = ["html", "json"]) -> Dict[str, str]:
    """Quick report generation from findings list"""
    from urllib.parse import urlparse
    domain = urlparse(target).netloc or target
    
    metadata = ReportMetadata(
        title="Security Assessment Report",
        target=target,
        target_domain=domain,
        scan_id=scan_id or hashlib.md5(target.encode()).hexdigest()[:12],
    )
    
    generator = ReportGenerator(metadata=metadata, output_dir=output_dir)
    
    for fd in findings:
        finding = FindingReport(
            id=fd.get("id", hashlib.md5(str(fd).encode()).hexdigest()[:8]),
            title=fd.get("title", "Finding"),
            severity=fd.get("severity", "info"),
            description=fd.get("description", ""),
            url=fd.get("url", ""),
            parameter=fd.get("parameter", ""),
            payload=fd.get("payload", ""),
            evidence=fd.get("evidence", ""),
            impact=fd.get("impact", ""),
            remediation=fd.get("remediation", ""),
            vulnerability_type=fd.get("vulnerability_type", ""),
        )
        generator.add_finding(finding)
    
    return generator.generate_all(formats=formats)


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "ReportGenerator",
    "ReportMetadata",
    "FindingReport",
    "ScanStatistics",
    "create_report",
    "SEVERITY_COLORS",
    "OWASP_TOP_10",
    "VULN_CLASSIFICATION",
]
