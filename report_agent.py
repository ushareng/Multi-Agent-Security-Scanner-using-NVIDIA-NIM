"""
agents/report_agent.py
Report Agent — aggregates all findings, dependency CVEs, and metadata
into a structured JSON report and a human-readable markdown report.
"""

import json
import os
from datetime import datetime
from dataclasses import asdict
from memory_store import MemoryStore


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


class ReportAgent:
    def __init__(self, store: MemoryStore):
        self.store = store
        self.output_dir = os.getenv("OUTPUT_DIR", "./output")
        os.makedirs(self.output_dir, exist_ok=True)

    def run(self) -> dict:
        """Generate JSON + Markdown reports. Returns report summary dict."""
        print("[Report] Generating final audit reports...")

        confirmed = self.store.get_confirmed_findings()
        confirmed.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 4))

        # Build summary
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in confirmed:
            if f.severity in severity_counts:
                severity_counts[f.severity] += 1

        exploitable_count = sum(1 for f in confirmed if f.poc_result == "EXPLOITABLE")
        dep_cves = {k: v for k, v in self.store.known_cves.items() if v}

        report = {
            "report_generated": datetime.utcnow().isoformat(),
            "summary": {
                "files_scanned": self.store.scan_metadata["files_scanned"],
                "total_candidates": self.store.scan_metadata["total_candidates"],
                "confirmed_findings": len(confirmed),
                "false_positives_eliminated": self.store.scan_metadata["false_positives_eliminated"],
                "findings_with_working_poc": exploitable_count,
                "severity_breakdown": severity_counts,
                "vulnerable_dependencies": len(dep_cves),
                "nim_api_calls": 0,  # updated below
            },
            "findings": [self._serialize_finding(f) for f in confirmed],
            "vulnerable_dependencies": dep_cves,
        }

        # Write JSON report
        json_path = os.path.join(self.output_dir, "audit_report.json")
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)

        # Write Markdown report
        md_path = os.path.join(self.output_dir, "audit_report.md")
        with open(md_path, "w") as f:
            f.write(self._generate_markdown(report, confirmed, dep_cves))

        print(f"[Report] Reports saved:")
        print(f"  JSON: {json_path}")
        print(f"  Markdown: {md_path}")

        return report["summary"]

    def _serialize_finding(self, f) -> dict:
        d = asdict(f)
        # Trim raw_code to avoid bloating report
        if len(d.get("raw_code", "")) > 500:
            d["raw_code"] = d["raw_code"][:500] + "\n... [truncated]"
        return d

    def _generate_markdown(self, report: dict, confirmed: list, dep_cves: dict) -> str:
        s = report["summary"]
        lines = [
            "# Code Audit Report",
            f"**Generated:** {report['report_generated']}",
            "",
            "## Executive Summary",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Files Scanned | {s['files_scanned']} |",
            f"| Raw Candidates | {s['total_candidates']} |",
            f"| False Positives Eliminated | {s['false_positives_eliminated']} |",
            f"| Confirmed Findings | {s['confirmed_findings']} |",
            f"| With Working PoC | {s['findings_with_working_poc']} |",
            f"| Vulnerable Dependencies | {s['vulnerable_dependencies']} |",
            "",
            "## Severity Breakdown",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev, count in s["severity_breakdown"].items():
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
            lines.append(f"| {emoji} {sev} | {count} |")

        lines += ["", "---", "", "## Confirmed Findings", ""]

        for i, finding in enumerate(confirmed, 1):
            sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(finding.severity, "⚪")
            poc_badge = "✅ PoC Confirmed" if finding.poc_result == "EXPLOITABLE" else f"⚠️ {finding.poc_result}"

            lines += [
                f"### {i}. {sev_emoji} {finding.vuln_type}",
                f"**File:** `{finding.filename}` | **Location:** {finding.location}",
                f"**Severity:** {finding.severity} | **CWE:** {finding.cwe_id} | **PoC:** {poc_badge}",
                "",
                f"**Reasoning:**",
                f"> {finding.reasoning}",
                "",
            ]

            if finding.classification and isinstance(finding.classification, dict):
                cvss = finding.classification.get("cvss_score") or finding.classification.get("cvss", "")
                cwe_name = finding.classification.get("cwe_name") or finding.classification.get("CWE_name", "")
                if cvss:
                    lines.append(f"**CVSS Score:** {cvss}")
                if cwe_name:
                    lines.append(f"**CWE Name:** {cwe_name}")
                lines.append("")

            if finding.raw_code:
                snippet = finding.raw_code[:300] + ("..." if len(finding.raw_code) > 300 else "")
                lines += [
                    "**Vulnerable Code:**",
                    f"```",
                    snippet,
                    "```",
                    "",
                ]

            if finding.remediation:
                lines += [
                    "**Remediation:**",
                    f"```",
                    finding.remediation[:600],
                    "```",
                    "",
                ]

            lines.append("---")
            lines.append("")

        # Vulnerable dependencies section
        if dep_cves:
            lines += ["## Vulnerable Dependencies", ""]
            lines += ["| Package | CVE | Severity | Summary |", "|---------|-----|----------|---------|"]
            for pkg, vulns in dep_cves.items():
                for vuln in vulns[:3]:  # Cap at 3 CVEs per package
                    lines.append(
                        f"| {pkg} | {vuln.get('id', 'N/A')} | {vuln.get('severity', 'UNKNOWN')} | "
                        f"{vuln.get('summary', '')[:80]} |"
                    )
            lines.append("")

        return "\n".join(lines)
