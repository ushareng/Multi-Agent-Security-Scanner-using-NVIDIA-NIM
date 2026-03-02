"""
agents/classification_agent.py
Classification Agent — uses NIM to generate structured CWE taxonomy,
CVSS v3.1 scoring, and remediation code for each proven finding.
"""

import json
import re
import time
from memory_store import MemoryStore, Finding
from nim_client import NIMClient


class ClassificationAgent:
    def __init__(self, store: MemoryStore, nim_client: NIMClient):
        self.store = store
        self.nim = nim_client

    def run(self, findings: list[Finding]) -> list[Finding]:
        """
        Classify and generate remediation for each finding.
        Updates store with structured classification data.
        """
        print(f"[Classification] Classifying {len(findings)} findings via NIM...")

        for i, finding in enumerate(findings):
            print(f"[Classification] [{i+1}/{len(findings)}] Classifying: {finding.vuln_type}")

            raw_classification = self.nim.classify_and_remediate(
                finding=f"""
Vulnerability Type: {finding.vuln_type}
CWE Candidate: {finding.cwe_id}
Severity Estimate: {finding.severity}
Location: {finding.filename} @ {finding.location}
PoC Result: {finding.poc_result}
Original Reasoning: {finding.reasoning}
""",
                code=finding.raw_code,
            )

            classification, remediation = self._parse_classification(raw_classification)
            self.store.update_classification(finding.id, classification, remediation)
            finding.classification = classification
            finding.remediation = remediation

            time.sleep(0.5)

        print(f"[Classification] Done.")
        return findings

    def _parse_classification(self, nim_response: str) -> tuple[dict, str]:
        """Parse NIM JSON response into classification dict and remediation string."""
        # Try to extract JSON block
        json_match = re.search(r"\{.*\}", nim_response, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group())
                remediation = data.pop("remediation", "See full response for remediation details.")
                return data, remediation
            except json.JSONDecodeError:
                pass

        # Fallback: return raw response as unstructured classification
        return {"raw": nim_response}, self._extract_remediation_fallback(nim_response)

    def _extract_remediation_fallback(self, text: str) -> str:
        """Extract remediation section from plain text NIM response."""
        lines = text.splitlines()
        remediation_lines = []
        in_remediation = False
        for line in lines:
            if "remediation" in line.lower() or "fix" in line.lower() or "mitigation" in line.lower():
                in_remediation = True
            if in_remediation:
                remediation_lines.append(line)
        return "\n".join(remediation_lines) if remediation_lines else text[:500]
