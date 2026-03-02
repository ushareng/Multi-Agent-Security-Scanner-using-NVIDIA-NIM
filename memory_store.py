"""
core/memory_store.py
Shared in-memory state store used by all agents in the pipeline.
Tracks findings, dependency graph, file index, and PoC results.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime


@dataclass
class Finding:
    id: str
    filename: str
    vuln_type: str
    severity: str                      # CRITICAL / HIGH / MEDIUM / LOW
    location: str                      # function or line reference
    reasoning: str
    cwe_id: str
    raw_code: str
    validation_status: str = "PENDING"  # PENDING / CONFIRMED / FALSE_POSITIVE
    poc_code: str = ""
    poc_result: str = ""               # EXPLOITABLE / NOT_EXPLOITABLE / ERROR
    classification: dict = field(default_factory=dict)
    remediation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class MemoryStore:
    def __init__(self):
        self.findings: dict[str, Finding] = {}
        self.dependency_graph: dict = {}        # pkg -> [transitive deps]
        self.known_cves: dict = {}              # pkg_version -> [CVE ids]
        self.file_index: dict = {}              # filename -> {hash, language, size}
        self.scan_metadata: dict = {
            "start_time": datetime.utcnow().isoformat(),
            "files_scanned": 0,
            "total_candidates": 0,
            "confirmed_findings": 0,
            "false_positives_eliminated": 0,
        }

    def add_finding(self, finding: Finding):
        self.findings[finding.id] = finding
        self.scan_metadata["total_candidates"] += 1

    def confirm_finding(self, finding_id: str, validation_text: str):
        if finding_id in self.findings:
            self.findings[finding_id].validation_status = "CONFIRMED"
            self.scan_metadata["confirmed_findings"] += 1

    def dismiss_finding(self, finding_id: str):
        if finding_id in self.findings:
            self.findings[finding_id].validation_status = "FALSE_POSITIVE"
            self.scan_metadata["false_positives_eliminated"] += 1

    def update_poc(self, finding_id: str, poc_code: str, poc_result: str):
        if finding_id in self.findings:
            self.findings[finding_id].poc_code = poc_code
            self.findings[finding_id].poc_result = poc_result

    def update_classification(self, finding_id: str, classification: dict, remediation: str):
        if finding_id in self.findings:
            self.findings[finding_id].classification = classification
            self.findings[finding_id].remediation = remediation

    def get_confirmed_findings(self) -> list[Finding]:
        return [f for f in self.findings.values() if f.validation_status == "CONFIRMED"]

    def save_to_disk(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        store_path = os.path.join(output_dir, "memory_store.json")
        data = {
            "metadata": self.scan_metadata,
            "findings": {k: asdict(v) for k, v in self.findings.items()},
            "dependency_graph": self.dependency_graph,
            "known_cves": self.known_cves,
        }
        with open(store_path, "w") as f:
            json.dump(data, f, indent=2)
        return store_path
