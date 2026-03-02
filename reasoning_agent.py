"""
agents/reasoning_agent.py
LLM Reasoning Agent — the core NIM-powered semantic validation layer.
Takes static scan candidates, uses NIM to validate each one:
- Is the code path actually reachable?
- Are there compensating controls?
- What is the real attack path?
Eliminates false positives before PoC generation.
"""

import time
from memory_store import MemoryStore, Finding
from nim_client import NIMClient
from llm_guard.input_scanners import PromptInjection, Toxicity
from llm_guard.output_scanners import Relevance


class ReasoningAgent:
    def __init__(self, store: MemoryStore, nim_client: NIMClient):
        self.store = store
        self.nim = nim_client
        # LLM Guard scanners — input protection before NIM calls
        try:
            self.injection_scanner = PromptInjection()
            self.toxicity_scanner = Toxicity()
            self.guard_available = True
        except Exception:
            print("[Reasoning] Warning: LLM Guard not available, running without input scanning")
            self.guard_available = False

    def run(self, candidates: list[Finding]) -> list[Finding]:
        """
        Validate each candidate finding through NIM semantic reasoning.
        Returns confirmed findings only.
        """
        print(f"[Reasoning] Validating {len(candidates)} candidates via NIM...")
        confirmed = []

        for i, finding in enumerate(candidates):
            print(f"[Reasoning] [{i+1}/{len(candidates)}] Validating: {finding.vuln_type} in {finding.filename}")

            # Guard: scan code before sending to NIM
            code_to_send = self._guard_input(finding.raw_code)
            if code_to_send is None:
                print(f"[Reasoning] Skipped {finding.id} — input guard flagged malicious content")
                self.store.dismiss_finding(finding.id)
                continue

            # Get broader file context (up to 50 lines around finding)
            context = self._get_file_context(finding.filename, finding.location)

            # NIM validation call
            validation = self.nim.validate_finding(
                code=finding.raw_code,
                finding=f"Type: {finding.vuln_type}\nCWE: {finding.cwe_id}\nReasoning: {finding.reasoning}",
                context=context,
            )

            if self._is_confirmed(validation):
                self.store.confirm_finding(finding.id, validation)
                finding.validation_status = "CONFIRMED"
                confirmed.append(finding)
                print(f"[Reasoning] ✓ CONFIRMED: {finding.vuln_type}")
            else:
                self.store.dismiss_finding(finding.id)
                print(f"[Reasoning] ✗ FALSE POSITIVE dismissed: {finding.vuln_type}")

            # Be polite to NIM free tier
            time.sleep(0.5)

        print(f"[Reasoning] Validation complete: {len(confirmed)} confirmed, "
              f"{len(candidates) - len(confirmed)} dismissed as false positives")
        return confirmed

    def _guard_input(self, code: str) -> str | None:
        """
        Run LLM Guard on code before sending to NIM.
        Returns sanitized code or None if malicious.
        """
        if not self.guard_available:
            return code
        try:
            sanitized, results_valid = self.injection_scanner.scan(None, code)
            if not results_valid:
                return None
            return sanitized
        except Exception:
            return code  # If guard fails, pass through (don't block analysis)

    def _get_file_context(self, filepath: str, location: str) -> str:
        """
        Read surrounding lines from actual file for richer context.
        Falls back to empty string if file not accessible.
        """
        try:
            # Extract line number from location string like "line 42"
            line_num = int(location.replace("line", "").strip())
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            start = max(0, line_num - 25)
            end = min(len(lines), line_num + 25)
            return "".join(lines[start:end])
        except Exception:
            return ""

    def _is_confirmed(self, validation_text: str) -> bool:
        """
        Parse NIM's validation response.
        Looks for CONFIRMED or FALSE_POSITIVE signal.
        """
        upper = validation_text.upper()
        if "FALSE_POSITIVE" in upper or "FALSE POSITIVE" in upper:
            return False
        if "CONFIRMED" in upper or "EXPLOITABLE" in upper or "VULNERABLE" in upper:
            return True
        # Ambiguous — use heuristic: if reasoning is long and detailed, lean confirmed
        if len(validation_text) > 300 and "compensating" not in upper:
            return True
        return False
