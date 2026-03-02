"""
core/nim_client.py
Handles all NVIDIA NIM API interactions using OpenAI-compatible interface.
NIM free tier: https://build.nvidia.com
"""

import os
import time
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()


class NIMClient:
    def __init__(self):
        api_key = os.getenv("NVIDIA_API_KEY")
        if not api_key or api_key == "nvapi-YOUR_KEY_HERE":
            raise ValueError(
                "NVIDIA_API_KEY not set. Get your free key from https://build.nvidia.com"
            )
        self.client = OpenAI(
            base_url=os.getenv("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1"),
            api_key=api_key,
        )
        self.model = os.getenv("NIM_MODEL", "meta/codellama-70b-instruct")
        self.request_count = 0

    def reason(self, system_prompt: str, user_prompt: str, max_tokens: int = 2048) -> str:
        """
        Core reasoning call to NIM. Used by all agents.
        Returns the model response as plain text.
        """
        self.request_count += 1
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=max_tokens,
                temperature=0.1,  # Low temp for deterministic security analysis
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            # Rate limit handling for free tier
            if "429" in str(e) or "rate" in str(e).lower():
                print(f"[NIM] Rate limit hit, waiting 30s... (request #{self.request_count})")
                time.sleep(30)
                return self.reason(system_prompt, user_prompt, max_tokens)
            raise RuntimeError(f"NIM API error: {e}")

    def analyze_code_chunk(self, code: str, filename: str) -> str:
        """Semantic vulnerability analysis on a code chunk."""
        system = (
            "You are an expert security researcher specializing in finding vulnerabilities. "
            "Analyze code for security issues including injection flaws, auth bypasses, "
            "insecure deserialization, path traversal, SSRF, XXE, and logic errors. "
            "Be precise. Only report actual vulnerabilities, not theoretical ones. "
            "For each finding, state: VULN_TYPE, LOCATION (line/function), SEVERITY, "
            "REASONING (why it is exploitable), CWE_ID."
        )
        user = f"File: {filename}\n\nAnalyze this code for vulnerabilities:\n\n```\n{code}\n```"
        return self.reason(system, user, max_tokens=1500)

    def validate_finding(self, code: str, finding: str, context: str) -> str:
        """
        Second-pass validation — eliminates false positives.
        Asks NIM to confirm if a finding is actually exploitable given full context.
        """
        system = (
            "You are a senior security engineer performing false positive triage. "
            "Given a vulnerability finding and the surrounding code context, determine: "
            "1. Is this genuinely exploitable? "
            "2. Are there compensating controls that mitigate it? "
            "3. What is the actual attack path? "
            "Respond with: CONFIRMED or FALSE_POSITIVE, followed by your reasoning."
        )
        user = (
            f"Finding:\n{finding}\n\n"
            f"Surrounding context:\n```\n{context}\n```\n\n"
            f"Vulnerable code:\n```\n{code}\n```"
        )
        return self.reason(system, user, max_tokens=1000)

    def generate_poc(self, finding: str, code: str, language: str) -> str:
        """
        Generate a Proof of Concept exploit for a confirmed vulnerability.
        PoC is used to prove exploitability — not for actual attacks.
        """
        system = (
            "You are a security researcher generating proof-of-concept exploit code "
            "to verify vulnerability findings in a controlled sandbox. "
            "Generate minimal, self-contained PoC code that demonstrates the vulnerability. "
            "The PoC must be executable in an isolated environment. "
            "Include: exploit code, expected output if successful, and what it proves."
        )
        user = (
            f"Language: {language}\n"
            f"Vulnerability:\n{finding}\n\n"
            f"Vulnerable code:\n```\n{code}\n```\n\n"
            "Generate PoC exploit code."
        )
        return self.reason(system, user, max_tokens=1500)

    def classify_and_remediate(self, finding: str, code: str) -> str:
        """
        Generate CWE classification, CVSS score, and remediation guidance.
        """
        system = (
            "You are a vulnerability classification expert. "
            "Given a confirmed vulnerability, provide: "
            "1. CWE-ID and CWE name "
            "2. CVSS v3.1 score and vector string "
            "3. Severity: CRITICAL/HIGH/MEDIUM/LOW "
            "4. Exact remediation — provide the fixed code snippet. "
            "5. References to relevant security standards (OWASP, NIST). "
            "Format as structured JSON."
        )
        user = f"Finding:\n{finding}\n\nCode:\n```\n{code}\n```"
        return self.reason(system, user, max_tokens=1200)
