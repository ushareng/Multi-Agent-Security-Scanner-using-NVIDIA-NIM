"""
agents/static_scan_agent.py
Static Scan Agent — fast pattern-based and taint analysis pass.
No LLM calls here — this is the cheap, high-recall first pass.
Generates candidate findings that are then validated by the LLM Reasoning Agent.
"""

import re
import uuid
from memory_store import MemoryStore, Finding

# Vulnerability patterns per language
# Format: (regex_pattern, vuln_type, cwe_id, severity, description)
PATTERNS = {
    "python": [
        (r"eval\s*\(", "Code Injection via eval()", "CWE-95", "HIGH",
         "Direct use of eval() with potentially user-controlled input"),
        (r"exec\s*\(", "Code Injection via exec()", "CWE-95", "HIGH",
         "Direct use of exec() with potentially user-controlled input"),
        (r"subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True", "Command Injection", "CWE-78", "CRITICAL",
         "subprocess with shell=True allows command injection"),
        (r"os\.system\s*\(", "Command Injection via os.system()", "CWE-78", "HIGH",
         "os.system() passes command to shell, injectable"),
        (r"pickle\.loads?\s*\(", "Insecure Deserialization", "CWE-502", "HIGH",
         "pickle.load/loads with untrusted data leads to RCE"),
        (r"yaml\.load\s*\([^,)]+\)", "Unsafe YAML Load", "CWE-502", "HIGH",
         "yaml.load without Loader=yaml.SafeLoader is unsafe"),
        (r"(password|secret|api_key|token)\s*=\s*['\"][^'\"]{6,}['\"]", "Hardcoded Secret", "CWE-798", "HIGH",
         "Credentials hardcoded in source code"),
        (r"hashlib\.md5\s*\(|hashlib\.sha1\s*\(", "Weak Cryptographic Hash", "CWE-327", "MEDIUM",
         "MD5/SHA1 are cryptographically broken"),
        (r"random\.(random|randint|choice)\s*\(", "Insecure Randomness", "CWE-338", "MEDIUM",
         "random module is not cryptographically secure"),
        (r"open\s*\([^)]*['\"]w['\"]", "File Write without Path Validation", "CWE-73", "MEDIUM",
         "File write operation — check if path is user-controlled"),
        (r"request\.(args|form|json|data|values)\[", "Unvalidated User Input", "CWE-20", "MEDIUM",
         "Direct use of user input without validation — trace the data flow"),
        (r"\.format\s*\(\s*request\.|f['\"].*\{request\.", "Potential SSTI", "CWE-94", "HIGH",
         "String formatting with request data can lead to SSTI"),
        (r"SELECT.+FROM.+WHERE.+\+|execute\(.+\+", "SQL Injection Risk", "CWE-89", "CRITICAL",
         "String concatenation in SQL query — use parameterized queries"),
        (r"verify\s*=\s*False", "SSL Verification Disabled", "CWE-295", "HIGH",
         "SSL certificate verification explicitly disabled"),
        (r"DEBUG\s*=\s*True", "Debug Mode Enabled", "CWE-215", "MEDIUM",
         "Debug mode exposes sensitive information"),
    ],
    "javascript": [
        (r"eval\s*\(", "Code Injection via eval()", "CWE-95", "HIGH",
         "eval() with potentially user-controlled input"),
        (r"innerHTML\s*=", "XSS via innerHTML", "CWE-79", "HIGH",
         "Direct assignment to innerHTML allows XSS"),
        (r"document\.write\s*\(", "XSS via document.write()", "CWE-79", "HIGH",
         "document.write with user input allows XSS"),
        (r"child_process|exec\s*\(|execSync\s*\(", "Command Injection", "CWE-78", "CRITICAL",
         "child_process execution with potentially untrusted input"),
        (r"(password|secret|api_key|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]", "Hardcoded Secret", "CWE-798", "HIGH",
         "Credentials hardcoded in source code"),
        (r"require\s*\(\s*req\.|require\s*\(\s*request\.", "Remote Code Execution Risk", "CWE-706", "CRITICAL",
         "Dynamic require() with user input allows RCE"),
        (r"JSON\.parse\s*\([^)]*req\.", "Unsafe JSON Parse", "CWE-502", "MEDIUM",
         "Parsing untrusted JSON — validate input schema"),
        (r"crypto\.createHash\s*\(['\"]md5['\"]|['\"]sha1['\"]", "Weak Cryptographic Hash", "CWE-327", "MEDIUM",
         "MD5/SHA1 are cryptographically broken"),
        (r"Math\.random\s*\(", "Insecure Randomness", "CWE-338", "MEDIUM",
         "Math.random() is not cryptographically secure"),
        (r"\.query\s*\([`'\"].*\$\{|\.query\s*\([`'\"].*\+", "SQL Injection Risk", "CWE-89", "CRITICAL",
         "Template literals or concatenation in SQL query"),
    ],
    "java": [
        (r"Runtime\.getRuntime\(\)\.exec\s*\(", "Command Injection", "CWE-78", "CRITICAL",
         "Runtime.exec() with potentially untrusted input"),
        (r"new\s+ProcessBuilder\s*\(", "Command Injection via ProcessBuilder", "CWE-78", "CRITICAL",
         "ProcessBuilder with potentially untrusted input"),
        (r"ObjectInputStream\s*\(", "Insecure Deserialization", "CWE-502", "CRITICAL",
         "Java deserialization via ObjectInputStream — RCE risk"),
        (r"(password|secret|apiKey)\s*=\s*['\"][^'\"]{6,}['\"]", "Hardcoded Secret", "CWE-798", "HIGH",
         "Credentials hardcoded in source"),
        (r"MessageDigest\.getInstance\s*\(['\"]MD5['\"]|['\"]SHA-1['\"]", "Weak Cryptographic Hash", "CWE-327", "MEDIUM",
         "MD5/SHA-1 are cryptographically broken"),
        (r"Statement\s+\w+\s*=.*createStatement|executeQuery\s*\([^)]*\+", "SQL Injection Risk", "CWE-89", "CRITICAL",
         "Non-parameterized SQL execution"),
        (r"\.printStackTrace\s*\(", "Information Disclosure via Stack Trace", "CWE-209", "LOW",
         "Stack traces expose internal structure to users"),
        (r"new\s+Random\s*\(", "Insecure Randomness", "CWE-338", "MEDIUM",
         "java.util.Random is not cryptographically secure — use SecureRandom"),
    ],
    "go": [
        (r"exec\.Command\s*\(", "Potential Command Injection", "CWE-78", "HIGH",
         "exec.Command — verify no user input reaches command args"),
        (r"(password|secret|apiKey)\s*:?=\s*['\"][^'\"]{6,}['\"]", "Hardcoded Secret", "CWE-798", "HIGH",
         "Credentials hardcoded in source"),
        (r"md5\.(New|Sum)|sha1\.(New|Sum)", "Weak Cryptographic Hash", "CWE-327", "MEDIUM",
         "MD5/SHA1 are cryptographically broken"),
        (r"fmt\.Sprintf.*SELECT|fmt\.Sprintf.*INSERT|fmt\.Sprintf.*UPDATE", "SQL Injection Risk", "CWE-89", "CRITICAL",
         "fmt.Sprintf for SQL construction is injectable"),
        (r"tls\.Config\{[^}]*InsecureSkipVerify\s*:\s*true", "TLS Verification Disabled", "CWE-295", "HIGH",
         "InsecureSkipVerify disables TLS cert validation"),
    ],
    "php": [
        (r"eval\s*\(", "Code Injection via eval()", "CWE-95", "HIGH",
         "eval() with potentially user-controlled input"),
        (r"system\s*\(|exec\s*\(|passthru\s*\(|shell_exec\s*\(", "Command Injection", "CWE-78", "CRITICAL",
         "Shell execution functions with potentially untrusted input"),
        (r"\$_GET\[|\$_POST\[|\$_REQUEST\[|\$_COOKIE\[", "Unvalidated User Input", "CWE-20", "MEDIUM",
         "Direct use of superglobal input — trace for injection sinks"),
        (r"mysql_query\s*\(.*\$_|mysqli_query\s*\(.*\$_", "SQL Injection Risk", "CWE-89", "CRITICAL",
         "User input directly in SQL query"),
        (r"unserialize\s*\(", "Insecure Deserialization", "CWE-502", "HIGH",
         "PHP unserialize() with untrusted data allows RCE"),
        (r"include\s*\(\s*\$_|require\s*\(\s*\$_", "Local/Remote File Inclusion", "CWE-98", "CRITICAL",
         "File inclusion with user-controlled path"),
        (r"md5\s*\(|sha1\s*\(", "Weak Cryptographic Hash", "CWE-327", "MEDIUM",
         "MD5/SHA1 are cryptographically broken for passwords"),
    ],
}

# Add typescript as alias for javascript patterns
PATTERNS["typescript"] = PATTERNS["javascript"]
PATTERNS["ruby"] = [
    (r"eval\s*\(", "Code Injection via eval()", "CWE-95", "HIGH", "eval() with untrusted input"),
    (r"`[^`]*#\{", "Shell Injection via Backtick", "CWE-78", "CRITICAL", "Backtick interpolation allows injection"),
    (r"(password|secret|api_key)\s*=\s*['\"][^'\"]{6,}['\"]", "Hardcoded Secret", "CWE-798", "HIGH", "Hardcoded credentials"),
    (r"Marshal\.load\s*\(", "Insecure Deserialization", "CWE-502", "HIGH", "Marshal.load with untrusted data"),
    (r"ActiveRecord::Base\.connection\.execute\s*\([^)]*\+", "SQL Injection Risk", "CWE-89", "CRITICAL", "Raw SQL with concatenation"),
]


class StaticScanAgent:
    def __init__(self, store: MemoryStore):
        self.store = store

    def run(self, chunks: list[dict]) -> list[Finding]:
        """
        Scan all code chunks with pattern matching.
        Returns candidate findings (not yet validated).
        """
        print(f"[StaticScan] Scanning {len(chunks)} chunks...")
        candidates = []

        for chunk in chunks:
            lang = chunk["language"]
            patterns = PATTERNS.get(lang, [])
            chunk_findings = self._scan_chunk(chunk, patterns)
            candidates.extend(chunk_findings)

        print(f"[StaticScan] Found {len(candidates)} raw candidates")
        return candidates

    def _scan_chunk(self, chunk: dict, patterns: list) -> list[Finding]:
        findings = []
        lines = chunk["content"].splitlines()

        for pattern, vuln_type, cwe_id, severity, description in patterns:
            for line_num, line in enumerate(lines, start=chunk["start_line"]):
                if re.search(pattern, line, re.IGNORECASE):
                    finding_id = str(uuid.uuid4())[:8]
                    # Extract 5 lines of context around the match
                    ctx_start = max(0, line_num - chunk["start_line"] - 2)
                    ctx_end = min(len(lines), line_num - chunk["start_line"] + 3)
                    context_snippet = "\n".join(lines[ctx_start:ctx_end])

                    finding = Finding(
                        id=finding_id,
                        filename=chunk["filepath"],
                        vuln_type=vuln_type,
                        severity=severity,
                        location=f"line {line_num}",
                        reasoning=description,
                        cwe_id=cwe_id,
                        raw_code=context_snippet,
                    )
                    self.store.add_finding(finding)
                    findings.append(finding)

        return findings
