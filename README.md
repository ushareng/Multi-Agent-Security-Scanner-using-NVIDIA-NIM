# Code Auditor — NIM-Powered Multi-Agent Security Pipeline

LLM-powered code security auditing using NVIDIA NIM + free open-source safety stack.
Replaces NeMo with NIM (free tier) + LLM Guard + Guardrails AI.

<img width="1631" height="962" alt="image" src="https://github.com/user-attachments/assets/d40cbc75-fc4f-482b-8960-3c3f9c6c827a" />


## Architecture

```
TARGET CODEBASE / GITHUB URL
         │
         ▼
  [ORCHESTRATOR]
         │
    ┌────┴────┐
    ▼         ▼           ← Phase 1: Parallel Fan-out
[INGESTION] [DEPENDENCY]
    │         │
    └────┬────┘
         ▼
  [STATIC SCAN]           ← Phase 2: Fast pattern + taint (no LLM)
         │
         ▼
[NIM REASONING AGENT]     ← Phase 3: Semantic validation, false positive elimination
         │
         ▼
  [EXPLOIT AGENT]         ← Phase 4: PoC generation + sandbox execution
         │
         ▼
[CLASSIFICATION AGENT]    ← Phase 5: CWE/CVSS via NIM
         │
         ▼
  [REPORT AGENT]          ← Phase 6: JSON + Markdown reports
```

## Stack
| Component | Technology | Cost |
|-----------|-----------|------|
| LLM Inference | NVIDIA NIM (codellama-70b) | Free tier |
| Input Safety | LLM Guard | Free / OSS |
| Output Validation | Guardrails AI | Free / OSS |
| Dependency CVEs | OSV.dev API | Free |
| Dep Graph | NetworkX | Free / OSS |
| Repo Cloning | GitPython | Free / OSS |

## Setup

### 1. Get free NVIDIA NIM API key
Go to https://build.nvidia.com → Sign up → API Key

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure environment
```bash
cp .env.example .env
# Edit .env and set NVIDIA_API_KEY=nvapi-your-key-here
```

### 4. Run the auditor

**Scan a local project:**
```bash
python main.py --target ./my_project
```

**Scan a GitHub repo:**
```bash
python main.py --target https://github.com/org/repo
```

**Limit files (recommended for free NIM tier):**
```bash
python main.py --target ./my_project --max-files 30
```

**Skip PoC execution (faster, no sandbox):**
```bash
python main.py --target ./my_project --skip-exploit
```

**Custom output directory:**
```bash
python main.py --target ./my_project --output ./audit_results
```

**Use a different NIM model:**
```bash
python main.py --target ./my_project --model mistralai/codestral-22b-instruct-v0.1
```

## Output Files

After a scan, the `./output` directory contains:

| File | Contents |
|------|----------|
| `audit_report.md` | Human-readable report with findings, severity, remediation |
| `audit_report.json` | Machine-readable full report |
| `memory_store.json` | Complete agent memory snapshot |

## Supported Languages
Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C, C++, C#, Rust

## Vulnerability Categories Detected
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Code Injection / eval() (CWE-95)
- Insecure Deserialization (CWE-502)
- XSS (CWE-79)
- Path Traversal (CWE-73)
- Hardcoded Secrets (CWE-798)
- Weak Cryptography (CWE-327)
- Insecure Randomness (CWE-338)
- SSL/TLS Bypass (CWE-295)
- SSTI (CWE-94)
- File Inclusion (CWE-98)
- Information Disclosure (CWE-209)
- Known CVEs in dependencies (via OSV.dev)

## Free Tier Limits (NIM)
- ~1000 API calls/month on free tier
- Recommended: `--max-files 30` keeps calls under 200 per scan
- Each file uses ~3 NIM calls (validation + PoC + classification)

## Notes
- PoC execution runs in restricted subprocess sandbox (no network, limited env)
- LLM Guard blocks prompt injection attempts in code before NIM calls
- OSV.dev dependency check requires internet access
- NIM model can be swapped — any CodeLlama/Codestral model on build.nvidia.com works
