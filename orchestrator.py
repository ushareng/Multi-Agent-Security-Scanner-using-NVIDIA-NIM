"""
orchestrator.py
Pipeline Orchestrator — coordinates all agents in sequence.
Fan-out: Ingestion + Dependency run in parallel threads.
Sequential gate: Static → Reasoning → Exploit → Classification → Report.
"""

import os
import time
import threading
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.table import Table

from nim_client import NIMClient
from memory_store import MemoryStore
from ingestion_agent import IngestionAgent
from static_scan_agent import StaticScanAgent
from dependency_agent import DependencyAgent
from reasoning_agent import ReasoningAgent
from exploit_agent import ExploitAgent
from classification_agent import ClassificationAgent
from report_agent import ReportAgent

console = Console()


class Orchestrator:
    def __init__(self, target: str):
        self.target = target
        self.store = MemoryStore()
        self.nim = NIMClient()
        self.output_dir = os.getenv("OUTPUT_DIR", "./output")

    def run(self):
        console.print(Panel.fit(
            "[bold cyan]Code Auditor — NIM-Powered Multi-Agent Pipeline[/bold cyan]\n"
            f"Target: [yellow]{self.target}[/yellow]",
            border_style="cyan"
        ))

        start_time = time.time()

        # ── Phase 1: Fan-out (Ingestion + Dependency in parallel) ──────────
        console.print("\n[bold]Phase 1:[/bold] Ingestion + Dependency Analysis (parallel)")

        chunks = []
        dep_results = {}
        ingestion_error = []
        dependency_error = []

        def run_ingestion():
            try:
                agent = IngestionAgent(self.store)
                nonlocal chunks
                chunks = agent.run(self.target)
            except Exception as e:
                ingestion_error.append(str(e))

        def run_dependency():
            try:
                agent = DependencyAgent(self.store)
                nonlocal dep_results
                dep_results = agent.run(self.target if not self.target.startswith("http") else "/tmp/audit_" + self.target[-8:])
            except Exception as e:
                dependency_error.append(str(e))

        t1 = threading.Thread(target=run_ingestion)
        t2 = threading.Thread(target=run_dependency)
        t1.start(); t2.start()
        t1.join(); t2.join()

        if ingestion_error:
            console.print(f"[red]Ingestion error: {ingestion_error[0]}[/red]")
            return
        if dependency_error:
            console.print(f"[yellow]Dependency scan warning: {dependency_error[0]}[/yellow]")

        console.print(f"  ✓ {len(chunks)} code chunks ingested")
        console.print(f"  ✓ {len(dep_results)} dependencies scanned")

        # ── Phase 2: Static Scan ────────────────────────────────────────────
        console.print("\n[bold]Phase 2:[/bold] Static Pattern Scan")
        static_agent = StaticScanAgent(self.store)
        candidates = static_agent.run(chunks)
        console.print(f"  ✓ {len(candidates)} raw candidates found")

        if not candidates:
            console.print("[green]No vulnerability candidates found. Codebase looks clean.[/green]")
            self._print_summary({}, start_time)
            return

        # ── Phase 3: LLM Semantic Reasoning (NIM) ──────────────────────────
        console.print("\n[bold]Phase 3:[/bold] NIM Semantic Validation (false positive elimination)")
        reasoning_agent = ReasoningAgent(self.store, self.nim)
        confirmed = reasoning_agent.run(candidates)
        console.print(f"  ✓ {len(confirmed)} confirmed findings")

        if not confirmed:
            console.print("[green]All candidates were false positives. Codebase looks clean.[/green]")
            self._print_summary({}, start_time)
            return

        # ── Phase 4: PoC Generation + Sandbox Execution ────────────────────
        console.print("\n[bold]Phase 4:[/bold] PoC Generation + Sandbox Execution")
        exploit_agent = ExploitAgent(self.store, self.nim)
        proven = exploit_agent.run(confirmed)

        # ── Phase 5: Classification ─────────────────────────────────────────
        console.print("\n[bold]Phase 5:[/bold] CWE/CVSS Classification + Remediation (NIM)")
        classification_agent = ClassificationAgent(self.store, self.nim)
        classified = classification_agent.run(proven)

        # ── Phase 6: Report Generation ──────────────────────────────────────
        console.print("\n[bold]Phase 6:[/bold] Report Generation")
        report_agent = ReportAgent(self.store)
        summary = report_agent.run()

        # Save memory store snapshot
        store_path = self.store.save_to_disk(self.output_dir)
        console.print(f"  ✓ Memory store saved: {store_path}")

        self._print_summary(summary, start_time)

    def _print_summary(self, summary: dict, start_time: float):
        elapsed = time.time() - start_time
        console.print()

        table = Table(title="Audit Complete", border_style="green")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        if summary:
            table.add_row("Files Scanned", str(summary.get("files_scanned", 0)))
            table.add_row("Raw Candidates", str(summary.get("total_candidates", 0)))
            table.add_row("False Positives Eliminated", str(summary.get("false_positives_eliminated", 0)))
            table.add_row("Confirmed Findings", str(summary.get("confirmed_findings", 0)))
            table.add_row("Findings with Working PoC", str(summary.get("findings_with_working_poc", 0)))
            table.add_row("Vulnerable Dependencies", str(summary.get("vulnerable_dependencies", 0)))

            severity = summary.get("severity_breakdown", {})
            severity_str = " | ".join(f"{k}: {v}" for k, v in severity.items() if v > 0) or "None"
            table.add_row("Severity Breakdown", severity_str)

        table.add_row("NIM API Calls", str(self.nim.request_count))
        table.add_row("Total Time", f"{elapsed:.1f}s")
        table.add_row("Reports", f"{self.output_dir}/audit_report.md\n{self.output_dir}/audit_report.json")

        console.print(table)
