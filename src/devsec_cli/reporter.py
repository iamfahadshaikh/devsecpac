"""Consolidated Reporting and Quality Gate Enforcement."""

from pathlib import Path
from typing import List
import json
from rich.console import Console
from rich.table import Table
from .contracts import ToolResult, StatusEnum


class Reporter:
    def __init__(self, console: Console = None):
        self.console = console or Console()

    def print_terminal_table(self, results: List[ToolResult]):
        """Prints a rich colored terminal table of all scanner results."""
        table = Table(title="🛡️ DevSecOps Autonomous Pipeline Scan Results", show_lines=True)
        table.add_column("Scanner / Tool", style="bold cyan")
        table.add_column("Category", style="magenta")
        table.add_column("Status", justify="center")
        table.add_column("Crit", justify="right", style="bold red")
        table.add_column("High", justify="right", style="red")
        table.add_column("Med", justify="right", style="yellow")
        table.add_column("Low", justify="right", style="blue")
        table.add_column("Duration", justify="right")
        table.add_column("Summary")

        status_styles = {
            StatusEnum.PASS: "[bold green]PASS[/bold green]",
            StatusEnum.FAIL: "[bold red]FAIL[/bold red]",
            StatusEnum.NOT_APPLICABLE: "[dim cyan]NOT_APPLICABLE[/dim cyan]",
            StatusEnum.SKIPPED: "[dim yellow]SKIPPED[/dim yellow]",
            StatusEnum.ERROR: "[bold white on red]ERROR[/bold white on red]",
        }

        for r in results:
            styled_status = status_styles.get(r.status, r.status.value)
            table.add_row(
                r.tool_name,
                r.category,
                styled_status,
                str(r.findings.critical),
                str(r.findings.high),
                str(r.findings.medium),
                str(r.findings.low),
                f"{r.duration_seconds}s",
                r.summary
            )

        self.console.print()
        self.console.print(table)
        self.console.print()

    def generate_markdown_summary(self, results: List[ToolResult], output_path: Path):
        """Generates an executive Markdown table compatible with Azure DevOps and GitHub."""
        md = []
        md.append("# 🛡️ Autonomous DevSecOps Pipeline Security Report\n")
        md.append("| Scanner / Tool | Category | Status | Crit | High | Med | Low | Duration | Summary |")
        md.append("|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---|")

        status_emojis = {
            StatusEnum.PASS: "✅ PASS",
            StatusEnum.FAIL: "❌ FAIL",
            StatusEnum.NOT_APPLICABLE: "⚪ N/A",
            StatusEnum.SKIPPED: "⏭️ SKIPPED",
            StatusEnum.ERROR: "⚠️ ERROR",
        }

        total_crit = sum(r.findings.critical for r in results)
        total_high = sum(r.findings.high for r in results)
        total_med = sum(r.findings.medium for r in results)
        total_low = sum(r.findings.low for r in results)

        for r in results:
            tag = status_emojis.get(r.status, r.status.value)
            md.append(
                f"| **{r.tool_name}** | {r.category} | {tag} | "
                f"{r.findings.critical} | {r.findings.high} | {r.findings.medium} | {r.findings.low} | "
                f"{r.duration_seconds}s | {r.summary} |"
            )

        md.append(
            f"| **TOTAL** | **ALL CATEGORIES** | - | **{total_crit}** | **{total_high}** | **{total_med}** | **{total_low}** | - | - |"
        )
        md.append("\n---\n")

        if (total_crit + total_high) > 0:
            md.append(f"> ❌ **GATE FAILED**: Found **{total_crit} Critical** and **{total_high} High** severity issue(s). Pipeline gate blocked.")
        else:
            md.append("> ✅ **GATE PASSED**: No Critical or High severity security issues detected.")

        output_path.write_text("\n".join(md), encoding="utf-8")

    def export_json_report(self, results: List[ToolResult], output_path: Path):
        """Consolidates status.json outputs into one JSON report."""
        report = {
            "total_tools": len(results),
            "summary": {
                "critical": sum(r.findings.critical for r in results),
                "high": sum(r.findings.high for r in results),
                "medium": sum(r.findings.medium for r in results),
                "low": sum(r.findings.low for r in results),
            },
            "gate_passed": (sum(r.findings.critical for r in results) + sum(r.findings.high for r in results)) == 0,
            "results": [r.to_dict() for r in results]
        }
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
