"""Consolidated Reporting, Finding Drill-Down, and Quality Gate Enforcement."""

from pathlib import Path
from typing import List
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from .contracts import ToolResult, StatusEnum, FindingDetail


class Reporter:
    def __init__(self, console: Console = None):
        self.console = console or Console()

    def print_terminal_table(self, results: List[ToolResult]):
        """Prints a refined, non-wrapping terminal table of all scanner results."""
        table = Table(
            title="🛡️ DevSecOps Autonomous Pipeline Scan Results",
            show_lines=True,
            header_style="bold cyan",
            expand=False
        )

        table.add_column("Scanner / Tool", style="bold white", no_wrap=True)
        table.add_column("Category", style="magenta", no_wrap=True)
        table.add_column("Status", justify="center", no_wrap=True)
        table.add_column("Crit", justify="right", style="bold red", no_wrap=True)
        table.add_column("High", justify="right", style="red", no_wrap=True)
        table.add_column("Med", justify="right", style="yellow", no_wrap=True)
        table.add_column("Low", justify="right", style="blue", no_wrap=True)
        table.add_column("Time", justify="right", style="dim", no_wrap=True)
        table.add_column("Summary", style="dim white")

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

    def print_findings_drilldown(self, results: List[ToolResult]):
        """Prints detailed findings grouped by file and severity."""
        all_items: List[FindingDetail] = []
        for r in results:
            all_items.extend(r.items)

        if not all_items:
            return

        # Separate items by severity
        crit_items = [i for i in all_items if i.severity.upper() == "CRITICAL"]
        high_items = [i for i in all_items if i.severity.upper() == "HIGH"]
        med_items = [i for i in all_items if i.severity.upper() == "MEDIUM"]
        low_items = [i for i in all_items if i.severity.upper() == "LOW"]

        total_crit = len(crit_items)
        total_high = len(high_items)
        total_med = len(med_items)
        total_low = len(low_items)

        summary_title = (
            f"🔍 Security Findings Breakdown: "
            f"[bold red]{total_crit} Critical[/bold red] | "
            f"[red]{total_high} High[/red] | "
            f"[yellow]{total_med} Medium[/yellow] | "
            f"[blue]{total_low} Low[/blue]"
        )

        table = Table(
            title=summary_title,
            show_lines=True,
            header_style="bold yellow",
            expand=False
        )

        table.add_column("Severity", justify="center", no_wrap=True)
        table.add_column("Scanner", style="cyan", no_wrap=True)
        table.add_column("Location (File:Line)", style="bold white")
        table.add_column("Rule / CVE", style="bold magenta", no_wrap=True)
        table.add_column("Description", style="dim white")

        sev_styles = {
            "CRITICAL": "[bold white on red] CRIT [/bold white on red]",
            "HIGH": "[bold red] HIGH [/bold red]",
            "MEDIUM": "[yellow] MED  [/yellow]",
            "LOW": "[blue] LOW  [/blue]",
            "INFO": "[dim] INFO [/dim]",
        }

        # Show in priority order: CRITICAL -> HIGH -> MEDIUM -> LOW
        for item in (crit_items + high_items + med_items + low_items):
            loc = f"{item.file}:{item.line}" if item.line else item.file
            table.add_row(
                sev_styles.get(item.severity.upper(), item.severity),
                item.tool,
                loc,
                item.rule or "-",
                item.description
            )

        self.console.print(table)
        self.console.print()

    def generate_markdown_summary(self, results: List[ToolResult], output_path: Path):
        """Generates an executive Markdown table with full findings drill-down."""
        md = []
        md.append("# 🛡️ Autonomous DevSecOps Pipeline Security Report\n")
        md.append("| Scanner / Tool | Category | Status | Crit | High | Med | Low | Time | Summary |")
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
            md.append(f"> ❌ **GATE FAILED**: Found **{total_crit} Critical** and **{total_high} High** severity issue(s). Pipeline gate blocked.\n")
        else:
            md.append("> ✅ **GATE PASSED**: No Critical or High severity security issues detected.\n")

        # Detailed Findings Table in Markdown
        all_items: List[FindingDetail] = []
        for r in results:
            all_items.extend(r.items)

        if all_items:
            md.append("## 🔍 Detailed Findings Drill-Down\n")
            md.append("| Severity | Scanner | Location (File:Line) | Rule / CVE | Description |")
            md.append("|:---:|:---|:---|:---|:---|")
            for item in all_items:
                loc = f"`{item.file}:{item.line}`" if item.line else f"`{item.file}`"
                md.append(f"| **{item.severity}** | {item.tool} | {loc} | `{item.rule}` | {item.description} |")
            md.append("\n")

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
