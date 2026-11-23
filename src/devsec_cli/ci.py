"""CI/CD Pull Request Commenter and DefectDojo ASPM Exporter for DevSecPac v2.0."""

from pathlib import Path
from typing import List, Dict
import json
import os
import urllib.request
from rich.console import Console
from .contracts import ToolResult, FindingDetail, FindingCounts
from .correlator import FindingCorrelator

console = Console()


class CICDIntegrator:
    """Provides GitHub Actions / GitLab CI PR commenting and DefectDojo push integrations."""

    @staticmethod
    def generate_pr_comment(results: List[ToolResult]) -> str:
        """Generates GitHub-flavored interactive collapsible PR comment Markdown."""
        deduped, stats = FindingCorrelator.deduplicate_findings(results)

        total_crit = sum(r.findings.critical for r in results)
        total_high = sum(r.findings.high for r in results)
        total_med = sum(r.findings.medium for r in results)
        total_low = sum(r.findings.low for r in results)

        gate_status = "PASSED" if (total_crit + total_high) == 0 else "FAILED"
        badge_color = "brightgreen" if gate_status == "PASSED" else "red"

        lines = [
            f"## ![DevSecOps Gate](https://img.shields.io/badge/Security_Gate-{gate_status}-{badge_color}) Autonomous Pipeline Report",
            "",
            f"**Findings Summary**: {total_crit} Critical | {total_high} High | {total_med} Medium | {total_low} Low",
            f"*(Auto-Deduplication: {stats['duplicates_removed']} duplicate alerts consolidated)*" if stats['duplicates_removed'] > 0 else "",
            "",
            "<details><summary><b>View Scanner Tool Execution Matrix</b></summary>",
            "",
            "| Scanner | Category | Status | Time | Summary |",
            "|:---|:---|:---:|:---:|:---|"
        ]

        for r in results:
            lines.append(f"| **{r.tool_name}** | {r.category} | `{r.status.value}` | {r.duration_seconds}s | {r.summary} |")

        lines.extend([
            "",
            "</details>",
            "",
            "### Critical & High Priority Action Items",
            ""
        ])

        blocking = [i for i in deduped if i.severity.upper() in ("CRITICAL", "HIGH")]
        if not blocking:
            lines.append("> [!NOTE]\n> No Critical or High vulnerabilities detected. Pipeline approved to merge.")
        else:
            lines.append("| Severity | Tool | Location | Rule / CVE | Description |")
            lines.append("|:---:|:---|:---|:---|:---|")
            for item in blocking[:25]:
                loc = f"`{item.file}:{item.line}`" if item.line else f"`{item.file}`"
                lines.append(f"| **{item.severity}** | {item.tool} | {loc} | `{item.rule}` | {item.description} |")

        lines.append("\n---\n*Report generated autonomously by [devsecpac v2](https://github.com/iamfahadshaikh)*")
        return "\n".join(lines)

    @staticmethod
    def push_to_defectdojo(json_report_path: Path, dojo_url: str, api_key: str, engagement_id: int) -> bool:
        """Pushes consolidated JSON report into an active OWASP DefectDojo instance."""
        if not json_report_path.exists():
            return False

        try:
            url = f"{dojo_url.rstrip('/')}/api/v2/import-scan/"
            boundary = "----DevSecDojoBoundary12345"
            headers = {
                "Authorization": f"Token {api_key}",
                "Content-Type": f"multipart/form-data; boundary={boundary}"
            }
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="scan_type"\r\n\r\nGeneric Findings Import\r\n'
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="engagement"\r\n\r\n{engagement_id}\r\n'
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{json_report_path.name}"\r\n'
                f"Content-Type: application/json\r\n\r\n{json_report_path.read_text(encoding='utf-8')}\r\n"
                f"--{boundary}--\r\n"
            ).encode("utf-8")

            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status in (200, 201)
        except Exception as e:
            console.print(f"[bold red][FAIL][/bold red] DefectDojo push error: {str(e)}")
            return False
