"""CI/CD Pull Request Commenter and DefectDojo ASPM Exporter for DevSecPac v2.0."""

from pathlib import Path
from typing import List, Dict
import json
import os
import requests
from rich.console import Console
from .contracts import ToolResult, FindingDetail, FindingCounts, StatusEnum
from .correlator import FindingCorrelator

console = Console()


class CICDIntegrator:
    """Provides GitHub Actions / GitLab CI PR commenting and DefectDojo push integrations."""

    @classmethod
    def load_results_from_json(cls, json_path: Path) -> List[ToolResult]:
        """Loads and reconstructs ToolResult objects from devsec-report.json."""
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        results: List[ToolResult] = []
        raw_results = data.get("results", [])
        for item in raw_results:
            findings_data = item.get("findings", {})
            fc = FindingCounts(
                critical=findings_data.get("critical", 0),
                high=findings_data.get("high", 0),
                medium=findings_data.get("medium", 0),
                low=findings_data.get("low", 0),
                info=findings_data.get("info", 0)
            )
            raw_items = item.get("items", [])
            detail_items = [
                FindingDetail(
                    severity=d.get("severity", "MEDIUM"),
                    tool=d.get("tool", item.get("tool_name", "")),
                    file=d.get("file", ""),
                    line=str(d.get("line", "")),
                    rule=d.get("rule", ""),
                    description=d.get("description", "")
                )
                for d in raw_items
            ]
            res = ToolResult(
                tool_name=item.get("tool_name", ""),
                category=item.get("category", ""),
                status=StatusEnum(item.get("status", "PASS")),
                exit_code=item.get("exit_code", 0),
                summary=item.get("summary", ""),
                findings=fc,
                duration_seconds=float(item.get("duration_seconds", 0.0)),
                items=detail_items,
                details=item.get("details", {})
            )
            results.append(res)
        return results

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

    @classmethod
    def push_to_defectdojo(cls, json_report_path: Path, dojo_url: str, api_key: str, engagement_id: int) -> bool:
        """Transforms unified devsec-report.json into DefectDojo Generic Findings format and pushes it."""
        if not json_report_path.exists():
            return False

        try:
            results = cls.load_results_from_json(json_report_path)
            deduped, _ = FindingCorrelator.deduplicate_findings(results)

            dojo_findings = []
            for item in deduped:
                sev = item.severity.capitalize()  # Critical, High, Medium, Low, Info
                if sev not in ("Critical", "High", "Medium", "Low", "Info"):
                    sev = "Medium"
                
                finding_obj = {
                    "title": f"[{item.tool}] {item.rule or item.description[:50]}",
                    "severity": sev,
                    "description": f"Tool: {item.tool}\nRule/CVE: {item.rule}\nFile: {item.file}:{item.line}\n\n{item.description}",
                    "file_path": item.file,
                    "active": True,
                    "verified": True
                }
                if item.line and item.line.isdigit():
                    finding_obj["line"] = int(item.line)
                if item.rule and (item.rule.startswith("CVE-") or item.rule.startswith("GHSA-")):
                    finding_obj["vulnerability_ids"] = [item.rule]

                dojo_findings.append(finding_obj)

            payload = {
                "name": "DevSecPac Unified Scan",
                "findings": dojo_findings
            }

            url = f"{dojo_url.rstrip('/')}/api/v2/import-scan/"
            headers = {
                "Authorization": f"Token {api_key}"
            }
            files = {
                "file": ("devsec-dojo.json", json.dumps(payload), "application/json")
            }
            data = {
                "scan_type": "Generic Findings Import",
                "engagement": str(engagement_id),
                "active": "true",
                "verified": "true"
            }
            resp = requests.post(url, headers=headers, files=files, data=data, timeout=45)
            return resp.status_code in (200, 201)
        except Exception as e:
            console.print(f"[bold red][FAIL][/bold red] DefectDojo push error: {str(e)}")
            return False
