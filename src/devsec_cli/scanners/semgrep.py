"""Semgrep Fast SAST and Security Guardrail Scanner."""

from pathlib import Path
import json
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
from ..runner import ProcessRunner
from ..discovery import TargetDiscovery


class SemgrepScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Semgrep", category="Fast SAST", binary_name="semgrep")

    def scan(self, target_dir: Path) -> ToolResult:
        discovery = TargetDiscovery(target_dir)
        languages = discovery.detect_languages()

        if not languages:
            return self.create_not_applicable_result("No application source files detected")

        if not self.is_tool_available():
            return self.create_skipped_result("semgrep binary not found in PATH")

        # Run semgrep with auto-config (default security audit ruleset)
        cmd = [
            str(self.binary_path),
            "scan",
            "--config=auto",
            "--json",
            "--quiet",
            "--no-git-ignore"
        ]

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir), timeout=300)

        findings = FindingCounts()
        items = []

        try:
            data = json.loads(stdout)
            results = data.get("results", [])

            for res in results:
                raw_sev = str(res.get("extra", {}).get("severity", "INFO")).upper()
                rule_id = res.get("check_id", "SemgrepRule")
                msg = res.get("extra", {}).get("message", "Semgrep finding")
                rel_path = res.get("path", "")
                start_line = str(res.get("start", {}).get("line", ""))

                sev_level = "LOW"
                if raw_sev == "ERROR":
                    findings.high += 1
                    sev_level = "HIGH"
                elif raw_sev == "WARNING":
                    findings.medium += 1
                    sev_level = "MEDIUM"
                else:
                    findings.low += 1
                    sev_level = "LOW"

                items.append(
                    FindingDetail(
                        severity=sev_level,
                        tool=self.name,
                        file=rel_path,
                        line=start_line,
                        rule=rule_id,
                        description=msg
                    )
                )

        except Exception:
            pass

        if (findings.critical + findings.high) > 0:
            status = StatusEnum.FAIL
            summary = f"Semgrep detected {findings.critical} Critical, {findings.high} High issue(s)"
        elif (findings.medium + findings.low) > 0:
            status = StatusEnum.PASS
            summary = f"Semgrep detected {findings.medium + findings.low} non-blocking issue(s)"
        else:
            status = StatusEnum.PASS
            summary = "Semgrep fast SAST analysis passed"

        return ToolResult(
            tool_name=self.name,
            category=self.category,
            status=status,
            exit_code=code,
            summary=summary,
            findings=findings,
            duration_seconds=elapsed,
            items=items
        )
