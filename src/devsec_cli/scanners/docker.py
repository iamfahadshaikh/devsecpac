"""Dockerfile linting with Hadolint."""

from pathlib import Path
import json
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts
from ..runner import ProcessRunner
from ..discovery import TargetDiscovery


class HadolintScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Hadolint", category="Container Security", binary_name="hadolint")

    def scan(self, target_dir: Path) -> ToolResult:
        discovery = TargetDiscovery(target_dir)
        dockerfiles = discovery.discover_dockerfiles()

        if not dockerfiles:
            return self.create_not_applicable_result("No Dockerfile detected in repository")

        if not self.is_tool_available():
            return self.create_skipped_result("hadolint binary not found in PATH")

        findings = FindingCounts()
        total_issues = 0
        total_time = 0.0

        for df in dockerfiles:
            cmd = [
                str(self.binary_path),
                "--format", "json",
                str(df)
            ]
            code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir))
            total_time += elapsed

            if stdout.strip():
                try:
                    items = json.loads(stdout)
                    for item in items:
                        total_issues += 1
                        level = item.get("level", "info").lower()
                        if level == "error":
                            findings.high += 1
                        elif level == "warning":
                            findings.medium += 1
                        elif level == "info":
                            findings.low += 1
                        else:
                            findings.info += 1
                except Exception:
                    pass

        status = StatusEnum.FAIL if findings.has_blocking else StatusEnum.PASS
        summary = (
            f"Analyzed {len(dockerfiles)} Dockerfile(s): {total_issues} issue(s) found "
            f"({findings.high} High, {findings.medium} Med, {findings.low} Low)"
        )

        return ToolResult(
            tool_name=self.name,
            category=self.category,
            status=status,
            exit_code=0,
            summary=summary,
            findings=findings,
            duration_seconds=round(total_time, 2)
        )
