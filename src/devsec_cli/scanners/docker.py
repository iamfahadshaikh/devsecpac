"""Dockerfile linting with Hadolint."""

from pathlib import Path
import json
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
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
        items = []
        total_issues = 0
        total_time = 0.0
        file_timings = {}

        for df in dockerfiles:
            rel_file = str(Path(df).relative_to(target_dir)) if str(df).startswith(str(target_dir)) else Path(df).name
            cmd = [
                str(self.binary_path),
                "--format", "json",
                str(df)
            ]
            code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir))
            total_time += elapsed
            file_timings[rel_file] = round(elapsed, 3)

            if stdout.strip():
                try:
                    entries = json.loads(stdout)
                    for entry in entries:
                        total_issues += 1
                        level = entry.get("level", "info").lower()
                        sev = "INFO"
                        if level == "error":
                            findings.high += 1
                            sev = "HIGH"
                        elif level == "warning":
                            findings.medium += 1
                            sev = "MEDIUM"
                        elif level == "info":
                            findings.low += 1
                            sev = "LOW"
                        else:
                            findings.info += 1

                        rel_file = str(Path(df).relative_to(target_dir)) if str(df).startswith(str(target_dir)) else Path(df).name
                        items.append(
                            FindingDetail(
                                severity=sev,
                                tool=self.name,
                                file=rel_file,
                                line=str(entry.get("line", "")),
                                rule=entry.get("code", "HadolintRule"),
                                description=entry.get("message", "")
                            )
                        )
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
            duration_seconds=round(total_time, 2),
            files_scanned=len(dockerfiles),
            file_timings=file_timings,
            items=items
        )
