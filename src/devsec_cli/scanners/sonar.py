"""SonarQube SAST and Quality Gate Scanner."""

from pathlib import Path
import os
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
from ..runner import ProcessRunner
from ..discovery import TargetDiscovery


class SonarQubeScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="SonarQube", category="Code Quality & SAST", binary_name="sonar-scanner")

    def scan(self, target_dir: Path) -> ToolResult:
        discovery = TargetDiscovery(target_dir)
        languages = discovery.detect_languages()

        if not languages:
            return self.create_not_applicable_result("No application source files detected")

        if not self.is_tool_available():
            return self.create_skipped_result("sonar-scanner binary not found in PATH")

        # Dynamic project properties if not provided
        sonar_host = os.environ.get("SONAR_HOST_URL", "http://localhost:9000")
        sonar_token = os.environ.get("SONAR_TOKEN", "")

        cmd = [
            str(self.binary_path),
            f"-Dsonar.projectKey={target_dir.name}",
            f"-Dsonar.sources={target_dir}",
            f"-Dsonar.host.url={sonar_host}"
        ]
        if sonar_token:
            cmd.append(f"-Dsonar.token={sonar_token}")

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir), timeout=600)

        findings = FindingCounts()
        items = []
        status = StatusEnum.PASS
        summary = "SonarQube analysis passed"

        # Check for Quality Gate failure in output
        output_combined = stdout + stderr
        if "QUALITY GATE STATUS: FAILED" in output_combined or "EXECUTION FAILURE" in output_combined:
            findings.high += 1
            status = StatusEnum.FAIL
            summary = "SonarQube Quality Gate FAILED"
            items.append(
                FindingDetail(
                    severity="HIGH",
                    tool=self.name,
                    file="sonar-project",
                    line="",
                    rule="QualityGateFailed",
                    description="Project failed SonarQube quality gate thresholds"
                )
            )
        elif code != 0:
            status = StatusEnum.ERROR
            summary = "SonarQube analysis execution failed (server unreachable?)"

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
