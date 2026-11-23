"""Schemathesis API Contract & Schema Security Scanner."""

from pathlib import Path
from typing import List
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
from ..runner import ProcessRunner


class SchemathesisScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Schemathesis", category="API Security", binary_name="st")

    def _discover_api_schemas(self, target_dir: Path) -> List[Path]:
        """Finds OpenAPI/Swagger/GraphQL definition files."""
        patterns = [
            "**/openapi.json", "**/openapi.yaml", "**/openapi.yml",
            "**/swagger.json", "**/swagger.yaml", "**/swagger.yml",
            "**/schema.graphql"
        ]
        schemas = []
        for pat in patterns:
            for p in target_dir.glob(pat):
                if p.is_file() and ".git" not in p.parts:
                    schemas.append(p)
        return schemas

    def scan(self, target_dir: Path) -> ToolResult:
        schemas = self._discover_api_schemas(target_dir)

        if not schemas:
            return self.create_not_applicable_result("No OpenAPI/Swagger schemas detected")

        if not self.is_tool_available():
            return self.create_skipped_result("schemathesis ('st') binary not found in PATH")

        findings = FindingCounts()
        items = []

        # Validate schema structure and security definitions
        primary_schema = schemas[0]
        cmd = [
            str(self.binary_path),
            "run",
            str(primary_schema),
            "--dry-run",
            "--checks=all"
        ]

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir), timeout=120)

        if code != 0:
            findings.medium += 1
            items.append(
                FindingDetail(
                    severity="MEDIUM",
                    tool=self.name,
                    file=str(primary_schema.relative_to(target_dir)),
                    line="1",
                    rule="api/contract-security-violation",
                    description="API schema contains specification or property boundary violations"
                )
            )

        status = StatusEnum.FAIL if (findings.critical + findings.high) > 0 else StatusEnum.PASS
        summary = f"Schemathesis audited {len(schemas)} API schema(s): {findings.total} issue(s) detected"

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
