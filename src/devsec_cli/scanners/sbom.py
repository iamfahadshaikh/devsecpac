"""Software Bill of Materials (SBOM) generation with Syft."""

from pathlib import Path
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts
from ..runner import ProcessRunner


class SyftScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Syft", category="SBOM Generation", binary_name="syft")

    def scan(self, target_dir: Path) -> ToolResult:
        if not self.is_tool_available():
            return self.create_skipped_result("syft binary not found in PATH")

        cyclonedx_file = target_dir / "sbom-cyclonedx.json"
        cmd = [
            str(self.binary_path),
            "scan",
            f"dir:{target_dir}",
            "-o", f"cyclonedx-json={cyclonedx_file}",
            "-q"
        ]

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir))

        status = StatusEnum.PASS if code == 0 and cyclonedx_file.exists() else StatusEnum.ERROR
        summary = f"Generated CycloneDX SBOM at {cyclonedx_file.name}" if status == StatusEnum.PASS else "Failed to generate SBOM"

        return ToolResult(
            tool_name=self.name,
            category=self.category,
            status=status,
            exit_code=code,
            summary=summary,
            findings=FindingCounts(),
            duration_seconds=elapsed
        )
