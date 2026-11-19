"""Secret detection scanners: Gitleaks & TruffleHog."""

from pathlib import Path
import json
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts
from ..runner import ProcessRunner


class GitleaksScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Gitleaks", category="Secret Detection", binary_name="gitleaks")

    def scan(self, target_dir: Path) -> ToolResult:
        if not self.is_tool_available():
            return self.create_skipped_result("gitleaks binary not found in PATH")

        report_file = target_dir / ".gitleaks_report.json"
        cmd = [
            str(self.binary_path),
            "detect",
            "--source", str(target_dir),
            "--report-format", "json",
            "--report-path", str(report_file),
            "--exit-code", "0",
            "--no-git" if not (target_dir / ".git").is_dir() else ""
        ]
        cmd = [c for c in cmd if c]

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir))

        findings = FindingCounts()
        summary = "No secrets detected"
        status = StatusEnum.PASS

        if report_file.exists():
            try:
                data = json.loads(report_file.read_text(encoding="utf-8"))
                if isinstance(data, list) and len(data) > 0:
                    findings.high = len(data)  # Gitleaks findings treated as High
                    status = StatusEnum.FAIL
                    summary = f"Detected {len(data)} potential secret(s)"
            except Exception:
                pass
            finally:
                report_file.unlink(missing_ok=True)

        return ToolResult(
            tool_name=self.name,
            category=self.category,
            status=status,
            exit_code=code,
            summary=summary,
            findings=findings,
            duration_seconds=elapsed
        )


class TruffleHogScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="TruffleHog", category="Secret Detection", binary_name="trufflehog")

    def scan(self, target_dir: Path) -> ToolResult:
        if not self.is_tool_available():
            return self.create_skipped_result("trufflehog binary not found in PATH")

        # TruffleHog scanning filesystem
        cmd = [
            str(self.binary_path),
            "filesystem",
            str(target_dir),
            "--json",
            "--only-verified"
        ]

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir))

        findings = FindingCounts()
        verified_count = 0

        # TruffleHog outputs line-delimited JSON
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if item.get("Verified", False):
                    verified_count += 1
            except Exception:
                continue

        if verified_count > 0:
            findings.critical = verified_count
            status = StatusEnum.FAIL
            summary = f"Detected {verified_count} verified active secret(s)!"
        else:
            status = StatusEnum.PASS
            summary = "No verified secrets detected"

        return ToolResult(
            tool_name=self.name,
            category=self.category,
            status=status,
            exit_code=code,
            summary=summary,
            findings=findings,
            duration_seconds=elapsed
        )
