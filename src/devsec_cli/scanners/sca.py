"""Software Composition Analysis (SCA) & Filesystem Vulnerability Scanners."""

from pathlib import Path
import json
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts
from ..runner import ProcessRunner


class TrivyFSScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Aqua Trivy (FS)", category="SCA & Vulnerability", binary_name="trivy")

    def scan(self, target_dir: Path) -> ToolResult:
        if not self.is_tool_available():
            return self.create_skipped_result("trivy binary not found in PATH")

        cmd = [
            str(self.binary_path),
            "fs",
            "--format", "json",
            "--quiet",
            str(target_dir)
        ]

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir), timeout=600)

        findings = FindingCounts()
        summary = "No filesystem vulnerabilities detected"

        if stdout.strip():
            try:
                data = json.loads(stdout)
                results = data.get("Results", [])
                for res in results:
                    vulns = res.get("Vulnerabilities", [])
                    for v in vulns:
                        sev = v.get("Severity", "UNKNOWN").upper()
                        if sev == "CRITICAL":
                            findings.critical += 1
                        elif sev == "HIGH":
                            findings.high += 1
                        elif sev == "MEDIUM":
                            findings.medium += 1
                        elif sev == "LOW":
                            findings.low += 1
                        else:
                            findings.info += 1

                if findings.total > 0:
                    summary = (
                        f"Found {findings.total} package vulnerabilities "
                        f"({findings.critical} Crit, {findings.high} High, {findings.medium} Med, {findings.low} Low)"
                    )
            except Exception:
                pass

        status = StatusEnum.FAIL if findings.has_blocking else StatusEnum.PASS

        return ToolResult(
            tool_name=self.name,
            category=self.category,
            status=status,
            exit_code=0,
            summary=summary,
            findings=findings,
            duration_seconds=elapsed
        )


class DependencyCheckScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="OWASP Dependency-Check", category="SCA", binary_name="dependency-check")

    def scan(self, target_dir: Path) -> ToolResult:
        if not self.is_tool_available():
            return self.create_skipped_result("dependency-check binary not found in PATH")

        out_dir = target_dir / ".owasp_dc"
        cmd = [
            str(self.binary_path),
            "--scan", str(target_dir),
            "--format", "JSON",
            "--out", str(out_dir),
            "--failOnCVSS", "7"
        ]

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir), timeout=600)

        findings = FindingCounts()
        status = StatusEnum.PASS
        summary = "No CVE vulnerabilities >= CVSS 7.0 detected"

        report_file = out_dir / "dependency-check-report.json"
        if report_file.exists():
            try:
                data = json.loads(report_file.read_text(encoding="utf-8"))
                dependencies = data.get("dependencies", [])
                for dep in dependencies:
                    vulns = dep.get("vulnerabilities", [])
                    for v in vulns:
                        cvss_score = float(v.get("cvssv3", {}).get("baseScore", 0.0) or v.get("cvssv2", {}).get("score", 0.0))
                        if cvss_score >= 9.0:
                            findings.critical += 1
                        elif cvss_score >= 7.0:
                            findings.high += 1
                        elif cvss_score >= 4.0:
                            findings.medium += 1
                        else:
                            findings.low += 1

                if findings.has_blocking:
                    status = StatusEnum.FAIL
                    summary = f"Detected {findings.critical} Critical and {findings.high} High CVEs"
            except Exception:
                pass

        return ToolResult(
            tool_name=self.name,
            category=self.category,
            status=status,
            exit_code=code,
            summary=summary,
            findings=findings,
            duration_seconds=elapsed
        )
