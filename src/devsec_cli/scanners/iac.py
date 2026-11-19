"""Infrastructure-as-Code and Kubernetes schema scanners: Checkov & Kubeconform."""

from pathlib import Path
import json
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts
from ..runner import ProcessRunner
from ..discovery import TargetDiscovery


class CheckovScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Checkov", category="IaC Security", binary_name="checkov")

    def scan(self, target_dir: Path) -> ToolResult:
        discovery = TargetDiscovery(target_dir)
        k8s_files = discovery.discover_k8s_manifests()
        iac_files = discovery.discover_iac_files()

        if not k8s_files and not iac_files:
            return self.create_not_applicable_result("No IaC or Kubernetes files detected")

        if not self.is_tool_available():
            return self.create_skipped_result("checkov binary not found in PATH")

        cmd = [
            str(self.binary_path),
            "-d", str(target_dir),
            "-o", "json",
            "--soft-fail",
            "--compact"
        ]

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir), timeout=600)

        findings = FindingCounts()
        summary = "No IaC security violations detected"

        if stdout.strip():
            try:
                data = json.loads(stdout)
                # Checkov can return a list or dict of reports
                reports = data if isinstance(data, list) else [data]
                for report in reports:
                    results = report.get("results", {})
                    failed_checks = results.get("failed_checks", [])
                    for check in failed_checks:
                        severity = str(check.get("severity") or "").upper()
                        if severity == "CRITICAL":
                            findings.critical += 1
                        elif severity == "HIGH":
                            findings.high += 1
                        elif severity == "MEDIUM":
                            findings.medium += 1
                        elif severity == "LOW":
                            findings.low += 1
                        else:
                            findings.medium += 1  # Default unrated checkov failures to medium

                if findings.total > 0:
                    summary = (
                        f"Found {findings.total} IaC misconfigurations "
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


class KubeconformScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Kubeconform", category="Kubernetes Security", binary_name="kubeconform")

    def scan(self, target_dir: Path) -> ToolResult:
        discovery = TargetDiscovery(target_dir)
        k8s_files = discovery.discover_k8s_manifests()

        if not k8s_files:
            return self.create_not_applicable_result("No Kubernetes manifests detected")

        if not self.is_tool_available():
            return self.create_skipped_result("kubeconform binary not found in PATH")

        cmd = [
            str(self.binary_path),
            "-summary",
            "-output", "json",
            "-strict",
            str(target_dir)
        ]

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir))

        findings = FindingCounts()
        status = StatusEnum.PASS
        summary = f"Validated {len(k8s_files)} Kubernetes manifest(s) successfully"

        if stdout.strip():
            try:
                data = json.loads(stdout)
                summary_data = data.get("summary", {})
                invalid_count = summary_data.get("invalid", 0)
                error_count = summary_data.get("errors", 0)
                if invalid_count > 0 or error_count > 0:
                    findings.high = invalid_count + error_count
                    status = StatusEnum.FAIL
                    summary = f"Schema validation failed: {invalid_count} invalid, {error_count} errors"
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
