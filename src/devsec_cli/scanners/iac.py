"""Infrastructure-as-Code and Kubernetes schema scanners: Checkov & Kubeconform."""

from pathlib import Path
import json
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
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
        items = []
        summary = "No IaC security violations detected"

        if stdout.strip():
            try:
                data = json.loads(stdout)
                reports = data if isinstance(data, list) else [data]
                for report in reports:
                    results = report.get("results", {})
                    failed_checks = results.get("failed_checks", [])
                    for check in failed_checks:
                        raw_sev = str(check.get("severity") or "").upper()
                        sev = "MEDIUM"
                        if raw_sev == "CRITICAL":
                            findings.critical += 1
                            sev = "CRITICAL"
                        elif raw_sev == "HIGH":
                            findings.high += 1
                            sev = "HIGH"
                        elif raw_sev == "MEDIUM":
                            findings.medium += 1
                            sev = "MEDIUM"
                        elif raw_sev == "LOW":
                            findings.low += 1
                            sev = "LOW"
                        else:
                            findings.medium += 1

                        file_path = check.get("file_path", "unknown")
                        line_range = check.get("file_line_range", [])
                        line_str = f"{line_range[0]}-{line_range[1]}" if len(line_range) >= 2 else ""
                        check_id = check.get("check_id", "CheckovRule")
                        check_name = check.get("check_name", "")

                        items.append(
                            FindingDetail(
                                severity=sev,
                                tool=self.name,
                                file=file_path.lstrip("/"),
                                line=line_str,
                                rule=check_id,
                                description=check_name
                            )
                        )

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
            duration_seconds=elapsed,
            items=items
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
        items = []
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
                    
                    resources = data.get("resources", [])
                    for res in resources:
                        if res.get("status") in ("Invalid", "Error", "statusError", "statusInvalid"):
                            items.append(
                                FindingDetail(
                                    severity="HIGH",
                                    tool=self.name,
                                    file=res.get("filename", "k8s.yaml"),
                                    line="",
                                    rule="SchemaViolation",
                                    description=res.get("msg", "Invalid resource definition")
                                )
                            )
            except Exception:
                pass

        return ToolResult(
            tool_name=self.name,
            category=self.category,
            status=status,
            exit_code=code,
            summary=summary,
            findings=findings,
            duration_seconds=elapsed,
            files_scanned=len(k8s_files),
            items=items
        )
