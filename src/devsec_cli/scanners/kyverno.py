"""Kyverno CLI Policy-as-Code scanner for Kubernetes manifests."""

from pathlib import Path
import json
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
from ..runner import ProcessRunner
from ..discovery import TargetDiscovery


class KyvernoScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Kyverno CLI", category="Policy-as-Code", binary_name="kyverno")

    def scan(self, target_dir: Path) -> ToolResult:
        discovery = TargetDiscovery(target_dir)
        k8s_files = discovery.discover_k8s_manifests()

        if not k8s_files:
            return self.create_not_applicable_result("No Kubernetes manifests detected")

        if not self.is_tool_available():
            return self.create_skipped_result("kyverno binary not found in PATH")

        # Kyverno apply checks manifests against built-in or directory policies
        # Using kyverno apply or test
        cmd = [
            str(self.binary_path),
            "apply",
            str(target_dir),
            "-r", str(target_dir),
            "-o", "json"
        ]

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir))

        findings = FindingCounts()
        items = []
        status = StatusEnum.PASS
        summary = f"Evaluated {len(k8s_files)} manifest(s) against policy rules"

        if stdout.strip():
            try:
                # Kyverno json format can output array of results
                data = json.loads(stdout)
                entries = data if isinstance(data, list) else [data]
                for entry in entries:
                    res_status = str(entry.get("status") or "").lower()
                    if res_status in ("fail", "error"):
                        findings.high += 1
                        policy_name = entry.get("policy", "KyvernoPolicy")
                        rule_name = entry.get("rule", "PolicyRule")
                        res_name = entry.get("resource", "resource")
                        msg = entry.get("message", "Policy validation failed")
                        items.append(
                            FindingDetail(
                                severity="HIGH",
                                tool=self.name,
                                file=res_name,
                                line="",
                                rule=f"{policy_name}/{rule_name}",
                                description=msg
                            )
                        )
            except Exception:
                pass

        if findings.has_blocking:
            status = StatusEnum.FAIL
            summary = f"Detected {findings.high} Kyverno policy violation(s)"

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
