"""KubeLinter Kubernetes Workload and Manifest Security Scanner."""

from pathlib import Path
import json
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
from ..runner import ProcessRunner
from ..discovery import TargetDiscovery


class KubeLinterScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="KubeLinter", category="Kubernetes Security", binary_name="kube-linter")

    def scan(self, target_dir: Path) -> ToolResult:
        discovery = TargetDiscovery(target_dir)
        k8s_files = discovery.discover_k8s_manifests()

        if not k8s_files:
            return self.create_not_applicable_result("No Kubernetes manifests detected")

        if not self.is_tool_available():
            return self.create_skipped_result("kube-linter binary not found in PATH")

        cmd = [
            str(self.binary_path),
            "lint",
            str(target_dir),
            "--format=json"
        ]

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir), timeout=180)

        findings = FindingCounts()
        items = []

        try:
            data = json.loads(stdout)
            reports = data.get("Reports", [])

            for rep in reports:
                check = rep.get("Check", "KubeLinterCheck")
                msg = rep.get("Remediation", rep.get("Diagnostic", {}).get("Message", "KubeLinter finding"))
                obj = rep.get("Object", {}).get("K8sObject", {})
                rel_path = rep.get("Diagnostic", {}).get("Path", "") or obj.get("Name", "manifest.yaml")

                # KubeLinter checks default to Medium/High posture violations
                findings.medium += 1
                items.append(
                    FindingDetail(
                        severity="MEDIUM",
                        tool=self.name,
                        file=rel_path,
                        line="1",
                        rule=check,
                        description=msg
                    )
                )

        except Exception:
            pass

        if (findings.critical + findings.high) > 0:
            status = StatusEnum.FAIL
            summary = f"KubeLinter detected {findings.critical} Critical, {findings.high} High issue(s)"
        elif (findings.medium + findings.low) > 0:
            status = StatusEnum.PASS
            summary = f"KubeLinter detected {findings.medium} Kubernetes security issue(s)"
        else:
            status = StatusEnum.PASS
            summary = "KubeLinter passed: all manifests adhere to security policies"

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
