"""Native Python structural Kubernetes security inspector.

Evaluates manifests for pod security standards, privileged containers, root execution,
host mounts, and resource constraints without external binaries.
"""

from pathlib import Path
import time
import yaml
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts
from ..discovery import TargetDiscovery


class K8sStructuralAuditScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="K8s Structural Security Inspector", category="Kubernetes Security", binary_name=None)

    def scan(self, target_dir: Path) -> ToolResult:
        start_time = time.time()
        discovery = TargetDiscovery(target_dir)
        manifests = discovery.discover_k8s_manifests()

        if not manifests:
            return self.create_not_applicable_result("No Kubernetes manifests detected")

        findings = FindingCounts()
        violations = []

        for manifest_path in manifests:
            try:
                content = manifest_path.read_text(encoding="utf-8", errors="ignore")
                docs = yaml.safe_load_all(content)
                for doc in docs:
                    if not isinstance(doc, dict):
                        continue
                    self._audit_document(doc, manifest_path.name, findings, violations)
            except Exception as e:
                # Syntax error or unparseable YAML
                findings.low += 1
                violations.append(f"{manifest_path.name}: Failed to parse YAML: {e}")

        elapsed = round(time.time() - start_time, 2)
        status = StatusEnum.FAIL if findings.has_blocking else StatusEnum.PASS

        if findings.total == 0:
            summary = f"Audited {len(manifests)} manifest(s): All Pod Security Standards passed!"
        else:
            summary = (
                f"Audited {len(manifests)} manifest(s): {findings.total} risk(s) identified "
                f"({findings.critical} Crit, {findings.high} High, {findings.medium} Med, {findings.low} Low)"
            )

        return ToolResult(
            tool_name=self.name,
            category=self.category,
            status=status,
            exit_code=1 if status == StatusEnum.FAIL else 0,
            summary=summary,
            findings=findings,
            duration_seconds=elapsed,
            details={"violations": violations[:50]}  # cap display
        )

    def _audit_document(self, doc: dict, filename: str, findings: FindingCounts, violations: list):
        kind = doc.get("kind", "")
        # Inspect specs of Pod, Deployment, DaemonSet, StatefulSet, Job, CronJob
        pod_spec = None
        if kind == "Pod":
            pod_spec = doc.get("spec", {})
        elif kind in ("Deployment", "DaemonSet", "StatefulSet", "Job"):
            pod_spec = doc.get("spec", {}).get("template", {}).get("spec", {})
        elif kind == "CronJob":
            pod_spec = doc.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})

        if not pod_spec:
            return

        # 1. Host Network / PID / IPC checks (High)
        if pod_spec.get("hostNetwork", False):
            findings.high += 1
            violations.append(f"{filename} [{kind}]: Shares host network namespace (hostNetwork: true)")
        if pod_spec.get("hostPID", False):
            findings.high += 1
            violations.append(f"{filename} [{kind}]: Shares host PID namespace (hostPID: true)")
        if pod_spec.get("hostIPC", False):
            findings.high += 1
            violations.append(f"{filename} [{kind}]: Shares host IPC namespace (hostIPC: true)")

        # 2. HostPath Volume checks (Critical)
        volumes = pod_spec.get("volumes", [])
        if isinstance(volumes, list):
            for vol in volumes:
                if isinstance(vol, dict) and "hostPath" in vol:
                    findings.critical += 1
                    violations.append(f"{filename} [{kind}]: Insecure host volume mount detected ({vol.get('name')})")

        # 3. Container SecurityContext & Resource checks
        containers = pod_spec.get("containers", [])
        if isinstance(containers, list):
            for container in containers:
                if not isinstance(container, dict):
                    continue
                c_name = container.get("name", "unknown")
                sec_ctx = container.get("securityContext", {}) or {}

                # Privileged mode (Critical)
                if sec_ctx.get("privileged", False):
                    findings.critical += 1
                    violations.append(f"{filename} [{kind}/{c_name}]: Running in privileged mode!")

                # Root Execution (High)
                run_as_user = sec_ctx.get("runAsUser")
                run_as_non_root = sec_ctx.get("runAsNonRoot")
                if run_as_user == 0 or run_as_non_root is False:
                    findings.high += 1
                    violations.append(f"{filename} [{kind}/{c_name}]: Explicitly configured to run as root")

                # Privilege Escalation (Medium)
                if sec_ctx.get("allowPrivilegeEscalation") is True:
                    findings.medium += 1
                    violations.append(f"{filename} [{kind}/{c_name}]: allowPrivilegeEscalation is enabled")

                # Read-only root filesystem (Low)
                if not sec_ctx.get("readOnlyRootFilesystem", False):
                    findings.low += 1

                # Missing Resource limits (Low)
                resources = container.get("resources", {}) or {}
                if not resources.get("limits"):
                    findings.low += 1
                    violations.append(f"{filename} [{kind}/{c_name}]: Missing CPU/Memory resource limits")
