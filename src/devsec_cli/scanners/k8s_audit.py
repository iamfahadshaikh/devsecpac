"""Native Python structural Kubernetes security inspector.

Evaluates manifests for pod security standards, privileged containers, root execution,
host mounts, and resource constraints without external binaries.
"""

from pathlib import Path
import time
import yaml
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
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
        items = []

        for manifest_path in manifests:
            try:
                content = manifest_path.read_text(encoding="utf-8", errors="ignore")
                docs = yaml.safe_load_all(content)
                rel_name = str(manifest_path.relative_to(target_dir)) if str(manifest_path).startswith(str(target_dir)) else manifest_path.name
                for doc in docs:
                    if not isinstance(doc, dict):
                        continue
                    self._audit_document(doc, rel_name, findings, items)
            except Exception as e:
                findings.low += 1
                items.append(
                    FindingDetail(
                        severity="LOW",
                        tool=self.name,
                        file=manifest_path.name,
                        line="",
                        rule="YAMLParseError",
                        description=f"Failed to parse YAML: {e}"
                    )
                )

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
            items=items
        )

    def _audit_document(self, doc: dict, filename: str, findings: FindingCounts, items: list):
        kind = doc.get("kind", "")
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
            items.append(FindingDetail("HIGH", self.name, filename, "", "K8S-HOST-NET", f"[{kind}] Shares host network namespace (hostNetwork: true)"))
        if pod_spec.get("hostPID", False):
            findings.high += 1
            items.append(FindingDetail("HIGH", self.name, filename, "", "K8S-HOST-PID", f"[{kind}] Shares host PID namespace (hostPID: true)"))
        if pod_spec.get("hostIPC", False):
            findings.high += 1
            items.append(FindingDetail("HIGH", self.name, filename, "", "K8S-HOST-IPC", f"[{kind}] Shares host IPC namespace (hostIPC: true)"))

        # 2. HostPath Volume checks (Critical)
        volumes = pod_spec.get("volumes", [])
        if isinstance(volumes, list):
            for vol in volumes:
                if isinstance(vol, dict) and "hostPath" in vol:
                    findings.critical += 1
                    items.append(FindingDetail("CRITICAL", self.name, filename, "", "K8S-HOST-PATH", f"[{kind}] Insecure host volume mount ({vol.get('name')})"))

        # 3. Container SecurityContext & Resource checks
        containers = pod_spec.get("containers", [])
        if isinstance(containers, list):
            for container in containers:
                if not isinstance(container, dict):
                    continue
                c_name = container.get("name", "unknown")
                sec_ctx = container.get("securityContext", {}) or {}

                if sec_ctx.get("privileged", False):
                    findings.critical += 1
                    items.append(FindingDetail("CRITICAL", self.name, filename, "", "K8S-PRIVILEGED", f"[{kind}/{c_name}] Container runs in privileged mode"))

                run_as_user = sec_ctx.get("runAsUser")
                run_as_non_root = sec_ctx.get("runAsNonRoot")
                if run_as_user == 0 or run_as_non_root is False:
                    findings.high += 1
                    items.append(FindingDetail("HIGH", self.name, filename, "", "K8S-RUN-AS-ROOT", f"[{kind}/{c_name}] Explicitly configured to run as root"))

                if sec_ctx.get("allowPrivilegeEscalation") is True:
                    findings.medium += 1
                    items.append(FindingDetail("MEDIUM", self.name, filename, "", "K8S-PRIV-ESC", f"[{kind}/{c_name}] allowPrivilegeEscalation is enabled"))

                resources = container.get("resources", {}) or {}
                if not resources.get("limits"):
                    findings.low += 1
                    items.append(FindingDetail("LOW", self.name, filename, "", "K8S-NO-LIMITS", f"[{kind}/{c_name}] Missing CPU/Memory resource limits"))
