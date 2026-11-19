"""OWASP ZAP Dynamic Application Security Testing (DAST) Scanner."""

from pathlib import Path
import os
import json
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
from ..runner import ProcessRunner
from ..discovery import TargetDiscovery


class OWASPZAPScanner(BaseScanner):
    def __init__(self):
        # Can run either via native zap-baseline.py CLI or zap.sh
        super().__init__(name="OWASP ZAP (Baseline)", category="DAST", binary_name="zap-baseline.py")

    def is_tool_available(self) -> bool:
        # Check either zap-baseline.py or zap.sh or docker
        return (
            super().is_tool_available()
            or ProcessRunner.find_binary("zap.sh") is not None
            or ProcessRunner.find_binary("docker") is not None
        )

    def scan(self, target_dir: Path) -> ToolResult:
        discovery = TargetDiscovery(target_dir)
        compose_files = discovery.discover_compose_files()
        target_url = os.environ.get("DAST_TARGET_URL")

        if not compose_files and not target_url:
            return self.create_not_applicable_result("No docker-compose file or DAST_TARGET_URL configured")

        if not self.is_tool_available():
            return self.create_skipped_result("Neither zap-baseline.py, zap.sh, nor docker found in PATH")

        # Default URL to scan if compose is present
        scan_url = target_url or "http://localhost:8080"
        report_json = target_dir / ".zap_report.json"

        # Determine run command (native zap-baseline.py or docker ghcr.io/zaproxy/zaproxy:stable)
        cmd = []
        if self.binary_path:
            cmd = [
                str(self.binary_path),
                "-t", scan_url,
                "-J", report_json.name,
                "-m", "2"  # 2 minute baseline limit
            ]
        elif ProcessRunner.find_binary("docker"):
            docker_bin = ProcessRunner.find_binary("docker")
            cmd = [
                str(docker_bin),
                "run", "--rm",
                "--network", "host",
                "-v", f"{target_dir}:/zap/wrk/:rw",
                "ghcr.io/zaproxy/zaproxy:stable",
                "zap-baseline.py",
                "-t", scan_url,
                "-J", report_json.name,
                "-m", "2"
            ]

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir), timeout=300)

        findings = FindingCounts()
        items = []
        status = StatusEnum.PASS
        summary = f"DAST baseline scan completed against {scan_url}"

        if report_json.exists():
            try:
                data = json.loads(report_json.read_text(encoding="utf-8"))
                site_alerts = data.get("site", [])
                for site in site_alerts:
                    alerts = site.get("alerts", [])
                    for alert in alerts:
                        riskcode = str(alert.get("riskcode", "0"))
                        sev = "LOW"
                        if riskcode == "3":
                            findings.high += 1
                            sev = "HIGH"
                        elif riskcode == "2":
                            findings.medium += 1
                            sev = "MEDIUM"
                        elif riskcode == "1":
                            findings.low += 1
                            sev = "LOW"
                        else:
                            findings.info += 1
                            sev = "INFO"

                        name = alert.get("alert", "ZAPAlert")
                        desc = alert.get("desc", "")[:100]
                        plugin_id = alert.get("pluginid", "ZAP")
                        uri = alert.get("instances", [{}])[0].get("uri", scan_url) if alert.get("instances") else scan_url

                        items.append(
                            FindingDetail(
                                severity=sev,
                                tool=self.name,
                                file=uri,
                                line="",
                                rule=f"ZAP-{plugin_id}",
                                description=f"{name}: {desc}"
                            )
                        )
            except Exception:
                pass
            finally:
                report_json.unlink(missing_ok=True)

        if findings.has_blocking:
            status = StatusEnum.FAIL
            summary = f"Detected {findings.high} High/Critical DAST vulnerability(ies) on {scan_url}"
        elif findings.total > 0:
            summary = f"Detected {findings.total} non-blocking alerts ({findings.medium} Med, {findings.low} Low)"

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
