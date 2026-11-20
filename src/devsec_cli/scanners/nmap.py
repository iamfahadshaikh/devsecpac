"""Nmap Container and Service Port Readiness Scanner."""

from pathlib import Path
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
from ..runner import ProcessRunner
from ..discovery import TargetDiscovery


class NmapScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Nmap (Port & Service Probe)", category="Network Security", binary_name="nmap")

    def scan(self, target_dir: Path) -> ToolResult:
        discovery = TargetDiscovery(target_dir)
        compose = discovery.discover_compose_files()

        # Only run Nmap if local container or compose configuration is present
        if not compose:
            return self.create_not_applicable_result("No docker-compose or containerized service detected for port inspection")

        if not self.is_tool_available():
            return self.create_skipped_result("nmap binary not found in PATH")

        # Probe standard application service ports on localhost
        ports = "80,443,3000,5000,8000,8080,8443,9000"
        cmd = [
            str(self.binary_path),
            "-p", ports,
            "-T4",
            "--open",
            "127.0.0.1"
        ]

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir), timeout=60)

        findings = FindingCounts()
        items = []
        open_ports = []

        for line in stdout.splitlines():
            line = line.strip()
            if "/tcp" in line and "open" in line:
                port_part = line.split("/")[0]
                open_ports.append(port_part)
                items.append(
                    FindingDetail(
                        severity="LOW",
                        tool=self.name,
                        file="localhost",
                        line=port_part,
                        rule="OPEN-SERVICE-PORT",
                        description=f"Port {port_part}/tcp is actively open and listening"
                    )
                )

        status = StatusEnum.PASS
        if open_ports:
            summary = f"Detected {len(open_ports)} listening service port(s): {', '.join(open_ports)}"
        else:
            summary = "No exposed service ports actively listening on localhost"

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
