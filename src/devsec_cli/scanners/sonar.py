"""SonarQube SAST and Quality Gate Scanner."""

from pathlib import Path
import os
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
from ..runner import ProcessRunner
from ..discovery import TargetDiscovery


"""SonarQube SAST and Quality Gate Scanner."""

from pathlib import Path
import os
import json
import urllib.request
import base64
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
from ..runner import ProcessRunner
from ..discovery import TargetDiscovery


class SonarQubeScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="SonarQube", category="Code Quality & SAST", binary_name="sonar-scanner")

    def _resolve_token(self) -> str:
        """Finds SonarQube token from environment or global sonar-scanner.properties config."""
        token = os.environ.get("SONAR_TOKEN", "")
        if token:
            return token

        # Check ~/.local/bin/sonar-scanner-*/conf/sonar-scanner.properties or /etc
        search_paths = [
            Path.home() / ".local" / "bin",
            Path.home() / ".local" / "opt"
        ]
        for base in search_paths:
            for conf in base.glob("**/conf/sonar-scanner.properties"):
                try:
                    for line in conf.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if line.startswith("sonar.token=") or line.startswith("sonar.login="):
                            return line.split("=", 1)[1].strip()
                except Exception:
                    pass
        return ""

    def _fetch_sonar_issues(self, sonar_host: str, sonar_token: str, project_key: str):
        """Fetches active security vulnerabilities and hotspots directly from SonarQube REST API."""
        findings = FindingCounts()
        items = []

        try:
            url = f"{sonar_host.rstrip('/')}/api/issues/search?componentKeys={project_key}&ps=100"
            req = urllib.request.Request(url)
            if sonar_token:
                # Sonar accepts token as Basic Auth username with empty password
                auth_str = base64.b64encode(f"{sonar_token}:".encode()).decode()
                req.add_header("Authorization", f"Basic {auth_str}")

            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                issues = data.get("issues", [])

                for issue in issues:
                    # Ignore resolved or closed issues
                    if issue.get("status") == "CLOSED" or issue.get("resolution"):
                        continue

                    # Filter for Security vulnerabilities, hotspots, or bugs
                    issue_type = issue.get("type", "")
                    severity = str(issue.get("severity", "INFO")).upper()
                    impacts = issue.get("impacts", [])
                    # Check if impact is security
                    is_security = issue_type in ("VULNERABILITY", "SECURITY_HOTSPOT", "BUG") or any(
                        imp.get("softwareQuality") == "SECURITY" for imp in impacts
                    )

                    if not is_security:
                        continue

                    sev_level = "LOW"
                    if severity in ("BLOCKER", "CRITICAL"):
                        findings.critical += 1
                        sev_level = "CRITICAL"
                    elif severity == "MAJOR":
                        findings.high += 1
                        sev_level = "HIGH"
                    elif severity == "MINOR":
                        findings.medium += 1
                        sev_level = "MEDIUM"
                    else:
                        findings.low += 1
                        sev_level = "LOW"

                    raw_component = issue.get("component", "")
                    clean_file = raw_component.replace(f"{project_key}:", "")
                    line_num = str(issue.get("line", issue.get("textRange", {}).get("startLine", "")))

                    items.append(
                        FindingDetail(
                            severity=sev_level,
                            tool=self.name,
                            file=clean_file,
                            line=line_num,
                            rule=issue.get("rule", "SonarRule"),
                            description=issue.get("message", "SonarQube issue detected")
                        )
                    )
        except Exception:
            pass

        return findings, items

    def scan(self, target_dir: Path) -> ToolResult:
        discovery = TargetDiscovery(target_dir)
        languages = discovery.detect_languages()

        if not languages:
            return self.create_not_applicable_result("No application source files detected")

        if not self.is_tool_available():
            return self.create_skipped_result("sonar-scanner binary not found in PATH")

        sonar_host = os.environ.get("SONAR_HOST_URL", "http://localhost:9000")
        sonar_token = self._resolve_token()
        project_key = target_dir.name

        cmd = [
            str(self.binary_path),
            f"-Dsonar.projectKey={project_key}",
            f"-Dsonar.sources={target_dir}",
            f"-Dsonar.host.url={sonar_host}"
        ]
        if sonar_token:
            cmd.append(f"-Dsonar.token={sonar_token}")

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir), timeout=600)

        if code != 0:
            return self.create_skipped_result("SonarQube server unreachable (export SONAR_HOST_URL & SONAR_TOKEN)")

        # Query REST API for detailed findings
        findings, items = self._fetch_sonar_issues(sonar_host, sonar_token, project_key)

        # Check for Quality Gate failure in CLI output
        output_combined = stdout + stderr
        qg_failed = "QUALITY GATE STATUS: FAILED" in output_combined

        if qg_failed or (findings.critical + findings.high) > 0:
            status = StatusEnum.FAIL
            summary = f"SonarQube detected {findings.critical} Critical, {findings.high} High issue(s)"
        elif (findings.medium + findings.low) > 0:
            status = StatusEnum.PASS
            summary = f"SonarQube detected {findings.medium + findings.low} non-blocking issue(s)"
        else:
            status = StatusEnum.PASS
            summary = "SonarQube analysis passed"

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
