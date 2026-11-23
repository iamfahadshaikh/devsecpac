"""SonarQube SAST and Quality Gate Scanner."""

from pathlib import Path
import os
import json
import time
import urllib.request
import base64
from rich.prompt import Confirm
from rich.console import Console
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
from ..runner import ProcessRunner
from ..discovery import TargetDiscovery

console = Console()


class SonarQubeScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="SonarQube", category="Code Quality & SAST", binary_name="sonar-scanner")

    def _save_cached_token(self, token: str):
        """Caches auto-generated token to ~/.devsec/sonar_token for future scans."""
        try:
            cache_file = Path.home() / ".devsec" / "sonar_token"
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(token.strip(), encoding="utf-8")
        except Exception:
            pass

    def _resolve_token(self) -> str:
        """Finds SonarQube token from environment, devsec cache, or global sonar-scanner.properties config."""
        token = os.environ.get("SONAR_TOKEN", "")
        if token:
            return token

        # Check ~/.devsec/sonar_token cache
        cache_file = Path.home() / ".devsec" / "sonar_token"
        if cache_file.exists():
            try:
                cached = cache_file.read_text(encoding="utf-8").strip()
                if cached:
                    return cached
            except Exception:
                pass

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

    def _check_server_reachable(self, sonar_host: str) -> bool:
        """Checks if SonarQube server is reachable and active."""
        try:
            req = urllib.request.Request(f"{sonar_host.rstrip('/')}/api/system/status")
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
                # Return True only if status is strictly UP
                return data.get("status") == "UP"
        except Exception:
            return False

    def _auto_generate_token(self, sonar_host: str) -> str:
        """Attempts to auto-generate a devsec-cli token using default admin:admin."""
        try:
            url = f"{sonar_host.rstrip('/')}/api/user_tokens/generate"
            params = f"name=devsec-cli-{int(time.time())}".encode("utf-8")
            req = urllib.request.Request(url, data=params, method="POST")
            auth_str = base64.b64encode(b"admin:admin").decode()
            req.add_header("Authorization", f"Basic {auth_str}")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                return data.get("token", "")
        except Exception as e:
            return ""

    def _prompt_start_sonarqube(self, sonar_host: str) -> str:
        """Prompts user if they want to start a local SonarQube container automatically."""
        import sys
        if not sys.stdin.isatty():
            return ""

        docker_bin = ProcessRunner.find_binary("docker")
        if not docker_bin:
            return ""

        console.print("\n[bold yellow]SonarQube server is not reachable.[/bold yellow]")
        if not Confirm.ask("Would you like devsec to launch a SonarQube container via Docker?"):
            return ""

        # Check if container named 'sonarqube' already exists
        code, stdout, _, _ = ProcessRunner.run_command([docker_bin, "ps", "-a", "--filter", "name=sonarqube", "--format", "{{.Names}}"])
        if "sonarqube" in stdout:
            console.print("  * Starting existing [bold cyan]sonarqube[/bold cyan] container...")
            ProcessRunner.run_command([docker_bin, "start", "sonarqube"])
        else:
            console.print("  * Pulling and starting [bold cyan]sonarqube:lts-community[/bold cyan] on port 9000...")
            ProcessRunner.run_command([
                docker_bin, "run", "-d", "--name", "sonarqube",
                "-p", "9000:9000", "sonarqube:lts-community"
            ])

        # Wait for SonarQube to be UP
        with console.status("[bold blue]Waiting for SonarQube server to become ready (this may take up to 45s)...[/bold blue]"):
            for _ in range(60):
                if self._check_server_reachable(sonar_host):
                    break
                time.sleep(2)

        # Attempt auto-generating token
        token = self._auto_generate_token(sonar_host)
        if token:
            self._save_cached_token(token)
            console.print(f"  * [bold green][OK][/bold green] Generated analysis token: [dim]{token[:12]}...[/dim]")
        return token

    def scan(self, target_dir: Path) -> ToolResult:
        discovery = TargetDiscovery(target_dir)
        languages = discovery.detect_languages()

        if not languages:
            return self.create_not_applicable_result("No application source files detected")

        if not self.is_tool_available():
            return self.create_skipped_result("sonar-scanner binary not found in PATH")

        sonar_host = os.environ.get("SONAR_HOST_URL", "http://localhost:9000")
        sonar_token = self._resolve_token()

        # If not reachable and no token, prompt user to start it or auto-connect
        if not self._check_server_reachable(sonar_host):
            new_token = self._prompt_start_sonarqube(sonar_host)
            if new_token:
                sonar_token = new_token
            elif not self._check_server_reachable(sonar_host):
                return self.create_skipped_result("SonarQube server unreachable (export SONAR_HOST_URL & SONAR_TOKEN)")

        # If server is reachable but token is still missing, try auto-generating or using default
        if not sonar_token and self._check_server_reachable(sonar_host):
            sonar_token = self._auto_generate_token(sonar_host)
            if sonar_token:
                self._save_cached_token(sonar_token)
                console.print(f"  * [bold green][OK][/bold green] SonarQube connected with auto-generated token: [dim]{sonar_token[:12]}...[/dim]")

        if sonar_token:
            console.print(f"  * SonarQube Auth: [bold green]Token authenticated[/bold green] ([dim]{sonar_token[:8]}...[/dim])")
        else:
            console.print("  * SonarQube Auth: [bold yellow]Anonymous (no token found)[/bold yellow]")

        # If still no token, pass empty or let sonar-scanner try anonymous/default
        console.print(f"  * SonarQube Target Host: [bold cyan]{sonar_host}[/bold cyan]")

        project_key = target_dir.name

        cmd = [
            str(self.binary_path),
            f"-Dsonar.projectKey={project_key}",
            f"-Dsonar.sources={target_dir}",
            f"-Dsonar.host.url={sonar_host}"
        ]
        # SonarQube token supports both -Dsonar.token and -Dsonar.login
        if sonar_token:
            cmd.extend([f"-Dsonar.token={sonar_token}", f"-Dsonar.login={sonar_token}"])

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir), timeout=600)

        if code != 0:
            console.print(f"  * [bold red][FAIL][/bold red] SonarQube Scanner Failed (Exit Code: {code}):")
            if stdout:
                console.print(f"[dim yellow]--- SonarScanner STDOUT ---[/dim yellow]\n{stdout}")
            if stderr:
                console.print(f"[dim red]--- SonarScanner STDERR ---[/dim red]\n{stderr}")
            return self.create_skipped_result("SonarQube analysis failed")

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
