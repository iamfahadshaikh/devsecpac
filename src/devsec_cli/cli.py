"""devsecpac / devsec-cli main entrypoint."""

import argparse
import sys
from pathlib import Path
from typing import List, Optional
from rich.console import Console

from .contracts import ToolResult, StatusEnum
from .discovery import TargetDiscovery
from .reporter import Reporter
from .installer import ToolInstaller
from .ingestion import RepoIngestion
from .scanners.secrets import GitleaksScanner, TruffleHogScanner
from .scanners.docker import HadolintScanner
from .scanners.iac import CheckovScanner, KubeconformScanner
from .scanners.kyverno import KyvernoScanner
from .scanners.codeql import CodeQLScanner
from .scanners.sonar import SonarQubeScanner
from .scanners.sca import TrivyFSScanner, DependencyCheckScanner
from .scanners.sbom import SyftScanner
from .scanners.dast import OWASPZAPScanner
from .scanners.k8s_audit import K8sStructuralAuditScanner
from .scanners.mobsf import MobSFScanner
from .scanners.nmap import NmapScanner
from .scanners.semgrep import SemgrepScanner
from .scanners.kubelinter import KubeLinterScanner


console = Console()


def build_scanners():
    return [
        GitleaksScanner(),
        TruffleHogScanner(),
        SemgrepScanner(),
        HadolintScanner(),
        CodeQLScanner(),
        SonarQubeScanner(),
        CheckovScanner(),
        KubeconformScanner(),
        KubeLinterScanner(),
        KyvernoScanner(),
        TrivyFSScanner(),
        DependencyCheckScanner(),
        SyftScanner(),
        OWASPZAPScanner(),
        NmapScanner(),
        MobSFScanner(),
        K8sStructuralAuditScanner(),
    ]


def filter_scanners(scanners, include_str: Optional[str] = None, exclude_str: Optional[str] = None):
    """Filters scanner instances by user-provided comma-separated include/exclude lists."""
    filtered = scanners

    def normalize(val: str) -> str:
        return val.lower().replace("-", "").replace("_", "").replace(" ", "")

    if include_str:
        targets = [normalize(t.strip()) for t in include_str.split(",") if t.strip()]
        selected = []
        for s in filtered:
            name_norm = normalize(s.name)
            bin_norm = normalize(s.binary_name) if s.binary_name else ""
            cat_norm = normalize(s.category.value if hasattr(s.category, "value") else str(s.category))
            if any(t in name_norm or (bin_norm and t in bin_norm) or t in cat_norm for t in targets):
                selected.append(s)
        filtered = selected

    if exclude_str:
        skips = [normalize(x.strip()) for x in exclude_str.split(",") if x.strip()]
        selected = []
        for s in filtered:
            name_norm = normalize(s.name)
            bin_norm = normalize(s.binary_name) if s.binary_name else ""
            cat_norm = normalize(s.category.value if hasattr(s.category, "value") else str(s.category))
            if not any(x in name_norm or (bin_norm and x in bin_norm) or x in cat_norm for x in skips):
                selected.append(s)
        filtered = selected

    return filtered


def run_info():
    """Prints diagnostic information about available security tools on the current host."""
    scanners = build_scanners()
    console.print("\n[bold cyan]DevSecOps Host Binary Detection Status (16 Engines)[/bold cyan]\n")
    for s in scanners:
        if s.binary_name is None:
            console.print(f"  * [green][OK][/green] {s.name:<32} (Native Python Engine)")
        elif s.binary_path or s.is_tool_available():
            found_path = s.binary_path or "Available (Container/CLI)"
            console.print(f"  * [green][OK][/green] {s.name:<32} Found: [dim]{found_path}[/dim]")
        else:
            console.print(f"  * [yellow][--][/yellow] {s.name:<32} [dim]Missing '{s.binary_name}' in PATH (will gracefully SKIP)[/dim]")
    console.print()
    console.print("[dim]Tip: Run 'devsec setup' to automatically install missing security scanners.[/dim]\n")


def run_setup():
    installer = ToolInstaller()
    installer.install_all()


def run_scan(
    target_path: Path,
    output_json: Path,
    output_md: Path,
    strict: bool = False,
    install_missing: bool = False,
    repo_url: Optional[str] = None,
    branch: Optional[str] = None,
    token: Optional[str] = None,
    keep_repo: bool = False,
    tools: Optional[str] = None,
    exclude: Optional[str] = None
) -> int:
    ingestion: Optional[RepoIngestion] = None

    # Handle remote repository ingestion
    if repo_url:
        ingestion = RepoIngestion(repo_url=repo_url, token=token, branch=branch, keep_repo=keep_repo)
        success, cloned_path, err = ingestion.clone_repository()
        if not success or not cloned_path:
            console.print(f"[bold red][FAIL] Remote Ingestion Failed:[/bold red] {err}\n")
            return 1
        target_path = cloned_path

    if install_missing:
        console.print("[bold blue]Checking and installing missing tools first...[/bold blue]")
        installer = ToolInstaller()
        installer.install_all()

    console.print(f"\n[bold green]Initiating DevSecOps Scan on:[/bold green] [bold white]{target_path.resolve()}[/bold white]\n")

    try:
        # Stack discovery
        discovery = TargetDiscovery(target_path)
        languages = discovery.detect_languages()
        dockerfiles = discovery.discover_dockerfiles()
        k8s = discovery.discover_k8s_manifests()
        iac = discovery.discover_iac_files()
        compose = discovery.discover_compose_files()

        console.print(f"  Target is Git repo: [bold]{'Yes' if discovery.is_git_repo() else 'No'}[/bold]")
        console.print(f"  Detected Runtimes: [bold]{', '.join(languages.keys()) if languages else 'None'}[/bold]")
        console.print(f"  Dockerfiles found: [bold]{len(dockerfiles)}[/bold]")
        console.print(f"  Kubernetes manifests: [bold]{len(k8s)}[/bold]")
        console.print(f"  IaC files found: [bold]{len(iac)}[/bold]")
        console.print(f"  Compose files found: [bold]{len(compose)}[/bold]")
        console.print()

        scanners = build_scanners()
        scanners = filter_scanners(scanners, include_str=tools, exclude_str=exclude)
        if not scanners:
            console.print("[bold yellow][WARN][/bold yellow] No security scanners matched the provided filters.\n")
            return 0
        results: List[ToolResult] = []

        for scanner in scanners:
            try:
                res = scanner.scan(target_path)
                results.append(res)
            except Exception as e:
                results.append(
                    ToolResult(
                        tool_name=scanner.name,
                        category=scanner.category,
                        status=StatusEnum.ERROR,
                        exit_code=1,
                        summary=f"Internal error: {str(e)}"
                    )
                )

        # Reporting & Terminal Output
        reporter = Reporter(console)
        reporter.print_terminal_table(results)
        reporter.print_findings_drilldown(results)
        reporter.generate_markdown_summary(results, output_md)
        reporter.export_json_report(results, output_json)

        console.print(f"[dim]Exported Markdown summary to: {output_md.name}[/dim]")
        console.print(f"[dim]Exported JSON report to:     {output_json.name}[/dim]\n")

        # Quality Gate evaluation
        total_crit = sum(r.findings.critical for r in results)
        total_high = sum(r.findings.high for r in results)
        total_med = sum(r.findings.medium for r in results)
        total_low = sum(r.findings.low for r in results)

        # Notify user with actionable guidance if SonarQube was skipped
        sonar_result = next((r for r in results if r.tool_name == "SonarQube"), None)
        if sonar_result and sonar_result.status == StatusEnum.SKIPPED and "unreachable" in sonar_result.summary.lower():
            console.print("[bold yellow]Tip: How to Enable SonarQube[/bold yellow]")
            console.print("  SonarQube was skipped because no running SonarQube server was detected.")
            console.print("  To enable SonarQube analysis:")
            console.print("    1. Start SonarQube: [cyan]docker run -d --name sonarqube -p 9000:9000 sonarqube:lts-community[/cyan]")
            console.print("    2. Open [link=http://localhost:9000]http://localhost:9000[/link] (Default login: [bold]admin[/bold] / [bold]admin[/bold])")
            console.print("    3. Generate Token: Go to [bold]User Icon (top-right) -> My Account -> Security -> Generate Token[/bold]")
            console.print("    4. Export variables in your terminal:")
            console.print("       [cyan]export SONAR_HOST_URL=\"http://localhost:9000\"[/cyan]")
            console.print("       [cyan]export SONAR_TOKEN=\"squ_your_token_here\"[/cyan]")
            console.print("  [dim]Note: GitHub CodeQL is already active and performing deep-AST SAST analysis.[/dim]\n")

        if (total_crit + total_high) > 0 or (strict and total_med > 0):
            console.print(
                f"[bold red][FAIL] Quality Gate FAILED[/bold red] "
                f"([bold red]{total_crit} Critical[/bold red], [red]{total_high} High[/red], "
                f"[yellow]{total_med} Med[/yellow], [blue]{total_low} Low[/blue] issues detected)!\n"
            )
            return 1
        else:
            console.print(
                f"[bold green][PASS] Quality Gate PASSED[/bold green] "
                f"(0 Critical, 0 High issues detected; [yellow]{total_med} Med[/yellow], [blue]{total_low} Low[/blue])!\n"
            )
            return 0

    finally:
        # Scrub temp cloned repository if applicable
        if ingestion:
            ingestion.cleanup()


def main():
    parser = argparse.ArgumentParser(
        prog="devsecpac",
        description="devsecpac: Universal Autonomous DevSecOps Scanner Orchestrator"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Run full security scan against target path or remote Git repo")
    scan_parser.add_argument("target", nargs="?", default=None, help="Local target path to scan (use '.' for current folder)")
    scan_parser.add_argument("-r", "--repo", help="Remote Git repository URL (HTTPS or SSH, e.g. https://github.com/org/repo.git)")
    scan_parser.add_argument("-b", "--branch", help="Specific branch/tag to checkout for remote repository scan")
    scan_parser.add_argument("--token", help="PAT / Token for private HTTPS repository ingestion")
    scan_parser.add_argument("--keep-repo", action="store_true", help="Preserve cloned repository files after scan finishes")
    scan_parser.add_argument("-t", "--tools", help="Comma-separated list of scanners to run (e.g. gitleaks,trivy,codeql)")
    scan_parser.add_argument("-x", "--exclude", help="Comma-separated list of scanners to exclude/skip")
    scan_parser.add_argument("--json", default="devsec-report.json", help="Path for JSON status report")
    scan_parser.add_argument("--md", default="devsec-summary.md", help="Path for Markdown executive summary")
    scan_parser.add_argument("--strict", action="store_true", help="Fail pipeline even on Medium severity issues")
    scan_parser.add_argument("--install-missing", action="store_true", help="Automatically download and install missing tools before scanning")

    # info command
    subparsers.add_parser("info", help="Show environment tool discovery status")

    # setup command
    subparsers.add_parser("setup", help="Auto-download and configure missing DevSecOps tools into user bin")

    args = parser.parse_args()

    if args.command == "info":
        run_info()
        sys.exit(0)
    elif args.command == "setup":
        run_setup()
        sys.exit(0)
    elif args.command == "scan":
        # Target must be explicitly '.' or a specific local directory, OR -r/--repo must be provided
        if not args.repo and args.target is None:
            console.print("[bold red][ERROR] Target not specified.[/bold red]")
            console.print("Please provide a target directory (use [bold cyan].[/bold cyan] for current folder) or [bold cyan]-r / --repo <url>[/bold cyan] for a remote Git repository.\n")
            scan_parser.print_help()
            sys.exit(1)

        target = Path(args.target).resolve() if args.target else Path(".").resolve()
        code = run_scan(
            target_path=target,
            output_json=Path(args.json),
            output_md=Path(args.md),
            strict=args.strict,
            install_missing=args.install_missing,
            repo_url=args.repo,
            branch=args.branch,
            token=args.token,
            keep_repo=args.keep_repo,
            tools=args.tools,
            exclude=args.exclude
        )
        sys.exit(code)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
