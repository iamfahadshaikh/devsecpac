"""devsecpac / devsec-cli main entrypoint."""

import argparse
import os
import sys
import time
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
from .scanners.schemathesis import SchemathesisScanner
from .scanners.cosign import CosignAttestationEngine


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
        KyvernoScanner(),
        TrivyFSScanner(),
        DependencyCheckScanner(),
        SyftScanner(),
        CosignAttestationEngine(),
        OWASPZAPScanner(),
        SchemathesisScanner(),
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
        # Stack and File discovery
        discovery = TargetDiscovery(target_path)
        languages = discovery.detect_languages()
        dockerfiles = discovery.discover_dockerfiles()
        k8s = discovery.discover_k8s_manifests()
        iac = discovery.discover_iac_files()
        compose = discovery.discover_compose_files()
        all_scannable_files = discovery.discover_scannable_files()
        total_files_count = len(all_scannable_files)

        console.print(f"  Target is Git repo: [bold]{'Yes' if discovery.is_git_repo() else 'No'}[/bold]")
        console.print(f"  Total Scannable Files: [bold]{total_files_count}[/bold]")
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

        total_scanners = len(scanners)
        start_overall_time = time.time()
        processed_files_set = set()

        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("[bold yellow]{task.completed}/{task.total} engines"),
            TextColumn("•"),
            TextColumn("[green]{task.fields[file_progress]}"),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=console,
            transient=True
        ) as progress:
            scan_task = progress.add_task(
                "Running security scan pipeline...",
                total=total_scanners,
                file_progress=f"0/{total_files_count} files"
            )

            for idx, scanner in enumerate(scanners, start=1):
                progress.update(
                    scan_task,
                    description=f"Scanning with [{idx}/{total_scanners}] {scanner.name}..."
                )
                progress.refresh()
                try:
                    res = scanner.scan(target_path)
                    results.append(res)
                except Exception as e:
                    res = ToolResult(
                        tool_name=scanner.name,
                        category=scanner.category,
                        status=StatusEnum.ERROR,
                        exit_code=1,
                        summary=f"Internal error: {str(e)}"
                    )
                    results.append(res)

                # Collect per-file count progress
                if res.file_timings:
                    for fpath in res.file_timings:
                        processed_files_set.add(fpath)
                elif res.status in (StatusEnum.PASS, StatusEnum.FAIL) and scanner.category in ("Fast SAST", "SAST", "Secret Detection", "SCA & Vulnerability", "SBOM Generation", "Code Quality & SAST"):
                    for f in all_scannable_files:
                        rel = str(f.relative_to(target_path)) if str(f).startswith(str(target_path)) else f.name
                        processed_files_set.add(rel)

                current_files_count = len(processed_files_set)
                if total_files_count > 0:
                    current_files_count = min(current_files_count, total_files_count)
                progress.update(
                    scan_task,
                    advance=1,
                    file_progress=f"{current_files_count}/{total_files_count} files"
                )

        total_elapsed_overall = round(time.time() - start_overall_time, 2)

        # Apply specific finding bypasses from .devsecignore if present
        from .bypass import FindingBypassManager
        bypass_mgr = FindingBypassManager(target_path)
        results, bypassed_total = bypass_mgr.filter_tool_results(results)
        if bypassed_total > 0:
            console.print(f"[dim cyan][INFO] Suppressed {bypassed_total} finding(s) matching .devsecignore rules.[/dim cyan]")

        # Reporting & Terminal Output
        reporter = Reporter(console)
        reporter.print_terminal_table(results)
        reporter.print_findings_drilldown(results)
        reporter.generate_markdown_summary(results, output_md)

        telemetry_payload = {
            "total_files": total_files_count,
            "total_elapsed_seconds": total_elapsed_overall,
            "total_engines": total_scanners
        }
        reporter.export_json_report(results, output_json, telemetry=telemetry_payload)

        console.print(f"[dim]Exported Markdown summary to: {output_md.name}[/dim]")
        console.print(f"[dim]Exported JSON report to:     {output_json.name}[/dim]")
        console.print(f"[bold cyan]Total Scan Time:[/bold cyan] [bold white]{total_elapsed_overall}s[/bold white] across [bold white]{total_files_count}[/bold white] files\n")

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

        total_all_issues = total_crit + total_high + total_med + total_low

        if total_all_issues > 0:
            console.print("[bold cyan]Automated Remediation & Fix Suggestions:[/bold cyan]")
            console.print("  Generate a recommended remediation patch to test locally before committing:")
            console.print("    [bold white]devsec fix . --patch-output devsec-fix.patch[/bold white]")
            console.print("  Inspect and test the patch locally (e.g. [dim]git apply --check devsec-fix.patch[/dim]).")
            console.print("  Once verified in your local environment, commit and push the updates.")
            console.print()
            console.print("[bold yellow]False Positive or Accepted Risk Bypass:[/bold yellow]")
            console.print("  To permanently suppress a specific finding without altering your global quality gate,")
            console.print("  add the exact file and rule/CVE to [bold white].devsecignore[/bold white]:")
            console.print("    [dim]echo \"Dockerfile:DL3008\" >> .devsecignore[/dim]    # Suppress rule on specific file")
            console.print("    [dim]echo \"CVE-2024-XXXX\" >> .devsecignore[/dim]       # Suppress specific vulnerability")
            console.print()

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
    scan_parser.add_argument("--defectdojo-push", action="store_true", help="Push consolidated findings to active DefectDojo instance")
    scan_parser.add_argument("--defectdojo-url", default=os.environ.get("DEFECTDOJO_URL", "http://localhost:8080"), help="DefectDojo base URL")
    scan_parser.add_argument("--defectdojo-key", default=os.environ.get("DEFECTDOJO_KEY", ""), help="DefectDojo API v2 Key")
    scan_parser.add_argument("--defectdojo-engagement", type=int, default=int(os.environ.get("DEFECTDOJO_ENGAGEMENT_ID", "1")), help="Target DefectDojo Engagement ID")

    # info command
    subparsers.add_parser("info", help="Show environment tool discovery status")

    # setup command
    subparsers.add_parser("setup", help="Auto-download and configure missing DevSecOps tools into user bin")

    # fix command
    fix_parser = subparsers.add_parser("fix", help="Generate recommended remediation patch for detected issues")
    fix_parser.add_argument("target", nargs="?", default=".", help="Local target path to fix (default: .)")
    fix_parser.add_argument("--patch-output", default="devsec-fix.patch", help="Path for output unified git patch file")

    # pr-comment command
    pr_parser = subparsers.add_parser("pr-comment", help="Generate or post interactive GitHub PR comment from scan results")
    pr_parser.add_argument("--json", default="devsec-report.json", help="Path of existing scan JSON report")
    pr_parser.add_argument("--output", default="devsec-pr-comment.md", help="Path to write PR markdown comment")

    args = parser.parse_args()

    if args.command == "info":
        run_info()
        sys.exit(0)
    elif args.command == "setup":
        run_setup()
        sys.exit(0)
    elif args.command == "pr-comment":
        from .ci import CICDIntegrator
        report_file = Path(args.json)
        if not report_file.exists():
            console.print(f"[bold red][ERROR] Report file not found: {report_file}[/bold red]")
            sys.exit(1)
        results = CICDIntegrator.load_results_from_json(report_file)
        comment_md = CICDIntegrator.generate_pr_comment(results)
        out_path = Path(args.output)
        out_path.write_text(comment_md, encoding="utf-8")
        console.print(f"[bold green][OK][/bold green] Generated PR Markdown comment at: [bold cyan]{out_path}[/bold cyan]")
        sys.exit(0)
    elif args.command == "fix":
        from .remediation import RemediationEngine
        target = Path(args.target).resolve()
        engine = RemediationEngine(target)
        patch_file = Path(args.patch_output)
        engine.generate_remediation_patch([], patch_file)
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

        if args.defectdojo_push or os.environ.get("DEFECTDOJO_PUSH"):
            from .ci import CICDIntegrator
            dojo_key = args.defectdojo_key or os.environ.get("DEFECTDOJO_KEY", "")
            if not dojo_key:
                console.print("[yellow][WARN] DefectDojo push skipped: API key not provided (pass --defectdojo-key or export DEFECTDOJO_KEY)[/yellow]")
            else:
                console.print(f"Pushed to DefectDojo engagement #{args.defectdojo_engagement} at {args.defectdojo_url}...", end=" ")
                pushed = CICDIntegrator.push_to_defectdojo(
                    json_report_path=Path(args.json),
                    dojo_url=args.defectdojo_url,
                    api_key=dojo_key,
                    engagement_id=args.defectdojo_engagement
                )
                if pushed:
                    console.print("[bold green][OK][/bold green]")
                else:
                    console.print("[bold red][FAILED][/bold red]")

        sys.exit(code)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
