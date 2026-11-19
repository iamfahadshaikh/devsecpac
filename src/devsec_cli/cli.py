"""devsec-cli main entrypoint."""

import argparse
import sys
from pathlib import Path
from typing import List
from rich.console import Console

from .contracts import ToolResult, StatusEnum
from .discovery import TargetDiscovery
from .reporter import Reporter
from .installer import ToolInstaller
from .scanners.secrets import GitleaksScanner, TruffleHogScanner
from .scanners.docker import HadolintScanner
from .scanners.iac import CheckovScanner, KubeconformScanner
from .scanners.sca import TrivyFSScanner, DependencyCheckScanner
from .scanners.sbom import SyftScanner
from .scanners.k8s_audit import K8sStructuralAuditScanner


console = Console()


def build_scanners():
    return [
        GitleaksScanner(),
        TruffleHogScanner(),
        HadolintScanner(),
        CheckovScanner(),
        KubeconformScanner(),
        TrivyFSScanner(),
        DependencyCheckScanner(),
        SyftScanner(),
        K8sStructuralAuditScanner(),
    ]


def run_info():
    """Prints diagnostic information about available security tools on the current host."""
    scanners = build_scanners()
    console.print("\n[bold cyan]🔧 DevSecOps Host Binary Detection Status[/bold cyan]\n")
    for s in scanners:
        if s.binary_name is None:
            console.print(f"  • [green]✔[/green] {s.name:<32} (Native Python Engine)")
        elif s.binary_path:
            console.print(f"  • [green]✔[/green] {s.name:<32} Found: [dim]{s.binary_path}[/dim]")
        else:
            console.print(f"  • [yellow]✘[/yellow] {s.name:<32} [dim]Missing '{s.binary_name}' in PATH (will gracefully SKIP)[/dim]")
    console.print()
    console.print("[dim]💡 Run 'devsec setup' to automatically install missing security scanners.[/dim]\n")


def run_setup():
    installer = ToolInstaller()
    installer.install_all()


def run_scan(target_path: Path, output_json: Path, output_md: Path, strict: bool = False, install_missing: bool = False) -> int:
    if install_missing:
        console.print("[bold blue]🔍 Checking and installing missing tools first...[/bold blue]")
        installer = ToolInstaller()
        installer.install_all()

    console.print(f"\n[bold green]🚀 Initiating DevSecOps Scan on:[/bold green] [bold white]{target_path.resolve()}[/bold white]\n")

    # Stack discovery
    discovery = TargetDiscovery(target_path)
    languages = discovery.detect_languages()
    dockerfiles = discovery.discover_dockerfiles()
    k8s = discovery.discover_k8s_manifests()
    iac = discovery.discover_iac_files()

    console.print(f"  📁 Target is Git repo: [bold]{'Yes' if discovery.is_git_repo() else 'No'}[/bold]")
    console.print(f"  📦 Detected Runtimes: [bold]{', '.join(languages.keys()) if languages else 'None'}[/bold]")
    console.print(f"  🐳 Dockerfiles found: [bold]{len(dockerfiles)}[/bold]")
    console.print(f"  ☸️  Kubernetes manifests: [bold]{len(k8s)}[/bold]")
    console.print(f"  🏗️  IaC files found: [bold]{len(iac)}[/bold]")
    console.print()

    scanners = build_scanners()
    results: List[ToolResult] = []

    with console.status("[bold blue]Executing security scanners...[/bold blue]", spinner="dots"):
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

    # Reporting
    reporter = Reporter(console)
    reporter.print_terminal_table(results)
    reporter.generate_markdown_summary(results, output_md)
    reporter.export_json_report(results, output_json)

    console.print(f"[dim]📄 Exported Markdown summary to: {output_md.name}[/dim]")
    console.print(f"[dim]📊 Exported JSON report to:     {output_json.name}[/dim]\n")

    # Quality Gate evaluation
    total_crit = sum(r.findings.critical for r in results)
    total_high = sum(r.findings.high for r in results)
    total_med = sum(r.findings.medium for r in results)

    if (total_crit + total_high) > 0 or (strict and total_med > 0):
        console.print("[bold red]❌ Quality Gate FAILED (High/Critical issues detected)![/bold red]\n")
        return 1
    else:
        console.print("[bold green]✅ Quality Gate PASSED![/bold green]\n")
        return 0


def main():
    parser = argparse.ArgumentParser(
        prog="devsec",
        description="devsec-cli: Universal Autonomous DevSecOps Scanner Orchestrator"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Run full security scan against target path")
    scan_parser.add_argument("target", nargs="?", default=".", help="Target path to scan (default: current directory)")
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
        target = Path(args.target).resolve()
        code = run_scan(target, Path(args.json), Path(args.md), strict=args.strict, install_missing=args.install_missing)
        sys.exit(code)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
