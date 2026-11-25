"""Autonomous Remediation Engine for DevSecPac v3.0."""

from pathlib import Path
from typing import List, Dict
import re
import difflib
from rich.console import Console
from .contracts import FindingDetail

console = Console()


class RemediationEngine:
    """Analyzes findings and generates standard unified git patches for common fixable issues.
    
    Supported Auto-Fixes:
      - Dockerfile caching: adds --no-cache-dir to pip install (DL3042)
      - Dockerfile package cleanup: adds -y --no-install-recommends and list cleanup to apt-get (DL3008)
      - Dockerfile numeric UID enforcement: replaces username with numeric UID if defined (DL3066)
      - Standard unified git diff generation compatible with `git apply --check`
    """

    def __init__(self, target_dir: Path):
        self.target_dir = target_dir

    def generate_remediation_patch(self, findings: List[FindingDetail], patch_path: Path) -> int:
        """Generates a standard unified git patch for fixable issues using difflib."""
        all_diffs = []
        fixes_applied = 0

        # Scan for Dockerfile issues
        dockerfiles = list(self.target_dir.glob("**/Dockerfile*"))
        for df in dockerfiles:
            if not df.is_file() or ".git" in df.parts:
                continue

            orig_text = df.read_text(encoding="utf-8")
            content = orig_text

            # Fix DL3042: Avoid cache directory with pip install by adding --no-cache-dir
            if re.search(r"pip\s+install\s+(?!.*--no-cache-dir)", content):
                content = re.sub(r"(pip\s+install\s+)", r"\1--no-cache-dir ", content)
                fixes_applied += 1

            # Fix DL3008: apt-get install without cleanup or without --no-install-recommends
            if "apt-get install" in content:
                if "--no-install-recommends" not in content:
                    content = content.replace("apt-get install", "apt-get install -y --no-install-recommends")
                    fixes_applied += 1
                if "rm -rf /var/lib/apt/lists/*" not in content and "apt-get update" in content:
                    content = content.replace("apt-get update", "apt-get update && rm -rf /var/lib/apt/lists/* # devsec-fix")
                    fixes_applied += 1

            # Fix DL3066: Non-numeric user-id (e.g. USER devsecuser -> USER 10001)
            uid_match = re.search(r"useradd\s+.*?-u\s+(\d+)\s+.*?(\w+)\s*(?:&&|$)", content)
            if uid_match:
                uid, uname = uid_match.group(1), uid_match.group(2)
                user_stmt = f"USER {uname}"
                if user_stmt in content:
                    count = content.count(user_stmt)
                    content = content.replace(user_stmt, f"USER {uid}")
                    fixes_applied += count

            if content != orig_text:
                rel_path = df.relative_to(self.target_dir).as_posix()
                orig_lines = orig_text.splitlines(keepends=True)
                new_lines = content.splitlines(keepends=True)
                diff = list(difflib.unified_diff(
                    orig_lines,
                    new_lines,
                    fromfile=f"a/{rel_path}",
                    tofile=f"b/{rel_path}",
                    n=3
                ))
                if diff:
                    all_diffs.extend(diff)

        if all_diffs:
            patch_content = "".join(all_diffs)
            # Write with newline='\n' to ensure clean Unix diff formatting for git apply
            with open(patch_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(patch_content)
            console.print(f"[bold green][OK][/bold green] Generated unified remediation patch: [bold cyan]{patch_path.name}[/bold cyan] ({fixes_applied} auto-fixable issue(s))")
            console.print(f"[dim]Tip: Review the suggested diff and apply with: git apply {patch_path.name}[/dim]")
        else:
            console.print("[dim yellow]No deterministic auto-fixes identified for current findings.[/dim yellow]")

        return fixes_applied
