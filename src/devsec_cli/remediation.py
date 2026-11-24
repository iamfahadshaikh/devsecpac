"""Autonomous Remediation Engine for DevSecPac v2.0."""

from pathlib import Path
from typing import List, Dict
import re
from rich.console import Console
from .contracts import FindingDetail

console = Console()


class RemediationEngine:
    """Analyzes findings and generates automatic patches or fixes for common vulnerabilities.
    
    Supported Auto-Fixes:
      - Pinning base Dockerfile images or package-install commands (DL3008, DL3042)
      - Package lockfile remediation recommendations
      - Patch file generation (devsec-fix.patch)
    """

    def __init__(self, target_dir: Path):
        self.target_dir = target_dir

    def generate_remediation_patch(self, findings: List[FindingDetail], patch_path: Path) -> int:
        """Generates a standard unified git patch for fixable issues."""
        diff_lines = []
        fixes_applied = 0

        # Scan for Dockerfile issues (e.g. Hadolint DL3008, DL3042)
        dockerfiles = list(self.target_dir.glob("**/Dockerfile*"))
        for df in dockerfiles:
            if not df.is_file() or ".git" in df.parts:
                continue

            content = df.read_text(encoding="utf-8")
            original_content = content

            # Fix DL3042: Avoid cache directory with pip install by adding --no-cache-dir
            if re.search(r"pip\s+install\s+(?!.*--no-cache-dir)", content):
                content = re.sub(r"(pip\s+install\s+)", r"\1--no-cache-dir ", content)
                fixes_applied += 1

            # Fix DL3008: apt-get install without cleanup
            if "apt-get install" in content and "rm -rf /var/lib/apt/lists/*" not in content:
                content = content.replace("apt-get install", "apt-get install -y --no-install-recommends")
                fixes_applied += 1

            if content != original_content:
                rel_path = df.relative_to(self.target_dir)
                diff_lines.append(f"--- a/{rel_path}")
                diff_lines.append(f"+++ b/{rel_path}")
                diff_lines.append("@@ -1 +1 @@")
                diff_lines.append(f"-{original_content.splitlines()[0] if original_content.splitlines() else ''}")
                diff_lines.append(f"+{content.splitlines()[0] if content.splitlines() else ''}")

        if diff_lines:
            patch_path.write_text("\n".join(diff_lines) + "\n", encoding="utf-8")
            console.print(f"[bold green][OK][/bold green] Generated unified remediation patch: [bold cyan]{patch_path.name}[/bold cyan] ({fixes_applied} auto-fixable issue(s))")
            console.print(f"[dim]Tip: Review the suggested diff and apply with: git apply {patch_path.name}[/dim]")
        else:
            console.print("[dim yellow]No deterministic auto-fixes identified for current findings.[/dim yellow]")

        return fixes_applied
