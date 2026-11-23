"""Universal Remote Git Ingestion Engine for devsecpac.

Securely clones any Git repository (GitHub, GitLab, Azure DevOps, Bitbucket, self-hosted)
via HTTPS or SSH with complete commit history across all branches without leaking credentials.
"""

import os
import sys
import shutil
import tempfile
import stat
from pathlib import Path
from typing import Optional, Tuple
from rich.console import Console
from .runner import ProcessRunner

console = Console()


class RepoIngestion:
    def __init__(self, repo_url: str, token: Optional[str] = None, branch: Optional[str] = None, keep_repo: bool = False):
        self.repo_url = repo_url.strip()
        self.token = token or os.environ.get("GIT_TOKEN") or os.environ.get("GITHUB_TOKEN") or os.environ.get("AZURE_DEVOPS_EXT_PAT") or os.environ.get("GITLAB_TOKEN")
        self.branch = branch
        self.keep_repo = keep_repo
        self.temp_dir: Optional[Path] = None

    def clone_repository(self) -> Tuple[bool, Optional[Path], str]:
        """
        Clones the remote repository with full history across all branches.
        Returns: (success: bool, target_path: Optional[Path], error_message: str)
        """
        git_bin = ProcessRunner.find_binary("git")
        if not git_bin:
            return False, None, "git executable not found in PATH"

        # Create temporary isolated directory
        self.temp_dir = Path(tempfile.mkdtemp(prefix="devsec_target_"))
        clone_target = self.temp_dir / "repo"

        console.print(f"[bold cyan]Ingesting Remote Repository:[/bold cyan] [bold white]{self.repo_url}[/bold white]")
        if self.token:
            console.print("  * Auth: [green]Secure Ephemeral Credential Helper (GIT_ASKPASS)[/green]")
        else:
            console.print("  * Auth: [yellow]Anonymous / SSH Agent Auth[/yellow]")

        askpass_path: Optional[Path] = None
        env = os.environ.copy()
        # Strictly disable interactive terminal prompts across all Git/SSH operations
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_SSH_COMMAND"] = "ssh -o BatchMode=yes"

        try:
            # Configure GIT_ASKPASS if token provided to prevent process table sniffing (ps aux)
            if self.token:
                askpass_path = self._create_askpass_helper(self.token)
                env["GIT_ASKPASS"] = str(askpass_path)
                env["DEVSEC_EPHEMERAL_PAT"] = self.token

            # Full un-shallow clone command with all branches
            clone_cmd = [
                git_bin,
                "clone",
                "--no-single-branch",  # Fetch all branches
                self.repo_url,
                str(clone_target)
            ]

            console.print("  * Fetching complete commit history (all branches & full depth)...")
            code, stdout, stderr, elapsed = ProcessRunner.run_command(clone_cmd, timeout=900, env=env)

            if code != 0:
                # Sanitized error message (strip token if inadvertently output)
                sanitized_err = stderr
                if self.token:
                    sanitized_err = sanitized_err.replace(self.token, "********")
                
                auth_hint = ""
                lower_err = sanitized_err.lower()
                if "could not read password" in lower_err or "terminal prompts disabled" in lower_err or "authentication failed" in lower_err or "permission denied" in lower_err:
                    auth_hint = (
                        "\n\n[bold yellow]Authentication Required / Failed:[/bold yellow]\n"
                        "This repository is private or requires authentication.\n"
                        "Provide your token or PAT using one of the following methods:\n"
                        "  1. [bold cyan]--token <PAT_OR_PASSWORD>[/bold cyan]\n"
                        "     Example: [dim]devsec scan -r \"<URL>\" --token \"YOUR_TOKEN_HERE\"[/dim]\n"
                        "  2. [bold cyan]Environment Variable:[/bold cyan]\n"
                        "     Example: [dim]export GIT_TOKEN=\"YOUR_TOKEN_HERE\"[/dim] (or GITHUB_TOKEN / AZURE_DEVOPS_EXT_PAT)\n"
                        "  3. [bold cyan]SSH Key Auth:[/bold cyan]\n"
                        "     Example: [dim]devsec scan -r \"git@ssh.dev.azure.com:v3/...\"[/dim] or [dim]\"git@github.com:...\"[/dim]"
                    )
                return False, None, f"Git clone failed (exit {code}): {sanitized_err.strip()}{auth_hint}"

            # Fetch all remote refs explicitly to guarantee full visibility
            fetch_cmd = [git_bin, "fetch", "--all", "--tags"]
            ProcessRunner.run_command(fetch_cmd, cwd=str(clone_target), timeout=300, env=env)

            # If a specific branch was requested, checkout to it
            if self.branch:
                checkout_cmd = [git_bin, "checkout", self.branch]
                ProcessRunner.run_command(checkout_cmd, cwd=str(clone_target), timeout=60, env=env)
                console.print(f"  * Switched to target branch: [bold cyan]{self.branch}[/bold cyan]")

            console.print(f"  * [bold green][OK][/bold green] Repository ingested successfully into: [dim]{clone_target}[/dim] ({elapsed}s)\n")
            return True, clone_target, ""

        except Exception as e:
            return False, None, f"Unexpected ingestion error: {str(e)}"
        finally:
            # Clean up the askpass helper immediately
            if askpass_path and askpass_path.exists():
                askpass_path.unlink(missing_ok=True)

    def cleanup(self):
        """Scrubs the ingested repository unless keep_repo is set."""
        if self.keep_repo:
            console.print(f"[dim]Preserved cloned repository at: {self.temp_dir}[/dim]")
            return

        if self.temp_dir and self.temp_dir.exists():
            try:
                # Handle git read-only files on Windows/Linux during rmtree
                def on_rm_error(func, path, exc_info):
                    os.chmod(path, stat.S_IWRITE)
                    func(path)

                shutil.rmtree(self.temp_dir, onerror=on_rm_error)
            except Exception:
                pass

    def _create_askpass_helper(self, token: str) -> Path:
        """Creates an ephemeral executable script that provides the PAT to Git."""
        if sys.platform == "win32":
            helper_path = self.temp_dir / "askpass.bat"
            helper_path.write_text(f"@echo {token}\n", encoding="utf-8")
        else:
            helper_path = self.temp_dir / "askpass.sh"
            helper_path.write_text(f'#!/bin/sh\necho "$DEVSEC_EPHEMERAL_PAT"\n', encoding="utf-8")
            helper_path.chmod(0o700)
        return helper_path
