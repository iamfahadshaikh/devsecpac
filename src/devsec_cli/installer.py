"""Autonomous Toolchain Installer for devsec-cli.

Detects host OS, architecture, and fetches official pre-compiled binaries
or packages directly to ~/.local/bin without requiring root/sudo privileges.
"""

import os
import sys
import platform
import shutil
import tarfile
import zipfile
import urllib.request
from pathlib import Path
from typing import Dict, Any, Optional
from rich.console import Console

console = Console()


class ToolInstaller:
    def __init__(self, install_dir: Optional[Path] = None):
        self.os_type = platform.system().lower()  # linux, windows, darwin
        self.arch = platform.machine().lower()
        if self.arch in ("x86_64", "amd64"):
            self.arch_norm = "amd64"
        elif self.arch in ("aarch64", "arm64"):
            self.arch_norm = "arm64"
        else:
            self.arch_norm = "amd64"

        # Determine target installation bin directory
        if install_dir:
            self.install_dir = install_dir.resolve()
        else:
            if self.os_type == "windows":
                self.install_dir = Path(os.environ.get("USERPROFILE", ".")) / ".local" / "bin"
            else:
                self.install_dir = Path.home() / ".local" / "bin"

        self.install_dir.mkdir(parents=True, exist_ok=True)

    def is_in_path(self, tool_name: str) -> bool:
        return shutil.which(tool_name) is not None

    def install_all(self):
        console.print(f"\n[bold green]🛠️ DevSecOps Toolchain Auto-Installer[/bold green]")
        console.print(f"  • Platform: [cyan]{self.os_type}[/cyan] ({self.arch_norm})")
        console.print(f"  • Target Directory: [yellow]{self.install_dir}[/yellow]\n")

        tools = [
            ("gitleaks", self.install_gitleaks),
            ("trufflehog", self.install_trufflehog),
            ("hadolint", self.install_hadolint),
            ("checkov", self.install_checkov),
            ("kubeconform", self.install_kubeconform),
            ("trivy", self.install_trivy),
            ("syft", self.install_syft),
        ]

        for name, installer_fn in tools:
            if self.is_in_path(name):
                console.print(f"  • [green]✔[/green] {name:<14} Already installed in PATH.")
                continue
            console.print(f"  • [bold blue]⬇[/bold blue] {name:<14} Installing...", end="\r")
            try:
                installer_fn()
                console.print(f"  • [green]✔[/green] {name:<14} [bold green]Installed successfully![/bold green]   ")
            except Exception as e:
                console.print(f"  • [red]✘[/red] {name:<14} [red]Failed:[/red] {e}")

        console.print(f"\n[bold yellow]💡 Tip:[/bold yellow] Ensure [cyan]{self.install_dir}[/cyan] is in your PATH:")
        if self.os_type == "windows":
            console.print(f'   [dim]$env:PATH += ";{self.install_dir}"[/dim]')
        else:
            console.print(f'   [dim]export PATH="{self.install_dir}:$PATH"[/dim]')
        console.print()

    def _download_file(self, url: str, dest: Path):
        req = urllib.request.Request(url, headers={"User-Agent": "devsec-cli-installer"})
        with urllib.request.urlopen(req, timeout=60) as response, open(dest, "wb") as out_file:
            shutil.copyfileobj(response, out_file)

    def install_gitleaks(self):
        ver = "8.18.4"
        ext = "zip" if self.os_type == "windows" else "tar.gz"
        os_str = "windows" if self.os_type == "windows" else ("linux" if self.os_type == "linux" else "darwin")
        arch_str = "x64" if self.arch_norm == "amd64" else "arm64"
        url = f"https://github.com/gitleaks/gitleaks/releases/download/v{ver}/gitleaks_{ver}_{os_str}_{arch_str}.{ext}"

        tmp_archive = self.install_dir / f"gitleaks_tmp.{ext}"
        self._download_file(url, tmp_archive)

        if ext == "zip":
            with zipfile.ZipFile(tmp_archive, "r") as z:
                z.extract("gitleaks.exe", self.install_dir)
        else:
            with tarfile.open(tmp_archive, "r:gz") as t:
                for member in t.getmembers():
                    if member.name == "gitleaks":
                        t.extract(member, self.install_dir)
                        (self.install_dir / "gitleaks").chmod(0o755)
        tmp_archive.unlink(missing_ok=True)

    def install_trufflehog(self):
        ver = "3.80.0"
        os_str = "windows" if self.os_type == "windows" else ("linux" if self.os_type == "linux" else "darwin")
        url = f"https://github.com/trufflesecurity/trufflehog/releases/download/v{ver}/trufflehog_{ver}_{os_str}_{self.arch_norm}.tar.gz"

        tmp_archive = self.install_dir / "trufflehog_tmp.tar.gz"
        self._download_file(url, tmp_archive)

        with tarfile.open(tmp_archive, "r:gz") as t:
            for member in t.getmembers():
                if member.name in ("trufflehog", "trufflehog.exe"):
                    t.extract(member, self.install_dir)
                    bin_path = self.install_dir / member.name
                    bin_path.chmod(0o755)
        tmp_archive.unlink(missing_ok=True)

    def install_hadolint(self):
        ver = "2.12.0"
        bin_name = "hadolint.exe" if self.os_type == "windows" else "hadolint"
        os_str = "Windows-x86_64.exe" if self.os_type == "windows" else ("Linux-x86_64" if self.os_type == "linux" else "Darwin-x86_64")
        url = f"https://github.com/hadolint/hadolint/releases/download/v{ver}/hadolint-{os_str}"

        dest = self.install_dir / bin_name
        self._download_file(url, dest)
        dest.chmod(0o755)

    def install_checkov(self):
        # Checkov is distributed via pip
        import subprocess
        cmd = [sys.executable, "-m", "pip", "install", "checkov"]
        subprocess.run(cmd, check=True, capture_output=True)

    def install_kubeconform(self):
        ver = "0.6.6"
        os_str = "windows" if self.os_type == "windows" else ("linux" if self.os_type == "linux" else "darwin")
        ext = "zip" if self.os_type == "windows" else "tar.gz"
        url = f"https://github.com/yannh/kubeconform/releases/download/v{ver}/kubeconform-{os_str}-{self.arch_norm}.{ext}"

        tmp_archive = self.install_dir / f"kubeconform_tmp.{ext}"
        self._download_file(url, tmp_archive)

        if ext == "zip":
            with zipfile.ZipFile(tmp_archive, "r") as z:
                z.extract("kubeconform.exe", self.install_dir)
        else:
            with tarfile.open(tmp_archive, "r:gz") as t:
                for member in t.getmembers():
                    if member.name == "kubeconform":
                        t.extract(member, self.install_dir)
                        (self.install_dir / "kubeconform").chmod(0o755)
        tmp_archive.unlink(missing_ok=True)

    def install_trivy(self):
        ver = "0.55.0"
        os_str = "windows" if self.os_type == "windows" else ("Linux" if self.os_type == "linux" else "macOS")
        arch_title = "64bit" if self.arch_norm == "amd64" else "ARM64"
        ext = "zip" if self.os_type == "windows" else "tar.gz"
        url = f"https://github.com/aquasecurity/trivy/releases/download/v{ver}/trivy_{ver}_{os_str}-{arch_title}.{ext}"

        tmp_archive = self.install_dir / f"trivy_tmp.{ext}"
        self._download_file(url, tmp_archive)

        if ext == "zip":
            with zipfile.ZipFile(tmp_archive, "r") as z:
                z.extract("trivy.exe", self.install_dir)
        else:
            with tarfile.open(tmp_archive, "r:gz") as t:
                for member in t.getmembers():
                    if member.name == "trivy":
                        t.extract(member, self.install_dir)
                        (self.install_dir / "trivy").chmod(0o755)
        tmp_archive.unlink(missing_ok=True)

    def install_syft(self):
        ver = "1.13.0"
        os_str = "windows" if self.os_type == "windows" else ("linux" if self.os_type == "linux" else "darwin")
        ext = "zip" if self.os_type == "windows" else "tar.gz"
        url = f"https://github.com/anchore/syft/releases/download/v{ver}/syft_{ver}_{os_str}_{self.arch_norm}.{ext}"

        tmp_archive = self.install_dir / f"syft_tmp.{ext}"
        self._download_file(url, tmp_archive)

        if ext == "zip":
            with zipfile.ZipFile(tmp_archive, "r") as z:
                z.extract("syft.exe", self.install_dir)
        else:
            with tarfile.open(tmp_archive, "r:gz") as t:
                for member in t.getmembers():
                    if member.name == "syft":
                        t.extract(member, self.install_dir)
                        (self.install_dir / "syft").chmod(0o755)
        tmp_archive.unlink(missing_ok=True)
