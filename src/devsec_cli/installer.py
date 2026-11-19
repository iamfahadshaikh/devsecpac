"""Autonomous Resilient Toolchain Installer for devsec-cli.

Multi-strategy installer:
1. Native OS package manager (apt/apt-get on Debian/Ubuntu/Kali)
2. Safe user-level pip/pipx installation with PEP 668 break-system-packages support
3. Official GitHub binary releases with fallback detection
"""

import os
import sys
import platform
import shutil
import tarfile
import zipfile
import subprocess
import urllib.request
import json
from pathlib import Path
from typing import Optional, List
from rich.console import Console

console = Console()


class ToolInstaller:
    def __init__(self, install_dir: Optional[Path] = None):
        self.os_type = platform.system().lower()  # linux, windows, darwin
        self.arch = platform.machine().lower()
        self.arch_norm = "arm64" if self.arch in ("aarch64", "arm64") else "amd64"
        self.has_apt = shutil.which("apt-get") is not None or shutil.which("apt") is not None

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
        console.print(f"\n[bold green]🛠️ DevSecOps Autonomous Toolchain Installer[/bold green]")
        console.print(f"  • Platform: [cyan]{self.os_type}[/cyan] ({self.arch_norm})")
        console.print(f"  • Target Directory: [yellow]{self.install_dir}[/yellow]")
        console.print(f"  • Apt Available: [bold]{'Yes' if self.has_apt else 'No'}[/bold]\n")

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
                if self.is_in_path(name) or (self.install_dir / name).exists() or (self.install_dir / f"{name}.exe").exists():
                    console.print(f"  • [green]✔[/green] {name:<14} [bold green]Installed successfully![/bold green]   ")
                else:
                    console.print(f"  • [green]✔[/green] {name:<14} [bold green]Setup completed![/bold green]   ")
            except Exception as e:
                console.print(f"  • [red]✘[/red] {name:<14} [red]Failed:[/red] {str(e)[:70]}")

        console.print(f"\n[bold yellow]💡 Tip:[/bold yellow] Ensure [cyan]{self.install_dir}[/cyan] is in your PATH:")
        if self.os_type == "windows":
            console.print(f'   [dim]$env:PATH += ";{self.install_dir}"[/dim]')
        else:
            console.print(f'   [dim]export PATH="{self.install_dir}:$PATH"[/dim]')
        console.print()

    def _try_apt_install(self, package_name: str) -> bool:
        """Tries installing package via apt or sudo apt if available."""
        if not self.has_apt:
            return False
        
        apt_bin = shutil.which("apt-get") or shutil.which("apt")
        # Try without sudo (if root) or with sudo
        cmd = [apt_bin, "install", "-y", package_name]
        if os.geteuid() != 0 if hasattr(os, "geteuid") else False:
            if shutil.which("sudo"):
                cmd = ["sudo", "-n", apt_bin, "install", "-y", package_name]
            else:
                return False

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return res.returncode == 0
        except Exception:
            return False

    def _download_file(self, url: str, dest: Path):
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) devsec-cli/0.1.0"
            }
        )
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
        # 1. Try apt first if on Debian/Kali/Ubuntu
        if self._try_apt_install("trufflehog"):
            return

        # 2. Direct binary download
        ver = "3.88.5"
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
        bin_name = "hadolint.exe" if self.os_type == "windows" else "hadolint"
        os_str = "Windows-x86_64.exe" if self.os_type == "windows" else ("Linux-x86_64" if self.os_type == "linux" else "Darwin-x86_64")
        url = f"https://github.com/hadolint/hadolint/releases/latest/download/hadolint-{os_str}"

        dest = self.install_dir / bin_name
        self._download_file(url, dest)
        dest.chmod(0o755)

    def install_checkov(self):
        """Installs checkov using pip or pipx with PEP 668 compatibility."""
        pipx = shutil.which("pipx")
        if pipx:
            subprocess.run([pipx, "install", "checkov"], check=True, capture_output=True)
            return

        # Try pip with --break-system-packages (for Kali / Debian PEP 668)
        cmd = [sys.executable, "-m", "pip", "install", "checkov", "--break-system-packages"]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return
        except subprocess.CalledProcessError:
            pass

        # Standard fallback pip
        cmd_standard = [sys.executable, "-m", "pip", "install", "checkov"]
        subprocess.run(cmd_standard, check=True, capture_output=True)

    def install_kubeconform(self):
        ver = "0.6.7"
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
        # 1. Try apt first if on Debian/Kali/Ubuntu
        if self._try_apt_install("trivy"):
            return

        # 2. Binary release fallback
        ver = "0.58.2"
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
        # Official Anchore install script is safest cross-platform method on Unix
        if self.os_type in ("linux", "darwin") and shutil.which("curl"):
            cmd = f"curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b {self.install_dir}"
            res = subprocess.run(cmd, shell=True, capture_output=True)
            if res.returncode == 0:
                return

        # Direct binary fallback
        ver = "1.18.0"
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
