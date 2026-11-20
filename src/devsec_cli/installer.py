"""Autonomous Resilient Toolchain Installer for devsec-cli.

Multi-strategy installer:
1. Native OS package manager (apt/apt-get on Debian/Ubuntu/Kali)
2. Safe user-level pip/pipx installation with PEP 668 break-system-packages support
3. Official GitHub binary releases with isolated wrapper scripts
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
            self.opt_dir = self.install_dir.parent / "opt"
        else:
            if self.os_type == "windows":
                base = Path(os.environ.get("USERPROFILE", ".")) / ".local"
                self.install_dir = base / "bin"
                self.opt_dir = base / "opt"
            else:
                base = Path.home() / ".local"
                self.install_dir = base / "bin"
                self.opt_dir = base / "opt"

        self.install_dir.mkdir(parents=True, exist_ok=True)
        self.opt_dir.mkdir(parents=True, exist_ok=True)

    def is_in_path(self, tool_name: str) -> bool:
        bin_path = shutil.which(tool_name)
        if bin_path and Path(bin_path).is_file():
            return True
        # Also check directly in install_dir
        local_bin = self.install_dir / (f"{tool_name}.exe" if self.os_type == "windows" else tool_name)
        return local_bin.is_file() and os.access(local_bin, os.X_OK)

    def install_all(self):
        console.print(f"\n[bold green]DevSecOps Autonomous Toolchain Installer[/bold green]")
        console.print(f"  * Platform: [cyan]{self.os_type}[/cyan] ({self.arch_norm})")
        console.print(f"  * Target Directory: [yellow]{self.install_dir}[/yellow]")
        console.print(f"  * Apt Available: [bold]{'Yes' if self.has_apt else 'No'}[/bold]\n")

        tools = [
            ("gitleaks", self.install_gitleaks),
            ("trufflehog", self.install_trufflehog),
            ("hadolint", self.install_hadolint),
            ("checkov", self.install_checkov),
            ("kubeconform", self.install_kubeconform),
            ("trivy", self.install_trivy),
            ("syft", self.install_syft),
            ("kyverno", self.install_kyverno),
            ("codeql", self.install_codeql),
            ("sonar-scanner", self.install_sonar),
            ("dependency-check", self.install_dependency_check),
            ("mobsfscan", self.install_mobsfscan),
            ("nmap", self.install_nmap),
        ]

        for name, installer_fn in tools:
            if self.is_in_path(name):
                console.print(f"  * [green][OK][/green] {name:<18} Already installed in PATH.")
                continue
            console.print(f"  * [bold blue][..][/bold blue] {name:<18} Installing...", end="\r")
            try:
                installer_fn()
                if self.is_in_path(name):
                    console.print(f"  * [green][OK][/green] {name:<18} [bold green]Installed successfully![/bold green]   ")
                else:
                    console.print(f"  * [green][OK][/green] {name:<18} [bold green]Setup completed![/bold green]   ")
            except Exception as e:
                console.print(f"  * [red][ERR][/red] {name:<18} [red]Failed:[/red] {str(e)[:70]}")

        console.print(f"\n[bold yellow]Tip:[/bold yellow] Ensure [cyan]{self.install_dir}[/cyan] is in your PATH:")
        if self.os_type == "windows":
            console.print(f'   [dim]$env:PATH += ";{self.install_dir}"[/dim]')
        else:
            console.print(f'   [dim]export PATH="{self.install_dir}:$PATH"[/dim]')
        console.print()

    def _try_apt_install(self, package_name: str) -> bool:
        if not self.has_apt:
            return False
        apt_bin = shutil.which("apt-get") or shutil.which("apt")
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
        with urllib.request.urlopen(req, timeout=180) as response, open(dest, "wb") as out_file:
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
        if self._try_apt_install("trufflehog"):
            return
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
        pipx = shutil.which("pipx")
        if pipx:
            subprocess.run([pipx, "install", "checkov"], check=True, capture_output=True)
            return

        cmd = [sys.executable, "-m", "pip", "install", "checkov", "--break-system-packages"]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return
        except subprocess.CalledProcessError:
            pass

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
        if self._try_apt_install("trivy"):
            return
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
        if self.os_type in ("linux", "darwin") and shutil.which("curl"):
            cmd = f"curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b {self.install_dir}"
            res = subprocess.run(cmd, shell=True, capture_output=True)
            if res.returncode == 0:
                return

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

    def install_kyverno(self):
        ver = "1.12.5"
        ext = "zip" if self.os_type == "windows" else "tar.gz"
        os_str = "windows" if self.os_type == "windows" else ("linux" if self.os_type == "linux" else "darwin")
        arch_str = "x86_64" if self.arch_norm == "amd64" else "arm64"
        url = f"https://github.com/kyverno/kyverno/releases/download/v{ver}/kyverno-cli_v{ver}_{os_str}_{arch_str}.{ext}"

        tmp_archive = self.install_dir / f"kyverno_tmp.{ext}"
        self._download_file(url, tmp_archive)

        if ext == "zip":
            with zipfile.ZipFile(tmp_archive, "r") as z:
                z.extract("kyverno.exe", self.install_dir)
        else:
            with tarfile.open(tmp_archive, "r:gz") as t:
                for member in t.getmembers():
                    if member.name == "kyverno":
                        t.extract(member, self.install_dir)
                        (self.install_dir / "kyverno").chmod(0o755)
        tmp_archive.unlink(missing_ok=True)

    def install_codeql(self):
        """Installs CodeQL into opt/codeql and creates a clean executable wrapper."""
        os_str = "win64" if self.os_type == "windows" else ("linux64" if self.os_type == "linux" else "osx64")
        url = f"https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-{os_str}.zip"

        codeql_opt = self.opt_dir / "codeql"
        if codeql_opt.exists():
            shutil.rmtree(codeql_opt, ignore_errors=True)

        tmp_zip = self.opt_dir / "codeql_tmp.zip"
        self._download_file(url, tmp_zip)

        with zipfile.ZipFile(tmp_zip, "r") as z:
            z.extractall(self.opt_dir)
        tmp_zip.unlink(missing_ok=True)

        # Ensure all extracted binaries and JRE sub-executables are marked executable on POSIX
        if self.os_type != "windows":
            for p in (self.opt_dir / "codeql").rglob("*"):
                if p.is_file() and not p.name.endswith((".txt", ".md", ".json", ".xml", ".properties")):
                    try:
                        p.chmod(p.stat().st_mode | 0o755)
                    except Exception:
                        pass

        # Remove any lingering directory named codeql in ~/.local/bin
        legacy_dir = self.install_dir / "codeql"
        if legacy_dir.is_dir():
            shutil.rmtree(legacy_dir, ignore_errors=True)
        elif legacy_dir.is_file():
            legacy_dir.unlink(missing_ok=True)

        real_bin = self.opt_dir / "codeql" / ("codeql.exe" if self.os_type == "windows" else "codeql")
        real_bin.chmod(0o755)

        # Create wrapper in bin/
        if self.os_type == "windows":
            wrapper = self.install_dir / "codeql.cmd"
            wrapper.write_text(f'@echo off\n"{real_bin}" %*\n', encoding="utf-8")
        else:
            wrapper = self.install_dir / "codeql"
            wrapper.write_text(f'#!/bin/sh\nexec "{real_bin}" "$@"\n', encoding="utf-8")
            wrapper.chmod(0o755)

    def install_sonar(self):
        ver = "6.2.1.4610"
        os_str = "windows-x64" if self.os_type == "windows" else ("linux-x64" if self.os_type == "linux" else "macosx-x64")
        url = f"https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-{ver}-{os_str}.zip"

        sonar_dir = self.opt_dir / f"sonar-scanner-{ver}-{os_str}"
        if not sonar_dir.exists():
            tmp_zip = self.opt_dir / "sonar_tmp.zip"
            self._download_file(url, tmp_zip)
            with zipfile.ZipFile(tmp_zip, "r") as z:
                z.extractall(self.opt_dir)
            tmp_zip.unlink(missing_ok=True)

            # Ensure bundled JRE executables (java, etc.) are executable on POSIX
            if self.os_type != "windows":
                for p in sonar_dir.rglob("*"):
                    if p.is_file() and not p.name.endswith((".txt", ".md", ".json", ".xml", ".properties")):
                        try:
                            p.chmod(p.stat().st_mode | 0o755)
                        except Exception:
                            pass

        real_bin = sonar_dir / "bin" / ("sonar-scanner.bat" if self.os_type == "windows" else "sonar-scanner")
        real_bin.chmod(0o755)

        if self.os_type == "windows":
            wrapper = self.install_dir / "sonar-scanner.cmd"
            wrapper.write_text(f'@echo off\n"{real_bin}" %*\n', encoding="utf-8")
        else:
            wrapper = self.install_dir / "sonar-scanner"
            wrapper.write_text(f'#!/bin/sh\nexec "{real_bin}" "$@"\n', encoding="utf-8")
            wrapper.chmod(0o755)

    def install_dependency_check(self):
        """Installs OWASP Dependency-Check into opt/ and creates a clean executable wrapper."""
        ver = "12.1.0"
        url = f"https://github.com/jeremylong/DependencyCheck/releases/download/v{ver}/dependency-check-{ver}-release.zip"

        dc_opt = self.opt_dir / "dependency-check"
        if not dc_opt.exists():
            tmp_zip = self.opt_dir / "dc_tmp.zip"
            self._download_file(url, tmp_zip)
            with zipfile.ZipFile(tmp_zip, "r") as z:
                z.extractall(self.opt_dir)
            tmp_zip.unlink(missing_ok=True)

            # Ensure bundled JRE executables (java, etc.) are executable on POSIX
            if self.os_type != "windows":
                for p in sonar_dir.rglob("*"):
                    if p.is_file() and not p.name.endswith((".txt", ".md", ".json", ".xml", ".properties")):
                        try:
                            p.chmod(p.stat().st_mode | 0o755)
                        except Exception:
                            pass

        # Remove any lingering directory named dependency-check in ~/.local/bin
        legacy = self.install_dir / "dependency-check"
        if legacy.is_dir():
            shutil.rmtree(legacy, ignore_errors=True)
        elif legacy.is_file():
            legacy.unlink(missing_ok=True)

        real_bin = self.opt_dir / "dependency-check" / "bin" / ("dependency-check.bat" if self.os_type == "windows" else "dependency-check.sh")
        real_bin.chmod(0o755)

        if self.os_type == "windows":
            wrapper = self.install_dir / "dependency-check.cmd"
            wrapper.write_text(f'@echo off\n"{real_bin}" %*\n', encoding="utf-8")
        else:
            wrapper = self.install_dir / "dependency-check"
            wrapper.write_text(f'#!/bin/sh\nexec "{real_bin}" "$@"\n', encoding="utf-8")
            wrapper.chmod(0o755)

    def install_mobsfscan(self):
        """Installs mobsfscan using pip or pipx with PEP 668 support."""
        pipx = shutil.which("pipx")
        if pipx:
            subprocess.run([pipx, "install", "mobsfscan"], check=True, capture_output=True)
            return

        cmd = [sys.executable, "-m", "pip", "install", "mobsfscan", "--break-system-packages"]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return
        except subprocess.CalledProcessError:
            pass

        cmd_standard = [sys.executable, "-m", "pip", "install", "mobsfscan"]
        subprocess.run(cmd_standard, check=True, capture_output=True)

    def install_nmap(self):
        """Installs nmap via apt if on Debian/Ubuntu/Kali."""
        if self._try_apt_install("nmap"):
            return
        raise RuntimeError("nmap should be installed via your system package manager (e.g. sudo apt install nmap)")
