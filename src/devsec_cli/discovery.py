"""Autonomous stack and target repository discovery."""

from pathlib import Path
from typing import List, Dict, Set


class TargetDiscovery:
    def __init__(self, target_dir: Path):
        self.target_dir = target_dir.resolve()

    def is_git_repo(self) -> bool:
        return (self.target_dir / ".git").is_dir()

    def discover_dockerfiles(self) -> List[Path]:
        dockerfiles = []
        # Standard Dockerfile, Dockerfile.*, *.dockerfile
        for p in self.target_dir.rglob("*"):
            if not p.is_file() or self._should_ignore(p):
                continue
            name_lower = p.name.lower()
            if name_lower == "dockerfile" or name_lower.startswith("dockerfile.") or name_lower.endswith(".dockerfile"):
                dockerfiles.append(p)
        return dockerfiles

    def discover_k8s_manifests(self) -> List[Path]:
        manifests = []
        for p in self.target_dir.rglob("*.y*ml"):
            if not p.is_file() or self._should_ignore(p):
                continue
            try:
                # Quick inspection for Kubernetes indicators
                content = p.read_text(encoding="utf-8", errors="ignore")
                if "apiVersion:" in content and "kind:" in content:
                    manifests.append(p)
            except Exception:
                continue
        return manifests

    def discover_iac_files(self) -> List[Path]:
        iac_files = []
        for ext in ("*.tf", "*.tfvars", "*.bicep"):
            for p in self.target_dir.rglob(ext):
                if p.is_file() and not self._should_ignore(p):
                    iac_files.append(p)
        return iac_files

    def discover_compose_files(self) -> List[Path]:
        compose = []
        for p in self.target_dir.rglob("*.y*ml"):
            if not p.is_file() or self._should_ignore(p):
                continue
            name = p.name.lower()
            if "compose" in name:
                compose.append(p)
        return compose

    def detect_languages(self) -> Dict[str, List[str]]:
        """Detects application runtimes and dependency manifests."""
        detected = {}

        patterns = {
            "nodejs": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
            "python": ["requirements.txt", "pyproject.toml", "Pipfile", "setup.py"],
            "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
            "golang": ["go.mod", "go.sum"],
            "rust": ["Cargo.toml", "Cargo.lock"],
            "dotnet": ["*.csproj", "*.fsproj", "*.sln"],
        }

        for lang, files in patterns.items():
            found_files = []
            for pattern in files:
                for p in self.target_dir.rglob(pattern):
                    if p.is_file() and not self._should_ignore(p):
                        found_files.append(p.name)
            if found_files:
                detected[lang] = sorted(list(set(found_files)))

        return detected

    def discover_scannable_files(self) -> List[Path]:
        """Discovers all non-ignored, scannable source and configuration files in target directory."""
        scannable = []
        try:
            for p in self.target_dir.rglob("*"):
                if p.is_file() and not self._should_ignore(p):
                    scannable.append(p)
        except Exception:
            pass
        return sorted(scannable)

    def _should_ignore(self, path: Path) -> bool:
        ignore_dirs = {
            ".git", "node_modules", ".venv", "venv", "__pycache__", 
            ".idea", ".vscode", "dist", "build", ".tox", ".mypy_cache", 
            ".pytest_cache", ".scannerwork", "target", ".egg-info"
        }
        return any(part in ignore_dirs or part.endswith(".egg-info") for part in path.parts)
