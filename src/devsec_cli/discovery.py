"""Autonomous stack and target repository discovery with single-pass filesystem traversal."""

import os
from pathlib import Path
from typing import List, Dict, Set


class TargetDiscovery:
    IGNORE_DIRS = {
        ".git", "node_modules", ".venv", "venv", "__pycache__", 
        ".idea", ".vscode", "dist", "build", ".tox", ".mypy_cache", 
        ".pytest_cache", ".scannerwork", "target", ".egg-info"
    }

    LANG_PATTERNS = {
        "nodejs": {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"},
        "python": {"requirements.txt", "pyproject.toml", "pipfile", "setup.py"},
        "java": {"pom.xml", "build.gradle", "build.gradle.kts"},
        "golang": {"go.mod", "go.sum"},
        "rust": {"cargo.toml", "cargo.lock"},
        "dotnet": {".csproj", ".fsproj", ".sln"},
    }

    def __init__(self, target_dir: Path):
        self.target_dir = target_dir.resolve()
        self._cached = False
        self._scannable_files: List[Path] = []
        self._dockerfiles: List[Path] = []
        self._k8s_manifests: List[Path] = []
        self._iac_files: List[Path] = []
        self._compose_files: List[Path] = []
        self._detected_languages: Dict[str, List[str]] = {}

    def is_git_repo(self) -> bool:
        return (self.target_dir / ".git").is_dir()

    def _traverse(self):
        """Single-pass top-down os.walk to discover all artifacts in sub-second time."""
        if self._cached:
            return

        scannable = []
        dockerfiles = []
        k8s = []
        iac = []
        compose = []
        lang_matches: Dict[str, Set[str]] = {k: set() for k in self.LANG_PATTERNS}

        for root, dirs, files in os.walk(str(self.target_dir)):
            # Prune ignored directories in-place so os.walk does not traverse inside them
            dirs[:] = [
                d for d in dirs 
                if d not in self.IGNORE_DIRS and not d.endswith(".egg-info")
            ]

            for f in files:
                fpath = Path(root) / f
                scannable.append(fpath)
                f_lower = f.lower()

                # Dockerfiles
                if f_lower == "dockerfile" or f_lower.startswith("dockerfile.") or f_lower.endswith(".dockerfile"):
                    dockerfiles.append(fpath)

                # Compose files
                if ("compose" in f_lower) and (f_lower.endswith(".yml") or f_lower.endswith(".yaml")):
                    compose.append(fpath)

                # IaC files
                if f_lower.endswith((".tf", ".tfvars", ".bicep")):
                    iac.append(fpath)

                # Kubernetes manifests
                if f_lower.endswith((".yml", ".yaml")):
                    try:
                        # Quick prefix read for k8s markers
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                            chunk = fh.read(4096)
                            if "apiVersion:" in chunk and "kind:" in chunk:
                                k8s.append(fpath)
                    except Exception:
                        pass

                # Language runtime detection
                for lang, patterns in self.LANG_PATTERNS.items():
                    if lang == "dotnet":
                        if any(f_lower.endswith(ext) for ext in patterns):
                            lang_matches[lang].add(f)
                    elif f_lower in patterns:
                        lang_matches[lang].add(f)

        self._scannable_files = sorted(scannable)
        self._dockerfiles = dockerfiles
        self._k8s_manifests = k8s
        self._iac_files = iac
        self._compose_files = compose
        self._detected_languages = {
            lang: sorted(list(files))
            for lang, files in lang_matches.items()
            if files
        }
        self._cached = True

    def discover_dockerfiles(self) -> List[Path]:
        self._traverse()
        return self._dockerfiles

    def discover_k8s_manifests(self) -> List[Path]:
        self._traverse()
        return self._k8s_manifests

    def discover_iac_files(self) -> List[Path]:
        self._traverse()
        return self._iac_files

    def discover_compose_files(self) -> List[Path]:
        self._traverse()
        return self._compose_files

    def detect_languages(self) -> Dict[str, List[str]]:
        self._traverse()
        return self._detected_languages

    def discover_scannable_files(self) -> List[Path]:
        self._traverse()
        return self._scannable_files
