"""Mobile Security Framework (MobSF) SAST Scanner for Android, iOS, Flutter, and React Native."""

from pathlib import Path
import json
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
from ..runner import ProcessRunner
from ..discovery import TargetDiscovery


class MobSFScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="MobSF (Mobile SAST)", category="Mobile Security", binary_name="mobsfscan")

    def _detect_mobile_project(self, target_dir: Path) -> dict:
        """
        Detects Android, iOS, Flutter, or React Native project footprints.
        Returns a dict with 'is_mobile': bool and 'framework': str.
        """
        res = {"is_mobile": False, "framework": None, "files": []}

        # 1. Flutter detection
        pubspec = target_dir / "pubspec.yaml"
        if pubspec.exists():
            try:
                content = pubspec.read_text(encoding="utf-8", errors="ignore")
                if "flutter:" in content:
                    res["is_mobile"] = True
                    res["framework"] = "Flutter"
                    res["files"].append("pubspec.yaml")
                    return res
            except Exception:
                pass

        # 2. React Native detection
        pkg_json = target_dir / "package.json"
        if pkg_json.exists():
            try:
                content = pkg_json.read_text(encoding="utf-8", errors="ignore")
                if "react-native" in content:
                    res["is_mobile"] = True
                    res["framework"] = "React Native"
                    res["files"].append("package.json")
                    return res
            except Exception:
                pass

        # 3. Android Native / Hybrid detection
        for p in target_dir.rglob("AndroidManifest.xml"):
            if not any(ign in p.parts for ign in (".git", "node_modules", "build", "dist")):
                res["is_mobile"] = True
                res["framework"] = "Android"
                res["files"].append(p.name)
                return res

        # 4. iOS Native detection
        for p in target_dir.rglob("*.xcodeproj"):
            if not any(ign in p.parts for ign in (".git", "node_modules", "build", "dist")):
                res["is_mobile"] = True
                res["framework"] = "iOS"
                res["files"].append(p.name)
                return res

        for p in target_dir.rglob("Podfile"):
            if not any(ign in p.parts for ign in (".git", "node_modules")):
                res["is_mobile"] = True
                res["framework"] = "iOS"
                res["files"].append("Podfile")
                return res

        return res

    def scan(self, target_dir: Path) -> ToolResult:
        detection = self._detect_mobile_project(target_dir)
        if not detection["is_mobile"]:
            return self.create_not_applicable_result("No mobile application project detected (Android/iOS/Flutter/React Native)")

        framework = detection["framework"]

        # mobsfscan is the official CLI tool from MobSF for static code analysis
        if not self.is_tool_available():
            return self.create_skipped_result(f"mobsfscan binary not found in PATH for {framework} SAST")

        out_json = target_dir / ".mobsf_results.json"
        cmd = [
            str(self.binary_path),
            str(target_dir),
            "--json",
            "-o", str(out_json)
        ]

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir), timeout=600)

        findings = FindingCounts()
        items = []
        status = StatusEnum.PASS
        summary = f"Completed mobile SAST analysis for {framework}"

        if out_json.exists():
            try:
                data = json.loads(out_json.read_text(encoding="utf-8"))
                results = data.get("results", {})
                for rule_id, details in results.items():
                    meta = details.get("metadata", {})
                    raw_sev = str(meta.get("severity", "WARNING")).upper()
                    desc = meta.get("description", "Mobile security warning")

                    files_list = details.get("files", [])
                    for f in files_list:
                        file_path = f.get("file_path", "unknown")
                        line_range = f.get("match_lines", [])
                        line_str = str(line_range[0]) if line_range else ""

                        sev = "MEDIUM"
                        if raw_sev in ("ERROR", "CRITICAL", "HIGH"):
                            findings.high += 1
                            sev = "HIGH"
                        elif raw_sev in ("WARNING", "MEDIUM"):
                            findings.medium += 1
                            sev = "MEDIUM"
                        else:
                            findings.low += 1
                            sev = "LOW"

                        items.append(
                            FindingDetail(
                                severity=sev,
                                tool=self.name,
                                file=file_path,
                                line=line_str,
                                rule=rule_id,
                                description=f"[{framework}] {desc}"
                            )
                        )
            except Exception:
                pass
            finally:
                out_json.unlink(missing_ok=True)

        if findings.has_blocking:
            status = StatusEnum.FAIL
            summary = f"Detected {findings.high} High severity mobile security issue(s) in {framework}"
        elif findings.total > 0:
            summary = f"Detected {findings.total} mobile security issue(s) in {framework}"

        return ToolResult(
            tool_name=self.name,
            category=self.category,
            status=status,
            exit_code=code,
            summary=summary,
            findings=findings,
            duration_seconds=elapsed,
            items=items
        )
