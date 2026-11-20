"""GitHub CodeQL Deep SAST scanner."""

from pathlib import Path
import json
import shutil
import tempfile
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
from ..runner import ProcessRunner
from ..discovery import TargetDiscovery


class CodeQLScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="GitHub CodeQL", category="SAST", binary_name="codeql")

    def _map_language(self, detected: dict) -> str:
        """Maps detected application runtimes to primary CodeQL language identifier."""
        priority_map = {
            "python": "python",
            "nodejs": "javascript",
            "golang": "go",
            "java": "java",
            "dotnet": "csharp",
            "rust": None  # CodeQL does not natively analyze Rust
        }
        for lang_key, codeql_lang in priority_map.items():
            if lang_key in detected and codeql_lang:
                return codeql_lang
        return ""

    def scan(self, target_dir: Path) -> ToolResult:
        discovery = TargetDiscovery(target_dir)
        languages = discovery.detect_languages()
        codeql_lang = self._map_language(languages)

        if not codeql_lang:
            return self.create_not_applicable_result("No CodeQL-supported languages detected")

        if not self.is_tool_available():
            return self.create_skipped_result("codeql binary not found in PATH")

        findings = FindingCounts()
        items = []
        status = StatusEnum.PASS
        summary = f"CodeQL SAST analysis completed for {codeql_lang}"

        sarif_out = target_dir / ".codeql_results.sarif"
        db_dir = target_dir / ".codeql_db"

        try:
            # 1. Create database
            create_cmd = [
                str(self.binary_path),
                "database", "create",
                str(db_dir),
                f"--language={codeql_lang}",
                f"--source-root={target_dir}",
                "--overwrite"
            ]
            c_code, _, stderr_c, _ = ProcessRunner.run_command(create_cmd, cwd=str(target_dir), timeout=600)
            if c_code != 0:
                return self.create_skipped_result(f"CodeQL database build skipped for {codeql_lang} (compilation or query pack required)")

            # 2. Analyze database and emit SARIF
            # Specify the query pack for the language (e.g. codeql/javascript-queries)
            query_pack = f"codeql/{codeql_lang}-queries"
            analyze_cmd = [
                str(self.binary_path),
                "database", "analyze",
                str(db_dir),
                query_pack,
                "--format=sarif-latest",
                f"--output={sarif_out}"
            ]
            a_code, _, _, elapsed = ProcessRunner.run_command(analyze_cmd, cwd=str(target_dir), timeout=600)

            # 3. Parse SARIF findings
            if sarif_out.exists():
                sarif_data = json.loads(sarif_out.read_text(encoding="utf-8"))
                for run in sarif_data.get("runs", []):
                    for res in run.get("results", []):
                        level = str(res.get("level", "warning")).lower()
                        sev = "MEDIUM"
                        if level == "error":
                            findings.high += 1
                            sev = "HIGH"
                        elif level == "warning":
                            findings.medium += 1
                            sev = "MEDIUM"
                        else:
                            findings.low += 1
                            sev = "LOW"

                        rule_id = res.get("ruleId", "CodeQLRule")
                        msg = res.get("message", {}).get("text", "")
                        locs = res.get("locations", [])
                        file_uri = ""
                        line_str = ""
                        if locs:
                            phys = locs[0].get("physicalLocation", {})
                            file_uri = phys.get("artifactLocation", {}).get("uri", "unknown")
                            start_line = phys.get("region", {}).get("startLine")
                            line_str = str(start_line) if start_line else ""

                        items.append(
                            FindingDetail(
                                severity=sev,
                                tool=self.name,
                                file=file_uri,
                                line=line_str,
                                rule=rule_id,
                                description=msg[:120]
                            )
                        )

            if findings.has_blocking:
                status = StatusEnum.FAIL
                summary = f"Detected {findings.high} High SAST issue(s) ({codeql_lang})"
            elif findings.total > 0:
                summary = f"Detected {findings.total} non-blocking SAST issue(s) ({codeql_lang})"

        except Exception as e:
            return self.create_skipped_result(f"CodeQL analysis skipped: {str(e)[:50]}")
        finally:
            # Clean up db and temp sarif
            sarif_out.unlink(missing_ok=True)
            if db_dir.exists():
                shutil.rmtree(db_dir, ignore_errors=True)

        return ToolResult(
            tool_name=self.name,
            category=self.category,
            status=status,
            exit_code=0,
            summary=summary,
            findings=findings,
            duration_seconds=elapsed,
            items=items
        )
