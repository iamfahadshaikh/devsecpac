"""Secret detection scanners: Gitleaks & TruffleHog."""

from pathlib import Path
import json
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
from ..runner import ProcessRunner


class GitleaksScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Gitleaks", category="Secret Detection", binary_name="gitleaks")

    def scan(self, target_dir: Path) -> ToolResult:
        if not self.is_tool_available():
            return self.create_skipped_result("gitleaks binary not found in PATH")

        report_file = target_dir / ".gitleaks_report.json"
        is_git = (target_dir / ".git").is_dir()

        cmd = [
            str(self.binary_path),
            "detect",
            "--source", str(target_dir),
            "--report-format", "json",
            "--report-path", str(report_file),
            "--exit-code", "0"
        ]
        if not is_git:
            cmd.append("--no-git")

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir), timeout=600)

        findings = FindingCounts()
        items = []
        summary = "No secrets detected"
        status = StatusEnum.PASS

        if report_file.exists():
            try:
                data = json.loads(report_file.read_text(encoding="utf-8"))
                if isinstance(data, list) and len(data) > 0:
                    findings.high = len(data)
                    status = StatusEnum.FAIL
                    summary = f"Detected {len(data)} potential secret(s)"

                    for finding in data:
                        file_path = finding.get("File", "unknown")
                        line_no = str(finding.get("StartLine", ""))
                        rule_id = finding.get("RuleID", "Secret")
                        desc = finding.get("Description", rule_id)
                        commit_hash = finding.get("Commit", "")
                        if commit_hash:
                            desc += f" (commit {commit_hash[:8]})"

                        items.append(
                            FindingDetail(
                                severity="HIGH",
                                tool=self.name,
                                file=file_path,
                                line=line_no,
                                rule=rule_id,
                                description=desc
                            )
                        )
            except Exception:
                pass
            finally:
                report_file.unlink(missing_ok=True)

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


class TruffleHogScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="TruffleHog", category="Secret Detection", binary_name="trufflehog")

    def scan(self, target_dir: Path) -> ToolResult:
        if not self.is_tool_available():
            return self.create_skipped_result("trufflehog binary not found in PATH")

        is_git = (target_dir / ".git").is_dir()

        # If git repo, scan git history right from root commit to latest
        if is_git:
            # TruffleHog git file://
            uri = target_dir.as_uri()
            cmd = [
                str(self.binary_path),
                "git",
                uri,
                "--json",
                "--only-verified"
            ]
        else:
            cmd = [
                str(self.binary_path),
                "filesystem",
                str(target_dir),
                "--json",
                "--only-verified"
            ]

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir), timeout=600)

        findings = FindingCounts()
        items = []
        verified_count = 0

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if item.get("Verified", False):
                    verified_count += 1
                    source_meta = item.get("SourceMetadata", {}).get("Data", {})
                    # Handle Git source vs Filesystem source metadata
                    git_meta = source_meta.get("Git", {})
                    fs_meta = source_meta.get("Filesystem", {})

                    file_path = git_meta.get("file") or fs_meta.get("file") or "unknown"
                    line_no = str(git_meta.get("line") or fs_meta.get("line") or "")
                    commit_hash = git_meta.get("commit", "")
                    detector = item.get("DetectorName", "VerifiedSecret")
                    desc = f"Verified {detector} credential"
                    if commit_hash:
                        desc += f" (in commit {commit_hash[:8]})"

                    items.append(
                        FindingDetail(
                            severity="CRITICAL",
                            tool=self.name,
                            file=file_path,
                            line=line_no,
                            rule=detector,
                            description=desc
                        )
                    )
            except Exception:
                continue

        if verified_count > 0:
            findings.critical = verified_count
            status = StatusEnum.FAIL
            summary = f"Detected {verified_count} verified active secret(s)!"
        else:
            status = StatusEnum.PASS
            summary = "No verified secrets detected"

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
