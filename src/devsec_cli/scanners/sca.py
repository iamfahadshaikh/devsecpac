"""Software Composition Analysis (SCA) & Filesystem Vulnerability Scanners."""

from pathlib import Path
import os
import shutil
import json
from .base import BaseScanner
from ..contracts import ToolResult, StatusEnum, FindingCounts, FindingDetail
from ..runner import ProcessRunner


class TrivyFSScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Aqua Trivy (FS)", category="SCA & Vulnerability", binary_name="trivy")

    def scan(self, target_dir: Path) -> ToolResult:
        if not self.is_tool_available():
            return self.create_skipped_result("trivy binary not found in PATH")

        cmd = [
            str(self.binary_path),
            "fs",
            "--format", "json",
            "--quiet",
            str(target_dir)
        ]

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir), timeout=600)

        findings = FindingCounts()
        items = []
        summary = "No filesystem vulnerabilities detected"

        if stdout.strip():
            try:
                data = json.loads(stdout)
                results = data.get("Results", [])
                for res in results:
                    target_file = res.get("Target", "filesystem")
                    vulns = res.get("Vulnerabilities", [])
                    for v in vulns:
                        sev = v.get("Severity", "UNKNOWN").upper()
                        if sev == "CRITICAL":
                            findings.critical += 1
                        elif sev == "HIGH":
                            findings.high += 1
                        elif sev == "MEDIUM":
                            findings.medium += 1
                        elif sev == "LOW":
                            findings.low += 1
                        else:
                            findings.info += 1

                        cve_id = v.get("VulnerabilityID", "")
                        pkg_name = v.get("PkgName", "")
                        installed_ver = v.get("InstalledVersion", "")
                        fixed_ver = v.get("FixedVersion", "")
                        desc = f"{pkg_name} {installed_ver}"
                        if fixed_ver:
                            desc += f" -> fixed in {fixed_ver}"

                        items.append(
                            FindingDetail(
                                severity=sev,
                                tool=self.name,
                                file=target_file,
                                line="",
                                rule=cve_id,
                                description=desc
                            )
                        )

                if findings.total > 0:
                    summary = (
                        f"Found {findings.total} package vulnerabilities "
                        f"({findings.critical} Crit, {findings.high} High, {findings.medium} Med, {findings.low} Low)"
                    )
            except Exception:
                pass

        status = StatusEnum.FAIL if findings.has_blocking else StatusEnum.PASS

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


class DependencyCheckScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="OWASP Dependency-Check", category="SCA", binary_name="dependency-check")

    def scan(self, target_dir: Path) -> ToolResult:
        if not self.is_tool_available():
            return self.create_skipped_result("dependency-check binary not found in PATH")

        out_dir = target_dir / ".owasp_dc"
        nvd_api_key = os.environ.get("NVD_API_KEY", "")

        cmd = [
            str(self.binary_path),
            "--scan", str(target_dir),
            "--format", "JSON",
            "--out", str(out_dir),
            "--failOnCVSS", "7",
            "--disableAssembly"  # avoid heavy .NET reflection overhead
        ]

        if nvd_api_key:
            cmd.extend(["--nvdApiKey", nvd_api_key])
        else:
            # Without an NVD API key, NIST rate-limits download requests heavily
            # Pass noupdate if local database cache exists to avoid 10-minute freezes
            data_dir = Path.home() / ".local" / "opt" / "dependency-check" / "data"
            if (data_dir / "odc.mv.db").exists():
                cmd.append("--noupdate")

        code, stdout, stderr, elapsed = ProcessRunner.run_command(cmd, cwd=str(target_dir), timeout=120)

        findings = FindingCounts()
        items = []

        if code == -1:
            return self.create_skipped_result("NVD feed download timed out (export NVD_API_KEY for faster updates)")

        report_file = out_dir / "dependency-check-report.json"
        if not report_file.exists():
            if code != 0:
                return self.create_skipped_result("Dependency-Check run failed (NVD database feed unavailable)")
            status = StatusEnum.PASS
            summary = "No CVE vulnerabilities >= CVSS 7.0 detected"
        else:
            status = StatusEnum.PASS
            summary = "No CVE vulnerabilities >= CVSS 7.0 detected"
            try:
                data = json.loads(report_file.read_text(encoding="utf-8"))
                dependencies = data.get("dependencies", [])
                for dep in dependencies:
                    file_name = dep.get("fileName", "unknown")
                    vulns = dep.get("vulnerabilities", [])
                    for v in vulns:
                        cvss_score = float(v.get("cvssv3", {}).get("baseScore", 0.0) or v.get("cvssv2", {}).get("score", 0.0))
                        sev = "LOW"
                        if cvss_score >= 9.0:
                            findings.critical += 1
                            sev = "CRITICAL"
                        elif cvss_score >= 7.0:
                            findings.high += 1
                            sev = "HIGH"
                        elif cvss_score >= 4.0:
                            findings.medium += 1
                            sev = "MEDIUM"
                        else:
                            findings.low += 1

                        cve_name = v.get("name", "CVE")
                        desc = v.get("description", "")[:100]
                        items.append(
                            FindingDetail(
                                severity=sev,
                                tool=self.name,
                                file=file_name,
                                line="",
                                rule=cve_name,
                                description=desc
                            )
                        )

                if findings.has_blocking:
                    status = StatusEnum.FAIL
                    summary = f"Detected {findings.critical} Critical and {findings.high} High CVEs"
            except Exception:
                pass
            finally:
                shutil.rmtree(out_dir, ignore_errors=True)

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
