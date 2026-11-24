"""Finding bypass and suppression mechanism (.devsecignore)."""

from pathlib import Path
from typing import List, Set, Tuple
from .contracts import FindingDetail, ToolResult, FindingCounts, StatusEnum


class FindingBypassManager:
    """Loads and checks rule or file-level bypass definitions from .devsecignore or .devsec-suppress."""

    def __init__(self, target_dir: Path):
        self.target_dir = target_dir
        self.ignore_rules: Set[str] = set()
        self.ignore_file_rules: Set[Tuple[str, str]] = set()  # (normalized_path, rule_id)
        self.ignore_cves: Set[str] = set()
        self._load_ignore_file()

    def _load_ignore_file(self):
        """Looks for .devsecignore or .devsec-suppress in repository root."""
        possible_files = [
            self.target_dir / ".devsecignore",
            self.target_dir / ".devsec-suppress"
        ]

        for pf in possible_files:
            if pf.is_file():
                try:
                    for line in pf.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        
                        # Format 1: file:rule (e.g. Dockerfile:DL3008 or requirements.txt:CVE-2024-1234)
                        if ":" in line:
                            parts = line.split(":", 1)
                            fpath_norm = parts[0].strip().replace("\\", "/").lower()
                            rule_norm = parts[1].strip().upper()
                            self.ignore_file_rules.add((fpath_norm, rule_norm))
                        # Format 2: standalone rule/CVE (e.g. DL3008, CK_DOCKER_3, CVE-2024-21626)
                        elif line.upper().startswith("CVE-") or line.upper().startswith("GHSA-"):
                            self.ignore_cves.add(line.upper())
                        else:
                            self.ignore_rules.add(line.upper())
                except Exception:
                    pass

    def is_bypassed(self, finding: FindingDetail) -> bool:
        """Determines if a finding is suppressed by a specific bypass rule."""
        if not self.ignore_rules and not self.ignore_file_rules and not self.ignore_cves:
            return False

        norm_file = finding.file.strip().replace("\\", "/").lower()
        rule_upper = (finding.rule or "").strip().upper()

        # Check global rule match
        if rule_upper in self.ignore_rules:
            return True

        # Check file + rule match
        for fpath, r in self.ignore_file_rules:
            if (fpath in norm_file or norm_file.endswith(fpath)) and r == rule_upper:
                return True

        # Check CVE match
        if rule_upper in self.ignore_cves:
            return True

        return False

    def filter_tool_results(self, results: List[ToolResult]) -> Tuple[List[ToolResult], int]:
        """Filters out bypassed findings from each ToolResult and recalculates finding counts."""
        bypassed_count = 0

        for r in results:
            if not r.items:
                continue

            active_items = []
            for item in r.items:
                if self.is_bypassed(item):
                    bypassed_count += 1
                else:
                    active_items.append(item)

            r.items = active_items

            # Recount findings for this tool
            r.findings.critical = sum(1 for i in active_items if i.severity.upper() == "CRITICAL")
            r.findings.high = sum(1 for i in active_items if i.severity.upper() == "HIGH")
            r.findings.medium = sum(1 for i in active_items if i.severity.upper() == "MEDIUM")
            r.findings.low = sum(1 for i in active_items if i.severity.upper() == "LOW")
            r.findings.info = sum(1 for i in active_items if i.severity.upper() == "INFO")

            # Adjust status if quality gate failed purely due to suppressed items
            if r.status == StatusEnum.FAIL and not r.findings.has_blocking:
                r.status = StatusEnum.PASS

        return results, bypassed_count
