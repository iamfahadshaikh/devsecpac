"""Unified Finding Deduplication and Cross-Engine Correlation Engine for DevSecPac v2.0."""

import re
from typing import List, Dict, Tuple, Set
from .contracts import ToolResult, FindingDetail, FindingCounts, StatusEnum


class FindingCorrelator:
    """Normalizes and deduplicates findings across different security scanners.
    
    Examples:
      - Correlates CVE-2024-XXXX and GHSA-YYYY between Trivy and Dependency-Check
      - Correlates leaked secret matches between Gitleaks and TruffleHog on the same file/line
      - Consolidates AST issues between CodeQL and SonarQube
    """

    @staticmethod
    def extract_cve(rule_str: str, desc_str: str) -> List[str]:
        """Extracts standard CVE identifiers (e.g. CVE-2024-12345) from strings."""
        combined = f"{rule_str} {desc_str}".upper()
        matches = re.findall(r"CVE-\d{4}-\d{4,7}", combined)
        return list(set(matches))

    @staticmethod
    def extract_ghsa(rule_str: str, desc_str: str) -> List[str]:
        """Extracts standard GitHub Advisory IDs (e.g. GHSA-xxxx-xxxx-xxxx)."""
        combined = f"{rule_str} {desc_str}"
        matches = re.findall(r"GHSA-[2-9a-z]{4}-[2-9a-z]{4}-[2-9a-z]{4}", combined, re.IGNORECASE)
        return list(set(m.upper() for m in matches))

    @classmethod
    def deduplicate_findings(cls, results: List[ToolResult]) -> Tuple[List[FindingDetail], Dict[str, any]]:
        """Deduplicates and correlates findings across all tool results.
        
        Returns:
            Tuple of (deduplicated_findings: List[FindingDetail], stats: Dict)
        """
        raw_items: List[FindingDetail] = []
        for r in results:
            raw_items.extend(r.items)

        if not raw_items:
            return [], {"total_raw": 0, "total_unique": 0, "duplicates_removed": 0}

        seen_keys: Dict[str, FindingDetail] = {}
        cve_index: Dict[Tuple[str, str], FindingDetail] = {}  # (file, CVE) -> canonical item
        secret_index: Dict[Tuple[str, str], FindingDetail] = {} # (file, line) -> secret item

        for item in raw_items:
            norm_file = item.file.strip().replace("\\", "/").lower()
            norm_line = str(item.line or "").strip()
            norm_rule = item.rule.strip().upper()

            # 1. Check for CVE / GHSA correlation in SCA findings
            cves = cls.extract_cve(item.rule, item.description)
            ghsas = cls.extract_ghsa(item.rule, item.description)

            correlated = False

            if cves or ghsas:
                for cve in (cves or ghsas):
                    cve_key = (norm_file, cve)
                    if cve_key in cve_index:
                        # Existing finding found - append reporting tool if not already present
                        canonical = cve_index[cve_key]
                        if item.tool not in canonical.tool:
                            canonical.tool = f"{canonical.tool}, {item.tool}"
                        correlated = True
                        break
                    else:
                        cve_index[cve_key] = item

            # 2. Check for Secret correlation (same file and line)
            if not correlated and item.tool.lower() in ("gitleaks", "trufflehog"):
                sec_key = (norm_file, norm_line)
                if norm_line and sec_key in secret_index:
                    canonical = secret_index[sec_key]
                    if item.tool not in canonical.tool:
                        canonical.tool = f"{canonical.tool}, {item.tool}"
                    correlated = True
                elif norm_line:
                    secret_index[sec_key] = item

            if correlated:
                continue

            # 3. Standard deduplication by (file, line, rule, severity)
            exact_key = f"{norm_file}::{norm_line}::{norm_rule}::{item.severity.upper()}"
            if exact_key in seen_keys:
                canonical = seen_keys[exact_key]
                if item.tool not in canonical.tool:
                    canonical.tool = f"{canonical.tool}, {item.tool}"
            else:
                seen_keys[exact_key] = item

        # Combine all unique items
        all_unique: Set[int] = set()
        deduped: List[FindingDetail] = []

        for item in list(cve_index.values()) + list(secret_index.values()) + list(seen_keys.values()):
            if id(item) not in all_unique:
                all_unique.add(id(item))
                deduped.append(item)

        stats = {
            "total_raw": len(raw_items),
            "total_unique": len(deduped),
            "duplicates_removed": len(raw_items) - len(deduped)
        }
        return deduped, stats
