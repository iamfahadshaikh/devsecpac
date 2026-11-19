"""Standardized Execution Contract and Status Schema."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Any, Optional
import json


class StatusEnum(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


@dataclass
class FindingCounts:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info

    @property
    def has_blocking(self) -> bool:
        """Determines if there are blocking issues (Critical or High)."""
        return (self.critical + self.high) > 0


@dataclass
class ToolResult:
    tool_name: str
    category: str
    status: StatusEnum
    exit_code: int = 0
    summary: str = ""
    findings: FindingCounts = field(default_factory=FindingCounts)
    duration_seconds: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["findings"] = asdict(self.findings)
        return data

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
