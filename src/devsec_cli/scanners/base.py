"""Base scanner interface."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, List
from ..contracts import ToolResult, StatusEnum, FindingCounts
from ..runner import ProcessRunner


class BaseScanner(ABC):
    def __init__(self, name: str, category: str, binary_name: Optional[str] = None):
        self.name = name
        self.category = category
        self.binary_name = binary_name
        self.binary_path = ProcessRunner.find_binary(binary_name) if binary_name else None

    def is_tool_available(self) -> bool:
        if self.binary_name is None:
            return True
        return self.binary_path is not None

    @abstractmethod
    def scan(self, target_dir: Path) -> ToolResult:
        """Executes the scan and returns a normalized ToolResult."""
        pass

    def create_not_applicable_result(self, reason: str) -> ToolResult:
        return ToolResult(
            tool_name=self.name,
            category=self.category,
            status=StatusEnum.NOT_APPLICABLE,
            exit_code=0,
            summary=f"N/A: {reason}",
            findings=FindingCounts()
        )

    def create_skipped_result(self, reason: str) -> ToolResult:
        return ToolResult(
            tool_name=self.name,
            category=self.category,
            status=StatusEnum.SKIPPED,
            exit_code=0,
            summary=f"Skipped: {reason}",
            findings=FindingCounts()
        )
