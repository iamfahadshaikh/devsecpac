"""Cross-platform process runner and binary locator."""

import shutil
import subprocess
import time
from typing import List, Optional, Tuple


class ProcessRunner:
    @staticmethod
    def find_binary(binary_name: str) -> Optional[str]:
        """Locates a binary executable across PATH (handles .exe on Windows and PATH on Linux)."""
        return shutil.which(binary_name)

    @staticmethod
    def run_command(
        args: List[str],
        cwd: Optional[str] = None,
        timeout: int = 300,
        env: Optional[dict] = None
    ) -> Tuple[int, str, str, float]:
        """
        Executes a command safely without shell=True.
        Returns: (exit_code, stdout, stderr, elapsed_time_seconds)
        """
        start = time.time()
        try:
            process = subprocess.run(
                args,
                cwd=cwd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                env=env,
                shell=False
            )
            elapsed = round(time.time() - start, 2)
            return process.returncode, process.stdout, process.stderr, elapsed
        except subprocess.TimeoutExpired:
            elapsed = round(time.time() - start, 2)
            return -1, "", f"Command timed out after {timeout} seconds", elapsed
        except Exception as e:
            elapsed = round(time.time() - start, 2)
            return -1, "", str(e), elapsed
