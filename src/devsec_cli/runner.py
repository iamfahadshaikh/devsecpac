"""Cross-platform process runner and binary locator."""

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Tuple


class ProcessRunner:
    @staticmethod
    def find_binary(binary_name: Optional[str]) -> Optional[str]:
        """Locates a binary executable across PATH and ~/.local/bin fallback."""
        if not binary_name:
            return None

        # 1. Standard PATH lookup
        found = shutil.which(binary_name)
        if found and Path(found).is_file():
            return found

        # 2. Local bin fallback (~/.local/bin or %USERPROFILE%\.local\bin)
        user_home = Path(os.environ.get("USERPROFILE") if os.name == "nt" else Path.home())
        local_bin = user_home / ".local" / "bin" / binary_name
        if local_bin.is_file() and (os.name == "nt" or os.access(local_bin, os.X_OK)):
            return str(local_bin)

        if os.name == "nt":
            for ext in (".exe", ".cmd", ".bat"):
                cand = user_home / ".local" / "bin" / f"{binary_name}{ext}"
                if cand.is_file():
                    return str(cand)

        return None

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
