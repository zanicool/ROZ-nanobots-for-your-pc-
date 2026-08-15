"""Abstract base class for all data collectors.

Collectors are responsible for gathering raw system data without
interpreting it. They handle tool availability gracefully — if a
required binary is not installed, the collector returns partial
results rather than crashing.
"""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import Any


class BaseCollector(ABC):
    """Interface that all collectors must implement.

    Subclasses override `collect()` to return a dict of raw system data.
    Helper methods for running commands and reading system files are
    provided here so subclasses stay focused on *what* to collect.
    """

    @abstractmethod
    def collect(self) -> dict[str, Any]:
        """Gather data and return it as a structured dict.

        Returns:
            Dict with collector-specific keys. Missing data should be
            represented as None, never omitted — this lets analyzers
            distinguish "not available" from "not checked".
        """
        ...

    # ------------------------------------------------------------------
    # Protected helpers — available to subclasses, not part of public API
    # ------------------------------------------------------------------

    def _run_cmd(
        self, cmd: list[str], timeout: int = 30
    ) -> str | None:
        """Execute a shell command and return stdout.

        Args:
            cmd:     Command as list of arguments (no shell=True).
            timeout: Max seconds to wait.

        Returns:
            Stripped stdout on success, None on any failure.
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            pass
        return None

    def _has_tool(self, name: str) -> bool:
        """Check whether a CLI tool is on PATH."""
        return shutil.which(name) is not None

    def _read_file(self, path: str) -> str | None:
        """Read a system file, return None if inaccessible."""
        try:
            with open(path) as f:
                return f.read().strip()
        except (FileNotFoundError, PermissionError, OSError):
            return None

    def _read_int(self, path: str) -> int | None:
        """Read a system file as a single integer value."""
        content = self._read_file(path)
        if content is not None:
            try:
                return int(content)
            except ValueError:
                pass
        return None
