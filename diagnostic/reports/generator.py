"""Report generator — selects and invokes the appropriate formatter.

This module acts as a facade over the individual formatters. The CLI
calls ReportGenerator.generate() with the desired format name and gets
back a formatted string without needing to know about formatter classes.
"""

from __future__ import annotations

from diagnostic.models import Finding, SystemSnapshot

from .ai_narrative import AiNarrativeFormatter
from .base import BaseFormatter
from .json_report import JsonFormatter
from .markdown import MarkdownFormatter
from .terminal import TerminalFormatter


class ReportGenerator:
    """Facade that dispatches to the correct formatter.

    Maintains a registry of format-name → formatter-instance. Adding a
    new output format only requires creating a BaseFormatter subclass
    and registering it here.
    """

    def __init__(self) -> None:
        """Initialize with all available formatters."""
        self._formatters: dict[str, BaseFormatter] = self._build_registry()

    @property
    def available_formats(self) -> list[str]:
        """List of supported format names."""
        return list(self._formatters.keys())

    def generate(
        self,
        collected: dict,
        findings: list[Finding],
        output_format: str = "terminal",
        *,
        comparison: dict | None = None,
        verbose: bool = False,
    ) -> str:
        """Generate a report in the specified format.

        Args:
            collected:     Raw collector data (used to build SystemSnapshot).
            findings:      Sorted findings from the analysis engine.
            output_format: One of available_formats.
            comparison:    Optional previous run for diff.
            verbose:       Whether to include raw data.

        Returns:
            Formatted report string.

        Raises:
            ValueError: If output_format is not recognized.
        """
        formatter = self._formatters.get(output_format)
        if formatter is None:
            available = ", ".join(self.available_formats)
            raise ValueError(
                f"Unknown format '{output_format}'. Available: {available}"
            )

        snapshot = SystemSnapshot(
            hardware=collected.get("hardware", {}),
            monitor=collected.get("monitor", {}),
            benchmark=collected.get("benchmark", {}),
            network=collected.get("network", {}),
            timestamp=collected.get("timestamp", ""),
        )

        return formatter.format(
            findings,
            snapshot,
            verbose=verbose,
            comparison=comparison,
        )

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _build_registry(self) -> dict[str, BaseFormatter]:
        """Map format names to formatter instances."""
        formatters = [
            TerminalFormatter(),
            MarkdownFormatter(),
            JsonFormatter(),
            AiNarrativeFormatter(),
        ]
        return {f.name: f for f in formatters}
