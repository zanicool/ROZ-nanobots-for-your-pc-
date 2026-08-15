"""Markdown formatter — structured report for documentation.

Produces a Markdown document suitable for saving to file, pasting into
GitHub issues, or sharing in team chat.
"""

from __future__ import annotations

from diagnostic.models import Finding, SystemSnapshot

from .base import BaseFormatter


class MarkdownFormatter(BaseFormatter):
    """Renders findings as a Markdown document.

    Output includes a system summary table, findings with headers per
    severity level, and a raw data appendix section.
    """

    @property
    def name(self) -> str:
        return "markdown"

    def format(
        self,
        findings: list[Finding],
        snapshot: SystemSnapshot,
        *,
        verbose: bool = False,
        comparison: dict | None = None,
    ) -> str:
        """Render findings as Markdown.

        Structure:
        - # Diagnostic Report
        - ## System Summary (table)
        - ## Findings (grouped by severity)
        - ## Comparison (if previous data provided)
        - ## Raw Data (if verbose)
        """
        raise NotImplementedError  # TODO: implement
