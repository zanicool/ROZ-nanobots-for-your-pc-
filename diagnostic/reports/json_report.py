"""JSON formatter — machine-readable structured output.

Produces a JSON document containing findings, system snapshot, and
metadata. Designed for programmatic consumption, CI pipelines, and
comparison between runs.
"""

from __future__ import annotations

from diagnostic.models import Finding, SystemSnapshot

from .base import BaseFormatter


class JsonFormatter(BaseFormatter):
    """Renders findings as structured JSON.

    Output schema:
    {
        "meta": { "timestamp", "version", "mode" },
        "system": { ... snapshot ... },
        "findings": [ ... findings ... ],
        "summary": { "critical", "warning", "info", "total" },
        "comparison": { ... if provided ... }
    }
    """

    @property
    def name(self) -> str:
        return "json"

    def format(
        self,
        findings: list[Finding],
        snapshot: SystemSnapshot,
        *,
        verbose: bool = False,
        comparison: dict | None = None,
    ) -> str:
        """Serialize findings and snapshot as JSON string.

        Always includes full data regardless of verbose flag (JSON is
        inherently verbose; consumers can filter what they need).
        """
        raise NotImplementedError  # TODO: implement
