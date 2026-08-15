"""AI narrative formatter — LLM-optimized natural language report.

Produces output specifically structured for an LLM to interpret and
act on. Unlike the terminal format (designed for human scanning), this
format provides rich context, explains causality chains, and structures
data so an AI can suggest precise fixes.

This is the "give this to ChatGPT/Claude and ask what to do" format.
"""

from __future__ import annotations

from diagnostic.models import Finding, SystemSnapshot

from .base import BaseFormatter


class AiNarrativeFormatter(BaseFormatter):
    """Renders findings as an AI-consumable narrative.

    The output tells a story:
    1. What system this is (hardware context)
    2. What the symptoms are (what the user experiences)
    3. What the probable causes are (with evidence)
    4. How causes relate to each other (causality chains)
    5. Suggested fixes in order of impact

    Example output:
        ## System: ThinkPad X1 Carbon, i7-1165G7, 16GB, 512GB NVMe

        ### Summary
        Your PC feels slow primarily because of **thermal throttling**
        which is compounded by **high I/O pressure** from a large file
        copy to a USB device.

        ### Findings (ranked by impact)
        1. 🔴 Thermal throttling (95% confidence)
           ...

        ### Causality
        The thermal issue forces CPU clocks down, which means the
        ffmpeg encoding takes longer, which extends the I/O pressure
        duration. Fixing thermals would partially resolve the I/O
        issue as well.

        ### Suggested Actions
        1. [immediate] ...
        2. [when convenient] ...
        3. [long-term] ...
    """

    @property
    def name(self) -> str:
        return "ai"

    def format(
        self,
        findings: list[Finding],
        snapshot: SystemSnapshot,
        *,
        verbose: bool = False,
        comparison: dict | None = None,
    ) -> str:
        """Generate AI-optimized narrative report.

        Combines findings into a coherent story with causality analysis
        and prioritized action items.
        """
        raise NotImplementedError  # TODO: implement
