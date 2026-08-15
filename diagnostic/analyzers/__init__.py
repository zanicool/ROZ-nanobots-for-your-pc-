"""Analyzers — pattern match collected data against known slowness causes.

Each analyzer is a subclass of BaseAnalyzer. It receives a SystemSnapshot
and returns zero or more Finding objects. Analyzers must not perform I/O
or call external commands — they operate purely on the snapshot data.
"""

from .engine import AnalysisEngine

__all__ = ["AnalysisEngine"]
