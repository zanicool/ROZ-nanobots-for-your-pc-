"""Report generation — format findings for humans and machines.

Each formatter is a subclass of BaseFormatter. The ReportGenerator
facade selects the right formatter based on the --format CLI flag.
"""

from .generator import ReportGenerator

__all__ = ["ReportGenerator"]
