"""GPU and compositor analyzers.

Detects:
- No hardware GPU acceleration (llvmpipe / software rendering)
- Desktop compositor misconfiguration (wrong backend, no VSync)
"""

from __future__ import annotations

from diagnostic.models import Finding, SystemSnapshot

from .base import BaseAnalyzer

# Known software renderer strings that indicate no HW acceleration
_SOFTWARE_RENDERERS = frozenset({
    "llvmpipe",
    "swrast",
    "softpipe",
    "mesa software",
})


class GpuAccelerationAnalyzer(BaseAnalyzer):
    """Detect missing GPU hardware acceleration.

    When the GPU driver is missing or broken, the desktop falls back to
    CPU-based rendering (llvmpipe). This makes everything sluggish:
    window animations, scrolling, video playback.
    """

    @property
    def name(self) -> str:
        return "GPU Acceleration"

    @property
    def category(self) -> str:
        return "gpu"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Check the OpenGL renderer string for software fallback.

        Looks at hardware.gpu.renderer and benchmark.gpu.renderer for
        any of the known software renderer identifiers.
        """
        raise NotImplementedError  # TODO: implement


class CompositorAnalyzer(BaseAnalyzer):
    """Detect desktop compositor issues.

    A misconfigured compositor (e.g. no VSync, wrong render backend,
    tearing, or running Xrender instead of OpenGL) can cause visible
    jank even when the system has plenty of resources.
    """

    @property
    def name(self) -> str:
        return "Compositor"

    @property
    def category(self) -> str:
        return "gpu"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Check compositor type, backend, and VSync configuration.

        Inspects hardware.gpu for compositor identification and flags
        known-bad configurations.
        """
        raise NotImplementedError  # TODO: implement
