"""Suitability analyzer — "What is my PC good for?"

Instead of only diagnosing problems, this analyzer matches the system's
hardware against known use-case profiles and reports what the machine
is well-suited for, what it can handle with compromises, and what will
be a poor experience.

This gives users actionable context: "Your system is great for
development and daily use, adequate for light video editing, but will
struggle with 4K rendering or running large LLMs."
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from diagnostic.models import Finding, SystemSnapshot

from .base import BaseAnalyzer


class CpuPreference(Enum):
    """What type of CPU performance a use case needs most."""

    SINGLE = "single-thread"
    MULTI = "multi-thread"
    BOTH = "both"


class StoragePreference(Enum):
    """What storage characteristic matters most."""

    IOPS = "random IOPS"
    BANDWIDTH = "sequential bandwidth"
    CAPACITY = "raw capacity"


class SuitabilityRating(Enum):
    """How well a system matches a use case."""

    EXCELLENT = "excellent"
    GOOD = "good"
    ADEQUATE = "adequate"
    POOR = "poor"
    UNSUITABLE = "unsuitable"


@dataclass(frozen=True)
class UseCaseProfile:
    """Hardware requirements for a specific use case.

    Each profile defines the minimum and ideal specs for a workload.
    The analyzer compares actual hardware against these thresholds to
    produce a suitability rating.

    Attributes:
        name:               Human-readable use case name.
        description:        What this workload involves.
        min_ram_gb:         Minimum usable RAM (below = unsuitable).
        ideal_ram_gb:       RAM for comfortable use (above = excellent).
        needs_gpu_accel:    Whether HW GPU acceleration is required.
        min_gpu_vram_gb:    Minimum dedicated VRAM (0 = integrated OK).
        ideal_gpu_vram_gb:  VRAM for comfortable use.
        cpu_preference:     Single-thread, multi-thread, or both.
        min_cores:          Minimum CPU cores.
        ideal_cores:        Cores for comfortable use.
        min_freq_ghz:       Minimum single-core boost clock.
        storage_preference: What kind of storage access pattern dominates.
        needs_nvme:         Whether NVMe speed is important.
        needs_hw_decode:    Whether hardware video decode matters.
        needs_hw_encode:    Whether hardware video encode matters.
        notes:              Extra context for the report.
    """

    name: str
    description: str
    min_ram_gb: float
    ideal_ram_gb: float
    needs_gpu_accel: bool
    min_gpu_vram_gb: float
    ideal_gpu_vram_gb: float
    cpu_preference: CpuPreference
    min_cores: int
    ideal_cores: int
    min_freq_ghz: float
    storage_preference: StoragePreference
    needs_nvme: bool
    needs_hw_decode: bool
    needs_hw_encode: bool
    notes: str = ""


# ======================================================================
# Use Case Registry — the top-20 workloads people buy PCs for
# ======================================================================

USE_CASE_PROFILES: tuple[UseCaseProfile, ...] = (
    UseCaseProfile(
        name="Daily use (browser, mail, office)",
        description="Web browsing, email, document editing, light multitasking",
        min_ram_gb=4,
        ideal_ram_gb=8,
        needs_gpu_accel=True,
        min_gpu_vram_gb=0,
        ideal_gpu_vram_gb=0,
        cpu_preference=CpuPreference.SINGLE,
        min_cores=2,
        ideal_cores=4,
        min_freq_ghz=1.5,
        storage_preference=StoragePreference.IOPS,
        needs_nvme=False,
        needs_hw_decode=True,
        needs_hw_encode=False,
        notes="SSD makes the biggest difference for perceived responsiveness.",
    ),
    UseCaseProfile(
        name="YouTube / streaming / media playback",
        description="4K video playback, streaming services, media consumption",
        min_ram_gb=4,
        ideal_ram_gb=8,
        needs_gpu_accel=True,
        min_gpu_vram_gb=0,
        ideal_gpu_vram_gb=0,
        cpu_preference=CpuPreference.SINGLE,
        min_cores=2,
        ideal_cores=4,
        min_freq_ghz=1.0,
        storage_preference=StoragePreference.BANDWIDTH,
        needs_nvme=False,
        needs_hw_decode=True,
        needs_hw_encode=False,
        notes="HW video decode is essential. Without it, CPU will max out on 4K.",
    ),
    UseCaseProfile(
        name="Software development",
        description="IDE, build systems, Docker, local testing, multiple terminals",
        min_ram_gb=8,
        ideal_ram_gb=32,
        needs_gpu_accel=False,
        min_gpu_vram_gb=0,
        ideal_gpu_vram_gb=0,
        cpu_preference=CpuPreference.BOTH,
        min_cores=4,
        ideal_cores=8,
        min_freq_ghz=2.5,
        storage_preference=StoragePreference.IOPS,
        needs_nvme=True,
        needs_hw_decode=False,
        needs_hw_encode=False,
        notes="NVMe + RAM are king. Build times scale with cores and IOPS.",
    ),
    UseCaseProfile(
        name="Gaming",
        description="Modern games at acceptable framerates and quality",
        min_ram_gb=8,
        ideal_ram_gb=16,
        needs_gpu_accel=True,
        min_gpu_vram_gb=4,
        ideal_gpu_vram_gb=8,
        cpu_preference=CpuPreference.SINGLE,
        min_cores=4,
        ideal_cores=6,
        min_freq_ghz=3.5,
        storage_preference=StoragePreference.BANDWIDTH,
        needs_nvme=True,
        needs_hw_decode=False,
        needs_hw_encode=False,
        notes="GPU is the primary bottleneck. Integrated graphics = very limited.",
    ),
    UseCaseProfile(
        name="Video editing",
        description="Timeline editing, color grading, rendering (DaVinci, Kdenlive)",
        min_ram_gb=16,
        ideal_ram_gb=64,
        needs_gpu_accel=True,
        min_gpu_vram_gb=4,
        ideal_gpu_vram_gb=8,
        cpu_preference=CpuPreference.MULTI,
        min_cores=6,
        ideal_cores=16,
        min_freq_ghz=2.5,
        storage_preference=StoragePreference.BANDWIDTH,
        needs_nvme=True,
        needs_hw_decode=True,
        needs_hw_encode=True,
        notes="Preview playback needs HW decode. Export needs cores + HW encode.",
    ),
    UseCaseProfile(
        name="LLM / AI inference (local models)",
        description="Running language models locally (ollama, llama.cpp)",
        min_ram_gb=16,
        ideal_ram_gb=64,
        needs_gpu_accel=True,
        min_gpu_vram_gb=6,
        ideal_gpu_vram_gb=24,
        cpu_preference=CpuPreference.MULTI,
        min_cores=4,
        ideal_cores=8,
        min_freq_ghz=2.0,
        storage_preference=StoragePreference.BANDWIDTH,
        needs_nvme=True,
        needs_hw_decode=False,
        needs_hw_encode=False,
        notes="Model must fit in RAM (CPU) or VRAM (GPU). Memory bandwidth = tokens/sec.",
    ),
    UseCaseProfile(
        name="3D modelling / rendering (Blender, CAD)",
        description="3D viewport, sculpting, rendering scenes",
        min_ram_gb=16,
        ideal_ram_gb=64,
        needs_gpu_accel=True,
        min_gpu_vram_gb=4,
        ideal_gpu_vram_gb=12,
        cpu_preference=CpuPreference.MULTI,
        min_cores=6,
        ideal_cores=16,
        min_freq_ghz=2.5,
        storage_preference=StoragePreference.BANDWIDTH,
        needs_nvme=False,
        needs_hw_decode=False,
        needs_hw_encode=False,
        notes="Viewport = GPU. Final render = GPU or many cores. Large scenes need RAM.",
    ),
    UseCaseProfile(
        name="Graphic design (Photoshop, GIMP, Figma)",
        description="Large canvases, many layers, filters, vector work",
        min_ram_gb=8,
        ideal_ram_gb=32,
        needs_gpu_accel=True,
        min_gpu_vram_gb=0,
        ideal_gpu_vram_gb=4,
        cpu_preference=CpuPreference.SINGLE,
        min_cores=4,
        ideal_cores=8,
        min_freq_ghz=3.0,
        storage_preference=StoragePreference.IOPS,
        needs_nvme=False,
        needs_hw_decode=False,
        needs_hw_encode=False,
        notes="Filter speed is single-threaded. Large PSD files need RAM.",
    ),
    UseCaseProfile(
        name="Music production (DAW)",
        description="Multi-track recording, plugin chains, low-latency audio",
        min_ram_gb=8,
        ideal_ram_gb=32,
        needs_gpu_accel=False,
        min_gpu_vram_gb=0,
        ideal_gpu_vram_gb=0,
        cpu_preference=CpuPreference.SINGLE,
        min_cores=4,
        ideal_cores=8,
        min_freq_ghz=3.0,
        storage_preference=StoragePreference.IOPS,
        needs_nvme=False,
        needs_hw_decode=False,
        needs_hw_encode=False,
        notes="Audio processing is latency-sensitive. Single-thread speed matters most.",
    ),
    UseCaseProfile(
        name="Home server (Plex, NAS, Docker stack)",
        description="Media serving, file sharing, containerized services",
        min_ram_gb=4,
        ideal_ram_gb=16,
        needs_gpu_accel=False,
        min_gpu_vram_gb=0,
        ideal_gpu_vram_gb=0,
        cpu_preference=CpuPreference.MULTI,
        min_cores=2,
        ideal_cores=4,
        min_freq_ghz=1.5,
        storage_preference=StoragePreference.BANDWIDTH,
        needs_nvme=False,
        needs_hw_decode=True,
        needs_hw_encode=True,
        notes="HW transcode for Plex. Storage throughput for NAS. Low power preferred.",
    ),
    UseCaseProfile(
        name="Virtualization (VMs, lab environments)",
        description="Running multiple VMs concurrently for dev/test",
        min_ram_gb=16,
        ideal_ram_gb=64,
        needs_gpu_accel=False,
        min_gpu_vram_gb=0,
        ideal_gpu_vram_gb=0,
        cpu_preference=CpuPreference.MULTI,
        min_cores=4,
        ideal_cores=12,
        min_freq_ghz=2.0,
        storage_preference=StoragePreference.IOPS,
        needs_nvme=True,
        needs_hw_decode=False,
        needs_hw_encode=False,
        notes="Each VM needs dedicated RAM. VT-x/VT-d required. NVMe for disk images.",
    ),
    UseCaseProfile(
        name="Photo editing / RAW processing",
        description="Large RAW batch processing, catalog management (Lightroom, Darktable)",
        min_ram_gb=8,
        ideal_ram_gb=32,
        needs_gpu_accel=True,
        min_gpu_vram_gb=0,
        ideal_gpu_vram_gb=4,
        cpu_preference=CpuPreference.MULTI,
        min_cores=4,
        ideal_cores=8,
        min_freq_ghz=2.5,
        storage_preference=StoragePreference.BANDWIDTH,
        needs_nvme=True,
        needs_hw_decode=False,
        needs_hw_encode=False,
        notes="Batch export scales with cores. Preview generation benefits from GPU.",
    ),
    UseCaseProfile(
        name="Live streaming / broadcasting (OBS)",
        description="Game capture + encoding + streaming simultaneously",
        min_ram_gb=8,
        ideal_ram_gb=16,
        needs_gpu_accel=True,
        min_gpu_vram_gb=4,
        ideal_gpu_vram_gb=6,
        cpu_preference=CpuPreference.MULTI,
        min_cores=6,
        ideal_cores=8,
        min_freq_ghz=3.0,
        storage_preference=StoragePreference.BANDWIDTH,
        needs_nvme=False,
        needs_hw_decode=False,
        needs_hw_encode=True,
        notes="HW encode (NVENC/VCE/QSV) is critical. Without it, CPU can't keep up.",
    ),
    UseCaseProfile(
        name="Data science / ML training",
        description="Jupyter, pandas on large datasets, model training",
        min_ram_gb=16,
        ideal_ram_gb=64,
        needs_gpu_accel=True,
        min_gpu_vram_gb=6,
        ideal_gpu_vram_gb=24,
        cpu_preference=CpuPreference.MULTI,
        min_cores=4,
        ideal_cores=8,
        min_freq_ghz=2.0,
        storage_preference=StoragePreference.BANDWIDTH,
        needs_nvme=True,
        needs_hw_decode=False,
        needs_hw_encode=False,
        notes="Training = GPU VRAM. Data loading = NVMe + RAM. Big datasets = lots of RAM.",
    ),
    UseCaseProfile(
        name="Heavy multitasking (50+ tabs, Teams, Slack, IDE)",
        description="Many Electron apps open simultaneously",
        min_ram_gb=16,
        ideal_ram_gb=32,
        needs_gpu_accel=True,
        min_gpu_vram_gb=0,
        ideal_gpu_vram_gb=0,
        cpu_preference=CpuPreference.SINGLE,
        min_cores=4,
        ideal_cores=8,
        min_freq_ghz=2.5,
        storage_preference=StoragePreference.IOPS,
        needs_nvme=True,
        needs_hw_decode=False,
        needs_hw_encode=False,
        notes="Each Electron app = ~500MB RAM. This is purely a RAM game.",
    ),
    UseCaseProfile(
        name="Retro gaming / emulation",
        description="Emulating older consoles (PS2, Switch, GameCube)",
        min_ram_gb=8,
        ideal_ram_gb=16,
        needs_gpu_accel=True,
        min_gpu_vram_gb=2,
        ideal_gpu_vram_gb=4,
        cpu_preference=CpuPreference.SINGLE,
        min_cores=4,
        ideal_cores=6,
        min_freq_ghz=3.5,
        storage_preference=StoragePreference.IOPS,
        needs_nvme=False,
        needs_hw_decode=False,
        needs_hw_encode=False,
        notes="Emulation is single-thread. Clock speed matters more than core count.",
    ),
    UseCaseProfile(
        name="CAD / Engineering (FreeCAD, SolidWorks)",
        description="Complex assemblies, simulation, technical drawing",
        min_ram_gb=16,
        ideal_ram_gb=64,
        needs_gpu_accel=True,
        min_gpu_vram_gb=4,
        ideal_gpu_vram_gb=8,
        cpu_preference=CpuPreference.BOTH,
        min_cores=4,
        ideal_cores=8,
        min_freq_ghz=3.0,
        storage_preference=StoragePreference.IOPS,
        needs_nvme=True,
        needs_hw_decode=False,
        needs_hw_encode=False,
        notes="OpenGL viewport = single-thread + GPU. Simulation = multi-core.",
    ),
    UseCaseProfile(
        name="Compiling large projects (kernel, Chromium)",
        description="Building massive codebases from source",
        min_ram_gb=16,
        ideal_ram_gb=64,
        needs_gpu_accel=False,
        min_gpu_vram_gb=0,
        ideal_gpu_vram_gb=0,
        cpu_preference=CpuPreference.MULTI,
        min_cores=4,
        ideal_cores=16,
        min_freq_ghz=2.5,
        storage_preference=StoragePreference.IOPS,
        needs_nvme=True,
        needs_hw_decode=False,
        needs_hw_encode=False,
        notes="Scales linearly with cores. Linking needs RAM. Object files need IOPS.",
    ),
    UseCaseProfile(
        name="Surveillance / NVR (home cameras)",
        description="Recording and decoding multiple camera streams 24/7",
        min_ram_gb=4,
        ideal_ram_gb=8,
        needs_gpu_accel=False,
        min_gpu_vram_gb=0,
        ideal_gpu_vram_gb=0,
        cpu_preference=CpuPreference.MULTI,
        min_cores=2,
        ideal_cores=4,
        min_freq_ghz=1.5,
        storage_preference=StoragePreference.BANDWIDTH,
        needs_nvme=False,
        needs_hw_decode=True,
        needs_hw_encode=False,
        notes="Sustained write bandwidth is critical. HW decode for many streams.",
    ),
    UseCaseProfile(
        name="Digital art / drawing (Krita, tablet)",
        description="Large canvases with many layers, pressure-sensitive input",
        min_ram_gb=8,
        ideal_ram_gb=16,
        needs_gpu_accel=True,
        min_gpu_vram_gb=0,
        ideal_gpu_vram_gb=2,
        cpu_preference=CpuPreference.SINGLE,
        min_cores=4,
        ideal_cores=6,
        min_freq_ghz=3.0,
        storage_preference=StoragePreference.IOPS,
        needs_nvme=False,
        needs_hw_decode=False,
        needs_hw_encode=False,
        notes="Brush lag is the enemy. Input latency and single-thread speed dominate.",
    ),
)


class SuitabilityAnalyzer(BaseAnalyzer):
    """Match system hardware against use-case profiles.

    Unlike other analyzers that detect problems, this one provides
    positive guidance: what the system IS good at, not just what's wrong.
    It produces INFO-level findings that describe suitability.

    The analyzer compares actual hardware specs (from the SystemSnapshot)
    against each UseCaseProfile's requirements and assigns a rating.
    """

    @property
    def name(self) -> str:
        return "Use Case Suitability"

    @property
    def category(self) -> str:
        return "suitability"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Rate the system against all known use-case profiles.

        Produces one Finding per use case where the system is either
        notably well-suited (GOOD or above) or notably poorly suited
        (POOR or below). ADEQUATE ratings are not reported to keep
        output focused.

        Each Finding contains:
        - cause: "{use_case}: {rating}"
        - evidence: hardware specs vs requirements
        - explanation: why this rating was given
        - suggestion: what upgrade would improve the rating
        """
        raise NotImplementedError  # TODO: implement

    # ------------------------------------------------------------------
    # Private — rating logic
    # ------------------------------------------------------------------

    def _rate_use_case(
        self, profile: UseCaseProfile, snapshot: SystemSnapshot
    ) -> SuitabilityRating:
        """Compare snapshot hardware against a single profile.

        Scoring rules:
        - Each requirement contributes a partial score (0.0 - 1.0)
        - Weighted average determines final rating
        - Any single "unsuitable" dimension forces overall POOR max
        """
        raise NotImplementedError  # TODO: implement

    def _check_ram(
        self, total_gb: float, profile: UseCaseProfile
    ) -> float:
        """Score RAM: 0.0 if below min, 1.0 if at or above ideal."""
        raise NotImplementedError  # TODO: implement

    def _check_gpu(
        self, snapshot: SystemSnapshot, profile: UseCaseProfile
    ) -> float:
        """Score GPU capability against profile requirements."""
        raise NotImplementedError  # TODO: implement

    def _check_cpu(
        self, snapshot: SystemSnapshot, profile: UseCaseProfile
    ) -> float:
        """Score CPU (cores * freq) against profile preferences."""
        raise NotImplementedError  # TODO: implement

    def _check_storage(
        self, snapshot: SystemSnapshot, profile: UseCaseProfile
    ) -> float:
        """Score storage type and speed against profile needs."""
        raise NotImplementedError  # TODO: implement

    def _format_finding(
        self,
        profile: UseCaseProfile,
        rating: SuitabilityRating,
        snapshot: SystemSnapshot,
    ) -> Finding:
        """Build a Finding for a noteworthy suitability rating."""
        raise NotImplementedError  # TODO: implement
