"""ROZ NanoBots — Diagnostic Toolkit.

A "Why is my PC slow?" tool that collects system data, matches it
against the top-20 known causes of slowness, and generates an
AI-interpretable report with fix suggestions.

Usage:
    sudo python3 -m diagnostic           # Full diagnosis
    sudo python3 -m diagnostic --quick   # Skip benchmarks
    sudo python3 -m diagnostic --format ai  # AI-optimized output
"""

__version__ = "0.1.0"
