"""CLI module — argument parsing and pipeline orchestration.

This is the top-level orchestrator. It:
1. Parses arguments
2. Runs collectors to build a SystemSnapshot
3. Feeds the snapshot to the AnalysisEngine
4. Passes findings to the ReportGenerator
5. Outputs or saves the result

No business logic lives here — it only wires the layers together.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from diagnostic.analyzers.engine import AnalysisEngine
from diagnostic.collectors.benchmark import BenchmarkCollector
from diagnostic.collectors.hardware import HardwareCollector
from diagnostic.collectors.monitor import MonitorCollector
from diagnostic.collectors.network import NetworkCollector
from diagnostic.models import SystemSnapshot
from diagnostic.reports.generator import ReportGenerator


def main() -> None:
    """Entry point for the diagnostic CLI."""
    args = _parse_args()
    _check_privileges()
    _print_banner()

    collected = _collect(quick=args.quick)
    findings = _analyze(collected)
    report = _report(collected, findings, args)

    _output(report, args)


# ------------------------------------------------------------------
# Private functions — one per pipeline phase
# ------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    """Define and parse CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="diagnostic",
        description="ROZ NanoBots — Why is my PC slow?",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 -m diagnostic              Full diagnosis
  sudo python3 -m diagnostic --quick      Quick (no benchmarks)
  sudo python3 -m diagnostic --format ai  AI-optimized report
  sudo python3 -m diagnostic -o report.json  Save to file
  sudo python3 -m diagnostic --compare old.raw.json  Diff with baseline
        """,
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="Skip benchmarks (faster, less complete)",
    )
    parser.add_argument(
        "--format", choices=["json", "markdown", "ai", "terminal"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    parser.add_argument(
        "--output", "-o", type=str,
        help="Write report to file",
    )
    parser.add_argument(
        "--compare", type=str,
        help="Compare with previous run (path to .raw.json)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Include raw collector data in output",
    )
    return parser.parse_args()


def _check_privileges() -> None:
    """Warn if not running with sufficient privileges."""
    if os.geteuid() != 0:
        print("⚠️  Not running as root — some data may be limited.")
        print("   Re-run with: sudo python3 -m diagnostic\n")


def _print_banner() -> None:
    """Print the startup banner."""
    print("╔══════════════════════════════════════════════════════╗")
    print("║  🔍 ROZ NanoBots — Why is my PC slow?              ║")
    print("╚══════════════════════════════════════════════════════╝\n")


def _collect(*, quick: bool) -> dict:
    """Run all collectors and return raw data dict.

    Args:
        quick: If True, skip benchmarks.
    """
    print("📡 Phase 1: Collecting system data...")
    collected: dict = {}

    collectors = [
        ("Hardware info", "hardware", HardwareCollector()),
        ("System monitoring", "monitor", MonitorCollector()),
        ("Network", "network", NetworkCollector()),
    ]

    for label, key, collector in collectors:
        print(f"  ├─ {label}...", end=" ", flush=True)
        try:
            collected[key] = collector.collect()
            print("✓")
        except NotImplementedError:
            collected[key] = {"status": "not_implemented"}
            print("⏭ (stub)")

    if not quick:
        print("  └─ Benchmarks (this takes a moment)...", end=" ", flush=True)
        try:
            collected["benchmark"] = BenchmarkCollector().collect()
            print("✓")
        except NotImplementedError:
            collected["benchmark"] = {"status": "not_implemented"}
            print("⏭ (stub)")
    else:
        collected["benchmark"] = {"skipped": True}
        print("  └─ Benchmarks skipped (--quick)")

    collected["timestamp"] = datetime.now(timezone.utc).isoformat()
    print()
    return collected


def _analyze(collected: dict) -> list:
    """Run the analysis engine over collected data."""
    print("🧠 Phase 2: Analyzing against top-20 causes...")
    engine = AnalysisEngine()
    print(f"  ├─ Running {engine.analyzer_count} analyzers...")

    snapshot = SystemSnapshot(
        hardware=collected.get("hardware", {}),
        monitor=collected.get("monitor", {}),
        benchmark=collected.get("benchmark", {}),
        network=collected.get("network", {}),
        timestamp=collected.get("timestamp", ""),
    )
    findings = engine.analyze(snapshot)
    print(f"  └─ {len(findings)} probable cause(s) found\n")
    return findings


def _report(collected: dict, findings: list, args: argparse.Namespace) -> str:
    """Generate the formatted report."""
    print("📝 Phase 3: Generating report...")

    comparison = None
    if args.compare:
        comparison = _load_comparison(args.compare)

    generator = ReportGenerator()
    try:
        return generator.generate(
            collected=collected,
            findings=findings,
            output_format=args.format,
            comparison=comparison,
            verbose=args.verbose,
        )
    except NotImplementedError:
        # Formatter is still a stub — produce a minimal fallback
        return _fallback_report(findings)


def _output(report: str, args: argparse.Namespace) -> None:
    """Output the report to terminal or file."""
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report)
        print(f"  └─ Report saved: {output_path}\n")
    else:
        print()
        print(report)


def _load_comparison(path: str) -> dict | None:
    """Load a previous run's JSON data for comparison."""
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"  ⚠️  Cannot load comparison file: {e}")
        return None


def _fallback_report(findings: list) -> str:
    """Minimal report when formatters are not yet implemented."""
    if not findings:
        return (
            "✅ No issues detected (or all analyzers are still stubs).\n"
            "   Implement collectors and analyzers to get real results."
        )
    lines = [f"Found {len(findings)} issue(s):\n"]
    for i, f in enumerate(findings, 1):
        lines.append(f"  {i}. [{f.severity.value}] {f.cause} ({f.confidence:.0%})")
        lines.append(f"     {f.explanation}")
    return "\n".join(lines)
