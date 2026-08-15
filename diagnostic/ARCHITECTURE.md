# Diagnostic Toolkit — Architecture & Feature Overview

## Purpose

A "Why is my PC slow?" tool that:
1. Collects system data (hardware, performance, monitoring)
2. Analyzes results against the top-20 known causes of slowness
3. Generates a narrative report that AI (or humans) can interpret and act on

## Feature Map

| # | Cause | Collector | Analyzer | Detection Method |
|---|-------|-----------|----------|------------------|
| 1 | CPU clock too low (power saving) | `hardware`, `monitor` | `CpuFrequencyAnalyzer` | Compare current vs max frequency |
| 2 | No GPU hardware acceleration | `hardware`, `benchmark` | `GpuAccelerationAnalyzer` | Check renderer string for llvmpipe/swrast |
| 3 | SSD slow or nearly full | `hardware`, `benchmark` | `StorageCapacityAnalyzer` | Disk usage % + fio throughput |
| 4 | Low RAM / heavy swap | `monitor` | `MemoryPressureAnalyzer` | Free RAM, swap usage, oom events |
| 5 | Single process hogging CPU | `monitor` | `CpuHogAnalyzer` | Top processes by CPU% |
| 6 | Thermal throttling | `monitor` | `ThermalAnalyzer` | Temps vs throttle threshold |
| 7 | Missing/bad drivers | `hardware` | `DriverAnalyzer` | Kernel modules, fallback drivers |
| 8 | Wrong power profile | `hardware` | `PowerProfileAnalyzer` | governor, TLP, power-profiles-daemon |
| 9 | External monitor/dock bottleneck | `hardware` | `DisplayLinkAnalyzer` | USB-C bandwidth, DisplayLink presence |
| 10 | Background tasks (indexing, updates) | `monitor` | `BackgroundLoadAnalyzer` | tracker-miner, snapd, packagekitd |
| 11 | Failing SSD (I/O errors) | `hardware` | `StorageHealthAnalyzer` | SMART data, dmesg errors |
| 12 | Network issues causing app hangs | `network` | `NetworkLatencyAnalyzer` | DNS latency, packet loss, gateway RTT |
| 13 | Filesystem errors | `hardware` | `FilesystemAnalyzer` | dmesg ext4 errors, read-only mounts |
| 14 | Memory leaks in applications | `monitor` | `MemoryLeakAnalyzer` | High-RSS processes relative to total RAM |
| 15 | Outdated BIOS/kernel | `hardware` | `FirmwareAnalyzer` | Kernel age, BIOS date |
| 16 | USB devices consuming resources | `hardware`, `monitor` | `UsbLoadAnalyzer` | USB errors in dmesg, interrupt counts |
| 17 | Virtualization overhead | `monitor` | `VirtualizationAnalyzer` | KVM/VBox processes, nested virt |
| 18 | Malware / cryptominers | `monitor` | `MalwareAnalyzer` | Suspicious high-CPU processes, known names |
| 19 | Desktop compositor misconfiguration | `hardware` | `CompositorAnalyzer` | Compositor type, VSync, render backend |
| 20 | Zombie / duplicate processes | `monitor` | `ZombieProcessAnalyzer` | Process state, duplicate detection |

## Package Structure

```
diagnostic/
├── __init__.py
├── __main__.py              # Entry point: python3 -m diagnostic
├── cli.py                   # Argument parsing, orchestration
│
├── collectors/              # Data gathering (no analysis logic)
│   ├── __init__.py
│   ├── base.py              # Abstract BaseCollector
│   ├── hardware.py          # Static hardware info (CPU, GPU, disks, RAM)
│   ├── benchmark.py         # Active benchmarks (sysbench, fio, glmark2)
│   ├── monitor.py           # Live monitoring (temps, processes, memory)
│   └── network.py           # Network diagnostics (latency, DNS, bandwidth)
│
├── analyzers/               # Pattern matching (no data collection)
│   ├── __init__.py
│   ├── base.py              # Abstract BaseAnalyzer + Finding dataclass
│   ├── cpu.py               # CpuFrequencyAnalyzer, CpuHogAnalyzer
│   ├── gpu.py               # GpuAccelerationAnalyzer, CompositorAnalyzer
│   ├── memory.py            # MemoryPressureAnalyzer, MemoryLeakAnalyzer
│   ├── storage.py           # StorageCapacityAnalyzer, StorageHealthAnalyzer
│   ├── thermal.py           # ThermalAnalyzer
│   ├── power.py             # PowerProfileAnalyzer
│   ├── drivers.py           # DriverAnalyzer, DisplayLinkAnalyzer
│   ├── network.py           # NetworkLatencyAnalyzer
│   ├── processes.py         # BackgroundLoadAnalyzer, ZombieProcessAnalyzer, MalwareAnalyzer
│   ├── system.py            # FirmwareAnalyzer, FilesystemAnalyzer, VirtualizationAnalyzer
│   ├── usb.py               # UsbLoadAnalyzer
│   └── engine.py            # AnalysisEngine: runs all analyzers, sorts findings
│
├── reports/                 # Output formatting (no analysis logic)
│   ├── __init__.py
│   ├── base.py              # Abstract BaseFormatter
│   ├── terminal.py          # Colored terminal output
│   ├── markdown.py          # Markdown report
│   ├── json_report.py       # Structured JSON for AI consumption
│   └── ai_narrative.py      # Natural-language narrative for LLM analysis
│
└── models.py                # Shared data classes (Finding, Severity, SystemSnapshot)
```

## Design Principles

1. **Single Responsibility** — Collectors only gather data. Analyzers only
   interpret data. Reporters only format output. No cross-concerns.

2. **Open/Closed** — Add new causes by adding a new Analyzer subclass.
   No modification to existing code needed.

3. **Dependency Inversion** — Analyzers depend on abstract data models
   (SystemSnapshot), not on specific collector implementations.

4. **Information Hiding** — Each module exposes only its public interface.
   Internal helpers are prefixed with `_`.

5. **Graceful Degradation** — Missing tools (e.g., no `fio` installed)
   produce a "skipped" result, never a crash.

## Data Flow

```
┌─────────────┐    SystemSnapshot    ┌─────────────┐    List[Finding]    ┌─────────────┐
│  Collectors │ ──────────────────► │  Analyzers  │ ──────────────────► │  Reporters  │
│  (gather)   │                      │  (diagnose) │                      │  (format)   │
└─────────────┘                      └─────────────┘                      └─────────────┘
```

## Key Data Models

```python
@dataclass
class Finding:
    cause: str              # e.g. "Thermal throttling detected"
    severity: Severity      # CRITICAL, WARNING, INFO
    evidence: str           # e.g. "CPU temp 94°C, throttle threshold 90°C"
    explanation: str        # Human-readable story of what's happening
    suggestion: str         # Actionable fix
    category: str           # e.g. "thermal", "gpu", "memory"
    confidence: float       # 0.0 - 1.0

class Severity(Enum):
    CRITICAL = "critical"   # Definitely causing slowness
    WARNING = "warning"     # Likely contributing
    INFO = "info"           # Worth noting but minor

@dataclass
class SystemSnapshot:
    hardware: dict          # Static hardware information
    monitor: dict           # Live monitoring data
    benchmark: dict         # Benchmark results (or skipped)
    network: dict           # Network diagnostics
    timestamp: str          # ISO 8601
```

## CLI Interface

```bash
# Run as module
sudo python3 -m diagnostic

# Options
sudo python3 -m diagnostic --quick          # Skip benchmarks
sudo python3 -m diagnostic --format json    # Machine-readable
sudo python3 -m diagnostic --format ai      # LLM-optimized narrative
sudo python3 -m diagnostic -o report.json   # Save to file
sudo python3 -m diagnostic --compare old.json  # Diff with baseline
```

## AI Report Format (--format ai)

The AI narrative format produces output like:

```
## System: Dell XPS 13, Intel i7-1165G7, 16GB RAM, 512GB NVMe

### Why your PC feels slow:

Your computer is experiencing **thermal throttling**. The CPU temperature
is 94°C which exceeds the throttle threshold of 90°C. This causes the CPU
to reduce its clock speed from 4.7 GHz to 1.2 GHz to prevent damage.

Additionally, you have **no GPU hardware acceleration**. The graphics
renderer shows "llvmpipe" which means your desktop is being drawn entirely
by the CPU. This compounds the throttling issue.

### Probable causes (ranked by confidence):

1. 🔴 **Thermal throttling** (confidence: 95%)
   - Evidence: CPU at 94°C, max turbo dropped from 4.7 to 1.2 GHz
   - Fix: Clean dust from vents, check thermal paste, use a cooling pad

2. 🔴 **Software rendering** (confidence: 90%)
   - Evidence: OpenGL renderer = "llvmpipe (LLVM 15.0.7, 256 bits)"
   - Fix: Install proper GPU driver: `sudo apt install intel-media-va-driver`

3. 🟡 **Background indexer running** (confidence: 60%)
   - Evidence: tracker-miner-fs using 45% CPU
   - Fix: `systemctl --user mask tracker-miner-fs-3`

### Raw data available in: report.raw.json
```

## Dependencies

Required (standard Linux tools, no pip packages):
- `python3 >= 3.9` (dataclasses, typing)
- `lscpu`, `lspci`, `lsusb` (pciutils, usbutils)
- `sensors` (lm-sensors)
- `/proc`, `/sys` filesystem access

Optional (for benchmarks):
- `sysbench` — CPU/memory benchmark
- `fio` — Storage benchmark
- `glmark2` — GPU benchmark

## Testing Strategy

- Unit tests per analyzer with mocked collector data
- Integration test with a sample SystemSnapshot fixture
- No real hardware access in tests — all file/command reads are mockable
