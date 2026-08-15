"""Monitor collector — live system state.

Captures a point-in-time snapshot of the system's runtime state:
temperatures, memory pressure, top processes, I/O wait, etc.
This data changes constantly, so it represents "right now".
"""

from __future__ import annotations

import os
import time
from typing import Any

from .base import BaseCollector


class MonitorCollector(BaseCollector):
    """Captures current system runtime state.

    Sources:
        - /proc/stat, /proc/meminfo, /proc/vmstat
        - /sys/class/thermal/
        - /proc/<pid>/stat for top processes
        - sensors (lm-sensors)
        - /proc/pressure/*
    """

    def collect(self) -> dict[str, Any]:
        """Snapshot current system state."""
        return {
            "cpu_usage": self._collect_cpu_usage(),
            "frequencies": self._collect_cpu_frequencies(),
            "temperatures": self._collect_temperatures(),
            "memory": self._collect_memory(),
            "io_pressure": self._collect_io_pressure(),
            "cpu_pressure": self._collect_cpu_pressure(),
            "memory_pressure": self._collect_memory_pressure(),
            "processes": self._collect_top_processes(),
            "load_average": self._collect_load_average(),
            "uptime": self._collect_uptime(),
        }

    def _collect_cpu_usage(self) -> dict[str, Any]:
        """Calculate CPU usage from /proc/stat over a 0.5-second interval."""
        def _read_stat() -> list[int]:
            content = self._read_file("/proc/stat")
            if content is None:
                return []
            # First line: cpu <user> <nice> <system> <idle> <iowait> ...
            first_line = content.split("\n")[0]
            return [int(x) for x in first_line.split()[1:]]

        before = _read_stat()
        time.sleep(0.5)
        after = _read_stat()

        if not before or not after:
            return {"total_pct": None, "iowait_pct": None}

        # Calculate deltas
        deltas = [a - b for a, b in zip(after, before)]
        total = sum(deltas)
        if total == 0:
            return {"total_pct": 0.0, "iowait_pct": 0.0}

        idle = deltas[3]  # idle is 4th field
        iowait = deltas[4] if len(deltas) > 4 else 0

        return {
            "total_pct": round((1 - idle / total) * 100, 1),
            "iowait_pct": round(iowait / total * 100, 1),
        }

    def _collect_cpu_frequencies(self) -> list[dict[str, Any]]:
        """Read current and max frequency per core from sysfs."""
        frequencies: list[dict[str, Any]] = []
        core = 0
        while True:
            base = f"/sys/devices/system/cpu/cpu{core}/cpufreq"
            cur = self._read_int(f"{base}/scaling_cur_freq")
            max_freq = self._read_int(f"{base}/scaling_max_freq")
            if cur is None:
                break
            frequencies.append({
                "core": core,
                "current_mhz": cur / 1000,
                "max_mhz": max_freq / 1000 if max_freq else None,
                "governor": self._read_file(f"{base}/scaling_governor"),
            })
            core += 1
        return frequencies

    def _collect_temperatures(self) -> list[dict[str, Any]]:
        """Read all thermal zones and hwmon sensors."""
        temps: list[dict[str, Any]] = []

        # Thermal zones
        zone = 0
        while True:
            base = f"/sys/class/thermal/thermal_zone{zone}"
            temp_raw = self._read_int(f"{base}/temp")
            if temp_raw is None:
                break
            temps.append({
                "source": f"thermal_zone{zone}",
                "label": self._read_file(f"{base}/type") or f"zone{zone}",
                "temp_c": temp_raw / 1000,
            })
            zone += 1

        # hwmon sensors (coretemp etc.)
        hwmon = 0
        while True:
            base = f"/sys/class/hwmon/hwmon{hwmon}"
            if not os.path.isdir(base):
                break
            name = self._read_file(f"{base}/name") or f"hwmon{hwmon}"
            sensor = 1
            while True:
                temp_raw = self._read_int(f"{base}/temp{sensor}_input")
                if temp_raw is None:
                    break
                label = self._read_file(f"{base}/temp{sensor}_label") or f"temp{sensor}"
                crit = self._read_int(f"{base}/temp{sensor}_crit")
                temps.append({
                    "source": name,
                    "label": label,
                    "temp_c": temp_raw / 1000,
                    "critical_c": crit / 1000 if crit else None,
                })
                sensor += 1
            hwmon += 1

        return temps

    def _collect_memory(self) -> dict[str, Any]:
        """Parse /proc/meminfo for RAM and swap state."""
        content = self._read_file("/proc/meminfo")
        if content is None:
            return {}

        info: dict[str, int] = {}
        for line in content.split("\n"):
            parts = line.split()
            if len(parts) >= 2:
                key = parts[0].rstrip(":")
                try:
                    info[key] = int(parts[1])  # Value in kB
                except ValueError:
                    pass

        total_mb = info.get("MemTotal", 0) / 1024
        available_mb = info.get("MemAvailable", 0) / 1024
        swap_total_mb = info.get("SwapTotal", 0) / 1024
        swap_used_mb = (info.get("SwapTotal", 0) - info.get("SwapFree", 0)) / 1024

        return {
            "total_mb": round(total_mb),
            "available_mb": round(available_mb),
            "used_pct": round((1 - available_mb / total_mb) * 100, 1) if total_mb > 0 else 0,
            "swap_total_mb": round(swap_total_mb),
            "swap_used_mb": round(swap_used_mb),
            "swap_used_pct": round(swap_used_mb / swap_total_mb * 100, 1) if swap_total_mb > 0 else 0,
        }

    def _collect_io_pressure(self) -> dict[str, Any]:
        """Read /proc/pressure/io for I/O stall metrics."""
        return self._parse_pressure("/proc/pressure/io")

    def _collect_cpu_pressure(self) -> dict[str, Any]:
        """Read /proc/pressure/cpu for CPU stall metrics."""
        return self._parse_pressure("/proc/pressure/cpu")

    def _collect_memory_pressure(self) -> dict[str, Any]:
        """Read /proc/pressure/memory for memory stall metrics."""
        return self._parse_pressure("/proc/pressure/memory")

    def _parse_pressure(self, path: str) -> dict[str, Any]:
        """Parse a PSI pressure file into structured data."""
        content = self._read_file(path)
        if content is None:
            return {}
        result: dict[str, Any] = {}
        for line in content.split("\n"):
            parts = line.split()
            if not parts:
                continue
            category = parts[0]  # "some" or "full"
            metrics: dict[str, float] = {}
            for part in parts[1:]:
                if "=" in part:
                    key, val = part.split("=", 1)
                    try:
                        metrics[key] = float(val)
                    except ValueError:
                        pass
            result[category] = metrics
        return result

    def _collect_top_processes(self) -> dict[str, list[dict[str, Any]]]:
        """Get top 15 processes by CPU and by memory (RSS)."""
        output = self._run_cmd(
            ["ps", "aux", "--sort=-%cpu", "--no-headers"],
            timeout=5,
        )
        if output is None:
            return {"by_cpu": [], "by_memory": []}

        processes: list[dict[str, Any]] = []
        for line in output.split("\n"):
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue
            try:
                processes.append({
                    "user": parts[0],
                    "pid": int(parts[1]),
                    "cpu_pct": float(parts[2]),
                    "mem_pct": float(parts[3]),
                    "rss_kb": int(parts[5]),
                    "state": parts[7],
                    "command": parts[10][:80],  # Truncate long commands
                })
            except (ValueError, IndexError):
                continue

        by_cpu = sorted(processes, key=lambda p: p["cpu_pct"], reverse=True)[:15]
        by_memory = sorted(processes, key=lambda p: p["rss_kb"], reverse=True)[:15]

        return {"by_cpu": by_cpu, "by_memory": by_memory}

    def _collect_load_average(self) -> dict[str, float]:
        """Read 1/5/15 min load averages from /proc/loadavg."""
        content = self._read_file("/proc/loadavg")
        if content is None:
            return {}
        parts = content.split()
        try:
            return {
                "1min": float(parts[0]),
                "5min": float(parts[1]),
                "15min": float(parts[2]),
                "running_tasks": parts[3],
            }
        except (IndexError, ValueError):
            return {}

    def _collect_uptime(self) -> float | None:
        """Read system uptime in seconds from /proc/uptime."""
        content = self._read_file("/proc/uptime")
        if content is None:
            return None
        try:
            return float(content.split()[0])
        except (IndexError, ValueError):
            return None
