"""Hardware collector — static system information.

Gathers information that does not change between runs: CPU model,
GPU, installed RAM, disk devices, kernel version, etc.
"""

from __future__ import annotations

from typing import Any

from .base import BaseCollector


class HardwareCollector(BaseCollector):
    """Collects static hardware and system identification data."""

    def collect(self) -> dict[str, Any]:
        """Return hardware inventory as structured dict."""
        return {
            "cpu": self._collect_cpu(),
            "gpu": self._collect_gpu(),
            "memory": self._collect_memory(),
            "storage": self._collect_storage(),
            "kernel": self._collect_kernel(),
        }

    def _collect_cpu(self) -> dict[str, Any]:
        """Gather CPU identification and capabilities."""
        info: dict[str, Any] = {}

        lscpu = self._run_cmd(["lscpu"])
        if lscpu:
            for line in lscpu.split("\n"):
                if ":" not in line:
                    continue
                key, _, val = line.partition(":")
                val = val.strip()
                key = key.strip()
                if key == "Model name":
                    info["model"] = val
                elif key == "CPU(s)":
                    try:
                        info["cores_logical"] = int(val)
                    except ValueError:
                        pass
                elif key == "Core(s) per socket":
                    try:
                        info["cores_physical"] = int(val)
                    except ValueError:
                        pass
                elif key == "CPU max MHz":
                    try:
                        info["max_mhz"] = float(val.replace(",", "."))
                    except ValueError:
                        pass
                elif key == "CPU min MHz":
                    try:
                        info["min_mhz"] = float(val.replace(",", "."))
                    except ValueError:
                        pass
                elif key == "Architecture":
                    info["arch"] = val

        return info

    def _collect_gpu(self) -> dict[str, Any]:
        """Gather GPU model, driver, and renderer string."""
        info: dict[str, Any] = {}

        # lspci for GPU hardware
        lspci = self._run_cmd(["lspci", "-nnk"])
        if lspci:
            in_vga = False
            for line in lspci.split("\n"):
                if "VGA" in line or "3D" in line or "Display" in line:
                    in_vga = True
                    info["device"] = line.strip()
                elif in_vga and "Kernel driver" in line:
                    info["driver"] = line.split(":")[-1].strip()
                    in_vga = False
                elif in_vga and line and not line.startswith("\t"):
                    in_vga = False

        # glxinfo for renderer (if available)
        glxinfo = self._run_cmd(["glxinfo", "-B"])
        if glxinfo:
            for line in glxinfo.split("\n"):
                if "OpenGL renderer" in line:
                    info["renderer"] = line.split(":")[-1].strip()
                elif "OpenGL version" in line:
                    info["gl_version"] = line.split(":")[-1].strip()

        return info

    def _collect_memory(self) -> dict[str, Any]:
        """Gather total RAM info."""
        content = self._read_file("/proc/meminfo")
        if content is None:
            return {}

        total_kb = 0
        for line in content.split("\n"):
            if line.startswith("MemTotal:"):
                parts = line.split()
                try:
                    total_kb = int(parts[1])
                except (IndexError, ValueError):
                    pass
                break

        return {
            "total_mb": total_kb // 1024,
            "total_gb": round(total_kb / 1024 / 1024, 1),
        }

    def _collect_storage(self) -> list[dict[str, Any]]:
        """Gather block device list with usage info."""
        devices: list[dict[str, Any]] = []

        # Use df for mounted filesystem usage
        df_output = self._run_cmd(["df", "-BM", "--output=source,size,used,avail,pcent,target"])
        if df_output:
            for line in df_output.split("\n")[1:]:  # Skip header
                parts = line.split()
                if len(parts) < 6:
                    continue
                if not parts[0].startswith("/"):
                    continue
                try:
                    devices.append({
                        "device": parts[0],
                        "size_mb": int(parts[1].rstrip("M")),
                        "used_mb": int(parts[2].rstrip("M")),
                        "avail_mb": int(parts[3].rstrip("M")),
                        "used_pct": int(parts[4].rstrip("%")),
                        "mount": parts[5],
                    })
                except ValueError:
                    continue

        # Detect SSD vs HDD
        lsblk = self._run_cmd(["lsblk", "-d", "-o", "NAME,ROTA,MODEL,SIZE", "--noheadings"])
        if lsblk:
            for line in lsblk.split("\n"):
                parts = line.split(None, 3)
                if len(parts) >= 2:
                    name = parts[0]
                    is_rotational = parts[1] == "1"
                    model = parts[2] if len(parts) > 2 else "unknown"
                    size = parts[3] if len(parts) > 3 else "unknown"
                    # Attach to matching device entries
                    for dev in devices:
                        if name in dev["device"]:
                            dev["type"] = "HDD" if is_rotational else "SSD/NVMe"
                            dev["model"] = model
                            dev["disk_size"] = size

        return devices

    def _collect_kernel(self) -> dict[str, Any]:
        """Gather kernel version and release date."""
        uname = self._run_cmd(["uname", "-r"])
        version = self._run_cmd(["uname", "-v"])
        return {
            "release": uname,
            "version": version,
        }
