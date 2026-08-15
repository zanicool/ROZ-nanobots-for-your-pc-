"""Benchmark collector — active performance measurements.

Runs standardized benchmarks to measure actual throughput. These tests
take time but give objective numbers to compare against known baselines.
Skipped entirely in --quick mode.
"""

from __future__ import annotations

from typing import Any

from .base import BaseCollector


class BenchmarkCollector(BaseCollector):
    """Runs CPU, GPU, memory, and storage benchmarks.

    Each benchmark checks for tool availability before running and
    returns None for that section if the tool is missing.

    Sources:
        - sysbench cpu (single + multi thread)
        - sysbench memory
        - fio (4K random read/write, sequential read)
        - glmark2 (OpenGL rendering + renderer string)
    """

    def collect(self) -> dict[str, Any]:
        """Run all available benchmarks and return results.

        Keys:
            cpu:     Events/sec single-thread and multi-thread.
            memory:  Throughput in MiB/s.
            storage: IOPS and bandwidth for various patterns.
            gpu:     glmark2 score and renderer identification.
        """
        return {
            "cpu": self._bench_cpu(),
            "memory": self._bench_memory(),
            "storage": self._bench_storage(),
            "gpu": self._bench_gpu(),
        }

    def _bench_cpu(self) -> dict[str, Any] | None:
        """Run sysbench CPU test (single + multi-thread).

        Returns:
            Dict with events_per_sec_single and events_per_sec_multi,
            or None if sysbench is not installed.
        """
        if not self._has_tool("sysbench"):
            return None
        raise NotImplementedError  # TODO: implement

    def _bench_memory(self) -> dict[str, Any] | None:
        """Run sysbench memory throughput test.

        Returns:
            Dict with throughput_mib_s, or None if unavailable.
        """
        if not self._has_tool("sysbench"):
            return None
        raise NotImplementedError  # TODO: implement

    def _bench_storage(self) -> dict[str, Any] | None:
        """Run fio random and sequential I/O tests.

        Returns:
            Dict with iops_4k_read, iops_4k_write, bw_seq_read_mbs,
            or None if fio is not installed.
        """
        if not self._has_tool("fio"):
            return None
        raise NotImplementedError  # TODO: implement

    def _bench_gpu(self) -> dict[str, Any] | None:
        """Run glmark2 and capture score + renderer string.

        Returns:
            Dict with score and renderer, or None if glmark2 is missing.
        """
        if not self._has_tool("glmark2"):
            return None
        raise NotImplementedError  # TODO: implement
