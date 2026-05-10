# ADR-001: Decompose nanobot.py into Single-Responsibility Modules

## Status

Proposed

## Context

`nanobot.py` is a single 4100+ line file containing ~60 functions across ~30 logical domains (package healing, GPU, SMART, network, security, docker, etc.). This creates several problems:

- **Testability**: impossible to unit-test individual modules in isolation
- **Readability**: navigating 4000+ lines to find a specific healing function
- **Merge conflicts**: any change touches the same file
- **Cognitive load**: contributors must understand the entire file to modify one module
- **Linting/type-checking**: slow on a single large file, errors are hard to locate

## Decision

Split `nanobot.py` into a package structure following the Single Responsibility Principle (SRP). Each module handles exactly one healing domain.

### Proposed Structure

```
nanobots/
├── nanobot.py              → thin entry point (CLI + daemon loop)
├── core/
│   ├── __init__.py
│   ├── config.py           → load_config, DEFAULT_CONFIG, cfg
│   ├── stats.py            → load_stats, save_stats, track
│   ├── runner.py           → run(), safe_run()
│   └── logging.py          → log setup
├── modules/
│   ├── __init__.py
│   ├── packages.py         → fix_dpkg_lock, fix_broken_packages, update_system
│   ├── kernel.py           → check_kernel_health, rebuild_grub
│   ├── gpu.py              → check_gpu
│   ├── disk.py             → check_disk_space, check_inodes, check_smart
│   ├── filesystem.py       → check_filesystems, check_fstab
│   ├── services.py         → check_failed_services, check_critical_services
│   ├── processes.py        → kill_zombies, check_high_cpu, check_oom
│   ├── memory.py           → check_memory, check_swap
│   ├── thermal.py          → check_thermals
│   ├── network.py          → check_network, check_dns
│   ├── security.py         → check_security, check_firewall, check_intrusions
│   ├── docker.py           → check_docker
│   ├── hardware.py         → check_usb, check_battery
│   ├── desktop.py          → check_xorg, check_audio, check_bluetooth
│   ├── cleanup.py          → show_cleanup (interactive disk analyzer)
│   └── ...                 → one file per remaining domain
├── cli/
│   ├── __init__.py
│   └── commands.py         → status, heal, quick, cleanup, config
└── tests/
    ├── test_packages.py
    ├── test_disk.py
    ├── test_network.py
    └── ...
```

### Migration Strategy

1. **Phase 1** — Extract `core/` (config, stats, runner, logging). These have zero domain logic and are imported by everything.
2. **Phase 2** — Extract modules one-by-one, starting with the simplest (e.g. `thermal.py` — single function, no dependencies on other modules).
3. **Phase 3** — Extract CLI commands into `cli/commands.py`.
4. **Phase 4** — Add tests per module.

Each phase keeps `nanobot.py` working — the entry point just imports and calls.

### Module Contract

Each module file exports functions with this signature pattern:

```python
from core.runner import run
from core.stats import track
from core.config import cfg

def check_thermals():
    """Monitor CPU/GPU temperatures."""
    ...
```

No module imports another module directly — shared state flows through `core/`.

### Entry Point (after migration)

```python
#!/usr/bin/env python3
from core.config import load_config, cfg
from cli.commands import main

if __name__ == "__main__":
    main()
```

## Consequences

### Positive

- Each module is independently testable with mocked `run()` and `track()`
- Contributors can work on one file without understanding the whole system
- Linting and type-checking run faster per-file
- Git blame/history becomes meaningful per domain
- New healing modules are added by creating a new file + registering it

### Negative

- Import paths change (breaking change for anyone importing directly)
- Slightly more files to navigate (mitigated by clear naming)
- Single-file deployment no longer works (need `pip install .` or copy the package)

### Mitigations

- Keep a `nanobot.py` shim at the root that imports and runs `main()` for backward compat
- The install script copies the entire package to `/opt/nanobot/`
- `pyproject.toml` already exists, extend it with package metadata

## Effort Estimate

| Phase | Effort | Risk |
|-------|--------|------|
| 1. Extract core/ | 1 hour | Low — pure refactor |
| 2. Extract modules | 2-3 hours | Low — mechanical moves |
| 3. Extract CLI | 30 min | Low |
| 4. Add tests | 2-4 hours | None — new code |

Total: ~1 day of focused work.
