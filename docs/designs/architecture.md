# NanoBots Architecture Design

## Project Tree (proposed modular structure)

```
nanobots/
├── nanobot.py                  # Entry point: CLI dispatch + daemon loop
├── core/
│   ├── __init__.py
│   ├── config.py               # load_config(), DEFAULT_CONFIG, cfg dict
│   ├── stats.py                # load_stats(), save_stats(), track()
│   ├── runner.py               # run(), safe_run() — subprocess wrapper
│   └── log.py                  # Logging setup
├── modules/
│   ├── __init__.py             # Module registry (auto-discovery)
│   ├── packages.py             # fix_dpkg_lock, fix_broken_packages, update_system
│   ├── kernel.py               # check_kernel_health, rebuild_grub, check_kernel_panics
│   ├── gpu.py                  # check_gpu, check_gpu_temp
│   ├── disk.py                 # check_disk_space, check_inodes, check_smart, check_smart_attributes
│   ├── filesystem.py           # check_filesystems, check_fstab, check_mounts
│   ├── services.py             # check_failed_services, check_critical_services
│   ├── processes.py            # kill_zombies, check_high_cpu, check_oom, check_duplicate_processes
│   ├── memory.py               # check_memory, check_swap_usage, check_hugepages
│   ├── thermal.py              # check_thermals, check_fans
│   ├── network.py              # check_network, check_dns, check_intrusions, check_arp_spoof
│   ├── security.py             # check_security, check_firewall, check_ssh_harden, check_apparmor
│   ├── docker.py               # check_docker
│   ├── hardware.py             # check_usb, check_battery, check_firmware, check_cpu_microcode
│   ├── desktop.py              # check_xorg, check_audio, check_bluetooth, check_display_manager
│   ├── systemd.py              # check_systemd_timers, check_systemd_scopes, ...
│   ├── cleanup.py              # show_cleanup (interactive disk analyzer)
│   └── sysctl.py               # check_sysctl, check_tcp_tuning, check_ip_forwarding
├── cli/
│   ├── __init__.py
│   └── commands.py             # status, heal, quick, cleanup, config
├── tests/
│   ├── conftest.py             # Shared fixtures (mock run, mock track)
│   ├── test_packages.py
│   ├── test_disk.py
│   ├── test_network.py
│   ├── test_security.py
│   └── test_cleanup.py
├── docs/
│   ├── README.md               # Documentation index
│   ├── adrs/
│   │   └── adr-001-module-decomposition.md
│   └── designs/
│       ├── architecture.md     # This file
│       └── c4-diagrams.md      # C4 model
├── Makefile
├── pyproject.toml
└── README.md
```

## Class Diagram

```mermaid
classDiagram
    class NanoBot {
        -cfg: dict
        -stats: dict
        -log: Logger
        -shutdown_requested: bool
        +main()
        +heal_full()
        +heal_quick()
        +show_status()
        +show_cleanup()
    }

    class Config {
        +CONFIG_FILE: str
        +DEFAULT_CONFIG: dict
        +load_config() dict
        +cfg: dict
    }

    class Stats {
        +STATS_FILE: str
        +load_stats() dict
        +save_stats(stats: dict)
        +track(key: str, count: int)
    }

    class Runner {
        +run(cmd: str, timeout: int) tuple~int,str~
        +safe_run(cmd: str, timeout: int) tuple~int,str~
    }

    class HealingModule {
        <<interface>>
        +check() void
    }

    class PackageHealing {
        +fix_dpkg_lock()
        +fix_broken_packages()
        +update_system()
    }

    class KernelHealing {
        +check_kernel_health()
        +rebuild_grub()
        +check_kernel_panics()
    }

    class DiskHealing {
        +check_disk_space()
        +check_inodes()
        +check_smart()
    }

    class NetworkHealing {
        +check_network()
        +check_dns()
        +check_intrusions()
    }

    class ServiceHealing {
        +check_failed_services()
        +check_critical_services()
    }

    class ProcessHealing {
        +kill_zombies()
        +check_high_cpu()
        +check_oom()
    }

    class SecurityHealing {
        +check_security()
        +check_firewall()
        +check_ssh_harden()
    }

    class CleanupAnalyzer {
        +show_cleanup()
        -scan_directories() list
        -generate_suggestions() list
        -execute_cleanup(indices: list)
    }

    NanoBot --> Config : uses
    NanoBot --> Stats : uses
    NanoBot --> Runner : uses
    NanoBot --> HealingModule : orchestrates

    HealingModule <|.. PackageHealing
    HealingModule <|.. KernelHealing
    HealingModule <|.. DiskHealing
    HealingModule <|.. NetworkHealing
    HealingModule <|.. ServiceHealing
    HealingModule <|.. ProcessHealing
    HealingModule <|.. SecurityHealing
    HealingModule <|.. CleanupAnalyzer

    PackageHealing --> Runner : calls
    KernelHealing --> Runner : calls
    DiskHealing --> Runner : calls
    NetworkHealing --> Runner : calls
    ServiceHealing --> Runner : calls
    ProcessHealing --> Runner : calls
    SecurityHealing --> Runner : calls

    PackageHealing --> Stats : track()
    DiskHealing --> Stats : track()
    NetworkHealing --> Stats : track()
    ServiceHealing --> Stats : track()
```

## Sequence Diagrams

### Daemon Startup & Main Loop

```mermaid
sequenceDiagram
    participant OS as systemd
    participant Main as nanobot.py
    participant Cfg as Config
    participant Log as Logger
    participant Heal as heal_full()
    participant Quick as heal_quick()

    OS->>Main: start service
    Main->>Cfg: load_config()
    Cfg-->>Main: cfg dict
    Main->>Log: setup logging
    Main->>Main: register signal handlers (SIGTERM, SIGINT)
    
    loop every cfg.interval (3600s)
        Main->>Heal: heal_full()
        Heal->>Heal: iterate all modules
        Heal-->>Main: done
        Main->>Main: save_stats()
        
        loop every cfg.realtime_interval (30s)
            alt shutdown_requested
                Main->>Main: break
            else
                Main->>Quick: heal_quick()
                Quick-->>Main: done
            end
        end
    end
    
    OS->>Main: SIGTERM
    Main->>Main: shutdown_requested = True
    Main->>Main: save_stats()
    Main-->>OS: exit 0
```

### Full Healing Cycle

```mermaid
sequenceDiagram
    participant HF as heal_full()
    participant Pkg as PackageHealing
    participant Disk as DiskHealing
    participant Svc as ServiceHealing
    participant Net as NetworkHealing
    participant R as Runner
    participant S as Stats

    HF->>Pkg: fix_broken_packages()
    Pkg->>R: run("dpkg --configure -a")
    R-->>Pkg: (exit_code, output)
    Pkg->>S: track("packages_fixed")
    Pkg-->>HF: done

    HF->>Disk: check_disk_space()
    Disk->>Disk: shutil.disk_usage("/")
    alt pct > 90%
        Disk->>R: run("apt-get autoclean -y")
        Disk->>R: run("journalctl --vacuum-time=2d")
        Disk->>S: track("disk_cleanups")
    end
    Disk-->>HF: done

    HF->>Svc: check_failed_services()
    Svc->>R: run("systemctl --failed")
    R-->>Svc: failed units list
    loop each failed unit
        Svc->>R: run("systemctl restart <unit>")
        Svc->>S: track("services_restarted")
    end
    Svc-->>HF: done

    HF->>Net: check_network()
    Net->>R: run("ping -c1 1.1.1.1")
    alt ping fails
        Net->>R: run("systemctl restart NetworkManager")
        Net->>S: track("network_restarts")
    end
    Net-->>HF: done
```

### Interactive Cleanup Flow

```mermaid
sequenceDiagram
    participant User
    participant CLI as nanobot.py cleanup
    participant CA as CleanupAnalyzer
    participant FS as Filesystem
    participant Sub as subprocess

    User->>CLI: python3 nanobot.py cleanup
    CLI->>CA: show_cleanup()
    
    CA->>FS: shutil.disk_usage("/")
    FS-->>CA: total, used, free
    CA->>CA: render disk bar

    CA->>Sub: du -sb ~/dirs
    Sub-->>CA: sizes per directory
    CA->>CA: render space map (sorted, with bars)

    CA->>CA: scan for cleanup opportunities
    CA->>Sub: du -sm ~/.cache/pip
    CA->>Sub: du -sm /var/cache/apt
    CA->>Sub: ollama list
    Sub-->>CA: sizes + model list
    CA->>CA: build suggestions list

    CA->>User: display suggestions with sizes
    CA->>User: prompt "Enter numbers or 'all'"
    User->>CA: "1 3 5"

    loop each selected suggestion
        CA->>Sub: execute cleanup command
        Sub-->>CA: result
        CA->>User: show ✓ Done
    end

    CA->>FS: shutil.disk_usage("/")
    CA->>User: show freed space
```

### CLI Command Dispatch

```mermaid
sequenceDiagram
    participant User
    participant Main as main()
    participant Status as show_status()
    participant Heal as heal_full()
    participant Quick as heal_quick()
    participant Cleanup as show_cleanup()

    User->>Main: python3 nanobot.py <cmd>
    
    alt cmd == "status"
        Main->>Status: show_status()
        Status->>Status: load_stats()
        Status->>User: render dashboard
    else cmd == "heal"
        Main->>Heal: heal_full()
        Heal->>Heal: run all modules
        Heal->>Main: save_stats()
    else cmd == "quick"
        Main->>Quick: heal_quick()
        Quick->>Quick: run critical checks only
    else cmd == "cleanup"
        Main->>Cleanup: show_cleanup()
        Cleanup->>User: interactive disk analysis
    else cmd == "config"
        Main->>Main: write DEFAULT_CONFIG to /etc/nanobot/config.json
    else no args
        Main->>Main: start daemon loop
    end
```
