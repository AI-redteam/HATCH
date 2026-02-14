<p align="center">
  <h1 align="center">HATCH</h1>
  <p align="center"><strong>Host Access Testing for Container Hardening</strong></p>
  <p align="center">
    A comprehensive container escape assessment framework for security professionals.
    <br />
    Detect misconfigurations. Validate isolation. Prove exploitability.
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/version-2.0.0-blue" alt="Version" />
    <img src="https://img.shields.io/badge/python-3.8%2B-green" alt="Python" />
    <img src="https://img.shields.io/badge/license-MIT-yellow" alt="License" />
    <img src="https://img.shields.io/badge/platform-Linux-lightgrey" alt="Platform" />
  </p>
</p>

---

## Overview

HATCH is a single-file, zero-dependency Python tool that systematically audits container environments for escape vectors, security misconfigurations, and hardening gaps. It combines passive detection with optional proof-of-concept exploitation, giving red teamers and security engineers a clear picture of what's actually exploitable — not just what's theoretically risky.

Built for real-world container penetration testing across Docker, Kubernetes, Podman, and LXC environments.

---

## Key Features

- **14 check modules** covering every major container escape category
- **Interactive, auto, and scan-only modes** for different engagement workflows
- **Proof-of-concept execution** with user confirmation gates at every step
- **Severity-ranked findings** (CRITICAL → INFO) with remediation guidance
- **Known CVE detection** with version-aware checks for runc, containerd, Docker, and kernel
- **Cloud metadata extraction** for AWS, GCP, and Azure credential harvesting
- **Zero dependencies** — runs on Python 3.8+ standard library only
- **Single-file deployment** — drop it in, run it, pull it out
- **JSON and Markdown report export** for documentation and handoff

---

## Check Modules

| # | Module | Description | PoC |
|---|--------|-------------|-----|
| 1 | **Container Environment** | Runtime detection (Docker, K8s, Podman, LXC), privilege assessment | — |
| 2 | **Linux Capabilities** | Full CapEff bitmask analysis, dangerous capability identification | `SYS_ADMIN` cgroup escape, `SYS_MODULE` module load, `SYS_PTRACE` process injection, `DAC_READ_SEARCH` file read |
| 3 | **Runtime Socket Exposure** | Docker, containerd, CRI-O, Podman socket detection and API access | Privileged container spawn, API enumeration, containerd `ctr` interaction |
| 4 | **procfs/sysfs Abuse** | `core_pattern`, `uevent_helper`, `sysrq-trigger`, `/proc/1/root`, `/proc/kcore`, `/dev/mem` | Host code execution via `core_pattern` and `uevent_helper`, host filesystem traversal |
| 5 | **Namespace Isolation** | PID, NET, MNT, UTS, IPC, USER namespace sharing analysis | Host process enumeration, network interface and service exposure |
| 6 | **Host Mount Detection** | Sensitive path mounts, block device exposure, host root mounts | Host filesystem read/write, block device mounting |
| 7 | **cgroup Escape** | v1/v2 detection, `release_agent` writability, `notify_on_release` | `release_agent` host code execution |
| 8 | **Security Profiles** | Seccomp, AppArmor, SELinux, NoNewPrivs, SUID binary analysis | GTFOBins-style SUID escalation |
| 9 | **Kubernetes** | Service account tokens, kubelet API, etcd, RBAC enumeration | K8s API enumeration, secret extraction, kubelet exec |
| 10 | **Cloud Metadata** | AWS, GCP, Azure metadata service reachability | IAM credential extraction (IMDSv1/v2), access token harvesting |
| 11 | **Credential Leakage** | Environment variable scanning (30+ patterns), credential file discovery | — |
| 12 | **Known CVEs** | Dirty Pipe, CVE-2022-0185, CVE-2024-21626, CVE-2019-5736, and more | Dirty Pipe compile-and-test verification |
| 13 | **Network Security** | Service enumeration, Docker TCP API, `containerd-shim` abstract sockets | Docker TCP API exploitation |
| 14 | **Filesystem Security** | Root filesystem writability, block device enumeration, `debugfs` | — |

---

## Installation

No installation required. HATCH is a single Python file with no external dependencies.

```bash
# Copy into target container
docker cp hatch.py <container_id>:/tmp/hatch.py

# Or download directly
curl -O https://raw.githubusercontent.com/<org>/hatch/main/hatch.py

# Or paste via kubectl
kubectl cp hatch.py <pod>:/tmp/hatch.py -c <container>
```

### Requirements

- Python 3.8+
- Linux environment (container or host)
- No pip packages required

Optional tools that enhance detection when present: `curl`, `gcc`, `docker`, `ctr`, `lsblk`, `ss`, `ip`.

---

## Usage

### Interactive Mode (Default)

Step through each check module with prompts. Ideal for manual assessments where you want control over what runs.

```bash
python3 hatch.py
```

### Auto Mode

Runs all detection checks automatically. Still prompts before executing any proof-of-concept.

```bash
python3 hatch.py --auto
```

### Scan-Only Mode

Detection and analysis only — no PoC execution prompts. Safe for initial reconnaissance or production-adjacent environments.

```bash
python3 hatch.py --scan-only
```

### Full Options

```
usage: hatch.py [-h] [--auto] [--scan-only] [--no-sudo] [--output OUTPUT]
                [--timeout TIMEOUT] [--version]

options:
  --auto          Auto-run all checks (still prompts before PoCs)
  --scan-only     Detection only, no PoC prompts
  --no-sudo       Do not use sudo for any checks
  --output FILE   Save report to file (.md, .json, or .txt)
  --timeout SEC   Per-command timeout in seconds (default: 8)
  --version       Show version and exit
```

### Examples

```bash
# Quick recon in a locked-down environment
python3 hatch.py --scan-only --no-sudo

# Full assessment with JSON report
python3 hatch.py --auto --output findings.json

# Markdown report for client deliverable
python3 hatch.py --auto --output assessment-report.md

# Interactive with extended timeouts (slow network)
python3 hatch.py --timeout 15
```

---

## Output

### Terminal Output

Findings are severity-ranked with color coding and inline evidence:

```
──────────────────────────────────────────────────────────────────
  Linux Capabilities
──────────────────────────────────────────────────────────────────
  [CRITICAL] Dangerous capability: CAP_SYS_ADMIN [PoC Available]
         Mount filesystems, trace, BPF, namespace manipulation, cgroup escape
         > Bit position: 21
  [CRITICAL] Dangerous capability: CAP_SYS_PTRACE [PoC Available]
         Trace any process - inject code into host processes if PID ns shared
         > Bit position: 19
  [HIGH] Dangerous capability: CAP_NET_ADMIN
         Network configuration - ARP spoofing, interface manipulation
```

### Assessment Summary

```
──────────────────────────────────────────────────────────────────
  Assessment Summary
──────────────────────────────────────────────────────────────────
  Total findings: 23
    CRITICAL  : 4
    HIGH      : 7
    MEDIUM    : 5
    LOW       : 2
    INFO      : 5

  PoCs available: 8

  OVERALL RISK: CRITICAL
  Container escape is likely possible through one or more vectors.

  Priority Remediations:
    → Run container without --privileged flag. Grant only needed capabilities.
    → Never mount Docker socket into containers.
    → Mount /proc/sys read-only or use read-only rootfs.
    → Enable user namespace remapping (userns-remap) in Docker daemon.
```

### Report Export

**JSON** — machine-readable format for integration with other tools and pipelines:

```json
{
  "timestamp": "2026-02-13T14:30:00",
  "system": {
    "kernel": "5.15.0-91-generic",
    "root": true,
    "container": true,
    "runtime": "docker",
    "userns": false
  },
  "findings": [
    {
      "category": "Capabilities",
      "title": "Dangerous capability: CAP_SYS_ADMIN",
      "severity": "CRITICAL",
      "detail": "Mount filesystems, trace, BPF, namespace manipulation, cgroup escape",
      "evidence": "Bit position: 21",
      "poc_available": true,
      "remediation": "Remove CAP_SYS_ADMIN from container capabilities."
    }
  ]
}
```

**Markdown** — structured report for client deliverables and documentation.

---

## Proof-of-Concept Workflow

HATCH follows a strict gate model for PoC execution:

```
Detection → Finding → PoC Available? → User Prompt → Confirmation → Execution → Cleanup
```

1. **Detection** identifies the vector and assesses exploitability
2. **Prompt** describes exactly what the PoC will do before execution
3. **Confirmation** requires explicit `y` input — never auto-executes destructive actions
4. **Cleanup** removes all artifacts (marker files, temp cgroups, test binaries)

### PoC Categories

| Vector | PoC Technique |
|--------|---------------|
| `CAP_SYS_ADMIN` | cgroup `release_agent` overwrite → host code execution |
| `CAP_SYS_MODULE` | `modprobe` dry-run and live module insertion |
| `CAP_SYS_PTRACE` | Host process enumeration and injection surface mapping |
| `CAP_DAC_READ_SEARCH` | Shocker-style `open_by_handle_at` file read |
| Docker socket | Privileged container spawn, host filesystem mount, API enumeration |
| `core_pattern` | Pipe command injection → crash trigger → host execution |
| `uevent_helper` | Helper overwrite → uevent trigger → host execution |
| `/proc/1/root` | Direct host filesystem traversal |
| Dirty Pipe | Compile-time `splice()` behavior verification |
| Kubernetes SA | API enumeration, RBAC permission extraction, secret listing |
| Cloud metadata | AWS/GCP/Azure IAM credential and access token extraction |
| Block devices | Host disk mount and filesystem read |
| SUID binaries | GTFOBins-style escalation path identification |

---

## Supported Environments

| Runtime | Detection | Socket Check | CVE Check |
|---------|-----------|--------------|-----------|
| Docker | ✓ | ✓ | ✓ |
| containerd | ✓ | ✓ | ✓ |
| Podman | ✓ | ✓ | — |
| CRI-O | ✓ | ✓ | — |
| LXC/LXD | ✓ | ✓ | — |
| Kubernetes | ✓ | ✓ (kubelet) | ✓ |

| Cloud | Metadata Detection | Credential Extraction |
|-------|-------------------|-----------------------|
| AWS | ✓ (IMDSv1 + v2) | ✓ |
| GCP | ✓ | ✓ |
| Azure | ✓ | ✓ |

---

## Tracked CVEs

| CVE | Component | Severity | Detection Method |
|-----|-----------|----------|------------------|
| CVE-2024-21626 | runc | CRITICAL | Version check |
| CVE-2022-0847 | kernel (Dirty Pipe) | CRITICAL | Kernel version range + compile-time PoC |
| CVE-2022-0185 | kernel (fsconfig) | CRITICAL | Kernel version + capability check |
| CVE-2021-41091 | Docker Engine | HIGH | Docker version check |
| CVE-2020-15257 | containerd-shim | HIGH | Abstract socket detection |
| CVE-2019-5736 | runc | CRITICAL | Version check |
| CVE-2023-0386 | kernel (OverlayFS) | HIGH | Kernel version range |
| CVE-2023-32233 | kernel (nf_tables) | HIGH | Kernel version range |
| CVE-2020-8558 | Kubernetes | MEDIUM | Network access check |

---

## Architecture

```
hatch.py
├── Context Initialization
│   ├── Identity & privilege detection
│   ├── Capability parsing
│   ├── Container runtime identification
│   └── Kernel & namespace analysis
│
├── Check Modules (14)
│   ├── Each module returns List[Finding]
│   ├── Findings carry severity, evidence, remediation
│   └── PoC functions attached to exploitable findings
│
├── PoC Engine
│   ├── Gated execution with user prompts
│   ├── Artifact cleanup on success and failure
│   └── Success/failure reporting
│
├── Reporting
│   ├── Terminal output (color-coded)
│   ├── JSON export
│   └── Markdown export
│
└── Assessment Summary
    ├── Severity breakdown
    ├── Overall risk rating
    └── Priority remediations
```

---

## Operational Notes

### Stealth Considerations

- **Scan-only mode** performs read-only checks with minimal footprint
- File reads use standard `/proc` and `/sys` interfaces
- Network probes use short-timeout TCP connects
- No files are written to disk in scan-only mode
- PoC artifacts are cleaned up immediately after execution

### Limitations

- Kernel exploit PoCs (Dirty Pipe) require `gcc` in the container
- Some checks require root or passwordless sudo for full coverage
- Cloud metadata checks require outbound network access to `169.254.169.254`
- Runtime version CVE checks depend on `runc`/`docker` CLI availability
- Seccomp profile content analysis is not supported (only mode detection)
- Does not detect custom LSM or gVisor/Kata runtime sandboxing beyond basic indicators

### Safety

- No PoC runs without explicit user confirmation
- All PoCs use benign marker files (touch + id + hostname) rather than destructive payloads
- Temporary files and cgroups are cleaned up on both success and failure
- `--scan-only` guarantees no system modifications

---

## Contributing

Contributions are welcome. Priority areas:

- Additional CVE detection modules
- gVisor / Kata Containers / Firecracker detection
- Windows container support
- Custom seccomp profile analysis
- Integration with CI/CD pipeline scanning
- Additional runtime socket interaction (Podman API, CRI-O)

---

## Legal

HATCH is intended for **authorized security testing only**. Always obtain explicit written permission before running this tool against any environment you do not own. Unauthorized use of this tool may violate applicable laws and regulations.

The authors assume no liability for misuse or damage caused by this tool.

---

## License

MIT License. See `LICENSE` for details.

---

<p align="center">
  <strong>HATCH</strong> — Because every container has a way out. The question is whether you find it first.
</p>
