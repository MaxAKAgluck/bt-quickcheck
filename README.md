# Blue Team QuickCheck (bt-quickcheck)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/bash-4.0%2B-green.svg)](https://www.gnu.org/software/bash/)
[![Linux](https://img.shields.io/badge/platform-linux-blue.svg)](https://kernel.org/)
[![Security](https://img.shields.io/badge/security-blue%20team-blue.svg)](https://github.com/MaxAKAgluck/bt-quickcheck)

A fast, no-hassle Linux one-liner to baseline a host from a blue team perspective. Inspired by linPEAS' ease-of-use, but focused on defensive posture checks (configuration, hygiene, and quick wins) instead of privilege escalation.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Why this exists](#why-this-exists)
- [How this was built](#how-this-was-built)
- [Project status](#project-status)
- [Installation](#installation)
- [Usage](#usage)
- [Sudo Requirements](#sudo-requirements)
- [Operation Modes](#operation-modes)
- [Security Assessment Categories](#security-assessment-categories)
- [Output Formats](#output-formats)
- [Workflows & Automation](#workflows--automation)
- [Implementation Progress](#implementation-progress)
- [Safety & Design Principles](#safety--design-principles)
- [References](#references)
- [Contributing](#contributing)
- [License](#license)
- [Contact & Support](#contact--support)
- [Acknowledgments](#acknowledgments)## Features

### Core Features
- **Fully Self-Contained**: No external configuration files required - works out of the box
- **Zero Dependencies**: Single Bash script with embedded defaults, runs anywhere
- **Blue Team Focused**: Defensive posture checks rather than privilege escalation
- **Read-Only by Design**: Does not change system state, safe for production; `--offline` guarantees no state changes and no network access
- **Strict by Construction**: `set -euo pipefail`, whitelist-based command validation, hardened path/file handling
- **One-Liner Friendly**: Quick remote deployment like LinPEAS for blue teams

### Assessment Capabilities
- **Comprehensive baseline**: 41 security sections (34 in personal mode, 41 in production mode)
- **Multiple output formats**: Console, JSON, HTML, and plain text (auto-detected by file extension)
- **Personal and production modes**: Context-aware recommendations for different environments
- **Actionable results**: Severity levels (OK/WARN/CRIT/INFO) with clear next steps
- **CIS/NIST aligned**: Checks aligned with common security guidance frameworks
- **Data-driven lifecycle checks**: Distro EOL detection via the [endoflife.date API](https://endoflife.date/docs/api/v1/), with an embedded snapshot fallback for offline runs
- **Modern detection**: systemd unit sandboxing exposure scores, SSH crypto posture (legacy primitives, post-quantum kex, agent forwarding), CrowdSec and current EDR/AV products

### Performance & Reliability
- **Parallel execution**: 30-50% faster scanning with `-p` flag
- **Intelligent caching**: Smart caching system for expensive operations (5-min TTL)
- **Graceful degradation**: Continues assessment even if individual checks fail

### Automation Workflows
- **`--fail-on CRIT|WARN`**: exit codes for CI/cron scheduling and alerting
- **`--baseline` / `--save-findings`**: drift comparison between runs - see NEW and RESOLVED issues since the last scan

### Advanced Detection
- **Malware detection**: Crypto-jacking, suspicious processes, LD_PRELOAD persistence
- **Rootkit detection**: Hidden processes, /dev/tcp backdoors, modified binaries
- **Behavioral analysis**: Time-based anomalies, sudo usage spikes, off-hours activity
- **Intrusion indicators**: Failed login attempts, suspicious cron jobs, bootloader tampering

## Quick Start

```bash
# One-liner execution (recommended)
bash <(curl -fsSL https://raw.githubusercontent.com/MaxAKAgluck/bt-quickcheck/main/bt-quickcheck.sh)

# Or download and run locally
curl -fsSL https://raw.githubusercontent.com/MaxAKAgluck/bt-quickcheck/main/bt-quickcheck.sh -o bt-quickcheck.sh
chmod +x bt-quickcheck.sh
sudo ./bt-quickcheck.sh
```

## Why this exists

I wanted a quick, practical way to baseline a Linux host from a defender’s point of view without hauling in a full-blown auditing suite. This script favors fast, useful signal over exhaustive checks, and tries to point you toward the next best action.

## How this was built

The v0.2–0.6 era of this project was built in the Cursor IDE with Claude (Sonnet) plus external research and manual review. The v0.7.0 revival and reorganization was driven by [OpenCode](https://opencode.ai), alternating between GLM and other supported models for code analysis, refactoring, and check research - all combined with manual review, hands-on testing (WSL smoke tests, no full production runs), and source research (endoflife.date API docs, CIS/NIST guidance, current EDR/AV/SIEM landscape). Expect some rough edges - suggestions and fixes are very welcome.

## Project status

This is an early, evolving tool. The script is still raw and under development. Output formats and checks may change as things improve. If something feels off, please open an issue or PR.

## Installation

### Prerequisites

- Linux system (any major distribution)
- Bash 4.0+ (included in most modern Linux distributions)
- `sudo` access for comprehensive assessment (see [Sudo Requirements](#sudo-requirements) below)

### Method 1: Download and Execute

```bash
# Download the script
curl -fsSL https://raw.githubusercontent.com/MaxAKAgluck/bt-quickcheck/main/bt-quickcheck.sh -o bt-quickcheck.sh

# Make executable
chmod +x bt-quickcheck.sh

# Run with sudo for full assessment
sudo ./bt-quickcheck.sh
```

### Method 2: Git Clone

```bash
git clone https://github.com/MaxAKAgluck/bt-quickcheck.git
cd bt-quickcheck
chmod +x bt-quickcheck.sh
sudo ./bt-quickcheck.sh
```

## Usage

### Basic Usage

```bash
# Comprehensive security assessment (recommended)
sudo ./bt-quickcheck.sh

# Limited assessment without sudo (see limitations below)
./bt-quickcheck.sh

# Get help
./bt-quickcheck.sh --help

# Check version
./bt-quickcheck.sh --version
```

### Command Line Options

```bash
Usage: ./bt-quickcheck.sh [OPTIONS]

OPTIONS:
  -h, --help              Show help message
  -v, --version           Show version information
  -o, --output FILE       Output file with format determined by extension (default: stdout)
  -m, --mode MODE         Operation mode: personal, production (default: personal)
  -p, --parallel          Enable parallel execution for independent checks
  -a, --audit             Enable comprehensive audit logging (disabled by default)
  --offline               Do not refresh metadata or query network data sources
                          (no apt-get update / dnf-yum metadata refresh / lifecycle API calls;
                          uses local package cache and embedded snapshot data only)
  --fail-on CRIT|WARN|none   Exit-code policy for CI/cron (default none; see [Workflows](#workflows--automation))
  --baseline FILE            Compare this run against a previous --save-findings file (drift mode)
  --save-findings FILE       Save this run's findings as a baseline file
      --privacy-level L   standard (default), high, off
      --anonymize         Hash identifiers (hostnames, usernames, IPs) with per-run salt
      --exclude-sections  Comma-separated list (e.g., accounts,file-integrity)
      --exclude-severity  Comma-separated list (e.g., INFO,OK)

OUTPUT FORMATS (determined by file extension):
  .json                  JSON structured output for automation/SIEM
  .html                  HTML report with styling
  .txt                   Plain text report
  (no extension)         Colored console output (default)
```

### Saving Reports to Current Directory

You can save reports directly in the directory where you run the script. Relative paths are allowed and validated safely.

Examples:

```bash
sudo ./bt-quickcheck.sh -m personal --anonymize -o report.json
sudo ./bt-quickcheck.sh -o ./report.html
sudo ./bt-quickcheck.sh -o results/report.txt
```

Allowed locations include your current working directory, your home directory, and standard temporary directories (`/tmp`, `/var/tmp`). Paths are canonicalized to prevent traversal attacks.

## Workflows & Automation

### Exit codes for CI/cron scheduling

With no flags the script always exits 0 (unless arguments are invalid). `--fail-on` turns findings into exit codes so scheduled runs can alert:

| Flag | Condition | Exit code |
|------|-----------|-----------|
| `--fail-on CRIT` | any CRIT finding in the scan | `2` |
| `--fail-on WARN` | any CRIT finding | `2`, else `1` when any WARN exists | 
| `--fail-on CRIT` / `WARN` | no findings at/above threshold | `0` |
| (default `none`) | - | always `0` |

`Summary`, `Drift`, and `Privilege Limitations Summary` bookkeeping entries never affect the exit code - only real scan findings do.

```bash
# Scheduled run with alerting: cron sends mail on non-zero exit
17 3 * * * sudo /opt/btqc/bt-quickcheck.sh --offline --fail-on WARN
```

### Drift mode (what changed since the last scan?)

Baselines are the script's own pipe-delimited findings files - not the JSON/HTML reports:

```bash
# First run: capture a baseline
sudo ./bt-quickcheck.sh --offline --save-findings /var/lib/btqc/baseline.findings

# Any later run: see NEW and RESOLVED issues
sudo ./bt-quickcheck.sh --offline --baseline /var/lib/btqc/baseline.findings

# Rolling baseline: compare, then overwrite the baseline with today's results
sudo ./bt-quickcheck.sh --offline \
  --baseline /var/lib/btqc/baseline.findings \
  --save-findings /var/lib/btqc/baseline.findings
```

Drift compares CRIT/WARN records by section and message. New issues appear in a dedicated **Drift** section with their original severity (a new CRIT prints as `[DRIFT][NEW]` with CRIT emphasis); resolved issues are listed as informational. The Drift section is included in JSON/HTML/TXT output automatically.

Anonymization note: baselines record exactly what the run reported. If you scan with `--anonymize`, keep using it for both runs of the comparison (messages are hashed differently per salt otherwise).

## Sudo Requirements

### Why Sudo is Recommended

While bt-quickcheck can run without sudo, **comprehensive security assessment requires elevated privileges** to access system files, logs, and configurations that are critical for security analysis.

### Running with Sudo (Recommended)

```bash
# Full security assessment
sudo ./bt-quickcheck.sh
```

**With sudo, you get access to:**
- **System log analysis** (auth.log, secure, system logs)
- **Password policy audit** (/etc/shadow access)
- **Sudo configuration review** (/etc/sudoers analysis)
- **System service configurations** (detailed service status)
- **Package integrity verification** (rpm -Va, debsums)
- **Advanced file permissions** (system-wide SUID/SGID scans)
- **Process forensics** (network connections, capabilities)
- **Container security** (privileged containers, host mounts)
- **Kernel module analysis** (loaded modules inspection)
- **EDR/monitoring agents** (detailed configuration)

### Running without Sudo (Limited)

```bash
# Limited security assessment
./bt-quickcheck.sh
```

**Without sudo, you only get:**
- **Basic system information** (kernel, distro, uptime)
- **Public network services** (listening ports)
- **User account structure** (UID 0 accounts only)
- **SSH client configuration** (user-accessible settings)
- **Available security tools** (installed packages)
- **User-accessible file permissions** (home directory only)
- **Personal configuration** (shell, environment)

### Console Warning System

When running without sudo, bt-quickcheck will:

1. **Display prominent warnings** at startup explaining limitations
2. **Show which checks are being skipped** and why they require sudo
3. **Provide a detailed summary** of what was checked vs. what was missed
4. **Recommend running with sudo** for comprehensive assessment

### Production vs Personal Mode

- **Production Mode**: Requires sudo for meaningful security assessment and compliance validation
- **Personal Mode**: Can provide basic security insights without sudo, but comprehensive assessment still requires elevated privileges

### Example Output Differences

#### With Sudo:
```
=== Accounts and Sudo === (Full access) [user security]
[OK] Only root has UID 0
[OK] No NOPASSWD sudo entries
[WARN] 3 accounts without passwords detected
```

#### Without Sudo:
```
=== Accounts and Sudo === (Limited - requires sudo) [user security]
[OK] Only root has UID 0
[WARN] NOPASSWD sudo check skipped - requires sudo access
[WARN] Password audit skipped - requires sudo access to /etc/shadow
```

## Operation Modes

### Personal Mode (Default)
```bash
sudo ./bt-quickcheck.sh -m personal
```
- Home/personal machine recommendations
- Security-through-obscurity suggestions
- User-friendly guidance

### Production Mode
```bash
sudo ./bt-quickcheck.sh -m production
```
- Stricter recommendations and severities
- Additional checks enabled (see below)
- Compliance and centralization focus

### Mode Differences

**Personal Mode** (34 sections):
- Home/personal machine focus with user-friendly guidance
- Skips enterprise-focused compliance and monitoring checks
- Security-through-obscurity suggestions acceptable
- Runs core security, hardening, and detection sections

**Production Mode** (41 sections):
- All personal mode sections PLUS 7 additional enterprise sections:
  1. Cloud & Remote Management (AWS, Azure, GCP agents)
  2. Endpoint Detection & Monitoring (EDR/AV expectations, SIEM forwarding)
  3. Resilience & Backup (backup tools, disaster recovery)
  4. Compliance & Audit (password policy, lockout policy, audit rules)
  5. Enhanced Logging Security (centralized logging, log tampering)
  6. Enhanced Network Access Controls (firewall policies, egress filtering)
  7. Resource Health (CPU/memory/disk monitoring)

**Severity & Recommendation Differences:**
- Firewall: production flags missing firewall as CRIT; personal as INFO
- Logging: production requires remote forwarding (WARN); personal optional (INFO)
- Time sync: production discourages systemd-timesyncd (WARN); personal accepts it (OK)
- EDR: production flags missing EDR as CRIT; personal skips this check entirely


## Security Assessment Categories

bt-quickcheck runs its sections from a single ordered registry in the script, so the list below always mirrors execution. **41 sections** total: **34** run in personal mode, the 7 marked *(production only)* are added with `-m production`.

### Core Baseline (21 sections - both modes)
1. **System**: Distribution, kernel, uptime, virtualization, crash indicators, **data-driven distro EOL detection** (endoflife.date API with embedded-snapshot offline fallback)
2. **Updates & Patching**: Pending updates per package manager (apt/dnf/yum/zypper), automatic-update status, last-update recency; `--offline` skips metadata refresh
3. **Listening Services**: Open ports, insecure services (telnet, FTP, rsh, rlogin, finger, tftp), privileged-port summary
4. **Firewall**: ufw/firewalld/nftables/iptables status, SSH rate-limiting detection
5. **SSH Hardening**: PermitRootLogin, PasswordAuthentication, Allow/Deny lists, Port, Protocol, MaxAuthTries, PubkeyAuthentication, **weak crypto primitives (SHA-1/3DES/CBC/Arcfour), OpenSSH version & post-quantum kex guidance, AllowAgentForwarding**
6. **Auditing/Hardening**: auditd status, audit rules count, log immutability, SELinux/AppArmor
7. **Accounts and Sudo**: UID 0 validation, passwordless accounts, inactive accounts (>90 days), sudo timeout
8. **Risky Permissions**: World-writable files, SUID/SGID binaries, unowned files, sensitive file permissions
9. **Intrusion Detection**: **fail2ban and CrowdSec** (engine state, ban/decision counts), FIM tools (AIDE, Tripwire, OSSEC, Wazuh)
10. **Time Synchronization**: chrony/NTP/systemd-timesyncd status, drift estimation
11. **Logging and Monitoring**: service status, remote logging configuration, log file health
12. **Network Security**: Promiscuous mode detection, risky port analysis, **DNS posture (resolv.conf sanity, systemd-resolved DNSSEC / DNS-over-TLS config)**
13. **Package Integrity**: rpm -Va / debsums verification, orphaned packages, GPG repo validation
14. **File Integrity**: AIDE/Tripwire, immutable attributes (chattr +i), suspicious binary modification
15. **Persistence Mechanisms**: Cron jobs, systemd timers/services, rc.local, shell configs, bootloader tampering
16. **Process & Forensics**: Process tree analysis, network connections, temp-directory execution, capabilities
17. **Secure Configuration**: Core dumps, umask, 2FA detection, **systemd sandboxing exposure scores (`systemd-analyze security`) discovered dynamically from services that own listening sockets**
18. **Container & Virtualization Security**: Docker/Podman/LXC/Kubernetes, privileged containers, image scanners, content trust, **daemon.json hardening (userns-remap, live-restore, log rotation, remote TCP API)**
19. **Kernel & System Hardening**: Secure Boot, lockdown mode, module signing, sysctl hardening (dmesg_restrict, kptr_restrict, ...), **kernel cmdline flag scan (mitigations=off, nopti, nokaslr, nospectre, ...)**
20. **Application-Level Protections**: Web server TLS, database binding validation, SSL/TLS enforcement
21. **Secrets & Sensitive Data**: AWS/SSH/Kubernetes credentials, .env files, SSH/GPG agent detection, **process-environment secret scan (/proc/*/environ var names only, with sudo)**

### Privilege Escalation Surface & Refinements (8 sections - both modes)
22. **Privilege Escalation Surface (Core)**: sudoers misconfiguration (NOPASSWD, timestamp_timeout, secure_path), **doas parity checks (nopass rules, keepenv, config presence)**, PATH hijack risks, SUID/SGID GTFOBins, ld.so.preload abuse, sudo version CVEs (CVE-2023-22809, Baron Samedit), PolKit/PwnKit, Docker socket, dangerous capabilities
23. **Task Runners & NFS Risk**: Cron security, anacron/at, NFS exports
24. **Container, SSH & Secrets Hygiene**: Home-directory SSH keys, Docker credentials, known_hosts, authorized_keys
25. **Kernel, Polkit & Filesystem Hardening**: ptrace_scope, tmpfs exec permissions, protected hardlinks/symlinks, **unprivileged eBPF restriction check, runtime /tmp//dev/shm//var/tmp mount-option verification (findmnt)**
26. **Privilege Escalation Surface (Extended)**: PAM backdoors, systemd timer hijacking, Python library path hijacking, LD_LOADER paths
27. **Enhanced Kernel Security**: Kernel version CVE checks, EOL kernel detection, lockdown validation
28. **Enhanced Network Security**: IP forwarding (v4/v6), TCP SYN cookies, ICMP redirects, source routing
29. **Enhanced Process Security**: Process namespaces, ASLR, RWX memory regions

### Advanced Detection (3 sections - both modes; parallelized with `-p`)
30. **Malware Detection**: Crypto-jacking (xmrig, minerd, ...), suspicious files/processes/network, LD_PRELOAD persistence
31. **Rootkit Detection**: Hidden processes, /dev/tcp backdoors, modified binaries, ls/find discrepancies
32. **Behavioral Analysis**: Zombie processes, off-hours activity, sudo usage spikes

### Wrap-up (2 sections - always run)
33. **Privilege Limitations Summary**: What was checked vs. skipped without sudo
34. **Summary**: Findings totals by severity, per-mode verdict

### Enterprise & Compliance (7 sections - production mode only)
35. **Cloud & Remote Management** *: Cloud agents (AWS, Azure, GCP), VNC/RDP/TeamViewer/AnyDesk detection
36. **Endpoint Detection & Monitoring** *: EDR/AV detection (including Defender for Linux, CrowdStrike falcon, Velociraptor, Elastic Agent), SIEM forwarding (incl. Wazuh agent, osqueryd), log analysis tools
37. **Resilience & Backup** *: Backup tools, snapshot capabilities (BTRFS, ZFS, LVM), disaster recovery
38. **Compliance & Audit** *: Password policy (PASS_MAX_DAYS), lockout policy (pam_faillock), auditd rules
39. **Enhanced Logging Security** *: logrotate, remote forwarding, log tampering, journal persistence
40. **Enhanced Network Access Controls** *: Default firewall policies, rate limiting, egress filtering
41. **Resource Health** *: CPU load, memory usage, disk space

\* production-only sections run after the core baseline and before the privilege-escalation group, matching the script's registry order.

Each finding includes:
- **Severity level**: OK, WARN, CRIT, INFO
- **Recommendations** tailored to mode (personal vs production)
- **Structured output** for automation and reporting
- **Cross-references** to related sections for comprehensive analysis

## Output Formats

### Console Output (Default)
```bash
sudo ./bt-quickcheck.sh
```
- Color-coded severity levels
- Real-time progress indication
- Human-readable formatting

### JSON Output
```bash
sudo ./bt-quickcheck.sh -o security-report.json
```
- Structured data for automation
- SIEM integration ready
- Machine-parseable format
 - Includes privacy header: `{ "privacy": { "level": "standard|high|off", "anonymize": true|false } }`

### HTML Report
```bash
sudo ./bt-quickcheck.sh -o security-report.html
```
- Professional styled report
- Executive summary ready
- Easy sharing and archiving
 - Header shows privacy and anonymization state

### Plain Text
```bash
sudo ./bt-quickcheck.sh -o security-report.txt
```
- Simple text format
- Email-friendly output
- Legacy system compatible

## Optional: Encrypt your report

bt-quickcheck is dependency-light and does not embed encryption. To encrypt your outputs, use standard tools you already trust:

```bash
# OpenSSL (AES-256-GCM)
openssl enc -aes-256-gcm -salt -pbkdf2 -iter 250000 \
  -in security-report.json -out security-report.json.enc

# GPG symmetric (AES256)
gpg --symmetric --cipher-algo AES256 security-report.json

# Age (if installed)
age -p -o security-report.json.age security-report.json
```

Recommended: store keys securely, avoid keeping plaintext after verifying the encrypted file, and follow your organization’s data handling standards.

## Implementation Progress

v0.8.0 (Latest - New checks + automation workflows)
- **Kernel cmdline mitigation scan**: flags `mitigations=off`, `nopti`, `nospectre_v1/v2`, `nospec_store_bypass_disable`, `nokaslr`, `nosmap/nosmep`, `ssbd/mds/l1tf/retbleed` disabling parameters (`/proc/cmdline`), CRIT (common perf-tuning leftovers)
- **Unprivileged eBPF check**: `kernel.unprivileged_bpf_disabled=0` warns - unprivileged eBPF is a live escalation surface
- **Runtime temp-dir mount options**: /tmp, /var/tmp, /dev/shm verified via `findmnt` (catches systemd auto-mounts without fstab entries); nosuid/nodev missing → WARN, noexec missing → INFO (may be intentional)
- **doas parity**: `/etc/doas.conf` + `/etc/doas.d/*` audited like sudoers (nopass rules, nopass+keepenv, missing config)
- **Docker daemon.json hardening**: userns-remap, live-restore, log rotation limits, and remote TCP API exposure in `hosts` (now checked in all modes, not just production)
- **Process-environment secret scan**: with sudo, variable NAMES matching secret patterns found in `/proc/*/environ` (values never printed), capped at 8 processes
- **Dynamic systemd sandbox scoring**: exposure scores now computed for services discovered at runtime as owning listening sockets (via `ss -tlnp`), the classic hardcoded set remains as fallback
- **DNS posture**: resolv.conf sanity (no nameservers configured → WARN) plus systemd-resolved DNSSEC / DNS-over-TLS configuration review
- **`--fail-on CRIT|WARN|none`**: exit-code policy for CI/cron - exit 2 on any CRIT (CRIT mode), exit 1 on any WARN/CRIT (WARN mode); bookkeeping sections are excluded
- **`--baseline` / `--save-findings` drift mode**: compares a run against a previous run's findings file and reports NEW/RESOLVED CRIT/WARN issues in a dedicated Drift section (included in all output formats); enables "what changed since last scan" workflows

v0.7.0 (Modernization & Engine Cleanup)
- **Dead code removed**: the unused RBAC/"permission level" layer, command templates, and a no-op integrity check that hashed itself but compared against nothing (~600 lines lighter)
- **Single section registry**: one ordered `SECTION_REGISTRY` array drives both sequential and parallel execution (the two duplicated section lists that could drift apart are gone)
- **Bug fix**: Resource Health section (production mode) was defined *after* the code path that invoked it, so it silently never ran - now defined before the registry loop
- **`--offline` flag**: `--offline` guarantees zero state changes and zero network access (no apt/dnf metadata refresh, no lifecycle API calls); results reflect the local package cache and embedded snapshot data only
- **Validation hardening**: parallel findings are merged only if each record has exactly 4 fields; malformed records are discarded and counted instead of silently corrupting the report

v0.7.0 - Detection modernization
- **Data-driven distro EOL**: replaces the hardcoded 2023-era distro/version table. Queries the endoflife.date API v1 (curl or wget, cached per run, 30-day TTL via `BTQC_EOL_CACHE_TTL`), falls back to an embedded snapshot (dated) when offline or unreachable, and the finding text always reports which source was used
- **systemd sandboxing exposure**: `systemd-analyze security` overall exposure score for common network-facing services (sshd/openssh-server, nginx, apache2/httpd); WARN in production mode when score >= 8/10
- **SSH crypto posture**: flags explicitly configured weak primitives (SHA-1 kex/MACs, 3DES/CBC/Arcfour ciphers), guides post-quantum hybrid kex on OpenSSH 9.x (> = 10.x defaults to ML-KEM), and checks `AllowAgentForwarding`
- **Current EDR/AV/SIEM lists**: adds Defender for Linux (mdatp), CrowdStrike falcon, Velociraptor, Elastic Agent, Wazuh agent, osqueryd, Sophos (savscan), ESET (esets)
- **CrowdSec detection**: recognizes the mainstream fail2ban successor (engine state + active decision count via `cscli`)

v0.6.3 (Security Hardened & Enhanced)
- **Critical Security Fixes** (5 vulnerabilities patched):
  - Configuration file command injection vulnerability (CVE-worthy)
  - Temporary file race conditions with secure `mktemp` implementation
  - Unsafe printf format string vulnerability
  - Unquoted variable expansion (word splitting prevention)
  - Log parsing DoS with rate limiting and size checks (100MB limit, 10K lines)
- **Self-Contained**: Embedded configuration directly in script - no external `.conf` file needed
- **Enhanced Security**: Fully self-contained like LinPEAS, optional external config with sanitization
- **Comprehensive Assessment**: 41 security sections with 52 new critical checks added
- **Code Quality**: 10 duplicate checks removed, proper cross-referencing between sections
- **Bug Fixes**: Sudo version detection (Baron Samedit false positives), systemd timer symlink handling, missing function call removed
- **All Variables**: Properly quoted and sanitized for `set -u` strict mode
- **Audit & Logging Hygiene**: Command stderr captured and surfaced as WARN findings, audit arguments sanitized, temporary log files auto-removed, and version strings unified across outputs

v0.6.2
- **Performance**: Parallel execution with `-p` flag for 30-50% faster scanning
- **Caching**: Intelligent caching system for expensive operations with 5-minute TTL
- **Security**: Malware signature detection and pattern matching
- **Detection**: Enhanced rootkit detection with hidden process analysis
- **Analysis**: Behavioral analysis for anomaly detection and risk assessment
- **Optimization**: Smart grouping of checks for maximum parallelization

v0.6.1
- Production mode enhancements with stricter checks and resource health monitoring
- Output suppression for non-console formats with progress indicators
- Enhanced error handling and section isolation

v0.6.0
- Enhanced input validation, command sanitization, and compliance-oriented checks
- Additional error handling and logging; section isolation
- CIS/NIST-aligned checks where practical
- Kernel, container, and compliance additions
- Expanded categories and checks

v0.5.1
- Security disclaimers, read-only safeguards, safer file access
- Input/path validation, stricter error handling
- Structured user notices and logging

v0.5.0
- Container security (Docker/Podman/LXC/Kubernetes) and hardening
- Kernel hardening (Secure Boot, lockdown mode, grsecurity detection)
- Application-level checks (web, DB, TLS)
- Secrets management, cloud/remote management, EDR/SIEM, backups

v0.4.0
- File integrity monitoring (SHA256 baselines, AIDE/Tripwire integration)
- Persistence detection (cron, timers, startup scripts, kernel modules)
- Process forensics and hidden process heuristics

v0.3.0
- Multiple output formats (JSON/HTML/TXT)
- Personal vs production modes
- Intrusion detection, time sync, logging validation

v0.2.0
- Core baseline: SSH hardening, firewall status, user account analysis, updates, permissions

## Configuration

### Embedded Configuration (v0.6.3+)
The script is **fully self-contained** with embedded default configuration. No external configuration file is required!

```bash
# Works out of the box - no setup needed
sudo ./bt-quickcheck.sh
```

### Environment Variable Overrides
You can override any default setting using environment variables:

```bash
# Override log level (1=ERROR, 2=WARN, 3=INFO, 4=DEBUG)
BTQC_LOG_LEVEL=4 sudo ./bt-quickcheck.sh

# Override output format
BTQC_OUTPUT_FORMAT=json sudo ./bt-quickcheck.sh -o report.json

# Enable parallel mode and increase workers
BTQC_PARALLEL_MODE=true BTQC_PARALLEL_WORKERS=8 sudo ./bt-quickcheck.sh -p

# Disable caching
BTQC_CACHE_ENABLED=false sudo ./bt-quickcheck.sh
```

### Available Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BTQC_LOG_LEVEL` | `3` (INFO) | Logging verbosity: 1=ERROR, 2=WARN, 3=INFO, 4=DEBUG |
| `BTQC_MEMORY_LIMIT` | `524288` | Memory limit in KB (512MB) |
| `BTQC_CPU_TIME_LIMIT` | `300` | CPU time limit in seconds (5 minutes) |
| `BTQC_FILE_SIZE_LIMIT` | `104857600` | File size limit in bytes (100MB) |
| `BTQC_PROCESS_LIMIT` | `100` | Maximum number of processes |
| `BTQC_CACHE_ENABLED` | `true` | Enable/disable caching system |
| `BTQC_CACHE_TTL` | `300` | Cache time-to-live in seconds |
| `BTQC_PRIVACY_LEVEL` | `standard` | Privacy level: standard, high, off |
| `BTQC_ANONYMIZE` | `false` | Anonymize hostnames, usernames, IPs |
| `BTQC_AUDIT_ENABLED` | `false` | Enable comprehensive audit logging |
| `BTQC_PARALLEL_MODE` | `false` | Enable parallel execution (same as `-p` flag) |
| `BTQC_OPERATION_MODE` | `personal` | Operation mode: personal, production |
| `BTQC_MAX_FINDINGS` | `1000` | Maximum findings to record |
| `BTQC_SECTION_TIMEOUT` | `30` | Timeout per section in seconds |
| `BTQC_OFFLINE` | `false` | Offline mode (same as `--offline` flag) |
| `BTQC_EOL_CACHE_TTL` | `2592000` | How long (seconds) a successful lifecycle API fetch is trusted (default 30 days) |

### Optional External Configuration File
For advanced users, you can still use an external configuration file:

```bash
# Create bt-quickcheck.conf with your custom settings
cat > bt-quickcheck.conf << 'EOF'
BTQC_LOG_LEVEL=4
BTQC_PARALLEL_MODE=true
BTQC_PRIVACY_LEVEL=high
EOF

# Script will automatically load it if present
sudo ./bt-quickcheck.sh
```

**Note:** External config values are sanitized for security and override embedded defaults.

## Safety & Design Principles

Historical security-hardening details (command injection fixes, temp-file race conditions, etc.) are documented per release in [Implementation Progress](#implementation-progress). The principles below describe how the tool stays safe today:

### Read-only by default
- All checks are read-only; no system configuration is modified
- With `--offline` there are zero state changes and zero network access (no package metadata refresh, no lifecycle API calls)
- Without `--offline`, the only state touched is package-manager metadata refresh (e.g. `apt-get update`) and per-run temp/cache dirs cleaned up on exit

### Command execution
- Whitelist-based validation: only well-known read-only system binaries can run, resolved to absolute paths in safe system directories
- Dangerous commands (`rm`, `dd`, `mkfs`, shutdown/reboot, ...) and interpreters/editors are blocked
- Argument length and character-set limits; no `eval`, no `source`, no `bash -c` with user content

### File & path handling
- Output paths are canonicalized; traversal (`../`) and unsafe roots are rejected
- `safe_read` enforces file size limits (default 1MB), rejects world-writable files, and refuses symlinks
- Log parsing is size- and line-limited (`safe_log_grep`) to prevent resource exhaustion

### Process & environment hygiene
- `mktemp` everywhere with 0700/0600 permissions for temp dirs and files
- `BASH_ENV` unset and exported functions disabled to prevent shell-injection via environment
- Strict mode (`set -euo pipefail`) with per-section error isolation: a failing section becomes a WARN finding, never a broken scan

### Privacy
- Sensitive-data patterns (passwords, tokens, API keys, credit cards, emails) are detected and redacted in JSON/HTML/TXT outputs
- `--privacy-level high` coarsens versions/IPs/paths; `--anonymize` hashes hostnames, usernames, and IPs with a per-run salt

## References

- Awesome lists and collections:
  - [Awesome Cybersecurity Blue Team](https://github.com/fabacab/awesome-cybersecurity-blueteam)
  - [WGU-CCDC Blue-Team-Tools](https://github.com/WGU-CCDC/Blue-Team-Tools)
  - [Blue Team Cheatsheet (Hackerium)](https://wiki.hackerium.io/blue-team/blue-team-cheatsheet)
- Auditing and benchmarks:
  - [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) (now integrated in v0.6.0)
  - [Lynis](https://github.com/CISOfy/lynis) (broader audit; we focus on fast baseline)
  - [OpenSCAP](https://www.open-scap.org/) (policy-based scanning)
- Telemetry and runtime security (out of scope for 1-liner, but informative):
  - [osquery](https://github.com/osquery/osquery)
  - [Wazuh](https://github.com/wazuh/wazuh)
  - [Falco](https://github.com/falcosecurity/falco)


## Contributing

I welcome contributions to improve bt-quickcheck! Here's how you can help:

### Reporting Issues
- **Bug Reports**: Use GitHub issues to report bugs with system details
- **Feature Requests**: Suggest new security checks or improvements
- **Documentation**: Help improve documentation and examples
- **Security Issues**: Report security vulnerabilities via GitHub's private vulnerability reporting

### Contributing Code
1. **Fork the repository** and create a feature branch
2. **Propose new checks** via issues first with:
   - Target Linux distributions
   - Command syntax and expected output
   - Severity justification
   - Security benchmark references (CIS, NIST, etc.)
3. **Follow the existing patterns**:
   - Read-only operations only; no external network connections (`--offline` must cover any new data sources)
   - Efficient execution (avoid deep recursive scans); regression-free under both sequential and `-p` parallel modes
   - Both personal and production mode recommendations; mode-aware severities
   - Clear, actionable recommendations; findings must parse through console/JSON/HTML/TXT sanitization
   - Add the section to `SECTION_REGISTRY` (or wire into an existing one) and document it in this README
4. **Test thoroughly** across different distributions
5. **Submit a pull request** with detailed description

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contact & Support

- Issues: [GitHub Issues](https://github.com/MaxAKAgluck/bt-quickcheck/issues)
- Discussions: [GitHub Discussions](https://github.com/MaxAKAgluck/bt-quickcheck/discussions)
- Security: Please report vulnerabilities via GitHub's private vulnerability reporting

## Acknowledgments

- Inspired by [LinPEAS](https://github.com/carlospolop/PEASS-ng) for its ease of use
- Built for the blue team community and defensive security practitioners
- Thanks to all contributors and security researchers who help improve this tool

---

Disclaimer: This tool is provided as-is for defensive assessment purposes. Only run it on systems you are authorized to assess.

Security notice: The script is read-only and includes safeguards to avoid risky operations. Data stays local.


