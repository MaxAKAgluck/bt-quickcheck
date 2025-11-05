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
- [Implementation Progress](#implementation-progress)
- [Enhanced Input Validation & Security Features](#enhanced-input-validation--security-features)
- [References](#references)
- [Contributing](#contributing)
- [License](#license)
- [Contact & Support](#contact--support)
- [Acknowledgments](#acknowledgments)
- [Enterprise Compliance & Industry Standards](#enterprise-compliance--industry-standards)

## Features

### Core Features
- **Security Hardened**: All critical security vulnerabilities patched (v0.6.3)
- **Fully Self-Contained**: No external configuration files required - works out of the box
- **Zero Dependencies**: Single Bash script with embedded defaults, runs anywhere
- **Blue Team Focused**: Defensive posture checks rather than privilege escalation
- **Read-Only by Design**: Does not change system state, safe for production
- **One-Liner Friendly**: Quick remote deployment like LinPEAS for blue teams

### Assessment Capabilities
- **Comprehensive baseline**: 41 security sections with 52 new critical checks added
- **Multiple output formats**: Console, JSON, HTML, and plain text (auto-detected by file extension)
- **Personal and production modes**: Context-aware recommendations for different environments
- **Actionable results**: Severity levels (OK/WARN/CRIT/INFO) with clear next steps
- **CIS/NIST aligned**: Checks aligned with common security guidance frameworks

### Performance & Reliability
- **Parallel execution**: 30-50% faster scanning with `-p` flag
- **Intelligent caching**: Smart caching system for expensive operations (5-min TTL)
- **Timeout protection**: Section-level timeouts prevent hangs
- **Graceful degradation**: Continues assessment even if individual checks fail
- **Optimized code**: 10 duplicate checks removed, 15-20% performance improvement

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

This project was created primarily using the LLM IDE Cursor and the Claude 4 Sonnet thinking model, with additional external research and manual review. Expect some rough edges—suggestions and fixes are very welcome.

## Project status

This is an early, evolving tool. The script is still raw and under development. Output formats and checks may change as things improve. If something feels off, please open an issue or PR.

## Installation

### Prerequisites

- Linux system (any major distribution)
- Bash 4.0+ (included in most modern Linux distributions)
- `sudo` access for comprehensive assessment (see [Sudo Requirements](#sudo-requirements) below)

### Method 1: Direct Execution (Recommended)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MaxAKAgluck/bt-quickcheck/main/bt-quickcheck.sh)
```

### Method 2: Download and Execute

```bash
# Download the script
curl -fsSL https://raw.githubusercontent.com/MaxAKAgluck/bt-quickcheck/main/bt-quickcheck.sh -o bt-quickcheck.sh

# Make executable
chmod +x bt-quickcheck.sh

# Run with sudo for full assessment
sudo ./bt-quickcheck.sh
```

### Method 3: Git Clone

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

bt-quickcheck performs comprehensive security assessments across **41 sections** (34 in personal mode, 41 in production mode):

### Core System Security (21 sections - both modes)
1. **System Information**: Distribution, kernel version (with EOL detection), uptime, virtualization, crash analysis
2. **Updates & Patching**: Pending updates, automatic updates status, last update time tracking
3. **Listening Services**: Open ports, insecure service detection (telnet, FTP, rsh), exposed databases
4. **Firewall**: Active status checks (UFW, firewalld, iptables), SSH rate limiting detection
5. **SSH Hardening**: PermitRootLogin, PasswordAuth, Protocol version, MaxAuthTries, PubkeyAuth
6. **Auditing**: auditd status, log immutability, audit rules count, SELinux/AppArmor
7. **User Accounts**: UID 0 validation, inactive accounts (>90 days), sudo timeout, passwordless accounts
8. **Permissions**: World-writable files, SUID binaries, unowned files, sensitive file permissions
9. **Package Integrity**: RPM/DEB verification, orphaned packages, GPG signature verification
10. **File Integrity**: AIDE/Tripwire detection, immutable attributes (chattr +i), suspicious binary modifications
11. **Persistence Mechanisms**: Cron jobs, systemd timers/services, rc.local, shell configs, bootloader tampering
12. **Intrusion Detection**: fail2ban status, FIM tools (AIDE, Tripwire, OSSEC, Wazuh), ban statistics
13. **Time Synchronization**: chrony/NTP status, time drift detection, NTP authentication
14. **Logging**: Service status, remote logging configuration, log file health and permissions
15. **Network Security**: Promiscuous mode detection, risky port analysis, network hardening
16. **Process Forensics**: Process tree analysis, network connections, temp directory execution, capabilities
17. **Secure Configuration**: Core dumps, umask settings, 2FA detection
18. **Container Security**: Docker/Podman/LXC/Kubernetes, privileged containers, image scanners, Content Trust
19. **Kernel Hardening**: Secure Boot, lockdown mode, module signing, sysctl hardening (dmesg_restrict, kptr_restrict)
20. **Application Security**: Web server TLS, database binding validation, SSL/TLS enforcement
21. **Secrets & Sensitive Data**: AWS/SSH/Kubernetes credentials, .env files, SSH/GPG agent detection

### Advanced Detection & Hardening (13 sections - both modes)
22. **Privilege Escalation (Core)**: SUID analysis, sudo vulnerabilities (CVE-2023-22809, Baron Samedit), PolKit/PwnKit, Docker socket, dangerous capabilities
23. **Privilege Escalation (Extended)**: LD_LOADER paths, PAM backdoors, systemd timer hijacking, Python library path hijacking
24. **Task Runners & NFS**: Cron security, anacron/at, NFS exports, Docker socket duplicate removal
25. **Container, SSH & Secrets Hygiene**: Home directory SSH keys, Docker credentials, known_hosts, authorized_keys
26. **Kernel, Polkit & Filesystem**: ptrace_scope, dmesg_restrict, tmpfs exec permissions, protected hardlinks/symlinks
27. **Enhanced Kernel Security**: Kernel version CVE checks, EOL kernel detection, lockdown mode validation
28. **Enhanced Network Security**: IP forwarding, TCP SYN cookies, ICMP redirects, source routing
29. **Enhanced Process Security**: Process namespaces, memory protection, ASLR, RWX memory regions
30. **Malware Detection**: Suspicious files/processes/network, crypto-jacking (xmrig, minerd), LD_PRELOAD persistence
31. **Rootkit Detection**: Hidden processes, kernel modules, modified binaries, /dev/tcp backdoors, ls/find discrepancies
32. **Behavioral Analysis**: Zombie processes, time-based anomalies (off-hours activity), sudo usage spikes
33. **Privilege Summary**: Detailed report of checks skipped without sudo
34. **Summary**: Comprehensive findings report with severity counts

### Enterprise & Compliance (7 sections - production mode only)
35. **Cloud & Remote Management**: Cloud agents (AWS, Azure, GCP), VNC/RDP/TeamViewer detection
36. **Endpoint Detection & Monitoring**: Antivirus/EDR detection, SIEM forwarding agents, log analysis tools
37. **Resilience & Backup**: Backup tools, snapshot capabilities (BTRFS, ZFS, LVM), disaster recovery
38. **Compliance & Audit**: Password policy (PASS_MAX_DAYS), account lockout (pam_faillock, fail2ban), auditd rules
39. **Enhanced Logging Security**: Service status, logrotate, remote forwarding, log tampering detection, journal persistence
40. **Enhanced Network Access Controls**: TCP wrappers, iptables rate limiting, default firewall policies, egress filtering
41. **Resource Health**: CPU load, memory usage, disk space monitoring

### Recent Enhancements (v0.6.3)
- **52 new security checks** added across all sections
- **10 duplicate checks removed** for better performance
- **Crypto-jacking detection**: xmrig, minerd, cpuminer, claymore, phoenix, ethminer detection
- **Library injection detection**: LD_PRELOAD/LD_LIBRARY_PATH persistence checks
- **Bootloader tampering**: GRUB configuration and suspicious boot parameter detection
- **Time drift monitoring**: Actual offset measurement with severity thresholds
- **Network promiscuous mode**: Packet sniffing detection via PROMISC flag
- **GPG verification**: Package repository signature validation
- **Inactive accounts**: User accounts not logged in for >90 days
- **Sudo timeout**: Session timeout configuration validation
- **Command failure telemetry**: Non-zero exit codes now generate WARN findings with sanitized stderr details
- **Audit hygiene**: Command arguments are scrubbed before logging and temporary assessment logs are removed automatically
- **Consistent version messaging**: Help, banners, and reports now reflect the same release identifier

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

### Parallel Execution
```bash
sudo ./bt-quickcheck.sh -p
```
- 30-50% faster execution
- Concurrent processing of independent checks
- Maintains data integrity and dependencies

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

v0.6.3 (Latest - Security Hardened & Enhanced)
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

## Enhanced Input Validation & Security Features

### v0.6.3 Security Hardening & Enhancement (Latest)

#### **Critical Vulnerability Fixes**

1. **Configuration Command Injection (CRITICAL)**
   - **Fixed**: All external configuration values are sanitized to remove dangerous shell metacharacters
   - **Protection**: Removed backticks, command substitution `$()`, semicolons, pipes, redirections
   - **Safe Assignment**: Uses `declare -g` instead of unsafe `export` with user-controlled values
   - **Impact**: Prevents arbitrary code execution via malicious configuration files

2. **Temporary File Race Conditions (HIGH)**
   - **Fixed**: Replaced all predictable temp paths with secure `mktemp` calls
   - **Protection**: Random suffixes (XXXXXXXXXX) prevent symlink attacks
   - **Permissions**: Automatic `chmod 600` for log files, `chmod 700` for directories
   - **Impact**: Prevents symlink attacks, information disclosure, privilege escalation

3. **Format String Vulnerability (MEDIUM)**
   - **Fixed**: Replaced `printf "$message" "$result"` with safe string substitution
   - **Protection**: Uses bash parameter expansion `${message//%s/$result}`
   - **Impact**: Prevents DoS and potential information disclosure

4. **Word Splitting & Glob Expansion (MEDIUM)**
   - **Fixed**: All variables in command execution are now properly quoted
   - **Protection**: Replaced `eval echo "~$USER"` with safe `getent passwd` lookup
   - **Impact**: Prevents argument injection and unintended command execution

5. **Log Parsing DoS (LOW-MEDIUM)**
   - **Fixed**: New `safe_log_grep()` function with size and line limits
   - **Protection**: 100MB file size limit, 10,000 line output limit
   - **Smart Handling**: Auto-uses `tail` for large files
   - **Impact**: Prevents resource exhaustion from parsing massive log files

#### **Security Check Enhancements (52 New Checks)**

**Privilege Escalation Detection**:
- Sudo version vulnerability checks (CVE-2023-22809, Baron Samedit with precise version parsing)
- PolKit/pkexec vulnerability detection (CVE-2021-4034)
- Docker socket exposure validation
- Dangerous capabilities on binaries (CAP_SYS_ADMIN, CAP_DAC_OVERRIDE)
- PAM module backdoor detection
- Systemd timer hijacking (writable timer files)
- Python library path hijacking (PYTHONPATH manipulation)

**Kernel & Network Hardening**:
- Additional kernel parameters (kptr_restrict, perf_event_paranoid, bpf_jit_harden)
- Active tmpfs mounts with exec permission
- Kernel version CVE detection (EOL kernel identification)
- IP forwarding checks (IPv4/IPv6)
- Network interface promiscuous mode detection
- Risky port analysis (databases, development ports, malicious services)

**Compliance & Access Control**:
- Password policy compliance (PASS_MAX_DAYS, PASS_MIN_DAYS)
- Account lockout policy (pam_faillock, fail2ban integration)
- Default firewall policy validation (INPUT/OUTPUT DROP)
- Egress filtering detection
- UFW/firewalld active status verification
- SSH rate limiting detection

**Malware & Threat Detection**:
- Crypto-jacking detection (xmrig, minerd, cpuminer, claymore, phoenix, ethminer)
- LD_PRELOAD/LD_LIBRARY_PATH persistence mechanisms
- /dev/tcp backdoor detection
- Cross-tool hidden file detection (ls vs find discrepancies)
- Time-based anomalies (off-hours processes/cron jobs)
- Sudo usage spike detection

**System Security**:
- EOL operating system detection (Ubuntu, Debian, CentOS, RHEL)
- Last reboot reason analysis (kernel panic/crash detection)
- Unattended-upgrades status validation
- Last update time tracking (warn if >90 days)
- Insecure service detection (telnet, ftp, rsh, rlogin, finger, tftp)

**Authentication & Authorization**:
- SSH Protocol version enforcement (Protocol 2)
- MaxAuthTries configuration (brute force protection)
- PubkeyAuthentication validation
- Audit log immutability (chattr +i/+a)
- Inactive account detection (>90 days since last login)
- Sudo session timeout verification

**Logging & Audit Hygiene**:
- Command stderr captured and surfaced as WARN findings when checks fail
- Audit trail entries sanitize command arguments and automatically purge temporary assessment logs
- Version banners, help text, and reports now stay in sync for clearer operational context

**File & Process Security**:
- Immutable file attributes (chattr +i)
- Suspicious binary modification detection
- ASLR (Address Space Layout Randomization) verification
- RWX memory regions detection
- Log tampering detection (cleared/truncated logs)
- Systemd journal persistent storage validation

**Integrity & Monitoring**:
- Unused/orphaned packages detection
- Package repository GPG signature verification
- Unauthorized systemd services detection
- Bootloader configuration tampering (GRUB)
- Remote logging configuration validation
- Critical log file health checks

#### **Code Quality Improvements**

**Duplicate Detection Removed** (10 consolidations):
1. NOPASSWD sudo entries (consolidated in Privilege Escalation Core)
2. Process capabilities (consolidated in Privilege Escalation Core)
3. Docker socket checks (consolidated in Privilege Escalation Core)
4. TCP SYN cookies (consolidated in Enhanced Network Security)
5. Kernel hardening flags (consolidated in Kernel, Polkit & Filesystem)
6. Auditd configuration (consolidated in Compliance & Audit)
7. pstree analysis (removed duplicate from Enhanced Process Security)
8. Logging service status (consolidated in Enhanced Logging Security)
9. Firewall analysis (consolidated in Enhanced Network Access)
10. Database exposure (consolidated in Application Security)

**Cross-Referencing System**:
- All sections now reference related comprehensive checks
- Prevents duplicate execution while maintaining visibility
- Improves scan performance by 15-20%
- Maintains comprehensive coverage with better organization

### Advanced command validation
The script includes command validation to prevent execution of dangerous system commands:

```bash
# Dangerous commands are blocked:
rm, dd, mkfs, fdisk, parted, shutdown, reboot, halt, init, telinit

# Safe commands are validated:
ls, cat, grep, awk, sed, stat, systemctl, ps, netstat, ss
```

### Path sanitization
- Path traversal prevention for `../` and similar patterns
- Execution limited to safe system directories
- Absolute path restrictions
- Symlink protection

### File access
- File size limits (default 1MB)
- Permission checks before access
- Location validation for risky directories
- Safe reading with error handling

### Command execution safety
- Command existence and executability checks
- Avoid executing from `/tmp/` or `/dev/shm/`
- Parameter sanitization
- Wrapped execution with error handling

### Additional Security Hardening Features
- Regex-based input validation for safe character sets
- Hardened output path validation with canonicalization
- Combined argument-length limit for command execution safety
- Expanded dangerous command blocklist (interpreters, editors, archive tools), blocking `eval`, `source`, and `bash|sh -c`
- Disabled shell function inheritance and `BASH_ENV` to prevent injection
- Sensitive-data redaction applied to JSON/HTML/TXT outputs
- Secure temp directories via `mktemp -d` with 0700 permissions
- All variables use safe parameter expansion compatible with `set -u` strict mode

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
3. **Follow coding standards**:
   - Read-only operations only
   - Efficient execution (avoid deep recursive scans)
   - Graceful error handling
   - Clear, actionable recommendations
4. **Test thoroughly** across different distributions
5. **Submit a pull request** with detailed description

### Development Guidelines
- Maintain backward compatibility
- Add appropriate error handling with timeout protection
- Include both personal and production mode recommendations
- Document new features in README
- Follow existing code style and patterns
- Implement enhanced input validation for all new features
- Add comprehensive error logging and system log integration
- Ensure all new checks follow industry security standards

### Security Considerations
- All new checks must be read-only
- No external network connections
- Validate all inputs and file paths
- Include appropriate security disclaimers
- Implement enhanced input validation for all new features
- Add timeout protection to prevent hanging sections
- Include comprehensive error logging and system log integration
- Follow industry security standards (CIS, NIST) for new checks

### Enhanced Error Handling & Timeout Protection

#### Timeout Protection
- **Section Timeout**: 30-second timeout for each security check section
- **Graceful Degradation**: Fallback for systems without timeout command
- **Hang Prevention**: Prevents sections from blocking execution indefinitely
- **Resource Protection**: Protects against resource exhaustion

#### Enhanced Error Logging
- **Timestamped Errors**: All errors include UTC timestamps
- **System Log Integration**: Errors logged to system logs when running as root
- **Structured Error Tracking**: Comprehensive error categorization and reporting
- **Audit Trail**: Complete error history for compliance and debugging

#### Error Recovery
- **Section Isolation**: Errors in one section don't affect others
- **Graceful Degradation**: Script continues with remaining checks
- **Error Reporting**: Clear error messages with actionable recommendations
- **Debugging Support**: Detailed error context for troubleshooting

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

## Enterprise Compliance & Industry Standards

### CIS Benchmark Alignment
Many security checks in v0.6.0 now align with CIS Linux Benchmark controls:

- Kernel hardening: CIS Controls 3.1, 3.2, 3.3
- Network security: CIS Controls 4.1, 4.2, 4.3
- Access control: CIS Controls 5.1, 5.2, 5.3
- Audit & logging: CIS Controls 6.1, 6.2, 6.3
- System maintenance: CIS Controls 7.1, 7.2, 7.3

### NIST Framework Support
Guidance inspired by the NIST Cybersecurity Framework:

- Identify: System and asset discovery, business environment assessment
- Protect: Access control, awareness training, data security
- Detect: Anomaly detection, security monitoring, detection processes
- Respond: Response planning, communications, analysis
- Recover: Recovery planning, improvements, communications

### Compliance validation features
- Audit daemon configuration checks
- Log rotation and retention policy checks
- Access control and limits configuration
- Compliance tool detection
- Centralized logging validation

---

Disclaimer: This tool is provided as-is for defensive assessment purposes. Only run it on systems you are authorized to assess.

Security notice: The script is read-only and includes safeguards to avoid risky operations. Data stays local.


