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

- Comprehensive baseline: 30+ categories and many targeted checks
- Fast and lightweight: single script, no install, minimal system impact
- Blue team focused: defensive posture checks rather than privilege escalation
- Read-only by design: does not change system state
- Multiple outputs: console, JSON, HTML, and plain text (format determined by file extension)
- Personal and production modes with contextual recommendations
- Actionable results with severity levels and next steps
- One-liner friendly for quick remote use
- Alignment with common guidance (CIS/NIST)
- Parallel execution for improved performance (30-50% faster with `-p` flag)
- Intelligent caching system for expensive operations
- Advanced malware signature detection and analysis
- Enhanced rootkit detection with cross-view analysis
- Behavioral analysis for anomaly detection
- Simplified command-line interface (no format flag needed)

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
- ✅ **System log analysis** (auth.log, secure, system logs)
- ✅ **Password policy audit** (/etc/shadow access)
- ✅ **Sudo configuration review** (/etc/sudoers analysis)
- ✅ **System service configurations** (detailed service status)
- ✅ **Package integrity verification** (rpm -Va, debsums)
- ✅ **Advanced file permissions** (system-wide SUID/SGID scans)
- ✅ **Process forensics** (network connections, capabilities)
- ✅ **Container security** (privileged containers, host mounts)
- ✅ **Kernel module analysis** (loaded modules inspection)
- ✅ **EDR/monitoring agents** (detailed configuration)

### Running without Sudo (Limited)

```bash
# Limited security assessment
./bt-quickcheck.sh
```

**Without sudo, you only get:**
- ⚠️ **Basic system information** (kernel, distro, uptime)
- ⚠️ **Public network services** (listening ports)
- ⚠️ **User account structure** (UID 0 accounts only)
- ⚠️ **SSH client configuration** (user-accessible settings)
- ⚠️ **Available security tools** (installed packages)
- ⚠️ **User-accessible file permissions** (home directory only)
- ⚠️ **Personal configuration** (shell, environment)

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

### Mode Differences (high-level)
- Firewall: production requires host firewall tooling/rules (WARN/CRIT if missing); personal suggests
- Logging: production expects remote forwarding to a central collector; personal optional
- Time sync: production discourages minimal timesyncd, prefers chrony/ntp with multiple sources
- File integrity: production checks for AIDE/Tripwire and recommends automated monitoring
- EDR: production may flag missing EDR as CRIT and expects SIEM/forwarding
- Resource health (production-only): CPU/memory/disk space checks


## Security Assessment Categories

### Core Security Checks
- System basics: distro, kernel, uptime, virtualization hints
- Patching: pending updates with mode-specific recommendations
- Network exposure: listening services summary and port analysis
- Firewall: ufw/firewalld/nftables/iptables presence and rules (prod requires)
- SSH hardening: PermitRootLogin, PasswordAuthentication, access controls, port configuration
- Auditing and hardening: auditd, SELinux/AppArmor status with activation guidance
- User accounts: unauthorized UID 0 accounts, passwordless accounts, NOPASSWD sudo entries
- Risky permissions: world-writable files/dirs, SUID binaries in sensitive paths
- Intrusion detection: fail2ban status, recent failed login attempts, suspicious activity
- Time synchronization: chrony/ntp/timesyncd status and configuration (prod prefers chrony/ntp)
- Logging and monitoring: rsyslog/syslog-ng, log file permissions, logrotate, remote forwarding (prod expects)
- Network security: TCP SYN cookies, excessive open ports, IPv6 status (personal mode)
- Package integrity: RPM/DEB verification (rpm -Va, debsums)
- File integrity: SHA256 hashes; prod checks for AIDE/Tripwire and monitoring
- Persistence mechanisms: cron jobs, timers, startup scripts, shell configs, kernel modules
- Process forensics: process tree analysis, capabilities, temp directory execution
- Secure configuration: kernel hardening flags, umask settings, core dumps, 2FA indicators
- Container security: Docker/Podman/LXC detection, privileged containers, host mounts, Kubernetes
- Kernel hardening: Secure Boot, lockdown mode, module signing, grsecurity, advanced sysctl flags
- Application security: web server TLS, database exposure, SSL/TLS enforcement
- Secrets management: API keys, SSH keys, .env files permissions, agent forwarding detection
- Cloud/remote management: cloud agents, VNC/RDP detection, remote access security
- EDR/monitoring: antivirus/EDR detection, SIEM/forwarding expectations (prod stricter)
- Backup/resilience: tools, snapshots, disaster recovery
- Resource health (production): CPU load, memory usage, disk space thresholds
- Malware detection: Signature-based detection of common malware patterns
- Rootkit detection: Advanced detection of hidden processes and kernel-level threats
- Behavioral analysis: Anomaly detection and risk assessment based on system behavior


Each finding includes:
- Severity level: OK, WARN, CRIT, INFO
- Recommendations tailored to mode (personal vs production)
- Structured output for automation and reporting

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

## Enhanced Input Validation & Security Features

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

### New Security Hardening Features
- Regex-based input validation for safe character sets
- Hardened output path validation with canonicalization
- Combined argument-length limit for command execution safety
- Expanded dangerous command blocklist (interpreters, editors, archive tools), blocking `eval`, `source`, and `bash|sh -c`
- Disabled shell function inheritance and `BASH_ENV` to prevent injection
- Sensitive-data redaction applied to JSON/HTML/TXT outputs
- Secure temp directories via `mktemp -d` with 0700 permissions

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
- 🐛 **Bug Reports**: Use GitHub issues to report bugs with system details
- 💡 **Feature Requests**: Suggest new security checks or improvements
- 📚 **Documentation**: Help improve documentation and examples
- 🔒 **Security Issues**: Report security vulnerabilities via GitHub's private vulnerability reporting

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


