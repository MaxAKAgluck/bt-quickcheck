# Blue Team QuickCheck (bt-quickcheck)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/bash-4.0%2B-green.svg)](https://www.gnu.org/software/bash/)
[![Linux](https://img.shields.io/badge/platform-linux-blue.svg)](https://kernel.org/)
[![Security](https://img.shields.io/badge/security-blue%20team-blue.svg)](https://github.com/MaxAKAgluck/bt-quickcheck)

A fast, no-hassle Linux one-liner to baseline a host from a blue team perspective. Inspired by linPEAS' ease-of-use, but focused on defensive posture checks (configuration, hygiene, and quick wins) instead of privilege escalation.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Security Assessment Categories](#security-assessment-categories)
- [Output Formats](#output-formats)
- [Operation Modes](#operation-modes)
- [Security & Safety](#security--safety)
- [Examples](#examples)
- [Implementation Progress](#implementation-progress)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [References](#references)
- [License](#license)

## Features

- 🛡️ **Comprehensive Security Assessment**: 24 security categories with 50+ specialized checks
- ⚡ **Fast & Lightweight**: Single script, no installation required, minimal system impact  
- 🎯 **Blue Team Focused**: Defensive security posture assessment, not penetration testing
- 🔒 **Read-Only & Safe**: Zero system modifications, enterprise-safe operation
- 📊 **Multiple Output Formats**: Console, JSON, HTML, and TXT reports
- 🏠 **Dual Operation Modes**: Personal and Production environments with tailored recommendations
- 🔍 **Actionable Results**: Clear severity levels with specific remediation guidance
- 🚀 **One-Liner Deployment**: Instant remote execution via curl

## Quick Start

```bash
# One-liner execution (recommended)
bash <(curl -fsSL https://raw.githubusercontent.com/MaxAKAgluck/bt-quickcheck/main/bt-quickcheck.sh)

# Or download and run locally
curl -fsSL https://raw.githubusercontent.com/MaxAKAgluck/bt-quickcheck/main/bt-quickcheck.sh -o bt-quickcheck.sh
chmod +x bt-quickcheck.sh
sudo ./bt-quickcheck.sh
```

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
  -f, --format FORMAT     Output format: console, json, html, txt (default: console)
  -o, --output FILE       Output file (default: stdout)
  -m, --mode MODE         Operation mode: personal, production (default: personal)
```

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

## Security Assessment Categories

- **System basics**: distro, kernel, uptime, virtualization hints
- **Patching**: pending updates (apt/dnf/yum/zypper) with mode-specific update recommendations
- **Network exposure**: listening services summary and port analysis
- **Firewall**: `ufw`, `firewalld`, `nftables`/`iptables` status and rules
- **SSH hardening**: `PermitRootLogin`, `PasswordAuthentication`, access controls, port configuration
- **Auditing and hardening**: `auditd`, SELinux/AppArmor status with activation guidance
- **User accounts**: unauthorized UID 0 accounts, passwordless accounts, NOPASSWD sudo entries
- **Risky permissions**: world-writable files/dirs, SUID binaries in sensitive paths
- **Intrusion detection**: `fail2ban` status, recent failed login attempts, suspicious activity
- **Time synchronization**: `chrony`, `ntpd`, `systemd-timesyncd` status and configuration
- **Logging and monitoring**: `rsyslog`/`syslog-ng`, log file permissions, `logrotate` configuration
- **Network security**: TCP SYN cookies, excessive open ports, IPv6 status (personal mode)
- **Package integrity**: RPM/DEB package modification detection (`rpm -Va`, `debsums`)
- **File integrity**: SHA256 hashes of critical binaries/configs, AIDE/Tripwire integration (production)
- **Persistence mechanisms**: Cron jobs, systemd timers, startup scripts, shell configs, kernel modules
- **Process forensics**: Process tree analysis, hidden process detection, temp directory execution
- **Secure configuration**: Kernel hardening flags, umask settings, core dumps, 2FA indicators
- **Container security**: Docker/Podman/LXC detection, privileged containers, dangerous host mounts, Kubernetes
- **Kernel hardening**: Secure Boot, lockdown mode, module signing, grsecurity, advanced sysctl flags
- **Application security**: Web server TLS config, database exposure, SSL/TLS enforcement
- **Secrets management**: API keys, SSH keys, .env files permissions, agent forwarding detection
- **Cloud/remote management**: Cloud agents, VNC/RDP detection, remote access security
- **EDR/monitoring**: Antivirus/EDR detection, SIEM forwarding, log analysis tools
- **Backup/resilience**: Backup tools, cloud configs, filesystem snapshots, disaster recovery

Each finding includes:
- ✅ **Severity level**: OK, WARN, CRIT, INFO
- 💡 **Actionable recommendations** tailored to operation mode (personal vs production)
- 📋 **Structured output** for automation and reporting

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
sudo ./bt-quickcheck.sh -f json -o security-report.json
```
- Structured data for automation
- SIEM integration ready
- Machine-parseable format

### HTML Report
```bash
sudo ./bt-quickcheck.sh -f html -o security-report.html
```
- Professional styled report
- Executive summary ready
- Easy sharing and archiving

### Plain Text
```bash
sudo ./bt-quickcheck.sh -f txt -o security-report.txt
```
- Simple text format
- Email-friendly output
- Legacy system compatible

## Operation Modes

### Personal Mode (Default)
```bash
sudo ./bt-quickcheck.sh -m personal
```
- Home/personal machine recommendations
- Security through obscurity suggestions
- User-friendly guidance

### Production Mode
```bash
sudo ./bt-quickcheck.sh -m production
```
- Enterprise environment recommendations
- Compliance-focused checks
- Business continuity considerations

### Mode Comparison

| Check Category | Personal Mode | Production Mode |
|---|---|---|
| **SSH Port** | Suggests changing from default port 22 | Focuses on access controls and key management |
| **Updates** | Recommends manual updates + auto-security | Emphasizes scheduled maintenance windows |
| **Fail2ban** | Basic SSH protection | Custom rules + centralized monitoring |
| **Time Sync** | Basic NTP setup | Enterprise NTP with multiple sources |
| **IPv6** | Suggests disabling if unused | Keeps enabled for business needs |
| **Logging** | Local log management | Centralized logging + compliance |
| **User Accounts** | Focus on home security practices | Emphasis on business policies |
| **File Integrity** | Quick SHA256 hashes of critical files | AIDE/Tripwire integration + monitoring |
| **Persistence** | Basic cron/startup script scanning | Full timer/module/service analysis |
| **Forensics** | Simple process tree analysis | Advanced ELF capabilities + network process mapping |
| **Containers** | Basic Docker security warnings | Comprehensive container hardening + K8s CIS benchmarks |
| **Kernel** | Basic hardening flag suggestions | Full compliance checking + module signing enforcement |
| **Applications** | Simple HTTPS recommendations | Enterprise TLS config + database security policies |
| **EDR/AV** | Basic antivirus suggestions | Corporate EDR requirements + SIEM integration |
| **Backups** | Personal backup tool recommendations | Enterprise DR procedures + offsite backup validation |

## Security & Safety

### 🔒 Read-Only Operations
- Zero system modifications - pure assessment tool
- Safe file access with permission validation
- Protected against accidental writes or changes

### 🛡️ Input Validation & Protection
- Path traversal attack prevention
- Command line argument validation
- Output file path sanitization

### ⚡ Robust Error Handling
- Strict shell mode (`set -euo pipefail`)
- Graceful degradation when commands unavailable
- Comprehensive error reporting and logging

### 🔍 Transparency & Compliance
- Clear security disclaimers and privacy notices
- Comprehensive operation logging
- No external data transmission
- Minimal privilege requirements with clear sudo justification

## Examples

### Basic Security Assessment
```bash
# Comprehensive assessment with console output (recommended)
sudo ./bt-quickcheck.sh

# Limited assessment without sudo (basic checks only)
./bt-quickcheck.sh -m personal
```

### Generate Reports
```bash
# JSON report for automation
sudo ./bt-quickcheck.sh -f json -o security-$(date +%Y%m%d).json

# HTML report for management
sudo ./bt-quickcheck.sh -m production -f html -o production-security-report.html

# Text report for documentation
sudo ./bt-quickcheck.sh -f txt -o baseline-$(hostname).txt
```

### Enterprise Usage
```bash
# Production environment assessment
sudo ./bt-quickcheck.sh -m production -f json -o /var/log/security-assessment.json

# Multiple format generation
sudo ./bt-quickcheck.sh -m production -f html -o security-report.html
sudo ./bt-quickcheck.sh -m production -f json -o security-report.json
```

## Implementation Progress

✅ **v0.5.1 - Security Hardened & Standards Compliant**
- 🔒 **Enhanced Security**: Comprehensive disclaimers, read-only operations, safe file access
- 🛡️ **Input Validation**: Path traversal protection, argument validation, error handling
- ⚡ **Strict Mode**: `set -euo pipefail` for robust error handling
- 🔍 **Safe Operations**: Protected file access functions, permission checks
- 📋 **User Transparency**: Clear security notices, privacy statements, operation logging
- ✅ **Cybersecurity Standards**: Aligned with defensive security best practices

✅ **v0.5.0 - Enterprise Security Assessment**
- Container security: Docker/Podman/LXC/Kubernetes detection and hardening
- Advanced kernel hardening: Secure Boot, lockdown mode, grsecurity detection
- Application-level security: Web servers, databases, TLS configuration
- Secrets management: API keys, SSH keys, sensitive file permissions
- Cloud and remote management security assessment
- EDR/AV detection and SIEM forwarding validation
- Backup and disaster recovery capability assessment
- 24 security categories with 50+ specialized checks

✅ **v0.4.0 - Advanced Security Hardening** 
- File integrity monitoring with SHA256 baselines and AIDE/Tripwire integration
- Persistence mechanism detection (cron, timers, startup scripts, kernel modules)
- Process forensics and hidden process detection
- Kernel hardening and secure configuration validation

✅ **v0.3.0 - Comprehensive Security Assessment**
- Multiple output formats (JSON, HTML, TXT) with structured data
- Personal vs Production operation modes with tailored recommendations
- Intrusion detection (fail2ban, auth logs, suspicious activity)
- Time synchronization and logging infrastructure validation
- Network security and package integrity verification

✅ **v0.2.0 - Core Security Baseline**
- Fast, read-only security posture assessment
- SSH hardening, firewall status, user account analysis
- Update management and basic permission auditing



## Roadmap

### Planned Features
- 🔧 **CIS Benchmark Integration**: Map checks to CIS Linux Benchmark controls
- 🐳 **Container Context Awareness**: Detect container vs host environment
- 🔌 **Pluggable Framework**: Enable/disable specific check categories
- 🔇 **Quiet Mode**: Fail-only output and minimal verbosity options
- 📊 **Enhanced SIEM Integration**: Improved JSON schema and log forwarding
- 🚀 **Performance Optimization**: Faster execution and reduced resource usage

### Long-term Vision
- Integration with popular security frameworks (NIST, ISO 27001)
- Cloud-native security assessments (AWS, Azure, GCP)
- Real-time monitoring mode with alert capabilities
- Plugin system for custom organizational checks

## References

- Awesome lists and collections:
  - [Awesome Cybersecurity Blue Team](https://github.com/fabacab/awesome-cybersecurity-blueteam)
  - [WGU-CCDC Blue-Team-Tools](https://github.com/WGU-CCDC/Blue-Team-Tools)
  - [Blue Team Cheatsheet (Hackerium)](https://wiki.hackerium.io/blue-team/blue-team-cheatsheet)
- Auditing and benchmarks:
  - [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) (map future checks to CIS items)
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
- Add appropriate error handling
- Include both personal and production mode recommendations
- Document new features in README
- Follow existing code style and patterns

### Security Considerations
- All new checks must be read-only
- No external network connections
- Validate all inputs and file paths
- Include appropriate security disclaimers

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contact & Support

- 📧 **Issues**: [GitHub Issues](https://github.com/MaxAKAgluck/bt-quickcheck/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/MaxAKAgluck/bt-quickcheck/discussions)
- 🔒 **Security Issues**: Please report security vulnerabilities via GitHub's private vulnerability reporting

## Acknowledgments

- Inspired by [LinPEAS](https://github.com/carlospolop/PEASS-ng) for its ease of use
- Built for the blue team community and defensive security practitioners
- Thanks to all contributors and security researchers who help improve this tool

---

**⚠️ Disclaimer**: This tool is provided as-is for defensive security assessment purposes. Always ensure you have proper authorization before running security assessments on any system.


