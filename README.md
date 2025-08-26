# Blue Team QuickCheck (bt-quickcheck)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/bash-4.0%2B-green.svg)](https://www.gnu.org/software/bash/)
[![Linux](https://img.shields.io/badge/platform-linux-blue.svg)](https://kernel.org/)
[![Security](https://img.shields.io/badge/security-blue%20team-blue.svg)](https://github.com/MaxAKAgluck/bt-quickcheck)

A fast, no-hassle Linux one-liner to baseline a host from a blue team perspective. Inspired by linPEAS' ease-of-use, but focused on defensive posture checks (configuration, hygiene, and quick wins) instead of privilege escalation. **Now with enhanced security features and industry-standard compliance validation.**

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

- 🛡️ **Comprehensive Security Assessment**: 32 security categories with 80+ specialized checks
- ⚡ **Fast & Lightweight**: Single script, no installation required, minimal system impact  
- 🎯 **Blue Team Focused**: Defensive security posture assessment, not penetration testing
- 🔒 **Read-Only & Safe**: Zero system modifications, enterprise-safe operation
- 🚀 **Enhanced Security (v0.6.0)**: Advanced input validation, command sanitization, and industry-standard compliance
- 📊 **Multiple Output Formats**: Console, JSON, HTML, and TXT reports
- 🏠 **Dual Operation Modes**: Personal and Production environments with tailored recommendations
- 🔍 **Actionable Results**: Clear severity levels with specific remediation guidance
- 🚀 **One-Liner Deployment**: Instant remote execution via curl
- 🏢 **Enterprise Ready**: CIS Benchmark and NIST Framework alignment

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

### Core Security Checks
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

### Enhanced Security Checks (v0.6.0) 🆕
- **Enhanced Kernel Security**: Advanced kernel hardening parameters, YAMA protection, reverse path filtering
- **Enhanced Network Security**: TCP timestamp protection, SYN cookies, Martian packet logging, namespace isolation
- **Compliance & Audit**: Audit configuration validation, log retention policies, compliance tools detection
- **Enhanced Container Security**: Docker daemon security, container security profiles, Kubernetes RBAC validation
- **Enhanced File Integrity**: Advanced integrity monitoring tools, AIDE database freshness, critical file tracking
- **Enhanced Process Security**: Process namespace isolation, elevated capabilities detection, memory protection
- **Enhanced Logging Security**: Log file permissions validation, ownership verification, remote forwarding
- **Enhanced Network Access Controls**: TCP wrappers configuration, firewall rate limiting, connection tracking

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

### 🛡️ Enhanced Input Validation & Protection (v0.6.0)
- **Advanced Command Validation**: Prevents execution of dangerous commands (rm, dd, mkfs, etc.)
- **Enhanced Path Sanitization**: Stronger protection against path traversal attacks
- **Command Path Validation**: Prevents execution from dangerous directories (/tmp, /dev/shm)
- **File Size Limits**: Prevents reading extremely large files (default 1MB limit)
- **Symlink Protection**: Prevents symlink-based attacks
- **Input Sanitization**: Comprehensive validation of all user inputs

### ⚡ Robust Error Handling & Timeout Protection
- **Strict Shell Mode**: `set -euo pipefail` for robust error handling
- **Enhanced Error Logging**: Timestamped error logging with system log integration
- **Timeout Protection**: 30-second timeout for sections to prevent hanging
- **Graceful Degradation**: Fallback for systems without timeout command
- **Comprehensive Error Reporting**: Detailed error tracking and reporting

### 🔍 Enhanced Transparency & Compliance
- **Clear Security Disclaimers**: Comprehensive security notices and privacy statements
- **Operation Logging**: Detailed logging of all security assessment activities
- **No External Transmission**: All data remains local for security
- **Minimal Privilege Requirements**: Clear sudo justification with privilege escalation guidance
- **Industry Standards Alignment**: CIS Benchmark and NIST Framework compliance

### 🚀 Advanced Security Features
- **Enhanced Kernel Security**: Advanced kernel hardening parameter validation
- **Network Security Hardening**: Comprehensive network security configuration analysis
- **Container Security**: Advanced container and Kubernetes security validation
- **Process Security**: Enhanced process isolation and capability analysis
- **File Integrity**: Advanced integrity monitoring and baseline management
- **Compliance Validation**: Enterprise-grade compliance and audit checking

## Enhanced Security Features (v0.6.0)

### 🚀 **Advanced Security Framework**
The latest version introduces enterprise-grade security features that align with industry best practices:

- **Enhanced Input Validation**: Prevents command injection and path traversal attacks
- **Advanced Command Sanitization**: Blocks execution of dangerous system commands
- **Comprehensive Path Protection**: Enhanced security against directory traversal attacks
- **Timeout Protection**: Prevents hanging sections from blocking execution
- **Enhanced Error Logging**: System log integration for audit trails

### 🏢 **Enterprise Compliance Features**
- **CIS Benchmark Alignment**: Many checks now align with CIS Linux Benchmark controls
- **NIST Framework Support**: Enhanced security controls following NIST cybersecurity framework
- **Advanced Kernel Security**: Comprehensive kernel hardening parameter validation
- **Container Security**: Advanced Docker and Kubernetes security analysis
- **Process Security**: Enhanced process isolation and capability analysis

### 🔍 **Enhanced Assessment Capabilities**
- **32 Security Categories**: Up from 24 categories in previous versions
- **80+ Specialized Checks**: Comprehensive security validation across all areas
- **Advanced Network Security**: Enhanced network hardening and access control validation
- **File Integrity Monitoring**: Advanced integrity checking and baseline management
- **Compliance Validation**: Enterprise-grade compliance and audit checking

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

### Enhanced Security Assessment (v0.6.0)
```bash
# Run enhanced security checks with new features
sudo ./bt-quickcheck.sh

# Production mode with enhanced compliance validation
sudo ./bt-quickcheck.sh -m production -f json -o production-security-v0.6.0.json

# Generate comprehensive HTML report with enhanced features
sudo ./bt-quickcheck.sh -m production -f html -o enhanced-security-report.html
```

### Enterprise Usage
```bash
# Production environment assessment
sudo ./bt-quickcheck.sh -m production -f json -o /var/log/security-assessment.json

# Multiple format generation
sudo ./bt-quickcheck.sh -m production -f html -o security-report.html
sudo ./bt-quickcheck.sh -m production -f json -o security-report.json
```

### New Enhanced Security Checks
```bash
# Enhanced kernel security validation
sudo ./bt-quickcheck.sh | grep "Enhanced Kernel Security"

# Advanced container security analysis
sudo ./bt-quickcheck.sh | grep "Enhanced Container Security"

# Compliance and audit validation
sudo ./bt-quickcheck.sh | grep "Compliance & Audit"

# Enhanced file integrity monitoring
sudo ./bt-quickcheck.sh | grep "Enhanced File Integrity"

# Process security analysis
sudo ./bt-quickcheck.sh | grep "Enhanced Process Security"

# Advanced logging security
sudo ./bt-quickcheck.sh | grep "Enhanced Logging Security"

# Network access controls
sudo ./bt-quickcheck.sh | grep "Enhanced Network Access Controls"
```

### Enhanced Security Check Details

#### Enhanced Kernel Security
- **YAMA Protection**: PTRACE scope restriction validation
- **Core Dump Prevention**: SUID core dump protection
- **Reverse Path Filtering**: Network spoofing protection
- **Source Route Protection**: Prevents source routing attacks
- **Security Module Detection**: AppArmor, SELinux, YAMA, capability, integrity

#### Enhanced Network Security
- **TCP Timestamp Protection**: Prevents timestamp-based attacks
- **SYN Cookie Validation**: SYN flood protection
- **Backlog Limits**: Connection queue management
- **Martian Packet Logging**: Suspicious packet detection
- **Network Namespace Isolation**: Container network security

#### Compliance & Audit
- **Audit Configuration**: Audit daemon settings validation
- **Log Retention**: Log rotation and retention policy checking
- **Security Policies**: Access control and limits configuration
- **Compliance Tools**: OpenSCAP, Lynis, Tiger, RKHunter detection

#### Enhanced Container Security
- **Docker Hardening**: Daemon security configuration validation
- **Security Profiles**: Container security profile analysis
- **Kubernetes RBAC**: Role-based access control validation
- **Network Policies**: Container network security policies
- **Unconfined Detection**: Containers without security profiles

#### Enhanced File Integrity
- **Integrity Tools**: AIDE, Tripwire, OSSEC, Samhain detection
- **Database Freshness**: AIDE database update validation
- **Critical File Tracking**: Important file modification monitoring
- **Baseline Management**: File integrity baseline establishment

#### Enhanced Process Security
- **Namespace Isolation**: Process namespace detection
- **Capability Analysis**: Elevated process capability identification
- **Memory Protection**: Memory writeback protection validation
- **Process Security**: Enhanced process isolation analysis

#### Enhanced Logging Security
- **Permission Validation**: Log file permission checking (600/640)
- **Ownership Verification**: Log file ownership validation
- **Remote Forwarding**: Centralized logging configuration
- **Audit Trail**: Comprehensive logging security analysis

#### Enhanced Network Access Controls
- **TCP Wrappers**: Host-based access control validation
- **Firewall Rules**: Rate limiting and connection tracking
- **Access Control**: Network access restriction validation
- **Security Policies**: Network security policy enforcement

## Implementation Progress

✅ **v0.6.0 - Enterprise Security & Industry Standards** 🆕
- 🚀 **Enhanced Security Framework**: Advanced input validation, command sanitization, and industry-standard compliance
- 🔒 **Advanced Input Validation**: Dangerous command prevention, enhanced path sanitization, symlink protection
- 🛡️ **Enhanced Error Handling**: Timeout protection, system log integration, comprehensive error tracking
- 🔍 **Industry Standards**: CIS Benchmark and NIST Framework alignment for enterprise environments
- 🏢 **Enterprise Features**: Advanced kernel security, container security, compliance validation
- 📊 **Enhanced Assessment**: 32 security categories with 80+ specialized checks
- ✅ **Blue Team Excellence**: Comprehensive defensive security posture assessment

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

### Recently Implemented (v0.6.0) ✅
- 🔧 **CIS Benchmark Integration**: Advanced checks aligned with CIS Linux Benchmark controls
- 🐳 **Enhanced Container Security**: Comprehensive container and Kubernetes security validation
- 🚀 **Advanced Security Framework**: Enhanced input validation and command sanitization
- 📊 **Industry Standards**: NIST Framework alignment and enterprise compliance features
- 🔍 **Enhanced Assessment**: 8 new security categories with advanced validation

### Planned Features
- 🔌 **Pluggable Framework**: Enable/disable specific check categories
- 🔇 **Quiet Mode**: Fail-only output and minimal verbosity options
- 📊 **Enhanced SIEM Integration**: Improved JSON schema and log forwarding
- 🚀 **Performance Optimization**: Faster execution and reduced resource usage
- 🔐 **Custom Policy Integration**: Support for organization-specific security policies
- 📈 **Trend Analysis**: Historical security posture tracking and reporting

### Long-term Vision
- Integration with popular security frameworks (NIST, ISO 27001)
- Cloud-native security assessments (AWS, Azure, GCP)
- Real-time monitoring mode with alert capabilities
- Plugin system for custom organizational checks

## Enhanced Input Validation & Security Features

### 🛡️ **Advanced Command Validation**
The script now includes comprehensive command validation to prevent execution of dangerous system commands:

```bash
# Dangerous commands are blocked:
rm, dd, mkfs, fdisk, parted, shutdown, reboot, halt, init, telinit

# Safe commands are validated:
ls, cat, grep, awk, sed, stat, systemctl, ps, netstat, ss
```

### 🔒 **Enhanced Path Sanitization**
- **Path Traversal Prevention**: Blocks `../`, `..*`, and directory traversal attempts
- **Safe Directory Validation**: Only allows execution from secure system directories
- **Absolute Path Protection**: Restricts absolute paths to safe locations
- **Symlink Protection**: Prevents symlink-based attacks

### 📁 **File Access Security**
- **File Size Limits**: Default 1MB limit prevents reading extremely large files
- **Permission Validation**: Checks file readability before access
- **Location Validation**: Prevents access to dangerous directories
- **Content Validation**: Safe file reading with error handling

### 🚫 **Command Execution Security**
- **Path Validation**: Commands must exist and be executable
- **Directory Validation**: Prevents execution from `/tmp/` or `/dev/shm/`
- **Command Sanitization**: Validates all command parameters
- **Safe Execution**: Wrapped execution with error handling

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

## Security Improvements in v0.6.0

### 🚀 **What's New in This Version**

#### Enhanced Input Validation & Security
- **Command Injection Prevention**: Blocks execution of dangerous system commands (rm, dd, mkfs, etc.)
- **Path Traversal Protection**: Enhanced security against directory traversal attacks
- **File Access Security**: Prevents reading from dangerous locations and symlinks
- **Input Sanitization**: Comprehensive validation of all user inputs and parameters
- **Command Path Validation**: Prevents execution from dangerous directories (/tmp, /dev/shm)
- **File Size Limits**: Prevents reading extremely large files (default 1MB limit)

#### Advanced Security Assessment
- **Enhanced Kernel Security**: Advanced kernel hardening parameter validation (YAMA, reverse path filtering)
- **Network Security Hardening**: Comprehensive network security configuration analysis
- **Container Security**: Advanced Docker and Kubernetes security validation
- **Process Security**: Enhanced process isolation and capability analysis
- **File Integrity**: Advanced integrity monitoring and baseline management
- **Compliance & Audit**: Enterprise-grade compliance and audit checking

#### Enterprise Compliance Features
- **CIS Benchmark Alignment**: Many checks now align with CIS Linux Benchmark controls
- **NIST Framework Support**: Enhanced security controls following NIST cybersecurity framework
- **Compliance Validation**: Enterprise-grade compliance and audit checking
- **Advanced Logging**: Enhanced error logging with system log integration
- **Timeout Protection**: 30-second timeout for sections to prevent hanging

### 🔒 **Security Benefits**
- **Reduced Attack Surface**: Enhanced input validation prevents common attack vectors
- **Better Compliance**: Industry-standard security validation for enterprise environments
- **Improved Reliability**: Timeout protection and enhanced error handling
- **Enhanced Audit Trail**: Comprehensive logging and error tracking
- **Industry Standards**: Alignment with CIS, NIST, and Blue Team best practices
- **Enterprise Ready**: Production-grade security assessment capabilities

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

- 📧 **Issues**: [GitHub Issues](https://github.com/MaxAKAgluck/bt-quickcheck/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/MaxAKAgluck/bt-quickcheck/discussions)
- 🔒 **Security Issues**: Please report security vulnerabilities via GitHub's private vulnerability reporting

## Acknowledgments

- Inspired by [LinPEAS](https://github.com/carlospolop/PEASS-ng) for its ease of use
- Built for the blue team community and defensive security practitioners
- Thanks to all contributors and security researchers who help improve this tool

---

## Enterprise Compliance & Industry Standards

### 🏢 **CIS Benchmark Alignment**
Many security checks in v0.6.0 now align with CIS Linux Benchmark controls:

- **Kernel Hardening**: CIS Controls 3.1, 3.2, 3.3
- **Network Security**: CIS Controls 4.1, 4.2, 4.3
- **Access Control**: CIS Controls 5.1, 5.2, 5.3
- **Audit & Logging**: CIS Controls 6.1, 6.2, 6.3
- **System Maintenance**: CIS Controls 7.1, 7.2, 7.3

### 📋 **NIST Framework Support**
Enhanced security controls following NIST Cybersecurity Framework:

- **Identify**: System and asset discovery, business environment assessment
- **Protect**: Access control, awareness training, data security
- **Detect**: Anomaly detection, security monitoring, detection processes
- **Respond**: Response planning, communications, analysis
- **Recover**: Recovery planning, improvements, communications

### 🔒 **Compliance Validation Features**
- **Audit Configuration**: Comprehensive audit daemon validation
- **Log Retention**: Log rotation and retention policy checking
- **Security Policies**: Access control and limits configuration
- **Compliance Tools**: Industry-standard compliance tool detection
- **Enterprise Logging**: Centralized logging and monitoring validation

### 🚀 **Production Environment Ready**
- **Enterprise Security**: Advanced security validation for business environments
- **Compliance Reporting**: Structured output for compliance audits
- **Risk Assessment**: Comprehensive security risk evaluation
- **Remediation Guidance**: Actionable recommendations for security improvements
- **Industry Best Practices**: Alignment with security industry standards

---

**⚠️ Disclaimer**: This tool is provided as-is for defensive security assessment purposes. Always ensure you have proper authorization before running security assessments on any system.

**🔒 Security Notice**: This tool includes enhanced security features to prevent common attack vectors. All operations are read-only and designed for defensive security assessment only.


