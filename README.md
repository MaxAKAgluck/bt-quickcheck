## Blue Team QuickCheck (bt-quickcheck)

A fast, no-hassle Linux one-liner to baseline a host from a blue team perspective. Inspired by linPEAS' ease-of-use, but focused on defensive posture checks (configuration, hygiene, and quick wins) instead of privilege escalation.

### Why

- Quickly assess a Linux system's defensive posture: firewall, SSH hardening, auditing, auth, updates, and risky permissions.
- Run anywhere with a single command; readable, color-coded output with actionable items.

### What it checks

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

Each finding includes:
- ✅ **Severity level**: OK, WARN, CRIT, INFO
- 💡 **Actionable recommendations** tailored to operation mode (personal vs production)
- 📋 **Structured output** for automation and reporting

### Implementation progress

✅ **v0.4.0 - Advanced Security Hardening** 
- File integrity monitoring with SHA256 baselines and AIDE/Tripwire integration
- Persistence mechanism detection (cron, timers, startup scripts, kernel modules)
- Process forensics and hidden process detection
- Kernel hardening and secure configuration validation
- Enhanced mode differentiation (17 security categories, 35+ checks)

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

### One-liner

Replace `<USER>` and `<REPO>` after you publish:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MaxAKAGluck/bt-quickcheck/main/bt-quickcheck.sh)
```

### Local usage (before publishing)

```bash
chmod +x ./bt-quickcheck.sh
sudo ./bt-quickcheck.sh
```

**New features in v0.4.0:**

#### Multiple output formats
```bash
# Console output (default, with colors)
sudo ./bt-quickcheck.sh

# JSON output for automation/SIEM
sudo ./bt-quickcheck.sh -f json -o security-report.json

# HTML report with styling
sudo ./bt-quickcheck.sh -f html -o security-report.html

# Plain text report
sudo ./bt-quickcheck.sh -f txt -o security-report.txt
```

#### Operation modes
```bash
# Personal mode (default) - home/personal machine recommendations
sudo ./bt-quickcheck.sh -m personal

# Production mode - business/server environment recommendations
sudo ./bt-quickcheck.sh -m production -f html -o production-report.html
```

Running with `sudo` is recommended to get full visibility; it will still run without elevated privileges but may miss checks.

#### Mode differences

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

### Design notes

- Minimize host impact: no changes, no package installs, avoid long-running scanning.
- Prefer native tools available on most distros; degrade gracefully when missing.
- Keep output concise; highlight actions the analyst can take immediately.

### Roadmap

- JSON output mode for SIEM ingestion
- Module-aware distro detection with safer/faster update checks
- CIS-aligned ruleset mapping with references
- Container/K8s context awareness (host vs. container)
- Pluggable check framework (enable/disable categories and thresholds)
- Quiet mode and fail-only output

### Research and references

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

### Contributing

- Propose new checks via issues first; include distro(s), command, expected output, severity, and benchmark references.
- Keep checks read-only and efficient; avoid deep recursive scans by default.

### License

MIT — see `LICENSE`.


