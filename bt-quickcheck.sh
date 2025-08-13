#!/usr/bin/env bash

set -u

VERSION="0.4.0"

# Output format (default: console)
OUTPUT_FORMAT="console"
OUTPUT_FILE=""
OPERATION_MODE="personal"

# Colors (only used in console mode)
COLOR_RED="\033[31m"
COLOR_YELLOW="\033[33m"
COLOR_GREEN="\033[32m"
COLOR_BLUE="\033[34m"
COLOR_RESET="\033[0m"

# Data structure to store findings
declare -a FINDINGS=()
declare -a SECTIONS=()

is_root() { [ "${EUID:-$(id -u)}" -eq 0 ]; }

# Add a finding to the global findings array
add_finding() {
    local section="$1"
    local severity="$2"  # OK, WARN, CRIT, INFO
    local message="$3"
    local recommendation="${4:-}"
    
    FINDINGS+=("$section|$severity|$message|$recommendation")
}

# Console output functions (original behavior)
print_section() {
    [ "$OUTPUT_FORMAT" = "console" ] && printf "\n${COLOR_BLUE}=== %s ===${COLOR_RESET}\n" "$1"
    SECTIONS+=("$1")
}

ok() { 
    [ "$OUTPUT_FORMAT" = "console" ] && printf "${COLOR_GREEN}[OK]${COLOR_RESET} %s\n" "$1"
}
warn() { 
    [ "$OUTPUT_FORMAT" = "console" ] && printf "${COLOR_YELLOW}[WARN]${COLOR_RESET} %s\n" "$1"
}
crit() { 
    [ "$OUTPUT_FORMAT" = "console" ] && printf "${COLOR_RED}[CRIT]${COLOR_RESET} %s\n" "$1"
}
info() { 
    [ "$OUTPUT_FORMAT" = "console" ] && printf "[INFO] %s\n" "$1"
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

# Get recommendation based on operation mode
get_recommendation() {
    local base_rec="$1"
    local personal_rec="${2:-}"
    local production_rec="${3:-}"
    
    case "$OPERATION_MODE" in
        personal)
            [ -n "$personal_rec" ] && echo "$personal_rec" || echo "$base_rec"
            ;;
        production)
            [ -n "$production_rec" ] && echo "$production_rec" || echo "$base_rec"
            ;;
        *)
            echo "$base_rec"
            ;;
    esac
}

# Output generation functions
generate_json_output() {
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local hostname=$(hostname 2>/dev/null || echo "unknown")
    
    echo "{"
    echo "  \"timestamp\": \"$timestamp\","
    echo "  \"hostname\": \"$hostname\","
    echo "  \"version\": \"$VERSION\","
    echo "  \"mode\": \"$OPERATION_MODE\","
    echo "  \"findings\": ["
    
    local first=true
    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r section severity message recommendation <<< "$finding"
        [ "$first" = true ] && first=false || echo ","
        echo -n "    {"
        echo -n "\"section\": \"$section\", "
        echo -n "\"severity\": \"$severity\", "
        echo -n "\"message\": \"$message\""
        [ -n "$recommendation" ] && echo -n ", \"recommendation\": \"$recommendation\""
        echo -n "}"
    done
    
    echo ""
    echo "  ]"
    echo "}"
}

generate_html_output() {
    local timestamp=$(date)
    local hostname=$(hostname 2>/dev/null || echo "unknown")
    
    cat << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Blue Team QuickCheck Report - $hostname</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { border-bottom: 2px solid #ddd; padding-bottom: 10px; margin-bottom: 20px; }
        .finding { margin: 10px 0; padding: 10px; border-left: 4px solid #ddd; }
        .ok { border-left-color: #28a745; background: #f8fff9; }
        .warn { border-left-color: #ffc107; background: #fffef8; }
        .crit { border-left-color: #dc3545; background: #fff8f8; }
        .info { border-left-color: #17a2b8; background: #f8fcff; }
        .severity { font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 0.8em; }
        .severity.ok { background: #28a745; color: white; }
        .severity.warn { background: #ffc107; color: black; }
        .severity.crit { background: #dc3545; color: white; }
        .severity.info { background: #17a2b8; color: white; }
        .recommendation { margin-top: 8px; font-style: italic; color: #666; }
        .section-header { color: #007bff; font-size: 1.2em; font-weight: bold; margin-top: 25px; margin-bottom: 10px; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Blue Team QuickCheck Report</h1>
        <p><strong>Host:</strong> $hostname | <strong>Mode:</strong> $OPERATION_MODE | <strong>Generated:</strong> $timestamp | <strong>Version:</strong> $VERSION</p>
    </div>
EOF

    local current_section=""
    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r section severity message recommendation <<< "$finding"
        
        if [ "$section" != "$current_section" ]; then
            [ -n "$current_section" ] && echo "</div>"
            echo "<div class=\"section-header\">$section</div>"
            echo "<div class=\"section\">"
            current_section="$section"
        fi
        
        echo "<div class=\"finding ${severity,,}\">"
        echo "<span class=\"severity ${severity,,}\">$severity</span> $message"
        [ -n "$recommendation" ] && echo "<div class=\"recommendation\">💡 $recommendation</div>"
        echo "</div>"
    done
    
    [ -n "$current_section" ] && echo "</div>"
    
    cat << EOF
</div>
</body>
</html>
EOF
}

generate_txt_output() {
    local timestamp=$(date)
    local hostname=$(hostname 2>/dev/null || echo "unknown")
    
    echo "==============================================="
    echo "Blue Team QuickCheck Report"
    echo "==============================================="
    echo "Host: $hostname"
    echo "Mode: $OPERATION_MODE"
    echo "Generated: $timestamp"
    echo "Version: $VERSION"
    echo "==============================================="
    echo
    
    local current_section=""
    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r section severity message recommendation <<< "$finding"
        
        if [ "$section" != "$current_section" ]; then
            echo
            echo "=== $section ==="
            current_section="$section"
        fi
        
        printf "%-6s %s\n" "[$severity]" "$message"
        [ -n "$recommendation" ] && printf "       → %s\n" "$recommendation"
    done
    
    echo
    echo "==============================================="
    echo "Report completed. Review WARN/CRIT items."
    echo "==============================================="
}

detect_pkg_mgr() {
	if command_exists apt-get; then echo apt; return; fi
	if command_exists dnf; then echo dnf; return; fi
	if command_exists yum; then echo yum; return; fi
	if command_exists zypper; then echo zypper; return; fi
	echo unknown
}

section_system() {
	print_section "System"
	
	# Kernel information
	kernel_info=$(uname -a 2>/dev/null)
	add_finding "System" "INFO" "Kernel: $kernel_info" ""
	[ "$OUTPUT_FORMAT" = "console" ] && echo "Kernel: $kernel_info"
	
	# Distribution information
	if [ -r /etc/os-release ]; then
		. /etc/os-release
		distro="${PRETTY_NAME:-unknown}"
		add_finding "System" "INFO" "Distribution: $distro" ""
		[ "$OUTPUT_FORMAT" = "console" ] && echo "Distro: $distro"
	fi
	
	# Uptime
	uptime_info=$(uptime -p 2>/dev/null || uptime 2>/dev/null | awk '{print $3,$4}')
	add_finding "System" "INFO" "Uptime: $uptime_info" ""
	[ "$OUTPUT_FORMAT" = "console" ] && echo "Uptime: $uptime_info"
	
	# Virtualization detection
	if command_exists systemd-detect-virt; then
		virt=$(systemd-detect-virt 2>/dev/null || true)
		if [ -n "$virt" ] && [ "$virt" != "none" ]; then
			add_finding "System" "INFO" "Virtualization: $virt" ""
			[ "$OUTPUT_FORMAT" = "console" ] && info "Virtualization: $virt"
		fi
	fi
}

section_updates() {
	print_section "Updates"
	pm=$(detect_pkg_mgr)
	case "$pm" in
		apt)
			if is_root; then apt-get update -qq >/dev/null 2>&1; fi
			cnt=$(apt-get -s upgrade 2>/dev/null | awk '/^[0-9]+ upgraded/ {print $1}')
			if [ -n "$cnt" ] && [ "$cnt" != 0 ]; then 
				rec=$(get_recommendation "Run 'sudo apt upgrade' to install updates" \
					"Run 'sudo apt upgrade' and consider enabling unattended-upgrades" \
					"Schedule maintenance window for 'sudo apt upgrade'. Consider automated security updates")
				add_finding "Updates" "WARN" "$cnt packages upgradable" "$rec"
				warn "$cnt packages upgradable"
			else 
				add_finding "Updates" "OK" "No pending upgrades detected" ""
				ok "No pending upgrades detected"
			fi
			;;
		dnf)
			cnt=$(dnf check-update 2>/dev/null | awk 'BEGIN{c=0} /^[A-Za-z0-9_.-]+\s+[A-Za-z0-9_.:-]+\s+[A-Za-z0-9_.:-]+/ {c++} END{print c}')
			[ -z "$cnt" ] && cnt=0
			if [ "$cnt" -gt 0 ]; then 
				rec=$(get_recommendation "Run 'sudo dnf upgrade' to install updates" \
					"Run 'sudo dnf upgrade' and consider enabling dnf-automatic" \
					"Schedule maintenance window for 'sudo dnf upgrade'. Configure dnf-automatic for security updates")
				add_finding "Updates" "WARN" "$cnt packages upgradable" "$rec"
				warn "$cnt packages upgradable"
			else 
				add_finding "Updates" "OK" "No pending upgrades detected" ""
				ok "No pending upgrades detected"
			fi
			;;
		yum)
			out=$(yum check-update 2>/dev/null || true)
			cnt=$(printf "%s" "$out" | awk 'BEGIN{c=0} /^[A-Za-z0-9_.-]+\s+[A-Za-z0-9_.:-]+\s+[A-Za-z0-9_.:-]+/ {c++} END{print c}')
			[ -z "$cnt" ] && cnt=0
			if [ "$cnt" -gt 0 ]; then 
				rec=$(get_recommendation "Run 'sudo yum update' to install updates" \
					"Run 'sudo yum update' and consider enabling yum-cron" \
					"Schedule maintenance window for 'sudo yum update'. Configure yum-cron for automated updates")
				add_finding "Updates" "WARN" "$cnt packages upgradable" "$rec"
				warn "$cnt packages upgradable"
			else 
				add_finding "Updates" "OK" "No pending upgrades detected" ""
				ok "No pending upgrades detected"
			fi
			;;
		zypper)
			if zypper -q lu 2>/dev/null | grep -qE "^v\s"; then
				rec=$(get_recommendation "Run 'sudo zypper update' to install updates" \
					"Run 'sudo zypper update' and consider automated patching" \
					"Schedule maintenance window for 'sudo zypper update'. Configure automatic updates")
				add_finding "Updates" "WARN" "Updates available" "$rec"
				warn "Updates available"
			else 
				add_finding "Updates" "OK" "No pending upgrades detected" ""
				ok "No pending upgrades detected"
			fi
			;;
		*)
			add_finding "Updates" "WARN" "Unknown package manager; cannot check updates" "Manually verify system update status"
			warn "Unknown package manager; skip check"
			;;
	 esac
}

section_listening() {
	print_section "Listening Services"
	if command_exists ss; then
		ss -tulpen 2>/dev/null | sed -n '1,30p'
	elif command_exists netstat; then
		netstat -tulpen 2>/dev/null | sed -n '1,30p'
	else
		warn "Neither ss nor netstat available"
	fi
}

section_firewall() {
	print_section "Firewall"
	if command_exists ufw; then
		ufw status verbose 2>/dev/null | sed 's/^/ufw: /'
	fi
	if command_exists firewall-cmd; then
		firewall-cmd --state 2>/dev/null | sed 's/^/firewalld: /'
		firewall-cmd --list-all 2>/dev/null | sed 's/^/firewalld: /' | sed -n '1,50p'
	fi
	if command_exists nft; then
		nft list ruleset 2>/dev/null | sed -n '1,50p' | sed 's/^/nftables: /'
	elif command_exists iptables; then
		iptables -S 2>/dev/null | sed -n '1,50p' | sed 's/^/iptables: /'
	fi
}

section_ssh() {
	print_section "SSH Hardening"
	sshd_cfg="/etc/ssh/sshd_config"
	
	if [ -r "$sshd_cfg" ]; then
		# PermitRootLogin check
		perm_root=$(grep -Ei '^\s*PermitRootLogin\s+' "$sshd_cfg" | tail -n1 | awk '{print tolower($2)}')
		if [[ "$perm_root" =~ ^(no|prohibit-password)$ ]]; then
			add_finding "SSH" "OK" "PermitRootLogin is $perm_root" ""
			ok "PermitRootLogin is $perm_root"
		else
			rec=$(get_recommendation "Set 'PermitRootLogin no' in $sshd_cfg" \
				"Set 'PermitRootLogin no' in $sshd_cfg and restart SSH service" \
				"Set 'PermitRootLogin no' in $sshd_cfg, test access, then restart SSH service")
			add_finding "SSH" "CRIT" "PermitRootLogin is ${perm_root:-unset}" "$rec"
			crit "PermitRootLogin is ${perm_root:-unset}"
		fi
		
		# PasswordAuthentication check
		pass_auth=$(grep -Ei '^\s*PasswordAuthentication\s+' "$sshd_cfg" | tail -n1 | awk '{print tolower($2)}')
		if [ "$pass_auth" = "no" ]; then
			add_finding "SSH" "OK" "PasswordAuthentication is no" ""
			ok "PasswordAuthentication is no"
		else
			rec=$(get_recommendation "Set 'PasswordAuthentication no' in $sshd_cfg and use SSH keys" \
				"Disable password auth: set 'PasswordAuthentication no', ensure SSH key access works first" \
				"Plan migration to key-based auth: set 'PasswordAuthentication no', document key management")
			add_finding "SSH" "WARN" "PasswordAuthentication is ${pass_auth:-unset}" "$rec"
			warn "PasswordAuthentication is ${pass_auth:-unset}"
		fi
		
		# Access control lists
		access_controls=$(grep -E '^(AllowUsers|AllowGroups|DenyUsers|DenyGroups)' "$sshd_cfg" 2>/dev/null || true)
		if [ -n "$access_controls" ]; then
			add_finding "SSH" "OK" "SSH access controls configured" ""
			[ "$OUTPUT_FORMAT" = "console" ] && echo "$access_controls" | sed 's/^/[cfg] /'
		else
			rec=$(get_recommendation "Consider adding AllowUsers or AllowGroups for access control" \
				"Add 'AllowUsers username' or 'AllowGroups groupname' to limit SSH access" \
				"Implement SSH access controls: AllowUsers/AllowGroups based on business requirements")
			add_finding "SSH" "INFO" "No SSH access controls configured" "$rec"
		fi
		
		# Additional hardening checks
		port=$(grep -Ei '^\s*Port\s+' "$sshd_cfg" | tail -n1 | awk '{print $2}')
		if [ -n "$port" ] && [ "$port" != "22" ]; then
			add_finding "SSH" "OK" "SSH running on non-default port $port" ""
		elif [ "$OPERATION_MODE" = "personal" ]; then
			rec="Consider changing SSH port: add 'Port 2222' to $sshd_cfg for security through obscurity"
			add_finding "SSH" "INFO" "SSH running on default port 22" "$rec"
		fi
		
	else
		add_finding "SSH" "WARN" "Cannot read $sshd_cfg" "Check SSH configuration file permissions"
		warn "Cannot read $sshd_cfg"
	fi
}

section_auditing() {
	print_section "Auditing/Hardening"
	
	# Auditd check
	if systemctl is-active --quiet auditd 2>/dev/null; then 
		add_finding "Auditing" "OK" "auditd active" ""
		ok "auditd active"
	else 
		rec=$(get_recommendation "Install and enable auditd: 'sudo apt install auditd && sudo systemctl enable auditd'" \
			"Enable system auditing with auditd for security monitoring" \
			"Deploy auditd with centralized logging and compliance-aligned rules")
		add_finding "Auditing" "WARN" "auditd not active" "$rec"
		warn "auditd not active"
	fi
	
	# SELinux check
	if command_exists getenforce; then
		mode=$(getenforce 2>/dev/null || true)
		if [ "$mode" = "Enforcing" ]; then
			add_finding "Auditing" "OK" "SELinux enforcing" ""
			ok "SELinux enforcing"
		else 
			rec=$(get_recommendation "Consider enabling SELinux: edit /etc/selinux/config" \
				"Enable SELinux for additional access controls (may require reboot)" \
				"Plan SELinux deployment: test in permissive mode, then enforce")
			add_finding "Auditing" "WARN" "SELinux mode: ${mode:-unknown}" "$rec"
			warn "SELinux mode: ${mode:-unknown}"
		fi
	fi
	
	# AppArmor check
	if [ -d /etc/apparmor.d ]; then
		if systemctl is-active --quiet apparmor 2>/dev/null; then 
			add_finding "Auditing" "OK" "AppArmor active" ""
			ok "AppArmor active"
		else 
			rec="Enable AppArmor: 'sudo systemctl enable apparmor && sudo systemctl start apparmor'"
			add_finding "Auditing" "WARN" "AppArmor not active" "$rec"
			warn "AppArmor not active"
		fi
	fi
}

section_accounts() {
	print_section "Accounts and Sudo"
	
	# Check for unauthorized root accounts (UID 0)
	unauthorized_root=$(awk -F: '($3 == "0" && $1 != "root") {print $1}' /etc/passwd 2>/dev/null)
	if [ -n "$unauthorized_root" ]; then
		rec=$(get_recommendation "Remove unauthorized UID 0 accounts or investigate: $unauthorized_root" \
			"CRITICAL: Investigate unauthorized root accounts immediately" \
			"SECURITY INCIDENT: Unauthorized root accounts detected - investigate and remediate immediately")
		add_finding "Accounts" "CRIT" "Unauthorized UID 0 accounts found: $unauthorized_root" "$rec"
		crit "Unauthorized UID 0 accounts found: $unauthorized_root"
	else
		add_finding "Accounts" "OK" "Only root has UID 0" ""
		ok "Only root has UID 0"
	fi
	
	# List all UID 0 accounts for reference
	all_uid0=$(awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')
	add_finding "Accounts" "INFO" "UID 0 accounts: $all_uid0" ""
	[ "$OUTPUT_FORMAT" = "console" ] && echo "UID0: $all_uid0"
	
	# Check for NOPASSWD sudo entries
	if [ -r /etc/sudoers ]; then
		nopasswd_entries=$(grep -R "NOPASSWD" /etc/sudoers /etc/sudoers.d 2>/dev/null || true)
		if [ -n "$nopasswd_entries" ]; then
			rec=$(get_recommendation "Review NOPASSWD sudo entries for security risks" \
				"Consider requiring passwords for sudo access or limit to specific commands" \
				"Audit NOPASSWD entries: document business justification or remove")
			add_finding "Accounts" "WARN" "NOPASSWD sudo entries found" "$rec"
			warn "NOPASSWD sudo entries found"
			[ "$OUTPUT_FORMAT" = "console" ] && echo "$nopasswd_entries" | sed 's/^/NOPASSWD: /'
		else
			add_finding "Accounts" "OK" "No NOPASSWD sudo entries" ""
			ok "No NOPASSWD sudo entries"
		fi
	fi
	
	# Check for accounts without passwords
	empty_pass=$(awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null | head -10 | tr '\n' ' ' || true)
	if [ -n "$empty_pass" ] && [ "$empty_pass" != " " ]; then
		rec=$(get_recommendation "Set passwords or lock accounts without passwords" \
			"Lock unused accounts: 'sudo usermod -L username' or set strong passwords" \
			"Audit passwordless accounts: lock service accounts, enforce password policy")
		add_finding "Accounts" "WARN" "Accounts without passwords: $empty_pass" "$rec"
		warn "Accounts without passwords detected"
	fi
}

section_permissions() {
	print_section "Risky Permissions"
	find_paths=(/etc /var /home /root)
	for p in "${find_paths[@]}"; do
		[ -d "$p" ] || continue
		find "$p" -xdev -type d -perm -0002 -maxdepth 2 2>/dev/null | sed "s/^/World-writable dir: /" | sed -n '1,20p'
		find "$p" -xdev -type f -perm -0002 -maxdepth 2 2>/dev/null | sed "s/^/World-writable file: /" | sed -n '1,20p'
	done
	find / -xdev -perm -4000 -type f 2>/dev/null | sed 's/^/SUID: /' | sed -n '1,30p'
}

section_intrusion_detection() {
	print_section "Intrusion Detection"
	
	# Check for fail2ban
	if command_exists fail2ban-client; then
		if systemctl is-active --quiet fail2ban 2>/dev/null; then
			add_finding "Intrusion Detection" "OK" "fail2ban is active" ""
			ok "fail2ban is active"
			
			# Get jail status
			if is_root; then
				jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | tr -d ' \t' || true)
				if [ -n "$jails" ] && [ "$jails" != "" ]; then
					add_finding "Intrusion Detection" "INFO" "fail2ban jails: $jails" ""
					[ "$OUTPUT_FORMAT" = "console" ] && info "Active jails: $jails"
				fi
			fi
		else
			rec=$(get_recommendation "Start fail2ban: 'sudo systemctl start fail2ban'" \
				"Enable fail2ban for brute force protection" \
				"Deploy fail2ban with custom rules and centralized monitoring")
			add_finding "Intrusion Detection" "WARN" "fail2ban installed but not active" "$rec"
			warn "fail2ban installed but not active"
		fi
	else
		rec=$(get_recommendation "Install fail2ban: 'sudo apt install fail2ban' or equivalent" \
			"Install fail2ban for SSH brute force protection" \
			"Deploy fail2ban with organization-specific jail configurations")
		add_finding "Intrusion Detection" "INFO" "fail2ban not installed" "$rec"
		[ "$OUTPUT_FORMAT" = "console" ] && info "fail2ban not installed"
	fi
	
	# Check for suspicious login attempts in auth logs
	if [ -r /var/log/auth.log ]; then
		failed_logins=$(grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5 | wc -l || echo 0)
		if [ "$failed_logins" -gt 3 ]; then
			rec="Review authentication logs for suspicious activity: 'sudo tail -50 /var/log/auth.log'"
			add_finding "Intrusion Detection" "WARN" "Recent failed login attempts detected" "$rec"
			warn "Recent failed login attempts detected"
		fi
	elif [ -r /var/log/secure ]; then
		failed_logins=$(grep "Failed password" /var/log/secure 2>/dev/null | tail -5 | wc -l || echo 0)
		if [ "$failed_logins" -gt 3 ]; then
			rec="Review authentication logs for suspicious activity: 'sudo tail -50 /var/log/secure'"
			add_finding "Intrusion Detection" "WARN" "Recent failed login attempts detected" "$rec"
			warn "Recent failed login attempts detected"
		fi
	fi
}

section_time_sync() {
	print_section "Time Synchronization"
	
	# Check for chrony
	if command_exists chronyc; then
		if systemctl is-active --quiet chronyd 2>/dev/null; then
			add_finding "Time Sync" "OK" "chronyd is active" ""
			ok "chronyd is active"
			
			if is_root; then
				sources=$(chronyc sources 2>/dev/null | grep "^\^" | wc -l || echo 0)
				if [ "$sources" -gt 0 ]; then
					add_finding "Time Sync" "OK" "Time sources configured: $sources" ""
				else
					rec="Configure NTP sources in /etc/chrony/chrony.conf"
					add_finding "Time Sync" "WARN" "No active time sources" "$rec"
				fi
			fi
		else
			rec="Enable chronyd: 'sudo systemctl enable --now chronyd'"
			add_finding "Time Sync" "WARN" "chronyd installed but not active" "$rec"
		fi
	# Check for ntpd
	elif command_exists ntpq; then
		if systemctl is-active --quiet ntp 2>/dev/null || systemctl is-active --quiet ntpd 2>/dev/null; then
			add_finding "Time Sync" "OK" "NTP daemon is active" ""
			ok "NTP daemon is active"
		else
			rec="Enable NTP service: 'sudo systemctl enable --now ntp'"
			add_finding "Time Sync" "WARN" "NTP installed but not active" "$rec"
		fi
	# Check for systemd-timesyncd
	elif systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
		add_finding "Time Sync" "OK" "systemd-timesyncd is active" ""
		ok "systemd-timesyncd is active"
	else
		rec=$(get_recommendation "Install and configure NTP: 'sudo apt install chrony && sudo systemctl enable chronyd'" \
			"Install chrony or NTP for accurate time synchronization" \
			"Deploy enterprise NTP solution with multiple time sources")
		add_finding "Time Sync" "WARN" "No time synchronization service detected" "$rec"
		warn "No time synchronization service detected"
	fi
}

section_logging() {
	print_section "Logging and Monitoring"
	
	# Check rsyslog
	if systemctl is-active --quiet rsyslog 2>/dev/null; then
		add_finding "Logging" "OK" "rsyslog is active" ""
		ok "rsyslog is active"
	elif systemctl is-active --quiet syslog-ng 2>/dev/null; then
		add_finding "Logging" "OK" "syslog-ng is active" ""
		ok "syslog-ng is active"
	else
		rec="Ensure logging service is running: 'sudo systemctl start rsyslog'"
		add_finding "Logging" "WARN" "No syslog service detected" "$rec"
		warn "No syslog service detected"
	fi
	
	# Check log file permissions
	log_files=("/var/log/auth.log" "/var/log/secure" "/var/log/messages" "/var/log/syslog")
	for log_file in "${log_files[@]}"; do
		if [ -f "$log_file" ]; then
			perms=$(stat -c "%a" "$log_file" 2>/dev/null || true)
			if [ -n "$perms" ] && [ "$perms" -gt 644 ]; then
				rec="Secure log file permissions: 'sudo chmod 640 $log_file'"
				add_finding "Logging" "WARN" "$log_file has loose permissions ($perms)" "$rec"
				warn "$log_file has loose permissions"
			fi
		fi
	done
	
	# Check logrotate
	if command_exists logrotate; then
		if [ -f /etc/logrotate.conf ]; then
			add_finding "Logging" "OK" "logrotate is configured" ""
			ok "logrotate is configured"
		else
			rec="Configure log rotation: create /etc/logrotate.conf"
			add_finding "Logging" "WARN" "logrotate not configured" "$rec"
		fi
	else
		rec=$(get_recommendation "Install logrotate: 'sudo apt install logrotate'" \
			"Install logrotate for log management" \
			"Deploy centralized log management with rotation and archival policies")
		add_finding "Logging" "INFO" "logrotate not installed" "$rec"
	fi
}

section_network_security() {
	print_section "Network Security"
	
	# Check for open ports with no firewall
	if command_exists ss; then
		listening_ports=$(ss -tuln 2>/dev/null | grep LISTEN | wc -l)
		if [ "$listening_ports" -gt 5 ]; then
			rec=$(get_recommendation "Review listening services and close unnecessary ports" \
				"Audit open ports: 'ss -tuln' and disable unused services" \
				"Implement network segmentation and service hardening policies")
			add_finding "Network Security" "INFO" "$listening_ports services listening" "$rec"
		fi
	fi
	
	# Check for IPv6 if not needed (personal mode suggestion)
	if [ "$OPERATION_MODE" = "personal" ]; then
		if [ -f /proc/net/if_inet6 ]; then
			rec="Consider disabling IPv6 if not needed: add 'net.ipv6.conf.all.disable_ipv6=1' to /etc/sysctl.conf"
			add_finding "Network Security" "INFO" "IPv6 is enabled" "$rec"
		fi
	fi
	
	# Check TCP SYN cookies
	syn_cookies=$(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null || echo 0)
	if [ "$syn_cookies" = "1" ]; then
		add_finding "Network Security" "OK" "TCP SYN cookies enabled" ""
		ok "TCP SYN cookies enabled"
	else
		rec="Enable SYN cookies: 'echo 1 | sudo tee /proc/sys/net/ipv4/tcp_syncookies'"
		add_finding "Network Security" "WARN" "TCP SYN cookies disabled" "$rec"
		warn "TCP SYN cookies disabled"
	fi
}

section_package_integrity() {
	print_section "Package Integrity"
	
	# RPM-based systems
	if command_exists rpm; then
		if is_root; then
			# Check for modified files (limit output)
			modified_files=$(rpm -Va 2>/dev/null | head -10 | wc -l || echo 0)
			if [ "$modified_files" -gt 0 ]; then
				rec="Review package modifications: 'sudo rpm -Va | head -20'"
				add_finding "Package Integrity" "WARN" "Modified package files detected" "$rec"
				warn "Modified package files detected"
			else
				add_finding "Package Integrity" "OK" "Package integrity verified" ""
				ok "Package integrity verified"
			fi
		else
			add_finding "Package Integrity" "INFO" "Package integrity check requires root" ""
		fi
	# Debian-based systems
	elif command_exists dpkg; then
		if command_exists debsums && is_root; then
			# Check for modified files
			modified=$(debsums -c 2>/dev/null | head -5 | wc -l || echo 0)
			if [ "$modified" -gt 0 ]; then
				rec="Review package modifications: 'sudo debsums -c | head -20'"
				add_finding "Package Integrity" "WARN" "Modified package files detected" "$rec"
				warn "Modified package files detected"
			else
				add_finding "Package Integrity" "OK" "Package integrity verified" ""
				ok "Package integrity verified"
			fi
		else
			rec="Install debsums for integrity checking: 'sudo apt install debsums'"
			add_finding "Package Integrity" "INFO" "debsums not available for integrity check" "$rec"
		fi
	fi
}

section_file_integrity() {
	print_section "File Integrity"
	
	# Define critical binaries to check
	critical_binaries=("/bin/bash" "/bin/sh" "/usr/bin/sudo" "/bin/su" "/usr/bin/ssh" "/sbin/init")
	critical_configs=("/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/ssh/sshd_config")
	
	# Personal mode: Quick hash checks
	if [ "$OPERATION_MODE" = "personal" ]; then
		for binary in "${critical_binaries[@]}"; do
			if [ -f "$binary" ]; then
				hash=$(sha256sum "$binary" 2>/dev/null | cut -d' ' -f1)
				if [ -n "$hash" ]; then
					add_finding "File Integrity" "INFO" "$(basename "$binary"): $hash" ""
					[ "$OUTPUT_FORMAT" = "console" ] && echo "$(basename "$binary"): ${hash:0:16}..."
				fi
			fi
		done
		
		for config in "${critical_configs[@]}"; do
			if [ -r "$config" ]; then
				hash=$(sha256sum "$config" 2>/dev/null | cut -d' ' -f1)
				if [ -n "$hash" ]; then
					add_finding "File Integrity" "INFO" "$(basename "$config"): $hash" ""
					[ "$OUTPUT_FORMAT" = "console" ] && echo "$(basename "$config"): ${hash:0:16}..."
				fi
			fi
		done
		
		rec="Save these hashes as baseline: 'sha256sum /bin/bash /etc/passwd > ~/system-baseline.txt'"
		add_finding "File Integrity" "INFO" "Critical file hashes captured" "$rec"
		
	# Production mode: More comprehensive checks
	else
		# Check if AIDE is installed
		if command_exists aide; then
			if [ -f /var/lib/aide/aide.db ]; then
				add_finding "File Integrity" "OK" "AIDE database found" ""
				ok "AIDE database found"
				if is_root; then
					rec="Run AIDE check: 'sudo aide --check' (this may take time)"
					add_finding "File Integrity" "INFO" "Run AIDE integrity check" "$rec"
				fi
			else
				rec="Initialize AIDE database: 'sudo aide --init && sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db'"
				add_finding "File Integrity" "WARN" "AIDE installed but not initialized" "$rec"
				warn "AIDE not initialized"
			fi
		else
			rec="Install AIDE for file integrity monitoring: 'sudo apt install aide && sudo aide --init'"
			add_finding "File Integrity" "INFO" "AIDE not installed" "$rec"
		fi
		
		# Check for Tripwire
		if command_exists tripwire; then
			add_finding "File Integrity" "OK" "Tripwire detected" ""
			ok "Tripwire detected"
		fi
		
		# Still do basic hash checks for immediate verification
		changed_files=0
		for binary in "${critical_binaries[@]}"; do
			if [ -f "$binary" ]; then
				hash=$(sha256sum "$binary" 2>/dev/null | cut -d' ' -f1)
				add_finding "File Integrity" "INFO" "$(basename "$binary"): $hash" ""
			fi
		done
		
		rec="Implement automated integrity monitoring with AIDE/Tripwire and baseline comparisons"
		add_finding "File Integrity" "INFO" "File integrity monitoring recommended" "$rec"
	fi
}

section_persistence_mechanisms() {
	print_section "Persistence Mechanisms"
	
	# Check crontabs for all users
	if command_exists crontab; then
		# Current user crontab
		user_cron=$(crontab -l 2>/dev/null | grep -v '^#' | wc -l || echo 0)
		if [ "$user_cron" -gt 0 ]; then
			rec=$(get_recommendation "Review user crontab entries: 'crontab -l'" \
				"Audit user cron jobs for unauthorized entries" \
				"Document and validate all scheduled tasks")
			add_finding "Persistence" "INFO" "User has $user_cron cron job(s)" "$rec"
			[ "$OUTPUT_FORMAT" = "console" ] && info "User cron jobs: $user_cron"
		fi
		
		# System-wide crontabs
		if is_root; then
			system_cron_files=("/etc/crontab" "/etc/cron.d/*" "/var/spool/cron/crontabs/*")
			for cron_pattern in "${system_cron_files[@]}"; do
				if ls $cron_pattern >/dev/null 2>&1; then
					cron_entries=$(grep -v '^#' $cron_pattern 2>/dev/null | grep -v '^$' | wc -l || echo 0)
					if [ "$cron_entries" -gt 0 ]; then
						add_finding "Persistence" "INFO" "System cron entries found: $cron_entries" ""
					fi
				fi
			done
		fi
	fi
	
	# Check systemd timers
	if command_exists systemctl; then
		active_timers=$(systemctl list-timers --no-pager 2>/dev/null | grep -c '\.timer' || echo 0)
		if [ "$active_timers" -gt 0 ]; then
			rec="Review active systemd timers: 'systemctl list-timers'"
			add_finding "Persistence" "INFO" "$active_timers systemd timer(s) active" "$rec"
			[ "$OUTPUT_FORMAT" = "console" ] && info "Active timers: $active_timers"
		fi
	fi
	
	# Check rc.local and startup scripts
	startup_files=("/etc/rc.local" "/etc/init.d/rc.local")
	for startup_file in "${startup_files[@]}"; do
		if [ -f "$startup_file" ] && [ -s "$startup_file" ]; then
			executable_lines=$(grep -v '^#' "$startup_file" | grep -v '^$' | wc -l)
			if [ "$executable_lines" -gt 1 ]; then  # More than just exit 0
				rec="Review startup script: 'cat $startup_file'"
				add_finding "Persistence" "WARN" "Active startup script: $startup_file" "$rec"
				warn "Startup script detected: $startup_file"
			fi
		fi
	done
	
	# Check user shell startup scripts (personal mode focus)
	if [ "$OPERATION_MODE" = "personal" ]; then
		user_home=$(eval echo "~$USER")
		shell_configs=("$user_home/.bashrc" "$user_home/.bash_profile" "$user_home/.zshrc" "$user_home/.profile")
		
		for config in "${shell_configs[@]}"; do
			if [ -f "$config" ]; then
				# Check for suspicious additions (simplified check)
				suspicious=$(grep -E '(curl|wget|nc |netcat|/tmp/|/dev/shm/)' "$config" 2>/dev/null | wc -l || echo 0)
				if [ "$suspicious" -gt 0 ]; then
					rec="Review shell config for suspicious entries: '$config'"
					add_finding "Persistence" "WARN" "Suspicious entries in $(basename "$config")" "$rec"
					warn "Suspicious shell config: $(basename "$config")"
				fi
			fi
		done
	fi
	
	# Check loaded kernel modules
	if command_exists lsmod; then
		total_modules=$(lsmod | wc -l)
		add_finding "Persistence" "INFO" "$total_modules kernel modules loaded" ""
		[ "$OUTPUT_FORMAT" = "console" ] && info "Loaded modules: $total_modules"
		
		# Check for uncommon modules (simplified check)
		uncommon_modules=$(lsmod | grep -iE '(rootkit|hide|stealth)' || true)
		if [ -n "$uncommon_modules" ]; then
			rec="Investigate suspicious kernel modules immediately"
			add_finding "Persistence" "CRIT" "Suspicious kernel modules detected" "$rec"
			crit "Suspicious kernel modules found"
		fi
	fi
}

section_process_forensics() {
	print_section "Process & Forensics"
	
	# Process tree analysis
	if command_exists pstree; then
		process_count=$(pstree -p 2>/dev/null | wc -l)
		add_finding "Process Forensics" "INFO" "$process_count processes in tree" ""
		[ "$OUTPUT_FORMAT" = "console" ] && info "Process tree depth: $process_count"
		
		# Look for suspicious parent-child relationships (simplified)
		suspicious_procs=$(pstree -p 2>/dev/null | grep -E '(sh|bash|nc|netcat|curl|wget).*\([0-9]+\).*\(' | wc -l || echo 0)
		if [ "$suspicious_procs" -gt 0 ]; then
			rec="Review process tree for anomalies: 'pstree -p | grep -E \"(sh|bash|nc|netcat)\""
			add_finding "Process Forensics" "WARN" "Suspicious process relationships detected" "$rec"
			warn "Unusual process tree detected"
		fi
	fi
	
	# Check for hidden processes (basic check)
	if [ -d /proc ]; then
		proc_count=$(ls -1 /proc | grep -E '^[0-9]+$' | wc -l)
		ps_count=$(ps aux --no-headers 2>/dev/null | wc -l || echo 0)
		
		if [ "$proc_count" -gt 0 ] && [ "$ps_count" -gt 0 ]; then
			diff=$((proc_count - ps_count))
			if [ "$diff" -gt 10 ]; then  # Allow some variance
				rec="Investigate process discrepancy: /proc shows $proc_count, ps shows $ps_count"
				add_finding "Process Forensics" "WARN" "Process count discrepancy detected" "$rec"
				warn "Process visibility discrepancy"
			else
				add_finding "Process Forensics" "OK" "Process counts consistent" ""
				ok "Process visibility normal"
			fi
		fi
	fi
	
	# Personal mode: Basic process analysis
	if [ "$OPERATION_MODE" = "personal" ]; then
		# Check for processes with network connections
		if command_exists lsof && is_root; then
			net_procs=$(lsof -i 2>/dev/null | grep -v COMMAND | wc -l || echo 0)
			if [ "$net_procs" -gt 10 ]; then
				rec="Review network-connected processes: 'sudo lsof -i'"
				add_finding "Process Forensics" "INFO" "$net_procs processes with network connections" "$rec"
			fi
		fi
		
		# Check for processes in tmp directories
		tmp_procs=$(ps aux 2>/dev/null | grep -E '/tmp/|/dev/shm/' | grep -v grep | wc -l || echo 0)
		if [ "$tmp_procs" -gt 0 ]; then
			rec="Investigate processes running from temporary directories"
			add_finding "Process Forensics" "WARN" "Processes running from temp directories" "$rec"
			warn "Processes in temp dirs detected"
		fi
	fi
	
	# Check for ELF capabilities (if available)
	if command_exists getcap && is_root; then
		cap_files=$(getcap -r /usr/bin /bin /sbin 2>/dev/null | wc -l || echo 0)
		if [ "$cap_files" -gt 0 ]; then
			rec="Review file capabilities: 'sudo getcap -r /usr/bin /bin /sbin'"
			add_finding "Process Forensics" "INFO" "$cap_files files with capabilities" "$rec"
		fi
	fi
}

section_secure_configuration() {
	print_section "Secure Configuration"
	
	# Check kernel hardening flags
	hardening_flags=("kernel.dmesg_restrict" "kernel.kptr_restrict" "net.ipv4.conf.all.send_redirects" "net.ipv4.conf.all.accept_redirects")
	
	for flag in "${hardening_flags[@]}"; do
		if [ -f /proc/sys/${flag//./\/} ]; then
			value=$(cat /proc/sys/${flag//./\/} 2>/dev/null || echo "unknown")
			case "$flag" in
				"kernel.dmesg_restrict"|"kernel.kptr_restrict")
					if [ "$value" = "1" ]; then
						add_finding "Secure Config" "OK" "$flag = $value (hardened)" ""
						ok "$flag enabled"
					else
						rec="Enable $flag: 'echo 1 | sudo tee /proc/sys/${flag//./\/}'"
						add_finding "Secure Config" "WARN" "$flag = $value (not hardened)" "$rec"
						warn "$flag not enabled"
					fi
					;;
				"net.ipv4.conf.all.send_redirects"|"net.ipv4.conf.all.accept_redirects")
					if [ "$value" = "0" ]; then
						add_finding "Secure Config" "OK" "$flag = $value (secure)" ""
						ok "$flag disabled"
					else
						rec="Disable $flag: 'echo 0 | sudo tee /proc/sys/${flag//./\/}'"
						add_finding "Secure Config" "WARN" "$flag = $value (insecure)" "$rec"
						warn "$flag enabled"
					fi
					;;
			esac
		fi
	done
	
	# Check /etc/security/limits.conf for basic protections
	if [ -f /etc/security/limits.conf ]; then
		core_limit=$(grep -E '^\s*\*\s+hard\s+core\s+0' /etc/security/limits.conf || true)
		if [ -n "$core_limit" ]; then
			add_finding "Secure Config" "OK" "Core dumps disabled in limits.conf" ""
			ok "Core dumps disabled"
		else
			rec="Disable core dumps: add '* hard core 0' to /etc/security/limits.conf"
			add_finding "Secure Config" "INFO" "Core dumps not explicitly disabled" "$rec"
		fi
	fi
	
	# Check umask setting
	current_umask=$(umask)
	if [ "$current_umask" = "0022" ] || [ "$current_umask" = "022" ]; then
		add_finding "Secure Config" "OK" "Secure umask: $current_umask" ""
		ok "Secure umask set"
	elif [ "$current_umask" = "0077" ] || [ "$current_umask" = "077" ]; then
		add_finding "Secure Config" "OK" "Very secure umask: $current_umask" ""
		ok "Very secure umask set"
	else
		rec=$(get_recommendation "Set secure umask in ~/.bashrc: 'umask 022'" \
			"Set secure umask: 'umask 022' for basic security" \
			"Enforce secure umask organization-wide via /etc/profile")
		add_finding "Secure Config" "WARN" "Permissive umask: $current_umask" "$rec"
		warn "Permissive umask detected"
	fi
	
	# Check for basic MFA indicators (personal mode)
	if [ "$OPERATION_MODE" = "personal" ]; then
		# Check for Google Authenticator PAM module
		if [ -f /etc/pam.d/common-auth ] && grep -q "pam_google_authenticator" /etc/pam.d/common-auth 2>/dev/null; then
			add_finding "Secure Config" "OK" "2FA PAM module detected" ""
			ok "2FA appears configured"
		else
			rec="Consider setting up 2FA: 'sudo apt install libpam-google-authenticator'"
			add_finding "Secure Config" "INFO" "No 2FA detected" "$rec"
		fi
	fi
}

section_summary() {
	print_section "Summary"
	
	# Count findings by severity
	total_findings=${#FINDINGS[@]}
	crit_count=0
	warn_count=0
	ok_count=0
	info_count=0
	
	for finding in "${FINDINGS[@]}"; do
		IFS='|' read -r section severity message recommendation <<< "$finding"
		case "$severity" in
			CRIT) ((crit_count++));;
			WARN) ((warn_count++));;
			OK) ((ok_count++));;
			INFO) ((info_count++));;
		esac
	done
	
	echo "bt-quickcheck v${VERSION} completed."
	echo "Total findings: $total_findings (CRIT: $crit_count, WARN: $warn_count, OK: $ok_count, INFO: $info_count)"
	echo "Mode: $OPERATION_MODE | Review CRIT and WARN items above."
	
	add_finding "Summary" "INFO" "Scan completed: $total_findings findings" ""
	add_finding "Summary" "INFO" "Critical: $crit_count, Warnings: $warn_count, OK: $ok_count, Info: $info_count" ""
}

show_help() {
	cat << EOF
bt-quickcheck v$VERSION - Blue Team Security Quick Check

Usage: $0 [OPTIONS]

OPTIONS:
  -h, --help              Show this help message
  -v, --version           Show version information
  -f, --format FORMAT     Output format: console, json, html, txt (default: console)
  -o, --output FILE       Output file (default: stdout)
  -m, --mode MODE         Operation mode: personal, production (default: personal)

MODES:
  personal               Home/personal machine recommendations (security through obscurity, etc.)
  production             Business/server environment recommendations (compliance, automation)

OUTPUT FORMATS:
  console               Colored console output (default)
  json                  JSON structured output for automation/SIEM
  html                  HTML report with styling
  txt                   Plain text report

EXAMPLES:
  $0                                    # Default console output
  $0 -f json -o report.json             # JSON output to file
  $0 -f html -o report.html -m production  # HTML production report
  $0 -m production                      # Production mode recommendations

EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
		--version|-v) echo "$VERSION"; exit 0;;
		--help|-h) show_help; exit 0;;
		--format|-f)
			shift
			case "$1" in
				console|json|html|txt) OUTPUT_FORMAT="$1";;
				*) echo "Error: Invalid format '$1'. Use: console, json, html, txt"; exit 1;;
			esac
			;;
		--output|-o)
			shift
			OUTPUT_FILE="$1"
			;;
		--mode|-m)
			shift
			case "$1" in
				personal|production) OPERATION_MODE="$1";;
				*) echo "Error: Invalid mode '$1'. Use: personal, production"; exit 1;;
			esac
			;;
		*) echo "Unknown arg: $1. Use --help for usage."; exit 1;;
	esac
	shift
done

# Run all checks
section_system
section_updates
section_listening
section_firewall
section_ssh
section_auditing
section_accounts
section_permissions
section_intrusion_detection
section_time_sync
section_logging
section_network_security
section_package_integrity
section_file_integrity
section_persistence_mechanisms
section_process_forensics
section_secure_configuration
section_summary

# Generate output based on format
generate_output() {
	case "$OUTPUT_FORMAT" in
		json) generate_json_output;;
		html) generate_html_output;;
		txt) generate_txt_output;;
		console) 
			[ "$OUTPUT_FORMAT" = "console" ] && echo
			;;
	esac
}

# Output to file or stdout
if [ -n "$OUTPUT_FILE" ]; then
	generate_output > "$OUTPUT_FILE"
	[ "$OUTPUT_FORMAT" != "console" ] && echo "Report generated: $OUTPUT_FILE" >&2
else
	generate_output
fi

exit 0


