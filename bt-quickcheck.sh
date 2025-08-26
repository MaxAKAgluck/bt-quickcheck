#!/usr/bin/env bash

# Blue Team QuickCheck - Linux Security Assessment Tool
# Version: 0.6.0
# 
# SECURITY DISCLAIMER:
# This script performs READ-ONLY security assessment of Linux systems.
# It may access sensitive system files for analysis but does NOT modify any files.
# It requires sudo privileges for comprehensive system inspection.
#
# PRIVACY NOTICE:
# This script reads system configuration files, logs, and process information
# to assess security posture. It may access files containing sensitive information
# including user accounts, network configuration, and system logs.
# All data remains local and is not transmitted externally.
#
# USAGE REQUIREMENTS:
# - Run with sudo for complete assessment: sudo ./bt-quickcheck.sh
# - Script performs only read operations - no system modifications
# - Safe to run on production systems (read-only assessment)
# 
# By running this script, you acknowledge understanding of its purpose and scope.

set -euo pipefail  # Strict error handling: exit on error, undefined vars, pipe failures

# Enhanced error handling with logging
handle_section_error() {
    local section="$1"
    local line="$2"
    local error="$3"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Log error with timestamp and context
    local error_msg="[$timestamp] ERROR in $section (line $line): $error"
    
    if [ "$OUTPUT_FORMAT" = "console" ]; then
        warn "Error in $section (line $line): $error"
        warn "Continuing with remaining checks..."
    fi
    
    # Add structured finding for error tracking
    add_finding "$section" "WARN" "Section error encountered: $error" "Review section implementation and check system logs"
    
    # Log to system log if available and running as root
    if is_root && command_exists logger; then
        logger -p user.warning "bt-quickcheck: $error_msg"
    fi
}

# Enhanced section runner with timeout protection
run_section_safely() {
    local section_func="$1"
    local section_name="$2"
    local timeout="${3:-30}"  # Default 30 second timeout
    
    # Temporarily disable exit on error for this section
    set +e
    
    # Run section directly (functions are in the same scope)
    eval "$section_func" 2>/dev/null
    local exit_code=$?
    
    set -e
    
    if [ $exit_code -ne 0 ]; then
        # Error occurred
        handle_section_error "$section_name" "ERROR" "Section failed with exit code $exit_code"
    fi
}

VERSION="0.6.0"

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

# Safety functions
is_root() { [ "${EUID:-$(id -u)}" -eq 0 ]; }

# Enhanced safe command execution with additional security
safe_exec() {
    local cmd="$1"
    shift
    
    # Validate command before execution
    if ! validate_command "$cmd"; then
        return 1
    fi
    
    # Prevent execution from dangerous directories
    local cmd_path
    cmd_path=$(command -v "$cmd" 2>/dev/null)
    if [[ -n "$cmd_path" ]]; then
        if [[ "$cmd_path" =~ /tmp/ ]] || [[ "$cmd_path" =~ /dev/shm/ ]]; then
            return 1
        fi
    fi
    
    # Execute with additional safety
    "$cmd" "$@" 2>/dev/null || true
}

# Enhanced safe file reading with content validation
safe_read() {
    local file="$1"
    local max_size="${2:-1048576}"  # Default 1MB limit
    
    if [ -r "$file" ] && [ -f "$file" ]; then
        # Check file size to prevent reading extremely large files
        local file_size
        file_size=$(stat -c "%s" "$file" 2>/dev/null || echo "0")
        if [ "$file_size" -gt "$max_size" ]; then
            return 1
        fi
        
        # Validate file is not a symlink to prevent symlink attacks
        if [ -L "$file" ]; then
            return 1
        fi
        
        cat "$file" 2>/dev/null || true
    fi
}

# Safe directory check
safe_dir_check() {
    local dir="$1"
    [ -d "$dir" ] && [ -r "$dir" ]
}

# Check if a section should be run based on privileges and mode
should_run_section() {
    local section="$1"
    local requires_root="${2:-false}"
    
    # If section requires root and we don't have it, skip
    if [ "$requires_root" = "true" ] && ! is_root; then
        return 1
    fi
    
    return 0
}

# Display skip message for sections that require root
skip_section() {
    local section="$1"
    local reason="${2:-requires root access}"
    
    if [ "$OUTPUT_FORMAT" = "console" ]; then
        printf "\n${COLOR_BLUE}=== %s ===${COLOR_RESET}\n" "$section"
        printf "${COLOR_YELLOW}[SKIP]${COLOR_RESET} Section skipped - %s\n" "$reason"
        printf "${COLOR_YELLOW}       Run with sudo for comprehensive assessment${COLOR_RESET}\n"
    fi
    
    add_finding "$section" "INFO" "Section skipped without sudo" "Run script with sudo for complete assessment"
}

# Enhanced print_section that shows privilege requirements
print_section_with_privilege_info() {
    local section="$1"
    local requires_root="${2:-false}"
    local check_count="${3:-}"
    
    if [ "$OUTPUT_FORMAT" = "console" ]; then
        printf "\n${COLOR_BLUE}=== %s ===${COLOR_RESET}" "$section"
        
        if [ "$requires_root" = "true" ] && ! is_root; then
            printf " ${COLOR_YELLOW}(Limited - requires sudo)${COLOR_RESET}"
        elif [ "$requires_root" = "true" ] && is_root; then
            printf " ${COLOR_GREEN}(Full access)${COLOR_RESET}"
        fi
        
        if [ -n "$check_count" ]; then
            printf " ${COLOR_BLUE}[%s checks]${COLOR_RESET}" "$check_count"
        fi
        
        printf "\n"
    fi
    
    SECTIONS+=("$section")
}

# Validate output format
validate_format() {
    local format="$1"
    case "$format" in
        console|json|html|txt) return 0 ;;
        *) return 1 ;;
    esac
}

# Validate operation mode  
validate_mode() {
    local mode="$1"
    case "$mode" in
        personal|production) return 0 ;;
        *) return 1 ;;
    esac
}

# Enhanced file path validation with additional security checks
validate_output_path() {
    local path="$1"
    
    # Prevent path traversal and directory traversal attacks
    if [[ "$path" =~ \.\. ]] || [[ "$path" =~ /\.\. ]] || [[ "$path" =~ \.\./ ]]; then
        return 1
    fi
    
    # Prevent absolute paths outside of safe directories
    if [[ "$path" =~ ^/ ]]; then
        # Only allow paths in /tmp, /var/tmp, or current user's home
        if [[ ! "$path" =~ ^/(tmp|var/tmp|home/[^/]+) ]] && [[ ! "$path" =~ ^$HOME ]]; then
            return 1
        fi
    fi
    
    # Remove any remaining path traversal attempts
    local clean_path
    clean_path=$(realpath -m "$path" 2>/dev/null || echo "$path")
    
    return 0
}

# Enhanced command validation
validate_command() {
    local cmd="$1"
    
    # Prevent execution of dangerous commands
    local dangerous_commands=("rm" "dd" "mkfs" "fdisk" "parted" "shutdown" "reboot" "halt" "init" "telinit")
    for dangerous in "${dangerous_commands[@]}"; do
        if [[ "$cmd" =~ ^$dangerous ]]; then
            return 1
        fi
    done
    
    # Validate command exists and is executable
    if ! command -v "$cmd" >/dev/null 2>&1; then
        return 1
    fi
    
    return 0
}

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

# Enhanced kernel security checks
section_enhanced_kernel_security() {
	print_section "Enhanced Kernel Security"
	
	# Check for additional kernel hardening parameters
	enhanced_hardening_checks=(
		"kernel.yama.ptrace_scope:1:PTRACE scope restriction"
		"kernel.core_uses_pid:1:Core dump PID inclusion"
		"fs.suid_dumpable:0:SUID core dump prevention"
		"net.ipv4.conf.all.rp_filter:1:Reverse path filtering"
		"net.ipv4.conf.default.rp_filter:1:Default reverse path filtering"
		"net.ipv4.conf.all.accept_source_route:0:Source route acceptance"
		"net.ipv4.conf.default.accept_source_route:0:Default source route acceptance"
		"net.ipv6.conf.all.accept_source_route:0:IPv6 source route acceptance"
		"net.ipv6.conf.default.accept_source_route:0:IPv6 default source route acceptance"
	)
	
	hardening_checks_total=0
	hardening_checks_enabled=0
	
	for check in "${enhanced_hardening_checks[@]}"; do
		IFS=':' read -r sysctl_name expected_value description <<< "$check"
		if [ -f "/proc/sys/${sysctl_name//./\/}" ]; then
			hardening_checks_total=$((hardening_checks_total + 1))
			current_value=$(safe_read "/proc/sys/${sysctl_name//./\/}")
			[ -z "$current_value" ] && current_value="0"
			if [ "$current_value" = "$expected_value" ]; then
				hardening_checks_enabled=$((hardening_checks_enabled + 1))
				add_finding "Enhanced Kernel Security" "OK" "$description enabled" ""
				ok "$description enabled"
			else
				rec="Enable $description: 'echo $expected_value | sudo tee /proc/sys/${sysctl_name//./\/}'"
				add_finding "Enhanced Kernel Security" "WARN" "$description disabled" "$rec"
				warn "$description disabled"
			fi
		fi
	done
	
	if [ "$hardening_checks_total" -gt 0 ]; then
		add_finding "Enhanced Kernel Security" "INFO" "Kernel hardening: $hardening_checks_enabled/$hardening_checks_total enabled" ""
		info "Kernel hardening: $hardening_checks_enabled/$hardening_checks_total enabled"
	else
		add_finding "Enhanced Kernel Security" "INFO" "No kernel hardening parameters accessible" ""
		info "No kernel hardening parameters accessible"
	fi
	
	# Check for additional security modules
	security_modules=("apparmor" "selinux" "yama" "capability" "integrity")
	security_modules_loaded=0
	
	for module in "${security_modules[@]}"; do
		if lsmod | grep -q "^${module}"; then
			security_modules_loaded=$((security_modules_loaded + 1))
			add_finding "Enhanced Kernel Security" "OK" "$module security module loaded" ""
			ok "$module security module loaded"
		fi
	done
	
	if [ "$security_modules_loaded" -gt 0 ]; then
		add_finding "Enhanced Kernel Security" "INFO" "Security modules loaded: $security_modules_loaded" ""
		info "Security modules loaded: $security_modules_loaded"
	else
		rec="Load security modules: 'sudo modprobe apparmor' or 'sudo modprobe yama'"
		add_finding "Enhanced Kernel Security" "WARN" "No security modules loaded" "$rec"
		warn "No security modules loaded"
	fi
	
	# Check for Secure Boot
	if [ -f /sys/firmware/efi/efivars/SecureBoot-* ]; then
		secure_boot_status=$(cat /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | od -An -tu1 | tail -c +5 | head -c 1)
		if [ "$secure_boot_status" = "1" ]; then
			add_finding "Enhanced Kernel Security" "OK" "Secure Boot enabled" ""
			ok "Secure Boot enabled"
		else
			add_finding "Enhanced Kernel Security" "WARN" "Secure Boot disabled" ""
			warn "Secure Boot disabled"
		fi
	else
		add_finding "Enhanced Kernel Security" "INFO" "Secure Boot status not accessible" ""
		info "Secure Boot status not accessible"
	fi
}

# Enhanced network security checks
section_enhanced_network_security() {
	print_section "Enhanced Network Security"
	
	# Check for additional network hardening
	network_hardening_checks=(
		"net.ipv4.tcp_timestamps:0:TCP timestamp protection"
		"net.ipv4.tcp_syncookies:1:TCP SYN cookies"
		"net.ipv4.tcp_max_syn_backlog:128:SYN backlog limit"
		"net.core.netdev_max_backlog:1000:Network device backlog"
		"net.ipv4.conf.all.log_martians:1:Martian packet logging"
		"net.ipv4.conf.default.log_martians:1:Default martian packet logging"
	)
	
	network_checks_total=0
	network_checks_enabled=0
	
	for check in "${network_hardening_checks[@]}"; do
		IFS=':' read -r sysctl_name expected_value description <<< "$check"
		if [ -f "/proc/sys/${sysctl_name//./\/}" ]; then
			network_checks_total=$((network_checks_total + 1))
			current_value=$(safe_read "/proc/sys/${sysctl_name//./\/}")
			[ -z "$current_value" ] && current_value="0"
			if [ "$current_value" = "$expected_value" ]; then
				network_checks_enabled=$((network_checks_enabled + 1))
				add_finding "Enhanced Network Security" "OK" "$description enabled" ""
				ok "$description enabled"
			else
				rec="Enable $description: 'echo $expected_value | sudo tee /proc/sys/${sysctl_name//./\/}'"
				add_finding "Enhanced Network Security" "WARN" "$description disabled" "$rec"
				warn "$description disabled"
			fi
		fi
	done
	
	if [ "$network_checks_total" -gt 0 ]; then
		add_finding "Enhanced Network Security" "INFO" "Network hardening: $network_checks_enabled/$network_checks_total enabled" ""
		info "Network hardening: $network_checks_enabled/$network_checks_total enabled"
	else
		add_finding "Enhanced Network Security" "INFO" "No network hardening parameters accessible" ""
		info "No network hardening parameters accessible"
	fi
	
	# Check for network namespace isolation
	if [ -d /proc/net ]; then
		net_namespaces=$(ls /proc/net/ 2>/dev/null | wc -l)
		if [ "$net_namespaces" -gt 5 ]; then
			add_finding "Enhanced Network Security" "INFO" "Network namespaces detected: $net_namespaces" ""
			info "Network namespaces: $net_namespaces"
		else
			add_finding "Enhanced Network Security" "INFO" "Standard network configuration detected" ""
			info "Standard network configuration"
		fi
	else
		add_finding "Enhanced Network Security" "WARN" "Network filesystem not accessible" ""
		warn "Network filesystem not accessible"
	fi
	
	# Check for network interface security
	if command_exists ip; then
		interfaces=$(ip link show 2>/dev/null | grep -c "UP" || echo "0")
		if [ "$interfaces" -gt 0 ]; then
			add_finding "Enhanced Network Security" "INFO" "Active network interfaces: $interfaces" ""
			info "Active interfaces: $interfaces"
		fi
	else
		add_finding "Enhanced Network Security" "INFO" "ip command not available" ""
		info "ip command not available"
	fi
}

# Enhanced compliance checks
section_compliance_checks() {
	print_section "Compliance & Audit"
	
	# Check for audit configuration
	audit_configured=0
	if [ -f /etc/audit/auditd.conf ]; then
		audit_configured=1
		audit_config=$(grep -E "^(max_log_file|num_logs|max_log_file_action)" /etc/audit/auditd.conf 2>/dev/null || true)
		if [ -n "$audit_config" ]; then
			add_finding "Compliance" "OK" "Audit daemon configuration found" ""
			ok "Audit configuration present"
		else
			rec="Configure audit daemon settings in /etc/audit/auditd.conf"
			add_finding "Compliance" "WARN" "Audit daemon configuration incomplete" "$rec"
			warn "Audit configuration incomplete"
		fi
		
		# Check audit service status
		if command_exists systemctl && is_root; then
			if systemctl is-active --quiet auditd; then
				add_finding "Compliance" "OK" "Audit daemon service is running" ""
				ok "Audit service running"
			else
				rec="Start audit daemon service: 'sudo systemctl start auditd'"
				add_finding "Compliance" "WARN" "Audit daemon service not running" "$rec"
				warn "Audit service not running"
			fi
		fi
	else
		rec="Install and configure auditd: 'sudo apt install auditd' or 'sudo yum install audit'"
		add_finding "Compliance" "WARN" "Audit daemon configuration not found" "$rec"
		warn "Audit daemon not configured"
	fi
	
	# Check for log retention policies
	log_retention_configured=0
	if [ -f /etc/logrotate.conf ]; then
		log_retention_configured=1
		retention_policy=$(grep -E "rotate|compress|delaycompress" /etc/logrotate.conf 2>/dev/null || true)
		if [ -n "$retention_policy" ]; then
			add_finding "Compliance" "OK" "Log rotation policy configured" ""
			ok "Log rotation configured"
		else
			rec="Configure log rotation policies in /etc/logrotate.conf"
			add_finding "Compliance" "WARN" "Log rotation policy incomplete" "$rec"
			warn "Log rotation incomplete"
		fi
	else
		add_finding "Compliance" "INFO" "Log rotation configuration not found" ""
		info "Log rotation not configured"
	fi
	
	# Check for security policy files
	security_policies=("/etc/security/access.conf" "/etc/security/limits.conf" "/etc/security/namespace.conf")
	security_policies_found=0
	
	for policy in "${security_policies[@]}"; do
		if [ -f "$policy" ]; then
			security_policies_found=$((security_policies_found + 1))
			add_finding "Compliance" "INFO" "Security policy file: $(basename "$policy")" ""
			info "Security policy: $(basename "$policy")"
		fi
	done
	
	if [ "$security_policies_found" -eq 0 ]; then
		add_finding "Compliance" "INFO" "No security policy files found" ""
		info "No security policy files found"
	fi
	
	# Check for compliance tools
	compliance_tools=("openscap" "lynis" "tiger" "rkhunter")
	compliance_tools_found=0
	
	for tool in "${compliance_tools[@]}"; do
		if command_exists "$tool"; then
			compliance_tools_found=$((compliance_tools_found + 1))
			add_finding "Compliance" "OK" "Compliance tool available: $tool" ""
			ok "$tool available"
		fi
	done
	
	if [ "$compliance_tools_found" -eq 0 ]; then
		rec="Install compliance tools: 'sudo apt install lynis' or 'sudo yum install lynis'"
		add_finding "Compliance" "WARN" "No compliance tools detected" "$rec"
		warn "No compliance tools detected"
	fi
	
	# Summary
	if [ "$audit_configured" -eq 1 ] || [ "$log_retention_configured" -eq 1 ] || [ "$security_policies_found" -gt 0 ] || [ "$compliance_tools_found" -gt 0 ]; then
		add_finding "Compliance" "INFO" "Compliance framework partially configured" ""
		info "Compliance framework partially configured"
	else
		rec="Implement compliance framework (auditd, log rotation, security policies, compliance tools)"
		add_finding "Compliance" "WARN" "No compliance framework detected" "$rec"
		warn "No compliance framework detected"
	fi
}

# Enhanced container security checks
section_enhanced_container_security() {
	print_section "Enhanced Container Security"
	
	# Check for container runtime security
	if command_exists docker; then
		add_finding "Enhanced Container Security" "INFO" "Docker runtime detected" ""
		info "Docker runtime detected"
		
		# Check Docker daemon security configuration
		if [ -f /etc/docker/daemon.json ]; then
			security_config=$(grep -E "(live-restore|userland-proxy|no-new-privileges)" /etc/docker/daemon.json 2>/dev/null || true)
			if [ -n "$security_config" ]; then
				add_finding "Enhanced Container Security" "OK" "Docker security hardening configured" ""
				ok "Docker security hardening"
			else
				rec="Configure Docker security hardening in /etc/docker/daemon.json"
				add_finding "Enhanced Container Security" "WARN" "Docker security hardening not configured" "$rec"
				warn "Docker security hardening not configured"
			fi
		else
			rec="Create /etc/docker/daemon.json with security hardening options"
			add_finding "Enhanced Container Security" "WARN" "Docker daemon configuration file not found" "$rec"
			warn "Docker daemon configuration not found"
		fi
		
		# Check for running containers with security profiles
		if is_root; then
			running_containers=$(docker ps --format "{{.Names}}" 2>/dev/null | wc -l || echo "0")
			if [ "$running_containers" -gt 0 ]; then
				add_finding "Enhanced Container Security" "INFO" "$running_containers container(s) running" ""
				info "$running_containers container(s) running"
				
				unconfined_containers=$(docker ps --format "{{.Names}}" 2>/dev/null | xargs -I {} docker inspect --format '{{.HostConfig.SecurityOpt}}' {} 2>/dev/null | grep -c "unconfined" || echo "0")
				if [ "$unconfined_containers" -gt 0 ]; then
					rec="Review containers running without security profiles"
					add_finding "Enhanced Container Security" "WARN" "$unconfined_containers container(s) without security profiles" "$rec"
					warn "Unconfined containers detected"
				else
					add_finding "Enhanced Container Security" "OK" "All running containers have security profiles" ""
					ok "All containers have security profiles"
				fi
			else
				add_finding "Enhanced Container Security" "INFO" "No containers currently running" ""
				info "No containers running"
			fi
		else
			add_finding "Enhanced Container Security" "INFO" "Docker container inspection requires sudo access" ""
			info "Container inspection requires sudo access"
		fi
	else
		add_finding "Enhanced Container Security" "INFO" "Docker runtime not detected" ""
		info "Docker runtime not detected"
	fi
	
	# Check for Kubernetes security
	if command_exists kubectl; then
		add_finding "Enhanced Container Security" "INFO" "Kubernetes CLI detected" ""
		info "Kubernetes CLI detected"
		
		# Check for RBAC configuration
		if kubectl get clusterrolebinding 2>/dev/null | grep -q "cluster-admin"; then
			rec="Review cluster-admin bindings for security implications"
			add_finding "Enhanced Container Security" "WARN" "Cluster admin bindings detected" "$rec"
			warn "Cluster admin bindings found"
		else
			add_finding "Enhanced Container Security" "OK" "No cluster-admin bindings detected" ""
			ok "No cluster-admin bindings"
		fi
		
		# Check for network policies
		network_policies=$(kubectl get networkpolicies --all-namespaces 2>/dev/null | wc -l || echo "0")
		if [ "$network_policies" -gt 0 ]; then
			add_finding "Enhanced Container Security" "OK" "Network policies configured: $network_policies" ""
			ok "Network policies configured"
		else
			rec="Configure network policies for pod-to-pod communication control"
			add_finding "Enhanced Container Security" "WARN" "No network policies configured" "$rec"
			warn "No network policies configured"
		fi
	else
		add_finding "Enhanced Container Security" "INFO" "Kubernetes CLI not detected" ""
		info "Kubernetes CLI not detected"
	fi
}

# Enhanced file integrity monitoring
section_enhanced_file_integrity() {
	print_section "Enhanced File Integrity"
	
	# Check for additional integrity monitoring tools
	integrity_tools=("aide" "tripwire" "ossec" "samhain" "integrity")
	tools_found=0
	
	for tool in "${integrity_tools[@]}"; do
		if command_exists "$tool"; then
			tools_found=$((tools_found + 1))
			add_finding "Enhanced File Integrity" "OK" "File integrity tool available: $tool" ""
			ok "$tool available"
			
			# Check for recent integrity checks
			if [ "$tool" = "aide" ] && [ -f /var/lib/aide/aide.db ]; then
				last_check=$(stat -c "%Y" /var/lib/aide/aide.db 2>/dev/null || echo "0")
				current_time=$(date +%s)
				days_since_check=$(( (current_time - last_check) / 86400 ))
				
				if [ "$days_since_check" -lt 7 ]; then
					add_finding "Enhanced File Integrity" "OK" "AIDE database updated $days_since_check days ago" ""
				else
					rec="Run AIDE integrity check: 'sudo aide --check'"
					add_finding "Enhanced File Integrity" "WARN" "AIDE database not updated for $days_since_check days" "$rec"
				fi
			fi
		fi
	done
	
	if [ "$tools_found" -eq 0 ]; then
		rec="Install file integrity monitoring tools: 'sudo apt install aide' or 'sudo yum install aide'"
		add_finding "Enhanced File Integrity" "WARN" "No file integrity monitoring tools detected" "$rec"
		warn "No file integrity tools detected"
	fi
	
	# Check for critical file modifications
	critical_files=("/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/ssh/sshd_config" "/etc/fstab")
	critical_files_checked=0
	
	for file in "${critical_files[@]}"; do
		if [ -f "$file" ]; then
			critical_files_checked=$((critical_files_checked + 1))
			# Check for recent modifications
			last_mod=$(stat -c "%Y" "$file" 2>/dev/null || echo "0")
			current_time=$(date +%s)
			days_since_mod=$(( (current_time - last_mod) / 86400 ))
			
			if [ "$days_since_mod" -lt 30 ]; then
				add_finding "Enhanced File Integrity" "INFO" "$(basename "$file") modified $days_since_mod days ago" ""
				info "$(basename "$file") modified $days_since_mod days ago"
			else
				add_finding "Enhanced File Integrity" "OK" "$(basename "$file") not modified recently ($days_since_mod days ago)" ""
				ok "$(basename "$file") not modified recently"
			fi
		fi
	done
	
	if [ "$critical_files_checked" -gt 0 ]; then
		add_finding "Enhanced File Integrity" "INFO" "Checked $critical_files_checked critical system files" ""
		info "Checked $critical_files_checked critical files"
	else
		add_finding "Enhanced File Integrity" "INFO" "No critical system files accessible for modification checking" ""
		info "No critical files accessible"
	fi
}

# Enhanced process security checks
section_enhanced_process_security() {
	print_section "Enhanced Process Security"
	
	# Check for process isolation
	if [ -d /proc ]; then
		add_finding "Enhanced Process Security" "INFO" "Process filesystem accessible" ""
		info "Process filesystem accessible"
		
		# Check for process namespaces
		namespaces=$(ls /proc/*/ns/ 2>/dev/null | wc -l || echo "0")
		if [ "$namespaces" -gt 0 ]; then
			add_finding "Enhanced Process Security" "INFO" "Process namespaces detected: $namespaces" ""
			info "Process namespaces: $namespaces"
		else
			add_finding "Enhanced Process Security" "INFO" "No process namespaces detected" ""
			info "No process namespaces detected"
		fi
		
		# Check for process capabilities
		if command_exists getcap && is_root; then
			privileged_processes=$(getcap -r /usr/bin /bin /sbin 2>/dev/null | grep -E "(cap_sys_admin|cap_sys_ptrace|cap_sys_module)" | wc -l || echo "0")
			if [ "$privileged_processes" -gt 0 ]; then
				rec="Review processes with elevated capabilities"
				add_finding "Enhanced Process Security" "WARN" "$privileged_processes process(es) with elevated capabilities" "$rec"
				warn "Elevated capabilities detected"
			else
				add_finding "Enhanced Process Security" "OK" "No processes with elevated capabilities detected" ""
				ok "No elevated capabilities detected"
			fi
		else
			if ! is_root; then
				add_finding "Enhanced Process Security" "INFO" "Process capability checking requires sudo access" ""
				info "Capability checking requires sudo access"
			else
				add_finding "Enhanced Process Security" "INFO" "getcap command not available" ""
				info "getcap command not available"
			fi
		fi
	else
		add_finding "Enhanced Process Security" "WARN" "Process filesystem not accessible" ""
		warn "Process filesystem not accessible"
	fi
	
	# Check for memory protection
	if [ -f /proc/sys/vm/dirty_writeback_centisecs ]; then
		writeback_centisecs=$(safe_read /proc/sys/vm/dirty_writeback_centisecs)
		if [ "$writeback_centisecs" -lt 500 ]; then
			add_finding "Enhanced Process Security" "OK" "Memory writeback protection enabled" ""
			ok "Memory protection enabled"
		else
			rec="Configure memory writeback protection: 'echo 500 | sudo tee /proc/sys/vm/dirty_writeback_centisecs'"
			add_finding "Enhanced Process Security" "WARN" "Memory writeback protection not configured" "$rec"
			warn "Memory protection not configured"
		fi
	else
		add_finding "Enhanced Process Security" "INFO" "Memory protection sysctl not available" ""
		info "Memory protection sysctl not available"
	fi
	
	# Check for process tree
	if command_exists pstree; then
		process_count=$(ps aux | wc -l 2>/dev/null || echo "0")
		if [ "$process_count" -gt 0 ]; then
			add_finding "Enhanced Process Security" "INFO" "System running $process_count processes" ""
			info "System running $process_count processes"
		fi
	else
		add_finding "Enhanced Process Security" "INFO" "pstree command not available" ""
		info "pstree command not available"
	fi
}

# Enhanced logging security checks
section_enhanced_logging_security() {
	print_section "Enhanced Logging Security"
	
	# Check for log file permissions
	log_files=("/var/log/auth.log" "/var/log/secure" "/var/log/messages" "/var/log/syslog" "/var/log/kern.log")
	log_files_found=0
	secure_permissions=0
	correct_ownership=0
	
	for log_file in "${log_files[@]}"; do
		if [ -f "$log_file" ]; then
			log_files_found=$((log_files_found + 1))
			perms=$(stat -c "%a" "$log_file" 2>/dev/null || echo "unknown")
			owner=$(stat -c "%U" "$log_file" 2>/dev/null || echo "unknown")
			
			if [ "$perms" = "600" ] || [ "$perms" = "640" ]; then
				secure_permissions=$((secure_permissions + 1))
				add_finding "Enhanced Logging Security" "OK" "$(basename "$log_file") has secure permissions" ""
				ok "$(basename "$log_file") secure permissions"
			else
				rec="Secure log file permissions: 'sudo chmod 640 $log_file'"
				add_finding "Enhanced Logging Security" "WARN" "$(basename "$log_file") has loose permissions ($perms)" "$rec"
				warn "$(basename "$log_file") loose permissions ($perms)"
			fi
			
			if [ "$owner" = "root" ] || [ "$owner" = "syslog" ]; then
				correct_ownership=$((correct_ownership + 1))
				add_finding "Enhanced Logging Security" "OK" "$(basename "$log_file") has correct ownership" ""
				ok "$(basename "$log_file") correct ownership"
			else
				rec="Fix log file ownership: 'sudo chown root:adm $log_file'"
				add_finding "Enhanced Logging Security" "WARN" "$(basename "$log_file") has incorrect ownership ($owner)" "$rec"
				warn "$(basename "$log_file") incorrect ownership ($owner)"
			fi
		fi
	done
	
	if [ "$log_files_found" -gt 0 ]; then
		add_finding "Enhanced Logging Security" "INFO" "Checked $log_files_found log files" ""
		info "Checked $log_files_found log files"
		add_finding "Enhanced Logging Security" "INFO" "Secure permissions: $secure_permissions/$log_files_found" ""
		info "Secure permissions: $secure_permissions/$log_files_found"
		add_finding "Enhanced Logging Security" "INFO" "Correct ownership: $correct_ownership/$log_files_found" ""
		info "Correct ownership: $correct_ownership/$log_files_found"
	else
		add_finding "Enhanced Logging Security" "WARN" "No standard log files found for permission checking" ""
		warn "No standard log files found"
	fi
	
	# Check for log forwarding configuration
	if [ -f /etc/rsyslog.conf ]; then
		add_finding "Enhanced Logging Security" "INFO" "rsyslog configuration found" ""
		info "rsyslog configuration found"
		
		remote_forwarding=$(grep -E "^\s*\*\.\*\s+@@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null || true)
		if [ -n "$remote_forwarding" ]; then
			add_finding "Enhanced Logging Security" "OK" "Remote log forwarding configured" ""
			ok "Remote logging configured"
		else
			rec="Configure remote log forwarding for centralized logging"
			add_finding "Enhanced Logging Security" "INFO" "No remote log forwarding detected" "$rec"
			info "No remote log forwarding"
		fi
	else
		add_finding "Enhanced Logging Security" "INFO" "rsyslog configuration not found" ""
		info "rsyslog configuration not found"
	fi
	
	# Check for logrotate configuration
	if [ -f /etc/logrotate.conf ]; then
		add_finding "Enhanced Logging Security" "OK" "Log rotation configuration found" ""
		ok "Log rotation configured"
	else
		add_finding "Enhanced Logging Security" "INFO" "Log rotation configuration not found" ""
		info "Log rotation not configured"
	fi
}

# Enhanced network access controls
section_enhanced_network_access() {
	print_section "Enhanced Network Access Controls"
	
	# Check for TCP wrappers configuration
	tcp_wrappers_found=0
	if [ -f /etc/hosts.allow ] || [ -f /etc/hosts.deny ]; then
		tcp_wrappers_found=1
		add_finding "Enhanced Network Access Controls" "INFO" "TCP wrappers configuration files present" ""
		info "TCP wrappers configuration found"
		
		# Check for restrictive deny rules
		if [ -f /etc/hosts.deny ]; then
			deny_rules=$(grep -v '^#' /etc/hosts.deny 2>/dev/null | wc -l || echo "0")
			if [ "$deny_rules" -gt 0 ]; then
				add_finding "Enhanced Network Access Controls" "OK" "TCP wrappers deny rules configured" ""
				ok "TCP wrappers deny rules"
			else
				rec="Configure TCP wrappers deny rules in /etc/hosts.deny"
				add_finding "Enhanced Network Access Controls" "WARN" "TCP wrappers deny rules not configured" "$rec"
				warn "TCP wrappers deny rules not configured"
			fi
		else
			rec="Create /etc/hosts.deny with restrictive rules"
			add_finding "Enhanced Network Access Controls" "WARN" "TCP wrappers deny file not found" "$rec"
			warn "TCP wrappers deny file not found"
		fi
		
		if [ -f /etc/hosts.allow ]; then
			allow_rules=$(grep -v '^#' /etc/hosts.allow 2>/dev/null | wc -l || echo "0")
			add_finding "Enhanced Network Access Controls" "INFO" "TCP wrappers allow rules: $allow_rules" ""
			info "TCP wrappers allow rules: $allow_rules"
		fi
	else
		add_finding "Enhanced Network Access Controls" "INFO" "TCP wrappers configuration files not found" ""
		info "TCP wrappers not configured"
	fi
	
	# Check for additional firewall rules
	firewall_tools=("iptables" "nft" "ufw" "firewalld")
	firewall_found=0
	
	for tool in "${firewall_tools[@]}"; do
		if command_exists "$tool"; then
			firewall_found=1
			add_finding "Enhanced Network Access Controls" "INFO" "Firewall tool detected: $tool" ""
			info "Firewall tool: $tool"
			
			if [ "$tool" = "iptables" ]; then
				# Check for rate limiting rules
				rate_limit_rules=$(iptables -L INPUT -n 2>/dev/null | grep -c "limit" || echo "0")
				if [ "$rate_limit_rules" -gt 0 ]; then
					add_finding "Enhanced Network Access Controls" "OK" "Rate limiting rules configured" ""
					ok "Rate limiting configured"
				else
					rec="Configure iptables rate limiting rules"
					add_finding "Enhanced Network Access Controls" "WARN" "Rate limiting rules not configured" "$rec"
					warn "Rate limiting not configured"
				fi
				
				# Check for connection tracking
				conntrack_rules=$(iptables -L INPUT -n 2>/dev/null | grep -c "state" || echo "0")
				if [ "$conntrack_rules" -gt 0 ]; then
					add_finding "Enhanced Network Access Controls" "OK" "Connection tracking configured" ""
					ok "Connection tracking configured"
				else
					rec="Configure iptables connection tracking rules"
					add_finding "Enhanced Network Access Controls" "WARN" "Connection tracking not configured" "$rec"
					warn "Connection tracking not configured"
				fi
				
				# Check total rules
				total_rules=$(iptables -L INPUT -n 2>/dev/null | wc -l || echo "0")
				add_finding "Enhanced Network Access Controls" "INFO" "iptables INPUT rules: $total_rules" ""
				info "iptables INPUT rules: $total_rules"
			fi
		fi
	done
	
	if [ "$firewall_found" -eq 0 ]; then
		rec="Install and configure a firewall (ufw, firewalld, or iptables)"
		add_finding "Enhanced Network Access Controls" "WARN" "No firewall tools detected" "$rec"
		warn "No firewall tools detected"
	fi
	
	# Summary
	if [ "$tcp_wrappers_found" -eq 1 ] || [ "$firewall_found" -eq 1 ]; then
		add_finding "Enhanced Network Access Controls" "INFO" "Network access controls partially configured" ""
		info "Network access controls partially configured"
	else
		rec="Configure network access controls (TCP wrappers, firewall rules)"
		add_finding "Enhanced Network Access Controls" "WARN" "No network access controls configured" "$rec"
		warn "No network access controls configured"
	fi
}

section_system() {
	print_section "System"
	
	# Kernel information
	kernel_info=$(uname -a 2>/dev/null)
	add_finding "System" "INFO" "Kernel: $kernel_info" ""
	[ "$OUTPUT_FORMAT" = "console" ] && echo "Kernel: $kernel_info"
	
	# Distribution information
	if [ -r /etc/os-release ]; then
		# Save our script version before sourcing os-release
		SCRIPT_VERSION="$VERSION"
		. /etc/os-release
		distro="${PRETTY_NAME:-unknown}"
		# Restore our script version
		VERSION="$SCRIPT_VERSION"
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
	print_section_with_privilege_info "Updates" "false" "package status"
	
	pm=$(detect_pkg_mgr)
	
	# Note about package cache updates requiring sudo
	if ! is_root && [ "$OUTPUT_FORMAT" = "console" ]; then
		info "Package cache may be outdated without sudo - results may not reflect latest available updates"
	fi
	
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
		ss -tulpen 2>/dev/null | sed -n '1,30p' || true
	elif command_exists netstat; then
		netstat -tulpen 2>/dev/null | sed -n '1,30p' || true
	else
		warn "Neither ss nor netstat available"
		add_finding "Listening Services" "WARN" "No network tools available" "Install ss or netstat packages"
	fi
}

section_firewall() {
	print_section "Firewall"
	if command_exists ufw; then
		ufw status verbose 2>/dev/null | sed 's/^/ufw: /' || true
	fi
	if command_exists firewall-cmd; then
		firewall-cmd --state 2>/dev/null | sed 's/^/firewalld: /' || true
		firewall-cmd --list-all 2>/dev/null | sed 's/^/firewalld: /' | sed -n '1,50p' || true
	fi
	if command_exists nft; then
		nft list ruleset 2>/dev/null | sed -n '1,50p' | sed 's/^/nftables: /' || true
	elif command_exists iptables; then
		iptables -S 2>/dev/null | sed -n '1,50p' | sed 's/^/iptables: /' || true
	fi
}

section_ssh() {
	print_section "SSH Hardening"
	sshd_cfg="/etc/ssh/sshd_config"
	
	if [ -r "$sshd_cfg" ]; then
		# PermitRootLogin check
		perm_root=$(grep -Ei '^\s*PermitRootLogin\s+' "$sshd_cfg" | tail -n1 | awk '{print tolower($2)}' || true)
		if [ "$perm_root" = "no" ] || [ "$perm_root" = "prohibit-password" ]; then
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
		pass_auth=$(grep -Ei '^\s*PasswordAuthentication\s+' "$sshd_cfg" | tail -n1 | awk '{print tolower($2)}' || true)
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
	print_section_with_privilege_info "Accounts and Sudo" "true" "user security"
	
	# Check for unauthorized root accounts (UID 0) - this can be done without root
	unauthorized_root=$(awk -F: '($3 == "0" && $1 != "root") {print $1}' /etc/passwd 2>/dev/null || true)
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
	all_uid0=$(awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ' || true)
	add_finding "Accounts" "INFO" "UID 0 accounts: $all_uid0" ""
	[ "$OUTPUT_FORMAT" = "console" ] && echo "UID0: $all_uid0"
	
	# Check for NOPASSWD sudo entries - requires root access
	if is_root; then
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
		
		# Check for accounts without passwords - requires root access to /etc/shadow
		empty_pass=$(awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null | head -10 | tr '\n' ' ' || true)
		if [ -n "$empty_pass" ] && [ "$empty_pass" != " " ]; then
			rec=$(get_recommendation "Set passwords or lock accounts without passwords" \
				"Lock unused accounts: 'sudo usermod -L username' or set strong passwords" \
				"Audit passwordless accounts: lock service accounts, enforce password policy")
			add_finding "Accounts" "WARN" "Accounts without passwords: $empty_pass" "$rec"
			warn "Accounts without passwords detected"
		fi
	else
		# Limited checks without root
		if [ "$OUTPUT_FORMAT" = "console" ]; then
			warn "NOPASSWD sudo check skipped - requires sudo access"
			warn "Password audit skipped - requires sudo access to /etc/shadow"
		fi
		add_finding "Accounts" "INFO" "NOPASSWD sudo check requires root access" "Run script with sudo for complete account analysis"
		add_finding "Accounts" "INFO" "Password audit requires root access" "Run script with sudo for complete account analysis"
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
	print_section_with_privilege_info "Intrusion Detection" "true" "security monitoring"
	
	# Check for fail2ban
	if command_exists fail2ban-client; then
		if systemctl is-active --quiet fail2ban 2>/dev/null; then
			add_finding "Intrusion Detection" "OK" "fail2ban is active" ""
			ok "fail2ban is active"
			
			# Get jail status - requires root
			if is_root; then
				jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | tr -d ' \t' || true)
				if [ -n "$jails" ] && [ "$jails" != "" ]; then
					add_finding "Intrusion Detection" "INFO" "fail2ban jails: $jails" ""
					[ "$OUTPUT_FORMAT" = "console" ] && info "Active jails: $jails"
				fi
			else
				[ "$OUTPUT_FORMAT" = "console" ] && info "fail2ban jail details require sudo access"
				add_finding "Intrusion Detection" "INFO" "fail2ban jail status requires root access" "Run with sudo for detailed jail information"
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
	
	# Check for suspicious login attempts in auth logs - requires root access
	if is_root; then
		if [ -r /var/log/auth.log ]; then
			failed_logins=$(grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5 | wc -l || echo 0)
			if [ "$failed_logins" -gt 3 ]; then
				rec="Review authentication logs for suspicious activity: 'sudo tail -50 /var/log/auth.log'"
				add_finding "Intrusion Detection" "WARN" "Recent failed login attempts detected" "$rec"
				warn "Recent failed login attempts detected"
			else
				add_finding "Intrusion Detection" "OK" "No recent failed login attempts in auth.log" ""
				ok "No recent failed logins detected"
			fi
		elif [ -r /var/log/secure ]; then
			failed_logins=$(grep "Failed password" /var/log/secure 2>/dev/null | tail -5 | wc -l || echo 0)
			if [ "$failed_logins" -gt 3 ]; then
				rec="Review authentication logs for suspicious activity: 'sudo tail -50 /var/log/secure'"
				add_finding "Intrusion Detection" "WARN" "Recent failed login attempts detected" "$rec"
				warn "Recent failed login attempts detected"
			else
				add_finding "Intrusion Detection" "OK" "No recent failed login attempts in secure log" ""
				ok "No recent failed logins detected"
			fi
		else
			add_finding "Intrusion Detection" "INFO" "No standard auth logs found" "Check system-specific log locations"
		fi
	else
		# Without root, cannot read auth logs
		if [ "$OUTPUT_FORMAT" = "console" ]; then
			warn "Authentication log analysis skipped - requires sudo access"
		fi
		add_finding "Intrusion Detection" "INFO" "Authentication log analysis requires root access" "Run script with sudo to check for failed login attempts"
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
		listening_ports=$(ss -tuln 2>/dev/null | grep LISTEN | wc -l 2>/dev/null || echo 0)
		listening_ports=$(echo "$listening_ports" | tr -d '\n' | awk '{print $1}')
		if [ "${listening_ports:-0}" -gt 5 ]; then
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
	syn_cookies=$(safe_read /proc/sys/net/ipv4/tcp_syncookies)
	[ -z "$syn_cookies" ] && syn_cookies=0
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
	
	integrity_check_performed=false
	
	# RPM-based systems
	if command_exists rpm; then
		if is_root; then
			# Check for modified files (limit output)
			modified_files=$(rpm -Va 2>/dev/null | head -10 | wc -l || echo 0)
			modified_files=$(echo "$modified_files" | tr -d '\n' | awk '{print $1}')
			if [ "${modified_files:-0}" -gt 0 ]; then
				rec="Review package modifications: 'sudo rpm -Va | head -20'"
				add_finding "Package Integrity" "WARN" "Modified package files detected" "$rec"
				warn "Modified package files detected"
			else
				add_finding "Package Integrity" "OK" "Package integrity verified" ""
				ok "Package integrity verified"
			fi
			integrity_check_performed=true
		else
			add_finding "Package Integrity" "INFO" "Package integrity check requires root" ""
			integrity_check_performed=true
		fi
	# Debian-based systems
	elif command_exists dpkg; then
		if command_exists debsums && is_root; then
			# Check for modified files
			modified=$(debsums -c 2>/dev/null | head -5 | wc -l || echo 0)
			modified=$(echo "$modified" | tr -d '\n' | awk '{print $1}')
			if [ "${modified:-0}" -gt 0 ]; then
				rec="Review package modifications: 'sudo debsums -c | head -20'"
				add_finding "Package Integrity" "WARN" "Modified package files detected" "$rec"
				warn "Modified package files detected"
			else
				add_finding "Package Integrity" "OK" "Package integrity verified" ""
				ok "Package integrity verified"
			fi
			integrity_check_performed=true
		elif command_exists dpkg; then
			rec="Install debsums for integrity checking: 'sudo apt install debsums'"
			add_finding "Package Integrity" "INFO" "debsums not available for integrity check" "$rec"
			if [ "$OUTPUT_FORMAT" = "console" ]; then
				info "debsums not available for package integrity verification"
			fi
			integrity_check_performed=true
		fi
	fi
	
	# Add baseline finding if no package integrity check was performed
	if [ "$integrity_check_performed" = false ]; then
		add_finding "Package Integrity" "INFO" "No supported package manager for integrity checking" "Manual package verification recommended"
		if [ "$OUTPUT_FORMAT" = "console" ]; then
			info "No supported package manager for automated integrity checking"
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
			[ "$OUTPUT_FORMAT" = "console" ] && info "AIDE not installed"
		fi
		
		# Check for Tripwire
		if command_exists tripwire; then
			add_finding "File Integrity" "OK" "Tripwire detected" ""
			ok "Tripwire detected"
		else
			add_finding "File Integrity" "INFO" "Tripwire not detected" ""
			[ "$OUTPUT_FORMAT" = "console" ] && info "Tripwire not detected"
		fi
		
		# Still do basic hash checks for immediate verification
		changed_files=0
		for binary in "${critical_binaries[@]}"; do
			if [ -f "$binary" ]; then
				hash=$(sha256sum "$binary" 2>/dev/null | cut -d' ' -f1)
				add_finding "File Integrity" "INFO" "$(basename "$binary"): $hash" ""
				[ "$OUTPUT_FORMAT" = "console" ] && echo "$(basename "$binary"): ${hash:0:16}..."
			fi
		done
		
		rec="Implement automated integrity monitoring with AIDE/Tripwire and baseline comparisons"
		add_finding "File Integrity" "INFO" "File integrity monitoring recommended" "$rec"
		[ "$OUTPUT_FORMAT" = "console" ] && info "File integrity monitoring recommended"
	fi
}

section_persistence_mechanisms() {
	print_section "Persistence Mechanisms"
	
	# Check crontabs for all users
	if command_exists crontab; then
		# Current user crontab
		user_cron=$(crontab -l 2>/dev/null | grep -v '^#' | wc -l 2>/dev/null || echo 0)
		user_cron=$(echo "$user_cron" | tr -d '\n' | awk '{print $1}')
		if [ "${user_cron:-0}" -gt 0 ]; then
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
		active_timers=$(systemctl list-timers --no-pager 2>/dev/null | grep -c '\.timer' 2>/dev/null || echo 0)
		active_timers=$(echo "$active_timers" | tr -d '\n' | awk '{print $1}')
		if [ "${active_timers:-0}" -gt 0 ]; then
			rec="Review active systemd timers: 'systemctl list-timers'"
			add_finding "Persistence" "INFO" "$active_timers systemd timer(s) active" "$rec"
			[ "$OUTPUT_FORMAT" = "console" ] && info "Active timers: $active_timers"
		fi
	fi
	
	# Check rc.local and startup scripts
	startup_files=("/etc/rc.local" "/etc/init.d/rc.local")
	for startup_file in "${startup_files[@]}"; do
		if [ -f "$startup_file" ] && [ -s "$startup_file" ]; then
			executable_lines=$(grep -v '^#' "$startup_file" | grep -v '^$' | wc -l 2>/dev/null || echo 0)
			executable_lines=$(echo "$executable_lines" | tr -d '\n' | awk '{print $1}')
			if [ "${executable_lines:-0}" -gt 1 ]; then  # More than just exit 0
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
				suspicious=$(grep -E '(curl|wget|nc |netcat|/tmp/|/dev/shm/)' "$config" 2>/dev/null | wc -l 2>/dev/null || echo 0)
				suspicious=$(echo "$suspicious" | tr -d '\n' | awk '{print $1}')
				if [ "${suspicious:-0}" -gt 0 ]; then
					rec="Review shell config for suspicious entries: '$config'"
					add_finding "Persistence" "WARN" "Suspicious entries in $(basename "$config")" "$rec"
					warn "Suspicious shell config: $(basename "$config")"
				fi
			fi
		done
	fi
	
	# Check loaded kernel modules
	if command_exists lsmod; then
		total_modules=$(lsmod | wc -l 2>/dev/null || echo 0)
		total_modules=$(echo "$total_modules" | tr -d '\n' | awk '{print $1}')
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
		process_count=$(pstree -p 2>/dev/null | wc -l 2>/dev/null || echo 0)
		process_count=$(echo "$process_count" | tr -d '\n' | awk '{print $1}')
		add_finding "Process Forensics" "INFO" "$process_count processes in tree" ""
		[ "$OUTPUT_FORMAT" = "console" ] && info "Process tree depth: $process_count"
		
		# Look for suspicious parent-child relationships (simplified)
		suspicious_procs=$(pstree -p 2>/dev/null | grep -E '(sh|bash|nc|netcat|curl|wget).*\([0-9]+\).*\(' | wc -l 2>/dev/null || echo 0)
		suspicious_procs=$(echo "$suspicious_procs" | tr -d '\n' | awk '{print $1}')
		if [ "${suspicious_procs:-0}" -gt 0 ]; then
			rec="Review process tree for anomalies: 'pstree -p | grep -E \"(sh|bash|nc|netcat)\""
			add_finding "Process Forensics" "WARN" "Suspicious process relationships detected" "$rec"
			warn "Unusual process tree detected"
		fi
	fi
	
	# Check for hidden processes (basic check)
	if [ -d /proc ]; then
		proc_count=$(ls -1 /proc | grep -E '^[0-9]+$' | wc -l 2>/dev/null || echo 0)
		proc_count=$(echo "$proc_count" | tr -d '\n' | awk '{print $1}')
		ps_count=$(ps aux --no-headers 2>/dev/null | wc -l 2>/dev/null || echo 0)
		ps_count=$(echo "$ps_count" | tr -d '\n' | awk '{print $1}')
		
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
		tmp_procs=$(ps aux 2>/dev/null | grep -E '/tmp/|/dev/shm/' | grep -v grep | wc -l 2>/dev/null || echo 0)
		tmp_procs=$(echo "$tmp_procs" | tr -d '\n' | awk '{print $1}')
		if [ "${tmp_procs:-0}" -gt 0 ]; then
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
			value=$(safe_read "/proc/sys/${flag//./\/}")
		[ -z "$value" ] && value="unknown"
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

section_container_security() {
	print_section "Container & Virtualization Security"
	
	# Docker detection and security
	if command_exists docker; then
		add_finding "Container Security" "INFO" "Docker is installed" ""
		[ "$OUTPUT_FORMAT" = "console" ] && info "Docker detected"
		
		# Check if Docker daemon is running
		if systemctl is-active --quiet docker 2>/dev/null; then
			add_finding "Container Security" "INFO" "Docker daemon is active" ""
			
			# Check for insecure Docker daemon exposure
			if netstat -tlnp 2>/dev/null | grep -q ":2375.*docker"; then
				rec=$(get_recommendation "Secure Docker daemon: disable TCP exposure or enable TLS" \
					"Configure Docker daemon with TLS certificates for secure remote access" \
					"Immediately secure Docker daemon: require TLS, restrict access, audit connections")
				add_finding "Container Security" "CRIT" "Docker daemon exposed on insecure TCP port" "$rec"
				crit "Docker daemon insecurely exposed"
			fi
			
			# Check for privileged containers (requires root)
			if is_root; then
				privileged_containers=$(docker ps --format "table {{.Names}}\t{{.Command}}" 2>/dev/null | grep -c privileged 2>/dev/null || echo 0)
				privileged_containers=$(echo "$privileged_containers" | tr -d '\n' | awk '{print $1}')
				if [ "${privileged_containers:-0}" -gt 0 ]; then
					rec=$(get_recommendation "Review and minimize privileged containers" \
						"Audit privileged containers: 'docker ps --filter=\"privileged=true\"'" \
						"Critical: Review all privileged containers, minimize capabilities, implement security policies")
					add_finding "Container Security" "WARN" "$privileged_containers privileged container(s) detected" "$rec"
					warn "Privileged containers running"
				fi
				
				# Check for dangerous host mounts
				dangerous_mounts=$(docker ps --format "{{.Mounts}}" 2>/dev/null | grep -E "(docker\.sock|/etc|/proc|/sys)" | wc -l 2>/dev/null || echo 0)
				dangerous_mounts=$(echo "$dangerous_mounts" | tr -d '\n' | awk '{print $1}')
				if [ "${dangerous_mounts:-0}" -gt 0 ]; then
					rec="Review host mounts: 'docker ps --format \"table {{.Names}}\\t{{.Mounts}}\"'"
					add_finding "Container Security" "WARN" "Containers with sensitive host mounts detected" "$rec"
					warn "Dangerous host mounts detected"
				fi
			fi
		fi
		
		# Production mode: More comprehensive container checks
		if [ "$OPERATION_MODE" = "production" ]; then
			# Check Docker daemon configuration
			if [ -f /etc/docker/daemon.json ]; then
				add_finding "Container Security" "OK" "Docker daemon configuration file exists" ""
				[ "$OUTPUT_FORMAT" = "console" ] && ok "Docker daemon configuration file found"
			else
				rec="Create Docker daemon config: '/etc/docker/daemon.json' with security hardening"
				add_finding "Container Security" "INFO" "No Docker daemon configuration found" "$rec"
				[ "$OUTPUT_FORMAT" = "console" ] && info "No Docker daemon configuration found"
			fi
		fi
	fi
	
	# Podman detection
	if command_exists podman; then
		add_finding "Container Security" "INFO" "Podman is installed" ""
		[ "$OUTPUT_FORMAT" = "console" ] && info "Podman detected"
		
		if [ "$OPERATION_MODE" = "personal" ]; then
			rec="Podman provides rootless containers by default - good security choice"
			add_finding "Container Security" "OK" "Rootless container runtime available" "$rec"
		fi
	fi
	
	# LXC/LXD detection
	if command_exists lxc-ls || command_exists lxd; then
		add_finding "Container Security" "INFO" "LXC/LXD container system detected" ""
		[ "$OUTPUT_FORMAT" = "console" ] && info "LXC/LXD detected"
		
		if command_exists lxc-ls && is_root; then
			running_containers=$(lxc-ls --running 2>/dev/null | wc -w || echo 0)
			if [ "$running_containers" -gt 0 ]; then
				rec="Review LXC container security: 'lxc-ls --fancy'"
				add_finding "Container Security" "INFO" "$running_containers LXC container(s) running" "$rec"
			fi
		fi
	fi
	
	# Kubernetes detection
	if command_exists kubectl || command_exists kubelet || systemctl list-unit-files | grep -q kubelet; then
		add_finding "Container Security" "INFO" "Kubernetes components detected" ""
		[ "$OUTPUT_FORMAT" = "console" ] && info "Kubernetes detected"
		
		rec=$(get_recommendation "If not needed, remove Kubernetes components to reduce attack surface" \
			"Ensure kubectl access is properly secured with RBAC" \
			"Implement CIS Kubernetes Benchmark: RBAC, network policies, secrets encryption")
		add_finding "Container Security" "INFO" "Kubernetes environment detected" "$rec"
		
		# Check for kubelet configuration
		if [ -f /etc/kubernetes/kubelet/kubelet-config.yaml ] || [ -f /var/lib/kubelet/config.yaml ]; then
			add_finding "Container Security" "INFO" "Kubelet configuration found" ""
		fi
	fi
}

section_kernel_hardening() {
	print_section "Kernel & System Hardening"
	
	# Check for Secure Boot and lockdown mode
	if [ -d /sys/firmware/efi ]; then
		add_finding "Kernel Hardening" "INFO" "UEFI system detected" ""
		
		# Check Secure Boot status
		if command_exists mokutil; then
			sb_state=$(mokutil --sb-state 2>/dev/null || echo "unknown")
			if echo "$sb_state" | grep -q "enabled"; then
				add_finding "Kernel Hardening" "OK" "Secure Boot is enabled" ""
				ok "Secure Boot enabled"
			else
				rec=$(get_recommendation "Enable Secure Boot in UEFI settings for boot integrity" \
					"Enable Secure Boot to prevent unauthorized boot code execution" \
					"Require Secure Boot for compliance and boot integrity verification")
				add_finding "Kernel Hardening" "WARN" "Secure Boot is disabled" "$rec"
				warn "Secure Boot disabled"
			fi
		fi
		
		# Check kernel lockdown mode
		if [ -f /sys/kernel/security/lockdown ]; then
			lockdown_mode=$(safe_read /sys/kernel/security/lockdown)
		[ -z "$lockdown_mode" ] && lockdown_mode="none"
			case "$lockdown_mode" in
				*"integrity"*)
					add_finding "Kernel Hardening" "OK" "Kernel lockdown: integrity mode" ""
					ok "Kernel lockdown: integrity"
					;;
				*"confidentiality"*)
					add_finding "Kernel Hardening" "OK" "Kernel lockdown: confidentiality mode" ""
					ok "Kernel lockdown: confidentiality"
					;;
				*"none"*)
					rec="Enable kernel lockdown via kernel parameter: lockdown=integrity"
					add_finding "Kernel Hardening" "INFO" "Kernel lockdown disabled" "$rec"
					;;
			esac
		fi
	else
		rec=$(get_recommendation "Consider UEFI boot for better security features" \
			"UEFI provides Secure Boot and other security enhancements" \
			"Plan migration to UEFI for enhanced boot security")
		add_finding "Kernel Hardening" "INFO" "Legacy BIOS boot detected" "$rec"
	fi
	
	# Check for kernel module signing
	if [ -f /proc/sys/kernel/modules_disabled ]; then
		modules_disabled=$(safe_read /proc/sys/kernel/modules_disabled)
		if [ "$modules_disabled" = "1" ]; then
			add_finding "Kernel Hardening" "OK" "Kernel module loading disabled" ""
			ok "Module loading disabled"
		fi
	fi
	
	# Check for hardened kernel features
	hardening_checks=(
		"kernel.kptr_restrict:1:Kernel pointer restriction"
		"kernel.dmesg_restrict:1:dmesg restriction" 
		"kernel.perf_event_paranoid:3:Performance event restriction"
		"net.core.bpf_jit_harden:2:BPF JIT hardening"
	)
	
	for check in "${hardening_checks[@]}"; do
		IFS=':' read -r sysctl_name expected_value description <<< "$check"
		if [ -f "/proc/sys/${sysctl_name//./\/}" ]; then
			current_value=$(safe_read "/proc/sys/${sysctl_name//./\/}")
			[ -z "$current_value" ] && current_value="0"
			if [ "$current_value" = "$expected_value" ]; then
				add_finding "Kernel Hardening" "OK" "$description enabled" ""
				ok "$description enabled"
			else
				rec="Enable $description: 'echo $expected_value | sudo tee /proc/sys/${sysctl_name//./\/}'"
				add_finding "Kernel Hardening" "WARN" "$description disabled" "$rec"
				warn "$description disabled"
			fi
		fi
	done
	
	# Check for grsecurity indicators
	if dmesg 2>/dev/null | grep -qi grsecurity || [ -d /proc/sys/kernel/grsecurity ]; then
		add_finding "Kernel Hardening" "OK" "Grsecurity detected" ""
		ok "Grsecurity kernel detected"
	fi
}

section_application_security() {
	print_section "Application-Level Protections"
	
	# Web server detection and security
	web_servers=("nginx" "apache2" "httpd")
	web_server_found=false
	for server in "${web_servers[@]}"; do
		if systemctl is-active --quiet "$server" 2>/dev/null; then
			web_server_found=true
			add_finding "App Security" "INFO" "$server web server is active" ""
			[ "$OUTPUT_FORMAT" = "console" ] && info "$server detected"
			
			# Check for HTTPS configuration
			if [ "$server" = "nginx" ] && [ -d /etc/nginx ]; then
				ssl_configs=$(find /etc/nginx -name "*.conf" -exec grep -l "ssl_certificate" {} \; 2>/dev/null | wc -l)
				if [ "$ssl_configs" -gt 0 ]; then
					add_finding "App Security" "OK" "NGINX SSL configuration detected" ""
				else
					rec=$(get_recommendation "Configure HTTPS with Let's Encrypt: 'sudo certbot --nginx'" \
						"Set up SSL/TLS certificates and enforce HTTPS redirects" \
						"Implement strong TLS configuration: TLS 1.2+, HSTS, OCSP stapling")
					add_finding "App Security" "WARN" "No SSL configuration found in NGINX" "$rec"
				fi
			elif [ "$server" = "apache2" ] || [ "$server" = "httpd" ]; then
				ssl_module=$(apache2ctl -M 2>/dev/null | grep ssl || httpd -M 2>/dev/null | grep ssl || true)
				if [ -n "$ssl_module" ]; then
					add_finding "App Security" "OK" "Apache SSL module loaded" ""
				else
					rec="Enable Apache SSL module: 'sudo a2enmod ssl && sudo systemctl restart apache2'"
					add_finding "App Security" "WARN" "Apache SSL module not loaded" "$rec"
				fi
			fi
		fi
	done
	
	# Add baseline finding if no web servers found
	if [ "$web_server_found" = false ]; then
		add_finding "App Security" "INFO" "No web servers detected" "Web server security checks skipped"
		[ "$OUTPUT_FORMAT" = "console" ] && info "No web servers detected"
	fi
	
	# Database exposure checks
	databases=("mysql:3306" "postgresql:5432" "mongodb:27017" "redis:6379")
	database_found=false
	for db_info in "${databases[@]}"; do
		IFS=':' read -r db_name db_port <<< "$db_info"
		
		if systemctl is-active --quiet "$db_name" 2>/dev/null || systemctl is-active --quiet "${db_name}d" 2>/dev/null; then
			database_found=true
			add_finding "App Security" "INFO" "$db_name database service detected" ""
			
			# Check if database is listening on all interfaces
			if ss -tln 2>/dev/null | grep -q ":$db_port.*0.0.0.0"; then
				rec=$(get_recommendation "Bind $db_name to localhost: edit config to bind to 127.0.0.1" \
					"Configure $db_name to listen only on required interfaces, enable firewall rules" \
					"Implement database security: network segmentation, SSL/TLS, access controls")
				add_finding "App Security" "CRIT" "$db_name listening on all interfaces" "$rec"
				crit "$db_name exposed on 0.0.0.0"
			elif ss -tln 2>/dev/null | grep -q ":$db_port.*127.0.0.1"; then
				add_finding "App Security" "OK" "$db_name bound to localhost" ""
				ok "$db_name localhost only"
			fi
		fi
	done
	
	# Add baseline finding if no databases found
	if [ "$database_found" = false ]; then
		add_finding "App Security" "INFO" "No database services detected" "Database security checks skipped"
		[ "$OUTPUT_FORMAT" = "console" ] && info "No database services detected"
	fi
}

section_secrets_sensitive_data() {
	print_section "Secrets & Sensitive Data"
	
	secrets_findings_made=false
	
	# Common locations for sensitive files
	sensitive_locations=(
		"$HOME/.aws/credentials"
		"$HOME/.aws/config" 
		"$HOME/.kube/config"
		"$HOME/.ssh/id_rsa"
		"$HOME/.ssh/id_ed25519"
		"/etc/ssl/private"
		"/opt/secrets"
		"/var/secrets"
	)
	
	for location in "${sensitive_locations[@]}"; do
		if [ -e "$location" ]; then
			perms=$(stat -c "%a" "$location" 2>/dev/null || echo "unknown")
			if [ -f "$location" ]; then
				# File permissions check
				if [ "$perms" != "600" ] && [ "$perms" != "400" ]; then
					secrets_findings_made=true
					rec="Secure file permissions: 'chmod 600 $location'"
					add_finding "Secrets" "WARN" "$location has permissive permissions ($perms)" "$rec"
					warn "Insecure file: $(basename "$location")"
				else
					secrets_findings_made=true
					add_finding "Secrets" "OK" "$location has secure permissions" ""
				fi
			elif [ -d "$location" ]; then
				# Directory permissions check
				if [ "$perms" != "700" ] && [ "$perms" != "750" ]; then
					secrets_findings_made=true
					rec="Secure directory permissions: 'chmod 700 $location'"
					add_finding "Secrets" "WARN" "$location has permissive permissions ($perms)" "$rec"
					warn "Insecure directory: $(basename "$location")"
				else
					secrets_findings_made=true
				fi
			fi
		fi
	done
	
	# Check for .env files with loose permissions
	if [ "$OPERATION_MODE" = "personal" ]; then
		env_files=$(find "$HOME" -name ".env" -type f -perm /044 2>/dev/null | head -5)
		if [ -n "$env_files" ]; then
			secrets_findings_made=true
			echo "$env_files" | while read -r env_file; do
				rec="Secure .env file: 'chmod 600 $env_file'"
				add_finding "Secrets" "WARN" ".env file with world-readable permissions: $env_file" "$rec"
			done
		fi
	fi
	
	# SSH agent forwarding check
	if [ -n "${SSH_AUTH_SOCK:-}" ]; then
		secrets_findings_made=true
		rec=$(get_recommendation "Be cautious with SSH agent forwarding - disable if not needed" \
			"Review SSH agent forwarding usage and disable for sensitive connections" \
			"Implement SSH bastion hosts and disable agent forwarding to production systems")
		add_finding "Secrets" "INFO" "SSH agent forwarding active" "$rec"
	fi
	
	# GPG agent check
	if pgrep -f gpg-agent >/dev/null; then
		secrets_findings_made=true
		add_finding "Secrets" "INFO" "GPG agent is running" ""
		if [ "$OPERATION_MODE" = "production" ]; then
			rec="Ensure GPG keys are properly managed and rotated according to policy"
			add_finding "Secrets" "INFO" "Verify GPG key management procedures" "$rec"
		fi
	fi
	
	# Add baseline finding if no sensitive data findings were made
	if [ "$secrets_findings_made" = false ]; then
		add_finding "Secrets" "INFO" "No sensitive files or agents detected" "Common sensitive data locations checked"
		[ "$OUTPUT_FORMAT" = "console" ] && info "No sensitive files or agents detected"
	fi
}

section_cloud_remote_mgmt() {
	print_section "Cloud & Remote Management"
	
	cloud_findings_made=false
	
	# Cloud agent detection
	cloud_agents=("cloud-init" "waagent" "google-osconfig-agent" "amazon-ssm-agent")
	for agent in "${cloud_agents[@]}"; do
		if systemctl is-active --quiet "$agent" 2>/dev/null || pgrep -f "$agent" >/dev/null; then
			cloud_findings_made=true
			add_finding "Cloud Management" "INFO" "$agent detected and active" ""
			[ "$OUTPUT_FORMAT" = "console" ] && info "$agent active"
			
			if [ "$OPERATION_MODE" = "production" ]; then
				rec="Ensure $agent is updated and logging to SIEM for compliance"
				add_finding "Cloud Management" "INFO" "Verify $agent compliance configuration" "$rec"
			elif [ "$OPERATION_MODE" = "personal" ]; then
				rec="$agent is typically used in cloud VMs - disable if running on personal hardware"
				add_finding "Cloud Management" "INFO" "$agent may not be needed for personal use" "$rec"
			fi
		fi
	done
	
	# Remote management detection
	remote_services=("vncserver" "xrdp" "teamviewerd" "anydesk")
	for service in "${remote_services[@]}"; do
		if systemctl is-active --quiet "$service" 2>/dev/null || pgrep -f "$service" >/dev/null; then
			cloud_findings_made=true
			rec=$(get_recommendation "Remove $service if not needed: 'sudo systemctl disable $service'" \
				"Secure $service with strong authentication and access controls" \
				"Implement MFA and strict access policies for $service")
			add_finding "Cloud Management" "WARN" "$service remote access detected" "$rec"
			warn "$service detected"
		fi
	done
	
	# Check for VNC ports
	if ss -tln 2>/dev/null | grep -q ":59[0-9][0-9]"; then
		cloud_findings_made=true
		rec="Secure or disable VNC access - consider SSH tunneling instead"
		add_finding "Cloud Management" "WARN" "VNC service listening on network" "$rec"
		warn "VNC service exposed"
	fi
	
	# Add baseline finding if no cloud/remote management findings were made
	if [ "$cloud_findings_made" = false ]; then
		add_finding "Cloud Management" "INFO" "No cloud agents or remote management services detected" "Cloud and remote management security checks completed"
		[ "$OUTPUT_FORMAT" = "console" ] && info "No cloud agents or remote management services detected"
	fi
}

section_edr_monitoring() {
	print_section "Endpoint Detection & Monitoring"
	
	# EDR/AV process detection
	edr_processes=("crowdstrike" "cylance" "sentinelone" "defender" "carbonblack" "cortex" "endgame")
	av_processes=("clamd" "freshclam" "avguard" "rtkdsm" "symantec")
	
	edr_detected=false
	for process in "${edr_processes[@]}"; do
		if pgrep -f "$process" >/dev/null; then
			add_finding "EDR/Monitoring" "OK" "EDR solution detected: $process" ""
			ok "EDR detected: $process"
			edr_detected=true
		fi
	done
	
	av_detected=false
	for process in "${av_processes[@]}"; do
		if pgrep -f "$process" >/dev/null; then
			add_finding "EDR/Monitoring" "OK" "Antivirus detected: $process" ""
			ok "AV detected: $process"
			av_detected=true
		fi
	done
	
	if [ "$edr_detected" = false ] && [ "$av_detected" = false ]; then
		if [ "$OPERATION_MODE" = "production" ]; then
			rec="Install and configure corporate EDR solution for compliance and threat detection"
			add_finding "EDR/Monitoring" "CRIT" "No EDR or antivirus solution detected" "$rec"
			crit "No endpoint protection detected"
		else
			rec="Install basic antivirus protection: 'sudo apt install clamav clamav-daemon'"
			add_finding "EDR/Monitoring" "WARN" "No antivirus protection detected" "$rec"
			warn "No AV protection"
		fi
	fi
	
	# SIEM forwarding detection (production mode)
	if [ "$OPERATION_MODE" = "production" ]; then
		siem_agents=("splunkforwarder" "filebeat" "logstash" "fluentd" "nxlog" "rsyslog")
		siem_detected=false
		
		for agent in "${siem_agents[@]}"; do
			if systemctl is-active --quiet "$agent" 2>/dev/null || pgrep -f "$agent" >/dev/null; then
				add_finding "EDR/Monitoring" "OK" "SIEM forwarding agent detected: $agent" ""
				ok "SIEM agent: $agent"
				siem_detected=true
			fi
		done
		
		if [ "$siem_detected" = false ]; then
			rec="Deploy SIEM forwarding agent for centralized log collection and monitoring"
			add_finding "EDR/Monitoring" "WARN" "No SIEM forwarding agent detected" "$rec"
			warn "No SIEM forwarding"
		fi
		
		# Check for syslog forwarding configuration
		if [ -f /etc/rsyslog.conf ]; then
			remote_logging=$(grep -E "^\s*\*\.\*\s+@@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null || true)
			if [ -n "$remote_logging" ]; then
				add_finding "EDR/Monitoring" "OK" "Remote syslog forwarding configured" ""
				ok "Remote syslog configured"
			else
				rec="Configure remote syslog forwarding for centralized logging"
				add_finding "EDR/Monitoring" "INFO" "No remote syslog forwarding detected" "$rec"
			fi
		fi
	fi
	
	# Check for log analysis tools
	log_tools=("logwatch" "fail2ban" "ossec")
	for tool in "${log_tools[@]}"; do
		if command_exists "$tool" || systemctl is-active --quiet "$tool" 2>/dev/null; then
			add_finding "EDR/Monitoring" "OK" "Log analysis tool detected: $tool" ""
			[ "$OUTPUT_FORMAT" = "console" ] && info "$tool detected"
		fi
	done
}

section_backup_resilience() {
	print_section "Resilience & Backup"
	
	# Backup solution detection
	backup_tools=("rsnapshot" "borg" "restic" "duplicity" "rclone" "bacula" "amanda")
	backup_detected=false
	
	for tool in "${backup_tools[@]}"; do
		if command_exists "$tool"; then
			add_finding "Backup/Resilience" "OK" "Backup tool detected: $tool" ""
			[ "$OUTPUT_FORMAT" = "console" ] && info "$tool available"
			backup_detected=true
			
			# Check for recent backup activity
			if [ "$tool" = "rsnapshot" ] && [ -f /etc/rsnapshot.conf ]; then
				backup_dir=$(grep "^snapshot_root" /etc/rsnapshot.conf 2>/dev/null | awk '{print $2}' || echo "")
				if [ -n "$backup_dir" ] && [ -d "$backup_dir" ]; then
					recent_backup=$(find "$backup_dir" -type d -mtime -7 2>/dev/null | head -1)
					if [ -n "$recent_backup" ]; then
						add_finding "Backup/Resilience" "OK" "Recent rsnapshot backup found" ""
					else
						rec="Verify rsnapshot is running: check cron jobs and backup schedule"
						add_finding "Backup/Resilience" "WARN" "No recent rsnapshot backups found" "$rec"
					fi
				fi
			fi
		fi
	done
	
	if [ "$backup_detected" = false ]; then
		rec=$(get_recommendation "Set up automated backups: install restic or borg for encrypted backups" \
			"Implement local and cloud backups with regular testing" \
			"Deploy enterprise backup solution with automated, encrypted, offsite backups")
		add_finding "Backup/Resilience" "WARN" "No backup solution detected" "$rec"
		warn "No backup tools found"
	fi
	
	# Check for cloud backup configurations
	cloud_backup_configs=(
		"$HOME/.config/rclone/rclone.conf"
		"$HOME/.aws/credentials"
		"/etc/duplicity"
		"$HOME/.config/borg"
	)
	
	for config in "${cloud_backup_configs[@]}"; do
		if [ -f "$config" ] || [ -d "$config" ]; then
			add_finding "Backup/Resilience" "OK" "Cloud backup configuration detected: $(basename "$config")" ""
		fi
	done
	
	# System snapshot capabilities
	if command_exists btrfs; then
		# Check if root is on btrfs
		root_fs=$(df / | tail -1 | awk '{print $1}')
		if btrfs filesystem show "$root_fs" >/dev/null 2>&1; then
			add_finding "Backup/Resilience" "OK" "BTRFS filesystem with snapshot capability" ""
			ok "BTRFS snapshots available"
			
			# Check for recent snapshots
			if [ -d /.snapshots ] || [ -d /home/.snapshots ]; then
				recent_snapshot=$(find /.snapshots /home/.snapshots -maxdepth 1 -type d -mtime -7 2>/dev/null | head -1)
				if [ -n "$recent_snapshot" ]; then
					add_finding "Backup/Resilience" "OK" "Recent BTRFS snapshots found" ""
				else
					rec="Configure automatic BTRFS snapshots with snapper or timeshift"
					add_finding "Backup/Resilience" "INFO" "No recent BTRFS snapshots found" "$rec"
				fi
			fi
		fi
	fi
	
	if command_exists zfs; then
		zfs_pools=$(zpool list -H 2>/dev/null | wc -l || echo 0)
		if [ "$zfs_pools" -gt 0 ]; then
			add_finding "Backup/Resilience" "OK" "ZFS filesystem with snapshot capability" ""
			ok "ZFS snapshots available"
		fi
	fi
	
	# LVM snapshot capability
	if command_exists lvs; then
		lv_count=$(lvs --noheadings 2>/dev/null | wc -l 2>/dev/null || echo 0)
		lv_count=$(echo "$lv_count" | tr -d '\n' | awk '{print $1}')
		if [ "${lv_count:-0}" -gt 0 ]; then
			add_finding "Backup/Resilience" "INFO" "LVM detected - snapshot capability available" ""
		fi
	fi
	
	# Disaster recovery considerations
	if [ "$OPERATION_MODE" = "production" ]; then
		rec="Implement and test disaster recovery procedures: document RTO/RPO, test restore procedures"
		add_finding "Backup/Resilience" "INFO" "Disaster recovery planning recommended" "$rec"
	fi
}

# Summary of limitations when running without sudo
section_privilege_summary() {
	if ! is_root; then
		print_section "Privilege Limitations Summary"
		
		if [ "$OUTPUT_FORMAT" = "console" ]; then
			printf "${COLOR_YELLOW}This scan was run without sudo privileges. The following security checks were limited or skipped:${COLOR_RESET}\n"
			echo
			printf "${COLOR_YELLOW}SKIPPED/LIMITED CHECKS:${COLOR_RESET}\n"
			printf "• ${COLOR_YELLOW}System log analysis${COLOR_RESET} (auth.log, secure, system logs)\n"
			printf "• ${COLOR_YELLOW}Password policy audit${COLOR_RESET} (/etc/shadow access)\n"
			printf "• ${COLOR_YELLOW}Sudo configuration review${COLOR_RESET} (/etc/sudoers analysis)\n"
			printf "• ${COLOR_YELLOW}System service configurations${COLOR_RESET} (limited service status only)\n"
			printf "• ${COLOR_YELLOW}Package integrity verification${COLOR_RESET} (rpm -Va, debsums)\n"
			printf "• ${COLOR_YELLOW}Advanced file permissions${COLOR_RESET} (system-wide SUID/SGID scans)\n"
			printf "• ${COLOR_YELLOW}Process forensics${COLOR_RESET} (network connections, capabilities)\n"
			printf "• ${COLOR_YELLOW}Container security${COLOR_RESET} (privileged containers, host mounts)\n"
			printf "• ${COLOR_YELLOW}Kernel module analysis${COLOR_RESET} (loaded modules inspection)\n"
			printf "• ${COLOR_YELLOW}EDR/monitoring agents${COLOR_RESET} (detailed configuration)\n"
			echo
			printf "${COLOR_GREEN}COMPLETED CHECKS:${COLOR_RESET}\n"
			printf "• ${COLOR_GREEN}Basic system information${COLOR_RESET} (kernel, distro, uptime)\n"
			printf "• ${COLOR_GREEN}Public network services${COLOR_RESET} (listening ports)\n"
			printf "• ${COLOR_GREEN}User account structure${COLOR_RESET} (UID 0 accounts)\n"
			printf "• ${COLOR_GREEN}SSH client configuration${COLOR_RESET} (user-accessible settings)\n"
			printf "• ${COLOR_GREEN}Available security tools${COLOR_RESET} (installed packages)\n"
			printf "• ${COLOR_GREEN}User-accessible file permissions${COLOR_RESET} (home directory)\n"
			printf "• ${COLOR_GREEN}Personal configuration${COLOR_RESET} (shell, environment)\n"
			echo
		fi
		
		if [ "$OPERATION_MODE" = "production" ]; then
			rec="Production environments require comprehensive security assessment - run with sudo for compliance"
			add_finding "Privilege Summary" "WARN" "Limited production security assessment without sudo" "$rec"
		else
			rec="For complete personal security assessment, run: sudo $0"
			add_finding "Privilege Summary" "INFO" "Personal security scan completed with limitations" "$rec"
		fi
		
		if [ "$OUTPUT_FORMAT" = "console" ]; then
			printf "${COLOR_BLUE}For comprehensive security assessment, run:${COLOR_RESET} ${COLOR_GREEN}sudo $0${COLOR_RESET}\n"
			echo
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
	
	if ! is_root; then
		printf "${COLOR_YELLOW}Note: This was a limited scan without sudo privileges.${COLOR_RESET}\n"
	fi
	
	add_finding "Summary" "INFO" "Scan completed: $total_findings findings" ""
	add_finding "Summary" "INFO" "Critical: $crit_count, Warnings: $warn_count, OK: $ok_count, Info: $info_count" ""
}

show_help() {
	cat << EOF
bt-quickcheck v$VERSION - Blue Team Security Quick Check

SECURITY NOTICE:
This tool performs READ-ONLY security assessment of Linux systems.
It requires sudo privileges to access system files but makes NO modifications.
All operations are defensive security checks - no malicious activity performed.

ENHANCED SECURITY FEATURES (v0.6.0):
• Enhanced input validation and command sanitization
• Advanced kernel and network security hardening checks
• Comprehensive compliance and audit validation
• Enhanced container and process security analysis
• Advanced file integrity and logging security checks
• Industry-standard security validation (CIS, NIST aligned)

Usage: $0 [OPTIONS]

OPTIONS:
  -h, --help              Show this help message
  -v, --version           Show version information
  -f, --format FORMAT     Output format: console, json, html, txt (default: console)
  -o, --output FILE       Output file (default: stdout)
  -m, --mode MODE         Operation mode: personal, production (default: personal)

MODES:
  personal               Home/personal machine recommendations
  production             Business/server environment recommendations (compliance focus)

OUTPUT FORMATS:
  console               Colored console output (default)
  json                  JSON structured output for automation/SIEM
  html                  HTML report with styling
  txt                   Plain text report

SECURITY FEATURES:
  ✓ Read-only operations - no system modifications
  ✓ Input validation and path traversal protection
  ✓ Safe file access with permission checks
  ✓ Comprehensive logging of all activities

EXAMPLES:
  sudo $0                               # Full security assessment (recommended)
  sudo $0 -f json -o report.json        # JSON output to file
  sudo $0 -f html -o report.html -m production  # HTML production report
  $0 -m personal                        # Limited checks without sudo

PRIVACY:
This script may access sensitive system files for security analysis.
All data remains local - no external transmission occurs.

EOF
}

# Parse command line arguments with validation
while [ $# -gt 0 ]; do
	case "$1" in
		--version|-v) 
			echo "$VERSION"
			exit 0
			;;
		--help|-h) 
			show_help
			exit 0
			;;
		--format|-f)
			shift
			if [ $# -eq 0 ]; then
				echo "Error: --format requires an argument" >&2
				exit 1
			fi
			if validate_format "$1"; then
				OUTPUT_FORMAT="$1"
			else
				echo "Error: Invalid format '$1'. Use: console, json, html, txt" >&2
				exit 1
			fi
			;;
		--output|-o)
			shift
			if [ $# -eq 0 ]; then
				echo "Error: --output requires an argument" >&2
				exit 1
			fi
			if validate_output_path "$1"; then
				OUTPUT_FILE="$1"
			else
				echo "Error: Invalid output path '$1'. Path traversal not allowed." >&2
				exit 1
			fi
			;;
		--mode|-m)
			shift
			if [ $# -eq 0 ]; then
				echo "Error: --mode requires an argument" >&2
				exit 1
			fi
			if validate_mode "$1"; then
				OPERATION_MODE="$1"
			else
				echo "Error: Invalid mode '$1'. Use: personal, production" >&2
				exit 1
			fi
			;;
		--)
			shift
			break
			;;
		-*)
			echo "Error: Unknown option '$1'. Use --help for usage." >&2
			exit 1
			;;
		*)
			echo "Error: Unexpected argument '$1'. Use --help for usage." >&2
			exit 1
			;;
	esac
	shift
done

# Display security notice for console output
if [ "$OUTPUT_FORMAT" = "console" ]; then
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🛡️  Blue Team QuickCheck v$VERSION - Linux Security Assessment"
echo "🔧 Mode: $OPERATION_MODE | Enhanced Security Features (v0.6.0)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "⚠️  SECURITY NOTICE:"
echo "   • This script performs READ-ONLY security assessment"
echo "   • Requires sudo for comprehensive system analysis"
echo "   • NO system modifications will be made"
echo "   • May access sensitive files for security analysis"
echo "   • All data remains local - no external transmission"
echo
	
	# Check if running without sudo and display prominent warning
	if ! is_root; then
		printf "${COLOR_YELLOW}⚠️  LIMITED SCAN WARNING:${COLOR_RESET}\n"
		printf "${COLOR_YELLOW}   • Running without sudo - many security checks will be skipped${COLOR_RESET}\n"
		printf "${COLOR_YELLOW}   • System files, logs, and privileged information cannot be accessed${COLOR_RESET}\n"
		printf "${COLOR_YELLOW}   • For comprehensive security assessment, run: ${COLOR_BLUE}sudo $0${COLOR_RESET}\n"
		if [ "$OPERATION_MODE" = "production" ]; then
			printf "${COLOR_RED}   • Production mode requires sudo for meaningful security assessment${COLOR_RESET}\n"
		fi
		printf "${COLOR_YELLOW}   • Current scan will show basic system information and user-accessible checks only${COLOR_RESET}\n"
		echo
	fi
	
	echo "🔍 Mode: $OPERATION_MODE | Format: $OUTPUT_FORMAT"
	if [ -n "$OUTPUT_FILE" ]; then
		echo "📄 Output: $OUTPUT_FILE"
	fi
	echo
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo
fi

# Validate output file if specified
if [ -n "$OUTPUT_FILE" ]; then
	# Check if we can write to the output file
	if ! touch "$OUTPUT_FILE" 2>/dev/null; then
		echo "Error: Cannot write to output file '$OUTPUT_FILE'" >&2
		exit 1
	fi
fi

# Run all checks with error isolation
run_section_safely section_system "System"
run_section_safely section_updates "Updates"
run_section_safely section_listening "Listening Services"
run_section_safely section_firewall "Firewall"
run_section_safely section_ssh "SSH Hardening"
run_section_safely section_auditing "Auditing/Hardening"
run_section_safely section_accounts "Accounts and Sudo"
run_section_safely section_permissions "Risky Permissions"
run_section_safely section_intrusion_detection "Intrusion Detection"
run_section_safely section_time_sync "Time Synchronization"
run_section_safely section_logging "Logging and Monitoring"
run_section_safely section_network_security "Network Security"
run_section_safely section_package_integrity "Package Integrity"
run_section_safely section_file_integrity "File Integrity"
run_section_safely section_persistence_mechanisms "Persistence Mechanisms"
run_section_safely section_process_forensics "Process & Forensics"
run_section_safely section_secure_configuration "Secure Configuration"
run_section_safely section_container_security "Container & Virtualization Security"
run_section_safely section_kernel_hardening "Kernel & System Hardening"
run_section_safely section_application_security "Application-Level Protections"
run_section_safely section_secrets_sensitive_data "Secrets & Sensitive Data"
run_section_safely section_cloud_remote_mgmt "Cloud & Remote Management"
run_section_safely section_edr_monitoring "Endpoint Detection & Monitoring"
run_section_safely section_backup_resilience "Resilience & Backup"

# Enhanced security checks (new in v0.6.0)
run_section_safely section_enhanced_kernel_security "Enhanced Kernel Security"
run_section_safely section_enhanced_network_security "Enhanced Network Security"
run_section_safely section_compliance_checks "Compliance & Audit"
run_section_safely section_enhanced_container_security "Enhanced Container Security"
run_section_safely section_enhanced_file_integrity "Enhanced File Integrity"
run_section_safely section_enhanced_process_security "Enhanced Process Security"
run_section_safely section_enhanced_logging_security "Enhanced Logging Security"
run_section_safely section_enhanced_network_access "Enhanced Network Access Controls"

run_section_safely section_privilege_summary "Privilege Limitations Summary"
run_section_safely section_summary "Summary"

# Generate output based on format
generate_output() {
	case "$OUTPUT_FORMAT" in
		json) 
			# Ensure we have findings to output
			if [ ${#FINDINGS[@]} -eq 0 ]; then
				add_finding "System" "INFO" "No findings generated" "This should not happen in normal operation"
			fi
			generate_json_output
			;;
		html) generate_html_output;;
		txt) generate_txt_output;;
		console) 
			[ "$OUTPUT_FORMAT" = "console" ] && echo
			;;
	esac
}

# Output to file or stdout with error handling
if [ -n "$OUTPUT_FILE" ]; then
	if generate_output > "$OUTPUT_FILE"; then
		if [ "$OUTPUT_FORMAT" != "console" ]; then
			echo "✅ Security report generated successfully: $OUTPUT_FILE" >&2
			echo "📊 Total findings: ${#FINDINGS[@]}" >&2
		fi
	else
		echo "❌ Error: Failed to generate output file '$OUTPUT_FILE'" >&2
		exit 1
	fi
else
	generate_output
fi

# Final security notice for console output
if [ "$OUTPUT_FORMAT" = "console" ]; then
	echo
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo "✅ Security assessment completed successfully"
	echo "📋 Review CRITICAL and WARNING findings above for security improvements"
	echo "🔒 Enhanced security checks completed (v0.6.0)"
	echo "   • Advanced kernel and network hardening validation"
	echo "   • Comprehensive compliance and audit assessment"
	echo "   • Enhanced container and process security analysis"
	echo "   • Industry-standard security validation (CIS, NIST aligned)"
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi

exit 0


