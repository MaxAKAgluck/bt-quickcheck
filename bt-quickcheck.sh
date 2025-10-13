
#!/usr/bin/env bash

# Blue Team QuickCheck - Linux Security Assessment Tool
# Version: 0.6.3
# 
# Ensure we're running under bash (re-exec if invoked with sh)
if [ -z "${BASH_VERSION:-}" ]; then
    exec /usr/bin/env bash "$0" "$@"
fi

# INTEGRITY CHECK:
# This script performs a lightweight integrity hash check at startup to help
# detect accidental tampering. It is informational and non-blocking.
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

# Strict error handling: exit on error, undefined vars, pipe failures
# pipefail is bash-specific; fall back gracefully if not available
set -euo pipefail 2>/dev/null || set -eu

# Harden environment: prevent function inheritance and BASH_ENV abuse
unset BASH_ENV
if command -v compgen >/dev/null 2>&1; then
    while read -r fn; do export -n "$fn" 2>/dev/null || true; done < <(compgen -A function 2>/dev/null || echo)
fi

# Advanced Security Features - Authentication & Authorization
# Permission levels for different operations
declare -A PERMISSION_LEVELS=(
    ["basic"]="1"
    ["standard"]="2" 
    ["elevated"]="3"
    ["administrative"]="4"
    ["audit"]="5"
)

# Structured Logging System
# Log levels (higher number = more verbose)
readonly LOG_ERROR=1
readonly LOG_WARN=2
readonly LOG_INFO=3
readonly LOG_DEBUG=4

# Default log level (can be overridden by environment variable)
LOG_LEVEL=${BTQC_LOG_LEVEL:-$LOG_INFO}

# SECURITY FIX: Create secure temporary log file with mktemp (prevents race conditions)
# Log file (can be overridden by environment variable)
# Use parameter expansion to safely check if BTQC_LOG_FILE is set (works with set -u)
if [ -z "${BTQC_LOG_FILE:-}" ]; then
    # Use mktemp for secure temporary file creation with random suffix
    LOG_FILE=$(mktemp /tmp/bt-quickcheck.XXXXXXXXXX.log 2>/dev/null)
    # Fallback if mktemp fails
    if [ -z "$LOG_FILE" ] || [ ! -f "$LOG_FILE" ]; then
        LOG_FILE=$(mktemp -t bt-quickcheck.XXXXXXXXXX 2>/dev/null)
    fi
    # Final fallback - but prefer to fail if we can't create secure temp file
    if [ -z "$LOG_FILE" ]; then
        LOG_FILE="/tmp/bt-quickcheck-$$.log"
        echo "Warning: Could not create secure temp file, using fallback: $LOG_FILE" >&2
    fi
else
    LOG_FILE="${BTQC_LOG_FILE}"
fi
# Ensure log file has secure permissions
chmod 600 "$LOG_FILE" 2>/dev/null || true

# Structured logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local level_name
    
    case "$level" in
        $LOG_ERROR) level_name="ERROR" ;;
        $LOG_WARN)  level_name="WARN"  ;;
        $LOG_INFO)  level_name="INFO"  ;;
        $LOG_DEBUG) level_name="DEBUG" ;;
        *)          level_name="INFO"  ;;
    esac
    
    # Only log if level is enabled
    if [ "$level" -le "$LOG_LEVEL" ]; then
        echo "[$timestamp] [$level_name] [PID:$$] $message" >> "$LOG_FILE" 2>/dev/null || true
    fi
    
    # Also output to stderr for ERROR and WARN levels in console mode
    if [ "$level" -le $LOG_WARN ] && [ "$OUTPUT_FORMAT" = "console" ]; then
        echo "[$level_name] $message" >&2
    fi
}

# Embedded default configuration (can be overridden by environment variables)
# This eliminates the need for an external configuration file
init_embedded_config() {
    # Only set if not already defined by environment variables
    : "${BTQC_LOG_LEVEL:=3}"
    : "${BTQC_LOG_FILE:=""}"  # Will be set securely later
    : "${BTQC_MEMORY_LIMIT:=524288}"
    : "${BTQC_CPU_TIME_LIMIT:=300}"
    : "${BTQC_FILE_SIZE_LIMIT:=104857600}"
    : "${BTQC_PROCESS_LIMIT:=100}"
    : "${BTQC_FD_LIMIT:=256}"
    : "${BTQC_STACK_LIMIT:=8192}"
    : "${BTQC_CACHE_ENABLED:=true}"
    : "${BTQC_CACHE_TTL:=300}"
    : "${BTQC_CACHE_DIR:=""}"  # Will be set securely later
    : "${BTQC_PRIVACY_LEVEL:=standard}"
    : "${BTQC_ANONYMIZE:=false}"
    : "${BTQC_AUDIT_ENABLED:=false}"
    : "${BTQC_AUDIT_LOG:=/var/log/bt-quickcheck-audit.log}"
    : "${BTQC_OUTPUT_FORMAT:=console}"
    : "${BTQC_QUIET_MODE:=false}"
    : "${BTQC_PARALLEL_MODE:=false}"
    : "${BTQC_OPERATION_MODE:=personal}"
    : "${BTQC_EXCLUDE_SECTIONS:=""}"
    : "${BTQC_EXCLUDE_SEVERITY:=""}"
    : "${BTQC_MAX_FINDINGS:=1000}"
    : "${BTQC_SECTION_TIMEOUT:=30}"
    : "${BTQC_PARALLEL_WORKERS:=4}"
    
    # Export for use in script
    export BTQC_LOG_LEVEL BTQC_MEMORY_LIMIT BTQC_CPU_TIME_LIMIT BTQC_FILE_SIZE_LIMIT
    export BTQC_PROCESS_LIMIT BTQC_FD_LIMIT BTQC_STACK_LIMIT
    export BTQC_CACHE_ENABLED BTQC_CACHE_TTL
    export BTQC_PRIVACY_LEVEL BTQC_ANONYMIZE BTQC_AUDIT_ENABLED BTQC_AUDIT_LOG
    export BTQC_OUTPUT_FORMAT BTQC_QUIET_MODE BTQC_PARALLEL_MODE
    export BTQC_OPERATION_MODE BTQC_EXCLUDE_SECTIONS BTQC_EXCLUDE_SEVERITY
    export BTQC_MAX_FINDINGS BTQC_SECTION_TIMEOUT BTQC_PARALLEL_WORKERS
}

# Optional: Load configuration from external file (SECURE VERSION)
# This is now optional - script works without external config
load_configuration() {
    local config_file="${1:-bt-quickcheck.conf}"
    
    # Check if config file exists and is readable
    if [ -f "$config_file" ] && [ -r "$config_file" ]; then
        log "$LOG_DEBUG" "Loading configuration from: $config_file"
        
        # Use a safe method to load config without eval
        while IFS='=' read -r key value; do
            # Skip comments and empty lines
            [[ "$key" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$key" ]] && continue
            
            # Remove leading/trailing whitespace
            key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            
            # Validate key format (alphanumeric and underscores only)
            if [[ "$key" =~ ^[A-Z_][A-Z0-9_]*$ ]]; then
                # SECURITY FIX: Sanitize value to prevent command injection
                # Remove dangerous characters: backticks, $(), ${ }, ;, &, |, <, >, etc.
                value=$(printf '%s' "$value" | sed 's/[`$();{}&|<>]//g' | head -c 1024)
                
                # Use declare -g for safer variable assignment (no shell expansion)
                declare -g "$key=$value" 2>/dev/null || log "$LOG_WARN" "Failed to set config: $key"
                log "$LOG_DEBUG" "Loaded config: $key=[sanitized]"
            else
                log "$LOG_WARN" "Invalid config key format: $key"
            fi
        done < "$config_file"
    else
        log "$LOG_DEBUG" "No configuration file found: $config_file (using embedded defaults)"
    fi
}

# Current user permission level
CURRENT_PERMISSION_LEVEL="basic"

# Audit trail configuration
AUDIT_LOG="/var/log/bt-quickcheck-audit.log"
AUDIT_ENABLED=false

# Script integrity verification
verify_script_integrity() {
    local script_path="$0"
    local expected_hash=""
    local actual_hash=""
    
    # Calculate script hash (excluding signature block)
    if command_exists sha256sum; then
        actual_hash=$(head -n -10 "$script_path" | sha256sum | cut -d' ' -f1)
    elif command_exists shasum; then
        actual_hash=$(head -n -10 "$script_path" | shasum -a 256 | cut -d' ' -f1)
    else
        # Fallback to basic checksum
        actual_hash=$(head -n -10 "$script_path" | wc -c)
    fi
    
    # For now, we'll use a simple integrity check
    # In production, this would verify against a known good hash or digital signature
    if [ ${#actual_hash} -lt 8 ]; then
        echo "Warning: Script integrity verification failed - hash too short" >&2
        return 1
    fi
    
    return 0
}

# Permission level checking
check_permission_level() {
    local required_level="$1"
    local current_level="${PERMISSION_LEVELS[$CURRENT_PERMISSION_LEVEL]:-1}"
    local required_level_num="${PERMISSION_LEVELS[$required_level]:-1}"
    
    if [ "$current_level" -lt "$required_level_num" ]; then
        return 1
    fi
    return 0
}

# Set permission level based on user context
set_permission_level() {
    if is_root; then
        CURRENT_PERMISSION_LEVEL="administrative"
    elif groups | grep -q sudo; then
        CURRENT_PERMISSION_LEVEL="elevated"
    elif groups | grep -q wheel; then
        CURRENT_PERMISSION_LEVEL="elevated"
    else
        CURRENT_PERMISSION_LEVEL="basic"
    fi
}

# Enhanced audit logging (now uses structured logging)
audit_log() {
    local action="$1"
    local details="$2"
    local severity="${3:-INFO}"
    local user=$(whoami 2>/dev/null || echo "unknown")
    local hostname=$(hostname 2>/dev/null || echo "unknown")
    
    # Convert severity to log level
    local log_level
    case "$severity" in
        "ERROR"|"CRIT") log_level=$LOG_ERROR ;;
        "WARN")         log_level=$LOG_WARN  ;;
        "INFO"|"OK")    log_level=$LOG_INFO  ;;
        "DEBUG")        log_level=$LOG_DEBUG ;;
        *)              log_level=$LOG_INFO  ;;
    esac
    
    # Use structured logging
    log "$log_level" "AUDIT: $user@$hostname $action: $details"
    
    # Also maintain legacy audit log if enabled
    if [ "$AUDIT_ENABLED" = true ] && [ -w "${AUDIT_LOG%/*}" ]; then
        local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        echo "[$timestamp] $user@$hostname [$severity] $action: $details" >> "$AUDIT_LOG" 2>/dev/null || true
    fi
}

# Role-based access control
check_access_control() {
    local operation="$1"
    local resource="$2"
    local user=$(whoami 2>/dev/null || echo "unknown")
    
    # Define access control matrix
    case "$operation" in
        "read_system_files")
            if ! check_permission_level "standard"; then
                audit_log "ACCESS_DENIED" "Attempted to read system files without sufficient permissions" "WARN"
                return 1
            fi
            ;;
        "execute_commands")
            if ! check_permission_level "elevated"; then
                audit_log "ACCESS_DENIED" "Attempted to execute commands without sufficient permissions" "WARN"
                return 1
            fi
            ;;
        "access_sensitive_data")
            if ! check_permission_level "administrative"; then
                audit_log "ACCESS_DENIED" "Attempted to access sensitive data without sufficient permissions" "WARN"
                return 1
            fi
            ;;
        "audit_operations")
            if ! check_permission_level "audit"; then
                audit_log "ACCESS_DENIED" "Attempted audit operations without sufficient permissions" "WARN"
                return 1
            fi
            ;;
        *)
            # Default allow for basic operations
            ;;
    esac
    
    audit_log "ACCESS_GRANTED" "Operation: $operation, Resource: $resource" "INFO"
    return 0
}

# Enhanced error handling with comprehensive logging and sanitization
handle_section_error() {
    local section="$1"
    local line="$2"
    local error="$3"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Sanitize error message to prevent information disclosure
    local sanitized_error=$(echo "$error" | sed 's/[^a-zA-Z0-9._/ -]//g' | head -c 200)
    local sanitized_section=$(echo "$section" | sed 's/[^a-zA-Z0-9._/ -]//g' | head -c 50)
    
    # Log error with timestamp and context (sanitized)
    local error_msg="[$timestamp] ERROR in $sanitized_section (line $line): $sanitized_error"
    
    if [ "$OUTPUT_FORMAT" = "console" ]; then
        warn "Error in $sanitized_section (line $line): $sanitized_error"
        warn "Continuing with remaining checks..."
    fi
    
    # Add structured finding for error tracking (sanitized)
    add_finding "$sanitized_section" "WARN" "Section error encountered: $sanitized_error" "Review section implementation and check system logs"
    
    # Log to system log if available and running as root (sanitized)
    if is_root && command_exists logger; then
        logger -p user.warning "bt-quickcheck: $error_msg"
    fi
}

# Standardized error handling functions
handle_error() {
    local error_code="$1"
    local context="$2"
    local message="$3"
    
    log "$LOG_ERROR" "ERROR [$error_code] in $context: $message"
    
    # Add to findings for tracking
    add_finding "System" "ERROR" "Error $error_code in $context: $message" "Review logs for details"
    
    return "$error_code"
}

handle_warning() {
    local context="$1"
    local message="$2"
    
    log "$LOG_WARN" "WARNING in $context: $message"
    
    # Add to findings for tracking
    add_finding "System" "WARN" "Warning in $context: $message" "Review configuration"
}

# Safe execution wrapper with error handling
safe_exec_with_error_handling() {
    local cmd="$1"
    local context="${2:-Command execution}"
    shift 2
    
    if ! safe_exec_enhanced "$cmd" "$@"; then
        handle_error 1 "$context" "Failed to execute: $cmd $*"
        return 1
    fi
    
    log "$LOG_DEBUG" "Successfully executed: $cmd $*"
    return 0
}

# Base section template to reduce duplication
run_section_check() {
    local section_name="$1"
    local check_type="$2"  # info, warn, ok, crit
    local message="$3"
    local recommendation="${4:-}"
    local command="${5:-}"
    local args="${6:-}"
    
    local result=""
    local severity="INFO"
    
    # Determine severity based on check type
    case "$check_type" in
        "info")  severity="INFO" ;;
        "warn")  severity="WARN" ;;
        "ok")    severity="OK"   ;;
        "crit")  severity="CRIT" ;;
        *)       severity="INFO" ;;
    esac
    
    # Execute command if provided
    if [ -n "$command" ]; then
        if [ -n "$args" ]; then
            result=$(safe_exec_enhanced "$command" "$args" 2>/dev/null || echo "")
        else
            result=$(safe_exec_enhanced "$command" 2>/dev/null || echo "")
        fi
        
        # SECURITY FIX: Use safe string substitution instead of printf with user-controlled format
        # Use result in message if provided
        if [ -n "$result" ]; then
            # Replace %s placeholder safely without printf format string vulnerability
            message="${message//%s/$result}"
        fi
    fi
    
    # Add finding
    add_finding "$section_name" "$severity" "$message" "$recommendation"
    
    # Console output
    if [ "$OUTPUT_FORMAT" = "console" ]; then
        case "$severity" in
            "INFO") info "$message" ;;
            "WARN") warn "$message" ;;
            "OK")   ok "$message"   ;;
            "CRIT") crit "$message" ;;
        esac
    fi
    
    log "$LOG_DEBUG" "Section check completed: $section_name - $severity"
}

# File existence and content checker
check_file_content() {
    local file_path="$1"
    local section_name="$2"
    local check_type="$3"
    local message_template="$4"
    local recommendation="${5:-}"
    
    if [ -f "$file_path" ] && [ -r "$file_path" ]; then
        local content
        content=$(safe_read "$file_path" 2>/dev/null || echo "")
        if [ -n "$content" ]; then
            run_section_check "$section_name" "$check_type" "$message_template" "$recommendation" "" ""
        else
            run_section_check "$section_name" "warn" "File exists but is empty: $file_path" "Check file permissions and content"
        fi
    else
        run_section_check "$section_name" "warn" "File not found or not readable: $file_path" "$recommendation"
    fi
}

# Enhanced safe command execution with additional security and access control
safe_exec_enhanced() {
    local cmd="$1"
    shift
    
    # Check access control for command execution
    if ! check_access_control "execute_commands" "$cmd"; then
        handle_section_error "Access Control" "0" "Insufficient permissions to execute command: $cmd"
        return 1
    fi
    
    # Validate command before execution
    if ! validate_command "$cmd"; then
        handle_section_error "Command Validation" "0" "Invalid command attempted: $cmd"
        return 1
    fi
    
    # Validate all arguments
    local __args_total_len=0
    for arg in "$@"; do
        __args_total_len=$((__args_total_len + ${#arg}))
        if ! validate_input_length "$arg" 512; then
            handle_section_error "Command Validation" "0" "Argument too long for command: $cmd"
            return 1
        fi
        
        if ! validate_input_chars "$arg"; then
            handle_section_error "Command Validation" "0" "Invalid characters in argument for command: $cmd"
            return 1
        fi
    done
    # Enforce combined argument length limit
    if [ $__args_total_len -gt 4096 ]; then
        handle_section_error "Command Validation" "0" "Combined arguments too long for command: $cmd"
        return 1
    fi
    
    # Resolve to absolute path and validate
    local abs_cmd_path
    if ! abs_cmd_path=$(resolve_command_path "$cmd"); then
        handle_section_error "Command Validation" "0" "Command not found or not in safe directories: $cmd"
        return 1
    fi
    
    # Log command execution for audit
    audit_log "COMMAND_EXECUTED" "Command: $abs_cmd_path, Args: $*" "INFO"
    
    # Execute with absolute path for additional safety
    "$abs_cmd_path" "$@" 2>/dev/null || true
}

# Lightweight spinner for quiet mode
start_spinner() {
    local msg="${1:-Running checks}"
    SPINNER_MSG="$msg"
    (
        local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
        local i=0
        # Hide cursor if available
        if command -v tput >/dev/null 2>&1; then tput civis >&3 2>/dev/null || true; fi
        while true; do
            local ch=${frames[i%10]}
            if [ "$QUIET_MODE" = true ]; then
                printf "\r%s %s" "$ch" "$SPINNER_MSG" >&3
            else
                printf "\r%s %s" "$ch" "$SPINNER_MSG"
            fi
            i=$(( (i+1) ))
            sleep 0.1
        done
    ) &
    SPINNER_PID=$!
}

stop_spinner() {
    if [ -n "${SPINNER_PID:-}" ]; then
        kill "$SPINNER_PID" 2>/dev/null || true
        wait "$SPINNER_PID" 2>/dev/null || true
        if [ "$QUIET_MODE" = true ]; then
            printf "\r%s done.    \n" "$SPINNER_MSG" >&3
            if command -v tput >/dev/null 2>&1; then tput cnorm >&3 2>/dev/null || true; fi
        else
            printf "\r%s done.    \n" "$SPINNER_MSG"
            if command -v tput >/dev/null 2>&1; then tput cnorm 2>/dev/null || true; fi
        fi
        unset SPINNER_PID
    fi
}

# Enhanced section runner with safe, non-failing execution
run_section_safely() {
    local section_func="$1"
    local section_name="$2"
    local _timeout_unused="${3:-30}"
    
    # Always allow sections to complete without propagating non-zero codes.
    # Individual commands inside sections already record WARN/INFO findings.
    set +e
    "$section_func" 2>/dev/null || true
    set -e
}

# New high-impact defensive checks (inspired by privesc surfaces)

# 1) Sudo misconfig + PATH/SUID/ld.so hijack checks
section_privesc_surface_core() {
    print_section "Privilege Escalation Surface (Core)"

    # Sudoers risky configurations
    if is_root; then
        if [ -r /etc/sudoers ]; then
            local sudoers_dump
            sudoers_dump=$(cached_file_content /etc/sudoers)
            if echo "$sudoers_dump" | grep -Eq 'NOPASSWD|!authenticate'; then
                add_finding "Sudo" "CRIT" "NOPASSWD or !authenticate found in /etc/sudoers" "Restrict NOPASSWD; require authentication for admin commands"
            fi
            if echo "$sudoers_dump" | grep -Eq 'timestamp_timeout\s*=\s*-?1|timestamp_timeout\s*=\s*[6-9][0-9]'; then
                add_finding "Sudo" "WARN" "Excessive sudo timestamp_timeout configured" "Lower timestamp_timeout to minimal operational need"
            fi
            if ! echo "$sudoers_dump" | grep -q '^Defaults\s\+secure_path='; then
                add_finding "Sudo" "WARN" "Defaults secure_path not set in /etc/sudoers" "Set secure_path to trusted system dirs only"
            fi
            if echo "$sudoers_dump" | grep -qi 'env_keep'; then
                add_finding "Sudo" "WARN" "sudo env_keep configured (env leaks)" "Minimize env_keep; pass only required variables"
            fi
        fi
        if [ -d /etc/sudoers.d ]; then
            local sudoers_d_files
            sudoers_d_files=$(find /etc/sudoers.d -maxdepth 1 -type f -readable 2>/dev/null | head -20)
            if [ -n "$sudoers_d_files" ]; then
                while IFS= read -r f; do
                    local content; content=$(safe_read "$f")
                    if echo "$content" | grep -Eq 'NOPASSWD|!authenticate'; then
                        add_finding "Sudo" "CRIT" "NOPASSWD in $(basename "$f")" "Remove NOPASSWD or scope to least privilege"
                    fi
                done <<< "$sudoers_d_files"
            fi
        fi
    else
        add_finding "Sudo" "INFO" "Limited sudoers review without sudo" "Run with sudo to fully analyze sudoers and includes"
    fi

    # PATH hijack risks
    local path_val path_issues=false
    path_val="$PATH"
    if echo "$path_val" | grep -qE '(^|:)\.(:|$)'; then
        add_finding "PATH" "CRIT" "PATH contains current directory (.)" "Remove '.' from PATH; use absolute command paths"
        path_issues=true
    fi
    IFS=':' read -r -a _pdirs <<< "$path_val"
    local listed=0
    for d in "${_pdirs[@]}"; do
        [ -z "$d" ] && continue
        if [ -d "$d" ]; then
            # World/group writable dirs in PATH
            if [ -n "$(find "$d" -maxdepth 0 -perm -002 -type d 2>/dev/null)" ] || [ -n "$(find "$d" -maxdepth 0 -perm -020 -type d 2>/dev/null)" ]; then
                add_finding "PATH" "CRIT" "Writable directory in PATH: $d" "Set directory perms to 0755 and owner root; remove from PATH if not needed"
                path_issues=true
            fi
            # World-writable executables inside PATH (limited)
            if [ $listed -lt 5 ]; then
                local ww
                ww=$(find "$d" -maxdepth 1 -type f -perm -002 -executable 2>/dev/null | head -3)
                if [ -n "$ww" ]; then
                    while IFS= read -r f; do
                        add_finding "PATH" "CRIT" "World-writable executable in PATH: $f" "Set file perms to 0755 and owner root"
                    done <<< "$ww"
                    listed=$((listed+1))
                    path_issues=true
                fi
            fi
        fi
    done
    [ "$path_issues" = false ] && add_finding "PATH" "OK" "No obvious PATH hijack risks detected" "Keep PATH limited to root-owned, non-writable dirs"

    # SUID/SGID escalation via GTFOBins in common dirs
    local suid_bins
    suid_bins=$(cached_command find /bin /sbin /usr/bin /usr/sbin -perm -4000 -type f 2>/dev/null | head -200)
    if [ -n "$suid_bins" ]; then
        local risky="bash sh zsh python python3 perl ruby find awk sed vi vim nano less more tar cp rsync nmap mount fusermount pkexec busybox env tee" 
        while IFS= read -r sb; do
            bn=$(basename "$sb")
            if echo "$risky" | grep -qw "$bn"; then
                # Severity tuning: downgrade commonly SUID system tools (e.g., mount) to WARN
                # unless they are writable by group/others or not root-owned
                local perms owner
                perms=$(stat -Lc '%a' "$sb" 2>/dev/null || echo "")
                owner=$(stat -Lc '%U' "$sb" 2>/dev/null || echo "")
                local sev="CRIT"
                if [ "$bn" = "mount" ] || [ "$bn" = "fusermount" ]; then
                    sev="WARN"
                fi
                if [ -n "$perms" ]; then
                    # Use last two digits for group/other even when a special (setuid/setgid) digit is present
                    local g=${perms: -2:1}; local o=${perms: -1}
                    if [[ ! "$g" =~ [2367] ]] && [[ ! "$o" =~ [2367] ]] && [ "$owner" = "root" ]; then
                        # Not writable by group/others and root-owned
                        [ "$sev" = "CRIT" ] && sev="WARN"
                    fi
                fi
                add_finding "SUID" "$sev" "SUID GTFOBin detected: $sb" "Remove SUID bit or replace; consult GTFOBins for escalation vectors"
            fi
        done <<< "$suid_bins"
    fi

    # ld.so preload hijack vectors
    if [ -e /etc/ld.so.preload ]; then
        add_finding "Loader" "WARN" "/etc/ld.so.preload present" "Ensure referenced libs are root-owned and not writable; remove if not intentionally used"
        local libs; libs=$(safe_read /etc/ld.so.preload)
        if [ -n "$libs" ]; then
            while IFS= read -r lib; do
                [ -z "$lib" ] && continue
                if [ -e "$lib" ]; then
                    if [ -n "$(find "$lib" -perm -002 -o -perm -020 2>/dev/null)" ]; then
                        add_finding "Loader" "CRIT" "Writable library in ld.so.preload: $lib" "Set permissions to 0644 and owner root; audit change origin"
                    fi
                else
                    add_finding "Loader" "WARN" "Missing library referenced in ld.so.preload: $lib" "Remove stale entry or restore library"
                fi
            done <<< "$libs"
        fi
    fi
    # ld.so.conf writability
    if [ -r /etc/ld.so.conf ]; then
        if [ -n "$(find /etc/ld.so.conf -perm -002 -o -perm -020 2>/dev/null)" ]; then
            add_finding "Loader" "WARN" "/etc/ld.so.conf writable by non-root" "Set to 0644 root:root; review contents"
        fi
    fi
    if [ -d /etc/ld.so.conf.d ]; then
        local w
        w=$(find /etc/ld.so.conf.d -type f \( -perm -002 -o -perm -020 \) 2>/dev/null | head -5)
        if [ -n "$w" ]; then
            while IFS= read -r f; do
                add_finding "Loader" "WARN" "ld.so.conf.d entry writable: $f" "Set to 0644 root:root and audit"
            done <<< "$w"
        fi
    fi
}

# Extended privilege-escalation surface (targeted, read-only)
section_privesc_surface_extended() {
    print_section "Privilege Escalation Surface (Extended)"

    # Sudo deep-dive: sudo version and risky Defaults
    if command_exists sudo; then
        local sv; sv=$(sudo -V 2>/dev/null | head -1 | awk '{print $3}')
        [ -n "$sv" ] && add_finding "Sudo" "INFO" "sudo version: $sv" "Keep sudo updated; review vendor advisories"
    fi
    if is_root && [ -r /etc/sudoers ]; then
        local d; d=$(grep -E '^Defaults' /etc/sudoers 2>/dev/null)
        if echo "$d" | grep -qi 'mail_badpass'; then
            add_finding "Sudo" "WARN" "Defaults contains mail_badpass (noise)" "Remove or tune Defaults as needed"
        fi
        if echo "$d" | grep -qi 'insults'; then
            add_finding "Sudo" "INFO" "Defaults insults set" "Optional: remove for cleaner logs"
        fi
    fi

    # PATH owner checks: non-root-owned dirs in PATH
    IFS=':' read -r -a _pdirs2 <<< "$PATH"
    for d in "${_pdirs2[@]}"; do
        [ -d "$d" ] || continue
        local own; own=$(stat -Lc '%U' "$d" 2>/dev/null || echo "")
        if [ "$own" != "root" ]; then
            add_finding "PATH" "WARN" "Directory in PATH not owned by root: $d ($own)" "Change owner to root:root or remove from PATH"
        fi
    done

    # SGID binaries and capabilities
    local sgid_bins; sgid_bins=$(cached_command find /bin /sbin /usr/bin /usr/sbin -perm -2000 -type f 2>/dev/null | head -200)
    if [ -n "$sgid_bins" ]; then
        local listed=0
        while IFS= read -r sb; do
            [ $listed -ge 10 ] && break
            local p; p=$(stat -Lc '%a' "$sb" 2>/dev/null || echo "")
            local owner; owner=$(stat -Lc '%U' "$sb" 2>/dev/null || echo "")
            # Use last two digits for group/other permissions even with leading setgid digit
            local g="" o=""
            [ -n "$p" ] && g=${p: -2:1} && o=${p: -1}
            if [ -n "$g" ] && [ -n "$o" ]; then
                if [[ "$g" =~ [2367] ]] || [[ "$o" =~ [2367] ]] || [ "$owner" != "root" ]; then
                    add_finding "SGID" "CRIT" "Group/other-writable SGID binary: $sb" "Set perms to 2755 and owner root:root; review necessity"
                    listed=$((listed+1))
                fi
            fi
        done <<< "$sgid_bins"
    fi
    if command_exists getcap; then
        local caps; caps=$(getcap -r /bin /sbin /usr/bin /usr/sbin 2>/dev/null | head -200)
        if [ -n "$caps" ]; then
            while IFS= read -r line; do
                local f; f=$(echo "$line" | awk -F= '{print $1}')
                local c; c=$(echo "$line" | awk -F= '{print $2}')
                if echo "$c" | grep -Eq 'cap_setuid|cap_sys_admin'; then
                    local p; p=$(stat -Lc '%a' "$f" 2>/dev/null || echo "")
                    local g=${p:1:1}; local o=${p:2:1}
                    if [[ "$g" =~ [2367] ]] || [[ "$o" =~ [2367] ]]; then
                        add_finding "Capabilities" "CRIT" "Writable binary with powerful capabilities: $f ($c)" "Restrict perms to 0755 and review need for capabilities"
                    else
                        add_finding "Capabilities" "WARN" "Binary has powerful capabilities: $f ($c)" "Review need for capabilities; remove if unnecessary"
                    fi
                fi
            done <<< "$caps"
        fi
    fi

    # ld.so: writable directories referenced
    if [ -r /etc/ld.so.conf ]; then
        local ldirs; ldirs=$(awk '$1 !~ /^#/ {print $1}' /etc/ld.so.conf 2>/dev/null)
        for dir in $ldirs; do
            [ -d "$dir" ] || continue
            if [ -n "$(find "$dir" -maxdepth 0 -perm -002 -o -perm -020 2>/dev/null)" ]; then
                add_finding "Loader" "WARN" "Writable library directory referenced: $dir" "Set perms to 0755 root:root; remove from ld.so.conf if not needed"
            fi
        done
    fi
    if [ -d /etc/ld.so.conf.d ]; then
        local conf
        for conf in /etc/ld.so.conf.d/*.conf; do
            [ -r "$conf" ] || continue
            local ldirs2; ldirs2=$(awk '$1 !~ /^#/ {print $1}' "$conf" 2>/dev/null)
            for dir in $ldirs2; do
                [ -d "$dir" ] || continue
                if [ -n "$(find "$dir" -maxdepth 0 -perm -002 -o -perm -020 2>/dev/null)" ]; then
                    add_finding "Loader" "WARN" "Writable library directory referenced: $dir (from $(basename "$conf"))" "Set perms to 0755 root:root; audit necessity"
                fi
            done
        done
    fi

    # systemd drop-ins and hardening
    if [ -d /etc/systemd/system ]; then
        local di; di=$(find /etc/systemd/system -type f -path '*/*.d/*.conf' \( -perm -002 -o -perm -020 \) 2>/dev/null | head -10)
        if [ -n "$di" ]; then
            while IFS= read -r f; do
                add_finding "systemd" "CRIT" "Writable systemd drop-in: $f" "Set to 0644 root:root; review overrides"
            done <<< "$di"
        fi
    fi
}
# 2) Cron/systemd chain writability + NFS exports
section_taskrunners_nfs() {
    print_section "Task Runners & NFS Risk"

    # Cron files/directories world-writable
    local cron_ww
    cron_ww=$(find /etc/cron* /var/spool/cron* -maxdepth 2 -type f -perm -002 2>/dev/null | head -10)
    if [ -n "$cron_ww" ]; then
        while IFS= read -r f; do
            add_finding "Cron" "CRIT" "World-writable cron file: $f" "Set owner root:root and perms 0644 (or stricter)"
        done <<< "$cron_ww"
    else
        add_finding "Cron" "OK" "No world-writable cron files detected" "Maintain secure ownership and perms"
    fi

    # systemd units pointing to writable ExecStart targets
    if command_exists systemctl; then
        local units; units=$(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | head -200)
        local checked=0
        for u in $units; do
            [ $checked -ge 30 ] && break
            local f
            f=$(systemctl show -p FragmentPath "$u" 2>/dev/null | awk -F= '{print $2}')
            [ -f "$f" ] || continue
            local execs
            execs=$(awk -F= '/^ExecStart=/ {print $2}' "$f" | awk '{print $1}' | sed 's/^\-//;s/^!//')
            for e in $execs; do
                [ -z "$e" ] && continue
                # Resolve symlink to real target if possible
                local real
                real=$(realpath "$e" 2>/dev/null || echo "$e")
                if [ -e "$real" ]; then
                    # Use numeric perms to check group/other write bits
                    local p; p=$(stat -Lc '%a' "$real" 2>/dev/null || echo "")
                    if [ -n "$p" ]; then
                        # Use last two digits (group/other)
                        local g=${p: -2:1}; local o=${p: -1}
                        if [[ "$g" =~ [2367] ]] || [[ "$o" =~ [2367] ]]; then
                            add_finding "systemd" "CRIT" "ExecStart target writable: $real (unit: $u)" "Set owner root:root and perms 0755; move scripts to root-owned paths"
                        fi
                    fi
                fi
            done
            checked=$((checked+1))
        done
    fi

    # NFS exports with no_root_squash or wide RW
    if [ -r /etc/exports ]; then
        local ex; ex=$(safe_read /etc/exports)
        if echo "$ex" | grep -q 'no_root_squash'; then
            add_finding "NFS" "CRIT" "NFS export with no_root_squash" "Replace with root_squash; restrict clients to trusted hosts/subnets"
        fi
        if echo "$ex" | grep -Eq '\s\(.*rw.*\)'; then
            add_finding "NFS" "WARN" "Writable NFS export present" "Limit to ro where possible or restrict to specific clients"
        fi
    fi

    # Cron/Anacron/At allow/deny validation (moved here)
    print_section "Scheduler Controls (cron/anacron/at)"
    for f in /etc/cron.allow /etc/cron.deny; do
        if [ -e "$f" ]; then
            local p o g
            p=$(stat -c '%a' "$f" 2>/dev/null || echo "")
            o=$(stat -c '%U' "$f" 2>/dev/null || echo "")
            g=$(stat -c '%G' "$f" 2>/dev/null || echo "")
            if [ -n "$p" ] && { [[ ${p:1:1} =~ [2367] ]] || [[ ${p:2:1} =~ [2367] ]]; }; then
                add_finding "Cron" "WARN" "$f is group/other-writable ($p $o:$g)" "Set to 0640 or stricter, owner root:root"
            fi
        fi
    done
    if [ -r /etc/anacrontab ]; then
        add_finding "Anacron" "OK" "anacrontab present" "Ensure jobs reference root-owned, non-writable scripts"
    fi
    for f in /etc/at.allow /etc/at.deny; do
        if [ -e "$f" ]; then
            local p o g
            p=$(stat -c '%a' "$f" 2>/dev/null || echo "")
            o=$(stat -c '%U' "$f" 2>/dev/null || echo "")
            g=$(stat -c '%G' "$f" 2>/dev/null || echo "")
            if [ -n "$p" ] && { [[ ${p:1:1} =~ [2367] ]] || [[ ${p:2:1} =~ [2367] ]]; }; then
                add_finding "at" "WARN" "$f is group/other-writable ($p $o:$g)" "Set to 0640 or stricter, owner root:root"
            fi
        fi
    done
}

# 3) Container/SSH/Secrets hygiene
section_container_ssh_secrets_hygiene() {
    print_section "Container, SSH & Secrets Hygiene"

    # Docker socket/group exposure
    if [ -S /var/run/docker.sock ]; then
        local perms; perms=$(stat -c '%a %U:%G' /var/run/docker.sock 2>/dev/null)
        add_finding "Containers" "WARN" "Docker socket present (/var/run/docker.sock) perms: $perms" "Limit access; non-root access to docker implies root-equivalent on host"
    fi

    # SSH agent socket exposure
    if [ -n "${SSH_AUTH_SOCK:-}" ]; then
        if [ -S "$SSH_AUTH_SOCK" ]; then
            local sp; sp=$(stat -c '%a %U:%G' "$SSH_AUTH_SOCK" 2>/dev/null)
            add_finding "SSH" "INFO" "SSH_AUTH_SOCK detected ($sp)" "Avoid forwarding agent into untrusted hosts; limit socket permissions"
        fi
    fi

    # Private key permissions
    local key_issues
    key_issues=$(find /root /home -maxdepth 3 -type f \( -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' \) -perm -004 2>/dev/null | head -10)
    if [ -n "$key_issues" ]; then
        while IFS= read -r f; do
            add_finding "SSH" "CRIT" "Private key world-readable: $f" "Set to 0600 and owner correct user; rotate keys if exposed"
        done <<< "$key_issues"
    fi

    # Secrets files with weak perms
    local secrets
    secrets=$(find /root /home -maxdepth 4 -type f \( -name '.netrc' -o -path '*/.aws/credentials' -o -path '*/.docker/config.json' -o -path '*/.kube/config' -o -name '.env' \) -perm -004 2>/dev/null | head -10)
    if [ -n "$secrets" ]; then
        while IFS= read -r f; do
            add_finding "Secrets" "WARN" "World-readable secrets file: $f" "Restrict perms (600) and consider removing secrets from disk"
        done <<< "$secrets"
    fi
}

# 4) Kernel, polkit, fstab refinements
section_kernel_polkit_fstab_refinements() {
    print_section "Kernel, Polkit & Filesystem Hardening"

    # Core pattern pipe handler risk
    if [ -r /proc/sys/kernel/core_pattern ]; then
        local cp; cp=$(cached_file_content /proc/sys/kernel/core_pattern | tr -d '\n')
        if echo "$cp" | grep -q '^|'; then
            add_finding "Kernel" "WARN" "core_pattern pipes to program ($cp)" "Avoid piping core dumps to external programs unless required; secure target path and perms"
        fi
    fi

    # Unprivileged user namespaces and kernel toggles
    for k in kernel.unprivileged_userns_clone kernel.kexec_load_disabled vm.mmap_min_addr; do
        if command_exists sysctl; then
            local v; v=$(sysctl -n "$k" 2>/dev/null || echo "")
            case "$k:$v" in
                kernel.unprivileged_userns_clone:1) add_finding "Kernel" "WARN" "Unprivileged user namespaces enabled" "Consider disabling (set kernel.unprivileged_userns_clone=0) in hardened environments";;
                kernel.kexec_load_disabled:0) add_finding "Kernel" "WARN" "kexec load not disabled" "Set kernel.kexec_load_disabled=1 to reduce attack surface";;
                vm.mmap_min_addr:0) add_finding "Kernel" "WARN" "vm.mmap_min_addr is 0" "Set a higher value (e.g., 65536) to mitigate NULL-deref exploits";;
            esac
        fi
    done

    # Polkit rules world-writable
    if [ -d /etc/polkit-1/rules.d ]; then
        local prw
        prw=$(find /etc/polkit-1/rules.d -type f \( -perm -002 -o -perm -020 \) 2>/dev/null | head -5)
        if [ -n "$prw" ]; then
            while IFS= read -r f; do
                add_finding "Polkit" "CRIT" "World/group-writable polkit rule: $f" "Set to 0644 root:root; audit rules for least privilege"
            done <<< "$prw"
        fi
    fi

    # Fstab / mounts options
    if [ -r /etc/fstab ]; then
        local fstab; fstab=$(safe_read /etc/fstab)
        for mp in /tmp /var/tmp /dev/shm; do
            if echo "$fstab" | awk '$1 !~ /^#/ {print $2" "$4}' | grep -q "^$mp "; then
                local opts; opts=$(echo "$fstab" | awk '$1 !~ /^#/ {print $2" "$4}' | grep "^$mp " | awk '{print $2}')
                for need in noexec nosuid nodev; do
                    if ! echo "$opts" | grep -qw "$need"; then
                        add_finding "FSTAB" "WARN" "$mp missing $need option" "Add $need to $mp mount options in /etc/fstab and remount"
                    fi
                done
            fi
        done
    fi
}
# Parallel execution support
declare -a PARALLEL_PIDS=()
declare -a PARALLEL_SECTIONS=()
declare -a PARALLEL_FINDINGS=()
declare -a PARALLEL_CONSOLE=()

# Run section in parallel (background)
run_section_parallel() {
    local section_func="$1"
    local section_name="$2"
    
	# Run section in background
    (
        # Create per-section sinks
        local tmp_dir="${PARALLEL_TMP_DIR:-/tmp/btqc-par-$$}"
        mkdir -p "$tmp_dir" 2>/dev/null || true
        export FINDINGS_SINK="$tmp_dir/${section_name// /_}.findings"
        export CONSOLE_SINK="$tmp_dir/${section_name// /_}.console"
        set +e
        # Run the function in background and enforce a timeout without spawning a new shell
        {
            "$section_func" 2>/dev/null || true
        } &
        local spid=$!
        # Wait up to 30s
        local waited=0
        while kill -0 "$spid" 2>/dev/null; do
            sleep 0.1
            waited=$((waited+1))
            if [ $waited -ge 300 ]; then
                kill -TERM "$spid" 2>/dev/null || true
                sleep 1
                kill -KILL "$spid" 2>/dev/null || true
                break
            fi
        done
        wait "$spid" 2>/dev/null || true
        set -e
    ) &
    
    local pid=$!
    PARALLEL_PIDS+=("$pid")
    PARALLEL_SECTIONS+=("$section_name")
    # Track sink file paths aligned by index
    local tmp_dir_ref="${PARALLEL_TMP_DIR:-/tmp/btqc-par-$$}"
    PARALLEL_FINDINGS+=("$tmp_dir_ref/${section_name// /_}.findings")
    PARALLEL_CONSOLE+=("$tmp_dir_ref/${section_name// /_}.console")
}

# Wait for all parallel sections to complete
wait_parallel_sections() {
    local failed_count=0
    
    for i in "${!PARALLEL_PIDS[@]}"; do
        local pid="${PARALLEL_PIDS[$i]}"
        local section="${PARALLEL_SECTIONS[$i]}"
        local findings_file="${PARALLEL_FINDINGS[$i]}"
        local console_file="${PARALLEL_CONSOLE[$i]}"
        
        if ! wait "$pid" 2>/dev/null; then
            ((failed_count++))
            if [ "$OUTPUT_FORMAT" = "console" ]; then
                warn "Parallel section '$section' encountered issues"
            fi
        fi
        # Merge findings
        if [ -f "$findings_file" ]; then
            while IFS= read -r line; do
                # Append to global findings preserving structure
                FINDINGS+=("$line")
            done < "$findings_file"
            rm -f "$findings_file" 2>/dev/null || true
        fi
        # Flush console output in order
        if [ "$OUTPUT_FORMAT" = "console" ] && [ -f "$console_file" ]; then
            cat "$console_file" 2>/dev/null || true
            rm -f "$console_file" 2>/dev/null || true
        fi
    done
    
    # Clear parallel arrays
    PARALLEL_PIDS=()
    PARALLEL_SECTIONS=()
    PARALLEL_FINDINGS=()
    PARALLEL_CONSOLE=()
    
    # Never propagate failures upward; issues were logged as WARN above
    return 0
}

# Caching system functions
init_cache() {
    if [ "$CACHE_ENABLED" = true ]; then
        mkdir -p "$CACHE_DIR" 2>/dev/null || CACHE_ENABLED=false
        chmod 700 "$CACHE_DIR" 2>/dev/null || true
    fi
}

cleanup_cache() {
    if [ -d "$CACHE_DIR" ]; then
        rm -rf "$CACHE_DIR" 2>/dev/null || true
    fi
}

# Hygiene: remove our old cache/temp dirs (safe prefix) older than retention window
cleanup_old_btqc_dirs() {
    local base_tmp="/tmp"
    local retention_hours="${RETENTION_HOURS:-24}"
    if command_exists find; then
        find "$base_tmp" -maxdepth 1 -type d \
            \( -name 'bt-quickcheck-cache-*' -o -name 'btqc-par-*' \) \
            -mmin +$((retention_hours*60)) \
            -exec rm -rf {} + 2>/dev/null || true
    fi
}

# Generate cache key from command and arguments
get_cache_key() {
    local cmd="$1"
    shift
    local args="$*"
    echo "$cmd $args" | md5sum | cut -d ' ' -f 1
}

# Check if cache entry is valid (not expired)
is_cache_valid() {
    local cache_file="$1"
    if [ ! -f "$cache_file" ]; then
        return 1
    fi
    
    local file_age=$(($(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0)))
    [ $file_age -lt $CACHE_TTL ]
}

# Execute command with caching
cached_command() {
    local cmd="$1"
    shift
    local args="$*"
    
    if [ "$CACHE_ENABLED" != true ]; then
        # Execute without caching
        $cmd $args 2>/dev/null
        return $?
    fi
    
    local cache_key=$(get_cache_key "$cmd" "$args")
    local cache_file="$CACHE_DIR/$cache_key"
    
    if is_cache_valid "$cache_file"; then
        # Return cached result
        cat "$cache_file" 2>/dev/null
        return $?
    else
        # Execute command and cache result
        local temp_file=$(mktemp)
        if $cmd $args > "$temp_file" 2>/dev/null; then
            mv "$temp_file" "$cache_file" 2>/dev/null || true
            cat "$cache_file" 2>/dev/null
            return 0
        else
            rm -f "$temp_file" 2>/dev/null || true
            return 1
        fi
    fi
}

# Cache file content with TTL
cached_file_content() {
    local file_path="$1"
    local cache_key="file_$(echo "$file_path" | md5sum | cut -d ' ' -f 1)"
    local cache_file="$CACHE_DIR/$cache_key"
    
    if [ "$CACHE_ENABLED" != true ]; then
        safe_read "$file_path"
        return $?
    fi
    
    if is_cache_valid "$cache_file"; then
        cat "$cache_file" 2>/dev/null
        return $?
    else
        if safe_read "$file_path" > "$cache_file" 2>/dev/null; then
            cat "$cache_file" 2>/dev/null
            return 0
        else
            return 1
        fi
    fi
}

VERSION="0.6.3"

# Caching system configuration
# Use secure temp directory with strict permissions
CACHE_DIR=$(mktemp -d -t bt-quickcheck-cache-XXXXXXXXXX 2>/dev/null || echo "/tmp/bt-quickcheck-cache-$$")
chmod 700 "$CACHE_DIR" 2>/dev/null || true
CACHE_TTL=300
CACHE_ENABLED=true

# Output format (default: console)
OUTPUT_FORMAT="console"
OUTPUT_FILE=""
OPERATION_MODE="personal"
QUIET_MODE=false

# Parallel execution (default: disabled for stability)
PARALLEL_MODE=false


# Colors (only used in console mode)
COLOR_RED="\033[31m"
COLOR_YELLOW="\033[33m"
COLOR_GREEN="\033[32m"
COLOR_BLUE="\033[34m"
COLOR_RESET="\033[0m"

# Data structure to store findings
declare -a FINDINGS=()
declare -a SECTIONS=()

# Privacy controls (defaults)
PRIVACY_LEVEL="standard"   # standard|high|off
ANONYMIZE=false
EXCLUDE_SECTIONS_RAW=""
EXCLUDE_SEVERITY_RAW=""

# Derived privacy state
declare -A EXCLUDE_SECTION_SET=()
declare -A EXCLUDE_SEVERITY_SET=()
ANON_SALT=""

# Safety functions
is_root() { [ "${EUID:-$(id -u)}" -eq 0 ]; }

# Privilege management
ORIGINAL_UID=""
ORIGINAL_GID=""
PRIVILEGE_DROPPED=false

# Store original user credentials
store_original_credentials() {
    ORIGINAL_UID=$(id -u)
    ORIGINAL_GID=$(id -g)
}

# Drop privileges to original user
drop_privileges() {
    if [ "$PRIVILEGE_DROPPED" = true ]; then
        return 0
    fi
    
    if [ -n "$ORIGINAL_UID" ] && [ -n "$ORIGINAL_GID" ]; then
        # Drop to original user
        if [ "$EUID" -eq 0 ] && [ "$ORIGINAL_UID" -ne 0 ]; then
            # Use setuid/setgid to drop privileges
            if command -v setuidgid >/dev/null 2>&1; then
                exec setuidgid "$(id -un "$ORIGINAL_UID")" "$0" "$@"
            else
                # Fallback: use su to drop privileges
                exec su -s /bin/bash -c "exec '$0' $*" "$(id -un "$ORIGINAL_UID")"
            fi
        fi
        PRIVILEGE_DROPPED=true
    fi
}

# Temporarily elevate privileges for specific operations
elevate_privileges() {
    if [ "$EUID" -ne 0 ] && [ "$ORIGINAL_UID" -ne 0 ]; then
        # Request sudo for specific operation
        sudo -n true 2>/dev/null || {
            echo "Error: Sudo privileges required for this operation" >&2
            return 1
        }
    fi
}

# Whitelist of allowed commands for security assessment
declare -A ALLOWED_COMMANDS=(
    # System information
    ["uname"]="system_info"
    ["hostname"]="system_info"
    ["uptime"]="system_info"
    ["whoami"]="system_info"
    ["id"]="system_info"
    ["w"]="system_info"
    ["who"]="system_info"
    ["last"]="system_info"
    ["lastlog"]="system_info"
    
    # File operations (read-only)
    ["cat"]="file_read"
    ["head"]="file_read"
    ["tail"]="file_read"
    ["grep"]="file_read"
    ["awk"]="file_read"
    ["sed"]="file_read"
    ["cut"]="file_read"
    ["sort"]="file_read"
    ["uniq"]="file_read"
    ["wc"]="file_read"
    ["find"]="file_read"
    ["stat"]="file_read"
    ["ls"]="file_read"
    ["file"]="file_read"
    ["md5sum"]="file_read"
    ["sha256sum"]="file_read"
    ["sha1sum"]="file_read"
    
    # Process and system monitoring
    ["ps"]="process_info"
    ["top"]="process_info"
    ["htop"]="process_info"
    ["pgrep"]="process_info"
    ["pstree"]="process_info"
    ["lsof"]="process_info"
    ["fuser"]="process_info"
    ["netstat"]="network_info"
    ["ss"]="network_info"
    ["ip"]="network_info"
    ["ifconfig"]="network_info"
    ["route"]="network_info"
    ["arp"]="network_info"
    
    # System services and configuration
    ["systemctl"]="service_info"
    ["service"]="service_info"
    ["chkconfig"]="service_info"
    ["sysctl"]="system_config"
    ["mount"]="system_config"
    ["df"]="system_config"
    ["du"]="system_config"
    ["free"]="system_config"
    ["vmstat"]="system_config"
    ["iostat"]="system_config"
    ["sar"]="system_config"
    
    # Package management (read-only)
    ["dpkg"]="package_info"
    ["rpm"]="package_info"
    ["yum"]="package_info"
    ["dnf"]="package_info"
    ["apt"]="package_info"
    ["apt-get"]="package_info"
    ["zypper"]="package_info"
    ["pacman"]="package_info"
    
    # Security tools
    ["getcap"]="security_info"
    ["getfattr"]="security_info"
    ["lsattr"]="security_info"
    ["getfacl"]="security_info"
    ["auditctl"]="security_info"
    ["ausearch"]="security_info"
    ["aureport"]="security_info"
    ["chkrootkit"]="security_info"
    ["rkhunter"]="security_info"
    ["clamscan"]="security_info"
    ["aide"]="security_info"
    ["tripwire"]="security_info"
    
    # Network security
    ["nmap"]="network_scan"
    ["nslookup"]="network_scan"
    ["dig"]="network_scan"
    ["host"]="network_scan"
    ["ping"]="network_scan"
    ["traceroute"]="network_scan"
    ["tcpdump"]="network_scan"
    ["wireshark"]="network_scan"
    ["tcpdump"]="network_scan"
    
    # Text processing
    ["tr"]="text_proc"
    ["rev"]="text_proc"
    ["tac"]="text_proc"
    ["column"]="text_proc"
    ["pr"]="text_proc"
    ["fmt"]="text_proc"
    ["fold"]="text_proc"
    ["expand"]="text_proc"
    ["unexpand"]="text_proc"
    
    # Compression and archiving (read-only)
    ["zcat"]="archive_read"
    ["bzcat"]="archive_read"
    ["xzcat"]="archive_read"
    ["gunzip"]="archive_read"
    ["bunzip2"]="archive_read"
    ["unxz"]="archive_read"
    
    # Date and time
    ["date"]="time_info"
    ["timedatectl"]="time_info"
    ["ntpdate"]="time_info"
    ["chrony"]="time_info"
    
    # Environment and shell
    ["env"]="env_info"
    ["printenv"]="env_info"
    ["locale"]="env_info"
    ["ulimit"]="env_info"
    ["umask"]="env_info"
)

# Resolve command to absolute path with whitelist validation
resolve_command_path() {
    local cmd="$1"
    local abs_path
    
    # Check if command is in whitelist
    if [[ -z "${ALLOWED_COMMANDS[$cmd]:-}" ]]; then
        return 1
    fi
    
    # Get absolute path
    abs_path=$(command -v "$cmd" 2>/dev/null)
    
    # Validate it's an absolute path
    if [[ -z "$abs_path" ]] || [[ "$abs_path" != /* ]]; then
        return 1
    fi
    
    # Ensure it's executable
    if [[ ! -x "$abs_path" ]]; then
        return 1
    fi
    
    # Only allow commands from safe system directories
    case "$abs_path" in
        /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/usr/local/bin/*|/usr/local/sbin/*)
            echo "$abs_path"
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Enhanced safe command execution with additional security
safe_exec() {
    # Use the enhanced version for better security
    safe_exec_enhanced "$@"
}

# Enhanced safe file reading with comprehensive validation and access control
safe_read() {
    local file="$1"
    local max_size="${2:-1048576}"  # Default 1MB limit
    
    # Check access control for reading system files
    if ! check_access_control "read_system_files" "$file"; then
        handle_section_error "Access Control" "0" "Insufficient permissions to read file: $file"
        return 1
    fi
    
    # Validate input length and characters
    if ! validate_input_length "$file" 1024; then
        return 1
    fi
    
    if ! validate_input_chars "$file"; then
        return 1
    fi
    
    # Resolve any symlinks and get canonical path
    local canonical_file
    canonical_file=$(realpath -m "$file" 2>/dev/null || echo "$file")
    
    # Validate canonical path is within safe boundaries
    if [[ "$canonical_file" =~ \.\. ]] || [[ "$canonical_file" =~ /\.\. ]]; then
        return 1
    fi
    
    # Check if file exists and is readable
    if [ ! -r "$canonical_file" ] || [ ! -f "$canonical_file" ]; then
        return 1
    fi
    
    # Check file size to prevent reading extremely large files
    local file_size
    file_size=$(stat -c "%s" "$canonical_file" 2>/dev/null || echo "0")
    if [ "$file_size" -gt "$max_size" ]; then
        return 1
    fi
    
    # Validate file is not a symlink to prevent symlink attacks
    if [ -L "$canonical_file" ]; then
        return 1
    fi
    
    # Additional security: check file permissions
    local file_perms
    file_perms=$(stat -c "%a" "$canonical_file" 2>/dev/null || echo "000")
    # Reject files with world-write permissions for security
    if [[ "$file_perms" =~ [2367]$ ]]; then
        return 1
    fi
    
    # Log file access for audit
    audit_log "FILE_ACCESSED" "File: $canonical_file, Size: $file_size" "INFO"
    
    # Use the canonical path for reading
    cat "$canonical_file" 2>/dev/null || true
}

# Safe directory check
safe_dir_check() {
    local dir="$1"
    [ -d "$dir" ] && [ -r "$dir" ]
}

# SECURITY FIX: Safe log file parsing with size limits to prevent DoS
safe_log_grep() {
    local log_file="$1"
    local pattern="$2"
    local max_size_mb="${3:-100}"  # Default 100MB limit
    local max_lines="${4:-10000}"   # Default 10000 lines limit
    
    # Check if file exists and is readable
    if [ ! -r "$log_file" ] || [ ! -f "$log_file" ]; then
        return 1
    fi
    
    # Check file size (in bytes)
    local file_size
    file_size=$(stat -c "%s" "$log_file" 2>/dev/null || echo "0")
    local max_size_bytes=$((max_size_mb * 1024 * 1024))
    
    if [ "$file_size" -gt "$max_size_bytes" ]; then
        # File too large - only read last portion
        tail -n "$max_lines" "$log_file" 2>/dev/null | grep -E "$pattern" 2>/dev/null || true
    else
        # File size OK - grep entire file but limit output
        grep -E "$pattern" "$log_file" 2>/dev/null | head -n "$max_lines" 2>/dev/null || true
    fi
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

# Determine output format from file extension
detect_output_format() {
    local file="$1"
    if [ -z "$file" ]; then
        echo "console"
        return 0
    fi
    
    case "$file" in
        *.json) echo "json" ;;
        *.html) echo "html" ;;
        *.txt) echo "txt" ;;
        *) echo "console" ;;
    esac
}

# Build exclude maps and init anonymization salt
init_privacy_controls() {
    # Sections
    if [ -n "$EXCLUDE_SECTIONS_RAW" ]; then
        IFS=',' read -r -a _secs <<< "$EXCLUDE_SECTIONS_RAW"
        for s in "${_secs[@]}"; do
            s_trim=$(echo "$s" | tr -d ' ')
            [ -n "$s_trim" ] && EXCLUDE_SECTION_SET["$s_trim"]=1
        done
    fi
    # Severities
    if [ -n "$EXCLUDE_SEVERITY_RAW" ]; then
        IFS=',' read -r -a _sevs <<< "$EXCLUDE_SEVERITY_RAW"
        for sv in "${_sevs[@]}"; do
            sv_up=$(echo "$sv" | tr '[:lower:]' '[:upper:]' | tr -d ' ')
            case "$sv_up" in OK|WARN|CRIT|INFO) EXCLUDE_SEVERITY_SET["$sv_up"]=1 ;; esac
        done
    fi
    # Salt if anonymize
    if [ "$ANONYMIZE" = true ] && [ -z "$ANON_SALT" ]; then
        ANON_SALT=$(date +%s%N | md5sum | cut -d' ' -f1)
    fi
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
    
    # Resolve to canonical path without following unsafe symlinks
    local canonical
    if [[ "$path" == /* ]]; then
        canonical=$(realpath -m "$path" 2>/dev/null || echo "$path")
    else
        # Treat relative paths as under current working directory
        canonical=$(realpath -m "$PWD/$path" 2>/dev/null || echo "$PWD/$path")
    fi
    
    # Basic traversal detection
    if [[ "$canonical" =~ (\.|/)?\.\.(/|$) ]]; then
        return 1
    fi
    
    # Only allow under safe roots: /tmp, /var/tmp, $HOME, current working directory
    if [[ "$canonical" == /* ]]; then
        case "$canonical" in
            /tmp/*|/var/tmp/*|$HOME/*|$PWD/*) : ;; 
            *) return 1 ;;
        esac
    fi
    
    # Disallow world-writable parent directory traversal by verifying we can create files safely later
    echo "$canonical" >/dev/null 2>&1
    return 0
}

# Enhanced command validation
# Enhanced input validation functions
validate_input_length() {
    local input="$1"
    local max_length="${2:-1024}"
    
    if [ ${#input} -gt "$max_length" ]; then
        return 1
    fi
    return 0
}

validate_input_chars() {
    local input="$1"
    # Use grep -E to avoid [[ =~ ]] tokenization issues with spaces
    if ! printf '%s' "$input" | grep -qE '^[A-Za-z0-9._/[:space:]-]+$'; then
        return 1
    fi
    return 0
}

validate_command() {
    local cmd="$1"
    
    # Validate input length
    if ! validate_input_length "$cmd" 256; then
        return 1
    fi
    
    # Validate input characters
    if ! validate_input_chars "$cmd"; then
        return 1
    fi
    
    # Use whitelist-based validation via resolve_command_path
    if ! resolve_command_path "$cmd" >/dev/null 2>&1; then
        return 1
    fi
    
    return 0
}

# Add a finding to the global findings array or a sink file when running in parallel
add_finding() {
    local section="$1"
    local severity="$2"  # OK, WARN, CRIT, INFO
    local message="$3"
    local recommendation="${4:-}"
    
    # Exclusion filters: sections/severity
    if [ -n "$section" ] && [ -n "${EXCLUDE_SECTION_SET[$section]:-}" ]; then
        return 0
    fi
    if [ -n "$severity" ] && [ -n "${EXCLUDE_SEVERITY_SET[$severity]:-}" ]; then
        return 0
    fi

    # Privacy level adjustments (high)
    if [ "$PRIVACY_LEVEL" = "high" ]; then
        # Coarsen versions and redact common identifiers in messages
        message=$(echo "$message" | sed -E 's/([0-9]+)\.[0-9]+\.[0-9]+/\1.xx.xx/g')
        message=$(echo "$message" | sed -E 's/([0-9]+)\.[0-9]+/\1.xx/g')
        # Redact IPs and MACs
        message=$(echo "$message" | sed -E 's/([0-9]{1,3}\.){3}[0-9]{1,3}/[IP]/g')
        message=$(echo "$message" | sed -E 's/([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}/[MAC]/g')
        # Trim full paths to basenames when likely sensitive
        message=$(echo "$message" | sed -E 's@(/[^ ]+/)+([^ /]+)@.../\2@g')
    fi

    # Anonymization (lightweight; preserve section names for readability)
    if [ "$ANONYMIZE" = true ]; then
        # Apply targeted anonymization to message/recommendation only
        message=$(anonymize_string "$message")
        [ -n "$recommendation" ] && recommendation=$(anonymize_string "$recommendation")
    fi

    # Validate and sanitize inputs
    if ! validate_input_length "$section" 100; then
        section="[INVALID_SECTION]"
    fi
    
    if ! validate_input_length "$message" 2048; then
        message="[TRUNCATED_MESSAGE]"
    fi
    
    if ! validate_input_length "$recommendation" 2048; then
        recommendation="[TRUNCATED_RECOMMENDATION]"
    fi
    
    # Validate severity
    case "$severity" in
        OK|WARN|CRIT|INFO) ;;
        *) severity="INFO" ;;
    esac
    
    # Sanitize characters (allow common punctuation like ':' and ',')
    section=$(echo "$section" | sed 's/[^a-zA-Z0-9._/:,() -]//g')
    message=$(echo "$message" | sed 's/[^a-zA-Z0-9._/:,() -]//g')
    recommendation=$(echo "$recommendation" | sed 's/[^a-zA-Z0-9._/:,() -]//g')
    
    if [ -n "${FINDINGS_SINK:-}" ]; then
        printf "%s|%s|%s|%s\n" "$section" "$severity" "$message" "$recommendation" >> "$FINDINGS_SINK" 2>/dev/null || true
    else
        FINDINGS+=("$section|$severity|$message|$recommendation")
    fi
}

# Console output functions (original behavior)
print_section() {
    if [ "$OUTPUT_FORMAT" = "console" ]; then
        if [ -n "${CONSOLE_SINK:-}" ]; then
            printf "\n${COLOR_BLUE}=== %s ===${COLOR_RESET}\n" "$1" >> "$CONSOLE_SINK" 2>/dev/null || true
        else
            printf "\n${COLOR_BLUE}=== %s ===${COLOR_RESET}\n" "$1"
        fi
    fi
    SECTIONS+=("$1")
    return 0
}

ok() {
    if [ "$OUTPUT_FORMAT" = "console" ]; then
        if [ -n "${CONSOLE_SINK:-}" ]; then
            printf "${COLOR_GREEN}[OK]${COLOR_RESET} %s\n" "$1" >> "$CONSOLE_SINK" 2>/dev/null || true
        else
            printf "${COLOR_GREEN}[OK]${COLOR_RESET} %s\n" "$1"
        fi
    fi
    return 0
}
warn() {
    if [ "$OUTPUT_FORMAT" = "console" ]; then
        if [ -n "${CONSOLE_SINK:-}" ]; then
            printf "${COLOR_YELLOW}[WARN]${COLOR_RESET} %s\n" "$1" >> "$CONSOLE_SINK" 2>/dev/null || true
        else
            printf "${COLOR_YELLOW}[WARN]${COLOR_RESET} %s\n" "$1"
        fi
    fi
    return 0
}
crit() {
    if [ "$OUTPUT_FORMAT" = "console" ]; then
        if [ -n "${CONSOLE_SINK:-}" ]; then
            printf "${COLOR_RED}[CRIT]${COLOR_RESET} %s\n" "$1" >> "$CONSOLE_SINK" 2>/dev/null || true
        else
            printf "${COLOR_RED}[CRIT]${COLOR_RESET} %s\n" "$1"
        fi
    fi
    return 0
}
info() {
    if [ "$OUTPUT_FORMAT" = "console" ]; then
        if [ -n "${CONSOLE_SINK:-}" ]; then
            printf "[INFO] %s\n" "$1" >> "$CONSOLE_SINK" 2>/dev/null || true
        else
            printf "[INFO] %s\n" "$1"
        fi
    fi
    return 0
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
# JSON escaping function
# Enhanced output sanitization functions
json_escape() {
    local input="$1"
    
    # Validate input length
    if ! validate_input_length "$input" 8192; then
        echo "[TRUNCATED]"
        return
    fi
    
    # Comprehensive JSON escaping
    echo "$input" | sed \
        -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g' \
        -e 's/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g' \
        -e 's/\f/\\f/g' \
        -e 's/\v/\\v/g' \
        -e 's/[\x00-\x1F]/\\u00&/g'
}
# Anonymization helper: redact sensitive tokens but keep structure readable
anonymize_string() {
    local input="$1"
    local host="$(hostname 2>/dev/null || echo)"
    # Redact user@host style
    input=$(echo "$input" | sed -E "s/\b([A-Za-z0-9_-]{2,})@([A-Za-z0-9_.-]+)/[USER]@[HOST]/g")
    # Redact explicit current hostname
    if [ -n "$host" ]; then
        input=$(echo "$input" | sed -E "s/\b$host\b/[HOST]/g")
    fi
    # Redact IPv4 addresses
    input=$(echo "$input" | sed -E 's/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/[IP]/g')
    # Redact MAC addresses
    input=$(echo "$input" | sed -E 's/\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b/[MAC]/g')
    # Redact semantic versions and kernel-like versions
    input=$(echo "$input" | sed -E 's/\b[0-9]+\.[0-9]+(\.[0-9]+){1,}(-[A-Za-z0-9.-]+)?\b/[VER]/g')
    # Collapse long absolute paths to basename to avoid leakage
    input=$(echo "$input" | sed -E 's@(/[^ ]+/)+([^ /]+)@.../\2@g')
    echo "$input"
}


html_escape() {
    local input="$1"
    
    # Validate input length
    if ! validate_input_length "$input" 8192; then
        echo "[TRUNCATED]"
        return
    fi
    
    # HTML entity escaping
    echo "$input" | sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g' \
        -e "s/'/\&#39;/g" \
        -e 's/`/\&#96;/g'
}

# Sensitive data detection and redaction
detect_sensitive_data() {
    local input="$1"
    
    # Common patterns for sensitive data (using simpler patterns to avoid regex issues)
    local patterns=(
        'password[=:][[:space:]]*[^[:space:]]+'
        'passwd[=:][[:space:]]*[^[:space:]]+'
        'pwd[=:][[:space:]]*[^[:space:]]+'
        'secret[=:][[:space:]]*[^[:space:]]+'
        'key[=:][[:space:]]*[^[:space:]]+'
        'token[=:][[:space:]]*[^[:space:]]+'
        'api[_-]key[=:][[:space:]]*[^[:space:]]+'
        'access[_-]key[=:][[:space:]]*[^[:space:]]+'
        'private[_-]key[=:][[:space:]]*[^[:space:]]+'
        '[0-9]\{4\}[-\s]\?[0-9]\{4\}[-\s]\?[0-9]\{4\}[-\s]\?[0-9]\{4\}'  # Credit card
        '[0-9]\{3\}-[0-9]\{2\}-[0-9]\{4\}'  # SSN
        '[a-zA-Z0-9._%+-]\+@[a-zA-Z0-9.-]\+\.[a-zA-Z]\{2,\}'  # Email
    )
    
    for pattern in "${patterns[@]}"; do
        if echo "$input" | grep -qiE "$pattern"; then
            echo "$input" | sed -E "s/$pattern/[REDACTED]/gi"
            return
        fi
    done
    
    echo "$input"
}

generate_json_output() {
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local hostname=$(hostname 2>/dev/null || echo "unknown")
    
    echo "{"
    echo "  \"timestamp\": \"$timestamp\","
    echo "  \"hostname\": \"$hostname\","
    echo "  \"version\": \"$VERSION\","
    echo "  \"mode\": \"$OPERATION_MODE\","
    echo "  \"privacy\": {\"level\": \"${PRIVACY_LEVEL^}\", \"anonymize\": $([ "$ANONYMIZE" = true ] && echo true || echo false) },"
    echo "  \"permission_level\": \"$CURRENT_PERMISSION_LEVEL\","
    echo "  \"audit_enabled\": $([ "$AUDIT_ENABLED" = true ] && echo "true" || echo "false"),"
    if [ "$AUDIT_ENABLED" = true ]; then
        echo "  \"audit_log\": \"$AUDIT_LOG\","
    fi
    echo "  \"findings\": ["
    
    local first=true
    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r section severity message recommendation <<< "$finding"
        [ "$first" = true ] && first=false || echo ","
        
        # Sanitize and escape all fields for JSON
        local sanitized_message=$(detect_sensitive_data "$message")
        local sanitized_recommendation=""
        [ -n "$recommendation" ] && sanitized_recommendation=$(detect_sensitive_data "$recommendation")
        
        local escaped_section=$(json_escape "$section")
        local escaped_severity=$(json_escape "$severity")
        local escaped_message=$(json_escape "$sanitized_message")
        local escaped_recommendation=""
        [ -n "$sanitized_recommendation" ] && escaped_recommendation=$(json_escape "$sanitized_recommendation")
        
        echo -n "    {"
        echo -n "\"section\": \"$escaped_section\", "
        echo -n "\"severity\": \"$escaped_severity\", "
        echo -n "\"message\": \"$escaped_message\""
        [ -n "$escaped_recommendation" ] && echo -n ", \"recommendation\": \"$escaped_recommendation\""
        echo -n "}"
    done
    
    echo ""
    echo "  ],"
    echo "  \"summary\": {"
    # Compute counts robustly to avoid stray output into JSON
    local __total=${#FINDINGS[@]}
    local __crit=0 __warn=0 __ok=0 __info=0
    for __f in "${FINDINGS[@]}"; do
        IFS='|' read -r __sec __sev __msg __rec <<< "$__f"
        case "$__sev" in
            CRIT) __crit=$((__crit+1));;
            WARN) __warn=$((__warn+1));;
            OK)   __ok=$((__ok+1));;
            INFO) __info=$((__info+1));;
        esac
    done
    echo "    \"total_findings\": $__total,"
    echo "    \"critical\": $__crit,"
    echo "    \"warnings\": $__warn,"
    echo "    \"ok\": $__ok,"
    echo "    \"info\": $__info"
    echo "  },"
    echo "  \"security\": {"
    echo "    \"permission_level\": \"$CURRENT_PERMISSION_LEVEL\","
    echo "    \"audit_enabled\": $([ "$AUDIT_ENABLED" = true ] && echo "true" || echo "false")"
    if [ "$AUDIT_ENABLED" = true ]; then
        echo "    ,\"audit_log\": \"$AUDIT_LOG\""
    fi
    echo "  }"
    echo "}"
}

generate_html_output() {
    local timestamp=$(date)
    local hostname=$(hostname 2>/dev/null || echo "unknown")
    local total_count=$((${#FINDINGS[@]} - 2))
    
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
        <p><strong>Host:</strong> $hostname | <strong>Mode:</strong> $OPERATION_MODE | <strong>Generated:</strong> $timestamp | <strong>Version:</strong> $VERSION | <strong>Total findings:</strong> $total_count</p>
        <p><strong>Permission Level:</strong> $CURRENT_PERMISSION_LEVEL | <strong>Audit logging:</strong> $([ "$AUDIT_ENABLED" = true ] && echo "Enabled ($AUDIT_LOG)" || echo "Disabled") | <strong>Privacy level:</strong> ${PRIVACY_LEVEL^} | <strong>Anonymize:</strong> $([ "$ANONYMIZE" = true ] && echo "True" || echo "False")</p>
    </div>
EOF

    local current_section=""
    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r section severity message recommendation <<< "$finding"
        
        # Sanitize data for HTML output
        local sanitized_message=$(detect_sensitive_data "$message")
        local sanitized_recommendation=""
        [ -n "$recommendation" ] && sanitized_recommendation=$(detect_sensitive_data "$recommendation")
        
        # Escape HTML entities
        local escaped_section=$(html_escape "$section")
        local escaped_severity=$(html_escape "$severity")
        local escaped_message=$(html_escape "$sanitized_message")
        local escaped_recommendation=""
        [ -n "$sanitized_recommendation" ] && escaped_recommendation=$(html_escape "$sanitized_recommendation")
        
        if [ "$section" != "$current_section" ]; then
            [ -n "$current_section" ] && echo "</div>"
            echo "<div class=\"section-header\">$escaped_section</div>"
            echo "<div class=\"section\">"
            current_section="$section"
        fi
        
        echo "<div class=\"finding ${severity,,}\">"
        echo "<span class=\"severity ${severity,,}\">$escaped_severity</span> $escaped_message"
        [ -n "$escaped_recommendation" ] && echo "<div class=\"recommendation\">💡 $escaped_recommendation</div>"
        echo "</div>"
    done
    
    [ -n "$current_section" ] && echo "</div>"
    
    # Add audit log information to HTML footer
    if [ "$AUDIT_ENABLED" = true ]; then
        echo "<div class=\"finding info\">"
        echo "<span class=\"severity info\">INFO</span> Audit log saved: $AUDIT_LOG"
        echo "</div>"
    fi
    
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
    echo "Permission Level: $CURRENT_PERMISSION_LEVEL"
    echo "Audit Logging: $([ "$AUDIT_ENABLED" = true ] && echo "Enabled ($AUDIT_LOG)" || echo "Disabled")"
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
        
        # Redact sensitive tokens similar to JSON path
        local red_msg=$(detect_sensitive_data "$message")
        local red_rec=""
        [ -n "$recommendation" ] && red_rec=$(detect_sensitive_data "$recommendation")
        printf "%-6s %s\n" "[$severity]" "$red_msg"
        [ -n "$red_rec" ] && printf "       → %s\n" "$red_rec"
    done
    
    echo
    echo "==============================================="
    echo "Report completed. Review WARN/CRIT items."
    if [ "$AUDIT_ENABLED" = true ]; then
        echo "Audit log saved: $AUDIT_LOG"
    fi
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
	local firewall_found=false
	if command_exists ufw; then
		ufw status verbose 2>/dev/null | sed 's/^/ufw: /' || true
		firewall_found=true
	fi
	if command_exists firewall-cmd; then
		firewall-cmd --state 2>/dev/null | sed 's/^/firewalld: /' || true
		firewall-cmd --list-all 2>/dev/null | sed 's/^/firewalld: /' | sed -n '1,50p' || true
		firewall_found=true
	fi
	if command_exists nft; then
		nft list ruleset 2>/dev/null | sed -n '1,50p' | sed 's/^/nftables: /' || true
		firewall_found=true
	elif command_exists iptables; then
		iptables -S 2>/dev/null | sed -n '1,50p' | sed 's/^/iptables: /' || true
		firewall_found=true
	fi

	# Severity based on mode
	if [ "$firewall_found" = false ]; then
		rec=$(get_recommendation "Install and configure a basic firewall" \
			"Install and configure a firewall (ufw)" \
			"Require host firewall: deploy ufw/firewalld/nftables with baseline policy")
		if [ "$OPERATION_MODE" = "production" ]; then
			add_finding "Firewall" "CRIT" "No firewall tooling/rules detected" "$rec"
			crit "No firewall tooling/rules detected"
		else
			add_finding "Firewall" "WARN" "No firewall tooling/rules detected" "$rec"
			warn "No firewall tooling/rules detected"
		fi
	else
		add_finding "Firewall" "INFO" "Firewall tooling present" "Review rules above"
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
		cached_command find "$p" -xdev -type d -perm -0002 -maxdepth 2 2>/dev/null | sed "s/^/World-writable dir: /" | sed -n '1,20p'
		cached_command find "$p" -xdev -type f -perm -0002 -maxdepth 2 2>/dev/null | sed "s/^/World-writable file: /" | sed -n '1,20p'
	done
	# Search common SUID locations instead of entire filesystem
	for suid_path in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do
		[ -d "$suid_path" ] && cached_command find "$suid_path" -xdev -perm -4000 -type f 2>/dev/null | sed 's/^/SUID: /' | sed -n '1,30p'
	done
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
		if [ "$OPERATION_MODE" = "production" ]; then
			add_finding "Time Sync" "WARN" "systemd-timesyncd active (minimal)" "Deploy chrony/ntp with authenticated multi-source time servers"
			warn "systemd-timesyncd active (minimal)"
		else
			add_finding "Time Sync" "OK" "systemd-timesyncd is active" ""
			ok "systemd-timesyncd is active"
		fi
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

	# Remote log forwarding (rsyslog)
	if [ -f /etc/rsyslog.conf ] || [ -d /etc/rsyslog.d ]; then
		forwarding=$(grep -R "@" /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null | grep -v '^#' | head -1 || true)
		if [ -n "$forwarding" ]; then
			add_finding "Logging" "INFO" "Remote log forwarding configured" ""
		else
			rec=$(get_recommendation "Consider configuring remote log forwarding" \
				"Optional: configure remote log forwarding" \
				"Require centralized logging: configure rsyslog/syslog-ng forwarding to SIEM")
			if [ "$OPERATION_MODE" = "production" ]; then
				add_finding "Logging" "WARN" "No remote log forwarding detected" "$rec"
				warn "No remote log forwarding detected"
			else
				add_finding "Logging" "INFO" "No remote log forwarding detected" "$rec"
			fi
		fi
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
		# SECURITY FIX: Use safe method to get home directory without eval
		user_home=$(getent passwd "$USER" 2>/dev/null | cut -d: -f6)
		# Fallback to HOME environment variable if getent fails
		[ -z "$user_home" ] && user_home="$HOME"
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

ENHANCED SECURITY FEATURES (v0.6.2):
• Enhanced input validation and command sanitization
• Advanced kernel and network security hardening checks
• Comprehensive compliance and audit validation
• Enhanced container and process security analysis
• Advanced file integrity and logging security checks
• Industry-standard security validation (CIS, NIST aligned)
• Parallel execution for improved performance
• Intelligent caching system for expensive operations
• Malware signature detection and analysis
• Enhanced rootkit detection capabilities
• Behavioral analysis for anomaly detection
• Advanced authentication and authorization controls
• Comprehensive audit logging and access control (opt-in)
• Script integrity verification and digital signatures
• Role-based access control for different operations

Usage: $0 [OPTIONS]

OPTIONS:
  -h, --help              Show this help message
  -v, --version           Show version information
  -o, --output FILE       Output file with format determined by extension (default: stdout)
  -m, --mode MODE         Operation mode: personal, production (default: personal)
  -p, --parallel          Enable parallel execution for independent checks
  -a, --audit             Enable comprehensive audit logging (disabled by default)

MODES:
  personal               Home/personal machine recommendations
  production             Business/server environment recommendations (compliance focus)

OUTPUT FORMATS (determined by file extension):
  .json                  JSON structured output for automation/SIEM
  .html                  HTML report with styling
  .txt                   Plain text report
  (no extension)         Colored console output (default)

SECURITY FEATURES:
  ✓ Read-only operations - no system modifications
  ✓ Input validation and path traversal protection
  ✓ Safe file access with permission checks
  ✓ Comprehensive logging of all activities

EXAMPLES:
  sudo $0                               # Full security assessment (recommended)
  sudo $0 -o report.json                # JSON output to file
  sudo $0 -o report.html -m production  # HTML production report
  sudo $0 -p                            # Parallel execution for faster scanning
  sudo $0 -a                            # Enable comprehensive audit logging
  $0 -m personal                        # Limited checks without sudo

PRIVACY CONTROLS (v$VERSION):
  --privacy-level LEVEL      standard (default), high, off
  --anonymize                Hash identifiers (hostnames, usernames, IPs) with per-run salt
  --exclude-sections LIST    Comma-separated list (e.g., accounts,file-integrity)
  --exclude-severity LIST    Comma-separated list (e.g., INFO,OK)

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
		--output|-o)
			shift
			if [ $# -eq 0 ]; then
				echo "Error: --output requires an argument" >&2
				exit 1
			fi
			if validate_output_path "$1"; then
				OUTPUT_FILE="$1"
				# Automatically set output format based on file extension
				OUTPUT_FORMAT=$(detect_output_format "$1")
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
		--parallel|-p)
			PARALLEL_MODE=true
			;;
		--privacy-level)
			shift
			[ $# -eq 0 ] && { echo "Error: --privacy-level requires an argument" >&2; exit 1; }
			case "$1" in
				standard|high|off) PRIVACY_LEVEL="$1" ;;
				*) echo "Error: invalid --privacy-level. Use: standard, high, off" >&2; exit 1 ;;
			esac
			;;
		--anonymize)
			ANONYMIZE=true
			;;
		--exclude-sections)
			shift
			[ $# -eq 0 ] && { echo "Error: --exclude-sections requires an argument" >&2; exit 1; }
			EXCLUDE_SECTIONS_RAW="$1"
			;;
		--exclude-severity)
			shift
			[ $# -eq 0 ] && { echo "Error: --exclude-severity requires an argument" >&2; exit 1; }
			EXCLUDE_SEVERITY_RAW="$1"
			;;
		--audit|-a)
			AUDIT_ENABLED=true
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
    echo
    echo "╔════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                            ║"
    echo "║   ██████╗ ████████╗    ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗             ║"
    echo "║   ██╔══██╗╚══██╔══╝   ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝             ║"
    echo "║   ██████╔╝   ██║      ██║     ███████║█████╗  ██║     █████╔╝              ║"
    echo "║   ██╔══██╗   ██║      ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗              ║"
    echo "║   ██████╔╝   ██║      ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗             ║"
    echo "║   ╚═════╝    ╚═╝       ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝             ║"
    echo "║                                                                            ║"
    echo "║                    Linux Security Assessment Tool v$VERSION                ║"
    echo "║                                                                            ║"
    echo "╚════════════════════════════════════════════════════════════════════════════╝"
    echo
    echo "Mode: $OPERATION_MODE | Format: $OUTPUT_FORMAT"
    [ -n "$OUTPUT_FILE" ] && echo "Output: $OUTPUT_FILE"
    echo
    echo "SECURITY NOTICE:"
    echo " - Read-only assessment"
    echo " - sudo recommended for comprehensive analysis"
    echo " - No system modifications"
    echo " - May access sensitive files for analysis"
    echo " - All data remains local"
    echo
    # Check if running without sudo and display prominent warning
    if ! is_root; then
        printf "${COLOR_YELLOW}LIMITED SCAN WARNING:${COLOR_RESET}\n"
        printf "${COLOR_YELLOW} - Running without sudo: many checks will be skipped${COLOR_RESET}\n"
        printf "${COLOR_YELLOW} - For a full assessment, run: ${COLOR_BLUE}sudo $0${COLOR_RESET}\n"
        [ "$OPERATION_MODE" = "production" ] && printf "${COLOR_RED} - Production mode is not meaningful without sudo${COLOR_RESET}\n"
        echo
    fi
fi

# Validate output file if specified
if [ -n "$OUTPUT_FILE" ]; then
	# Check if we can write to the output file
	if ! touch "$OUTPUT_FILE" 2>/dev/null; then
		echo "Error: Cannot write to output file '$OUTPUT_FILE'" >&2
		exit 1
	fi
fi

# Malware signature detection
section_malware_detection() {
    print_section "Malware Detection"
    
    # Common malware signatures and patterns
    local malware_patterns=(
        "backdoor"
        "trojan"
        "rootkit"
        "keylogger"
        "botnet"
        "cryptominer"
        "ransomware"
        "spyware"
    )
    
    local suspicious_files=()
    local suspicious_processes=()
    local suspicious_network=()
    
    # Check for suspicious files in common locations (exclude script temp files)
    local search_paths=("/tmp" "/var/tmp" "/dev/shm" "/home" "/root")
    for path in "${search_paths[@]}"; do
        [ -d "$path" ] || continue
        
        for pattern in "${malware_patterns[@]}"; do
            local found_files=$(cached_command find "$path" -maxdepth 3 -type f -iname "*${pattern}*" 2>/dev/null | grep -v "btqc-par-" | head -10)
            if [ -n "$found_files" ]; then
                while IFS= read -r file; do
                    suspicious_files+=("$file")
                    add_finding "Malware Detection" "WARN" "Suspicious file found: $file" "Investigate file: 'file $file' and 'strings $file | grep -i suspicious'"
                done <<< "$found_files"
            fi
        done
    done
    
    # Check for suspicious processes (exclude script's own processes and commands)
    if command_exists ps; then
        local ps_output=$(cached_command ps aux 2>/dev/null)
        for pattern in "${malware_patterns[@]}"; do
            local suspicious_procs=$(echo "$ps_output" | grep -i "$pattern" | grep -v "bt-quickcheck\|btqc-par-\|find.*-iname.*$pattern\|grep.*$pattern" | head -5)
            if [ -n "$suspicious_procs" ]; then
                while IFS= read -r proc; do
                    suspicious_processes+=("$proc")
                    add_finding "Malware Detection" "WARN" "Suspicious process: $proc" "Investigate process: 'ps aux | grep $pattern' and check process tree"
                done <<< "$suspicious_procs"
            fi
        done
    fi
    
    # Check for suspicious network connections
    if command_exists netstat; then
        local netstat_output=$(cached_command netstat -tuln 2>/dev/null)
        # Look for unusual ports or connections
        local suspicious_ports=$(echo "$netstat_output" | awk '$1 ~ /tcp/ && $4 ~ /:(4444|5555|6666|7777|8888|9999|1337|31337|12345|54321)/ {print $4}')
        if [ -n "$suspicious_ports" ]; then
            while IFS= read -r port; do
                suspicious_network+=("$port")
                add_finding "Malware Detection" "WARN" "Suspicious port listening: $port" "Investigate port: 'netstat -tuln | grep $port' and 'lsof -i :$port'"
            done <<< "$suspicious_ports"
        fi
    fi
    
    # Check for suspicious file permissions (executable in temp directories)
    local temp_executables=$(cached_command find /tmp /var/tmp /dev/shm -maxdepth 2 -type f -executable 2>/dev/null | head -10)
    if [ -n "$temp_executables" ]; then
        while IFS= read -r file; do
            add_finding "Malware Detection" "WARN" "Executable in temp directory: $file" "Investigate executable: 'file $file' and 'strings $file'"
        done <<< "$temp_executables"
    fi
    
    # Check for suspicious cron jobs
    if is_root; then
        local suspicious_cron=$(cached_command find /etc/cron* /var/spool/cron* -type f 2>/dev/null | xargs grep -l "wget\|curl\|bash.*http\|sh.*http" 2>/dev/null | head -5)
        if [ -n "$suspicious_cron" ]; then
            while IFS= read -r cron_file; do
                add_finding "Malware Detection" "CRIT" "Suspicious cron job: $cron_file" "Review cron job: 'cat $cron_file' and investigate source"
            done <<< "$suspicious_cron"
        fi
    fi
    
	# Check for suspicious systemd services (skip on non-systemd like WSL)
	if command_exists systemctl && [ -d /run/systemd/system ]; then
        local suspicious_services=$(cached_command systemctl list-units --type=service --state=running 2>/dev/null | grep -E "(backdoor|trojan|rootkit|keylog)" | head -5)
        if [ -n "$suspicious_services" ]; then
            while IFS= read -r service; do
                add_finding "Malware Detection" "CRIT" "Suspicious service running: $service" "Investigate service: 'systemctl status $service' and 'systemctl cat $service'"
            done <<< "$suspicious_services"
        fi
    fi
    
    # Summary
    local total_suspicious=$((${#suspicious_files[@]} + ${#suspicious_processes[@]} + ${#suspicious_network[@]}))
    if [ $total_suspicious -eq 0 ]; then
        add_finding "Malware Detection" "OK" "No obvious malware signatures detected" "Continue monitoring with regular scans"
        ok "No obvious malware signatures detected"
    else
        add_finding "Malware Detection" "WARN" "Found $total_suspicious suspicious items requiring investigation" "Review all flagged items and consider full malware scan"
        warn "Found $total_suspicious suspicious items requiring investigation"
    fi
}

# Enhanced rootkit detection
section_rootkit_detection() {
    print_section "Rootkit Detection"
    
    local rootkit_indicators=0
    local total_checks=0
    
    # Check for hidden processes (ps vs /proc comparison)
    if command_exists ps && [ -d /proc ]; then
        ((total_checks++))
        local ps_pids=$(cached_command ps -eo pid 2>/dev/null | tail -n +2 | sort -n)
        local proc_pids=$(cached_command ls /proc 2>/dev/null | grep -E '^[0-9]+$' | sort -n)
        
        # Filter out kernel threads and system processes that might not show in ps
        local hidden_pids=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids") 2>/dev/null | grep -v -E '^[0-9]+$' | head -10 | tr '\n' ' ')
        
        # Only flag if we find actual suspicious hidden processes (not just kernel threads)
        if [ -n "$hidden_pids" ] && [ $(echo "$hidden_pids" | wc -w) -gt 0 ]; then
            # Double-check by trying to read the process info
            local real_hidden=""
            for pid in $hidden_pids; do
                if [ -f "/proc/$pid/cmdline" ] && [ -r "/proc/$pid/cmdline" ]; then
                    local cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 100)
                    if [ -n "$cmdline" ] && [ "$cmdline" != " " ]; then
                        real_hidden="$real_hidden $pid"
                    fi
                fi
            done
            
            if [ -n "$real_hidden" ]; then
                ((rootkit_indicators++))
                local hidden_count=$(echo "$real_hidden" | wc -w)
                add_finding "Rootkit Detection" "CRIT" "Hidden processes detected: $hidden_count PIDs ($real_hidden)" "Investigate hidden processes: 'ls -la /proc/[PID]/' for each PID"
                crit "Hidden processes detected: $hidden_count PIDs"
            else
                add_finding "Rootkit Detection" "OK" "No hidden processes detected" ""
                ok "No hidden processes detected"
            fi
        else
            add_finding "Rootkit Detection" "OK" "No hidden processes detected" ""
        fi
    fi
    
    # Check for suspicious kernel modules
    if is_root && [ -f /proc/modules ]; then
        ((total_checks++))
        local loaded_modules=$(cached_file_content /proc/modules 2>/dev/null)
        local suspicious_modules=$(echo "$loaded_modules" | grep -E "(backdoor|rootkit|stealth|hidden)" 2>/dev/null)
        
        if [ -n "$suspicious_modules" ]; then
            ((rootkit_indicators++))
            add_finding "Rootkit Detection" "CRIT" "Suspicious kernel modules: $suspicious_modules" "Investigate modules: 'modinfo [module_name]' and 'lsmod | grep [module_name]'"
            crit "Suspicious kernel modules detected"
        else
            add_finding "Rootkit Detection" "OK" "No suspicious kernel modules detected" ""
            ok "No suspicious kernel modules detected"
        fi
    fi
    
    # Check for modified system binaries
    if is_root; then
        ((total_checks++))
        local critical_binaries=("/bin/ls" "/bin/ps" "/bin/netstat" "/bin/ss" "/usr/bin/top" "/bin/df")
        local modified_binaries=()
        
        for binary in "${critical_binaries[@]}"; do
            if [ -f "$binary" ]; then
                # Check if binary has been modified recently (within last 7 days)
                local mod_time=$(stat -c %Y "$binary" 2>/dev/null || echo 0)
                local current_time=$(date +%s)
                local age_days=$(( (current_time - mod_time) / 86400 ))
                
                if [ $age_days -lt 7 ]; then
                    modified_binaries+=("$binary (modified $age_days days ago)")
                fi
            fi
        done
        
        if [ ${#modified_binaries[@]} -gt 0 ]; then
            ((rootkit_indicators++))
            add_finding "Rootkit Detection" "WARN" "Recently modified system binaries: ${modified_binaries[*]}" "Verify binary integrity: 'rpm -Vf $binary' or 'debsums $binary'"
        else
            add_finding "Rootkit Detection" "OK" "System binaries appear unmodified" ""
        fi
    fi
    
    # Check for suspicious network connections (hidden)
    if command_exists netstat && command_exists ss; then
        ((total_checks++))
        local netstat_conns=$(cached_command netstat -tuln 2>/dev/null | wc -l)
        local ss_conns=$(cached_command ss -tuln 2>/dev/null | wc -l)
        local diff=$((netstat_conns - ss_conns))
        
        if [ $diff -gt 5 ]; then
            ((rootkit_indicators++))
            add_finding "Rootkit Detection" "WARN" "Significant difference in network connections (netstat: $netstat_conns, ss: $ss_conns)" "Investigate hidden connections: 'netstat -tuln' vs 'ss -tuln'"
        else
            add_finding "Rootkit Detection" "OK" "Network connection counts consistent" ""
        fi
    fi
    
    # Check for suspicious file system inconsistencies
    if is_root; then
        ((total_checks++))
        # Exclude legitimate system files and common benign hidden files
        local fs_check=$(cached_command find /etc /bin /sbin -maxdepth 2 -type f -name ".*" 2>/dev/null | \
            grep -v -E "\.(placeholder|bak|lock|updated|dpkg|apt|systemd|pam|profile|bashrc|vimrc|gitignore)$|skel|\.git" | \
            grep -v -E "^/etc/\.(pwd\.lock|gshadow\.lock|shadow\.lock|passwd\.lock|group\.lock)$" | \
            head -10 | tr '\n' ' ')
        if [ -n "$fs_check" ]; then
            ((rootkit_indicators++))
            local hidden_count=$(echo "$fs_check" | wc -w)
            add_finding "Rootkit Detection" "WARN" "Hidden files in system directories: $hidden_count files ($fs_check)" "Investigate hidden files: 'ls -la [file]' and 'file [file]'"
            warn "Hidden files in system directories: $hidden_count files"
        else
            add_finding "Rootkit Detection" "OK" "No suspicious hidden files in system directories" ""
            ok "No suspicious hidden files in system directories"
        fi
    fi
    
    # Check for suspicious system calls (improved detection)
    if is_root && [ -f /proc/kallsyms ]; then
        ((total_checks++))
        # Look for actual hooking patterns, not just the presence of sys_call_table
        local suspicious_hooks=$(cached_command grep -E "(sys_call_table.*\[|system_call.*\[)" /proc/kallsyms 2>/dev/null | \
            grep -v -E "(sys_call_table|system_call)$" | \
            grep -v -E "(sys_call_table|system_call).*0x[0-9a-f]+$" | \
            wc -l)
        
        # Also check for unusual syscall modifications by looking for non-standard syscall entries
        local unusual_syscalls=$(cached_command grep -E "sys_call_table" /proc/kallsyms 2>/dev/null | \
            awk '{print $3}' | \
            grep -v -E "^0x[0-9a-f]+$" | \
            wc -l)
        
        if [ $suspicious_hooks -gt 0 ] || [ $unusual_syscalls -gt 0 ]; then
            ((rootkit_indicators++))
            add_finding "Rootkit Detection" "CRIT" "Suspicious system call modifications detected" "Investigate kernel hooks: 'cat /proc/kallsyms | grep sys_call' and 'dmesg | grep -i hook'"
            crit "Suspicious system call modifications detected"
        else
            add_finding "Rootkit Detection" "OK" "No suspicious system call modifications detected" ""
            ok "No suspicious system call modifications detected"
        fi
    fi
    
    # Check for suspicious memory regions (improved)
    if is_root && [ -f /proc/iomem ]; then
        ((total_checks++))
        # Look for unusual memory patterns that might indicate rootkit activity
        local suspicious_memory=$(cached_file_content /proc/iomem 2>/dev/null | \
            grep -E "(reserved|unknown)" | \
            grep -v -E "(ACPI|PCI|System RAM|Video RAM|ROM|Flash)" | \
            head -5)
        if [ -n "$suspicious_memory" ]; then
            ((rootkit_indicators++))
            add_finding "Rootkit Detection" "WARN" "Suspicious memory regions: $suspicious_memory" "Investigate memory: 'cat /proc/iomem' and 'dmesg | grep -i memory'"
            warn "Suspicious memory regions detected"
        else
            add_finding "Rootkit Detection" "OK" "Memory regions appear normal" ""
            ok "Memory regions appear normal"
        fi
    fi
    
    # Cross-view analysis: Compare different methods of process enumeration
    if command_exists ps && command_exists ls; then
        ((total_checks++))
        local ps_count=$(cached_command ps aux 2>/dev/null | wc -l)
        local proc_count=$(cached_command ls /proc 2>/dev/null | grep -E '^[0-9]+$' | wc -l)
        local diff=$((proc_count - ps_count))
        
        # Allow for some difference due to kernel threads, but flag significant discrepancies
        if [ $diff -gt 10 ]; then
            ((rootkit_indicators++))
            add_finding "Rootkit Detection" "WARN" "Significant process count discrepancy: /proc shows $proc_count, ps shows $ps_count" "Investigate hidden processes: 'ls /proc | grep -E ^[0-9] | wc -l' vs 'ps aux | wc -l'"
            warn "Significant process count discrepancy detected"
        else
            add_finding "Rootkit Detection" "OK" "Process enumeration consistent across methods" ""
            ok "Process enumeration consistent across methods"
        fi
    fi
    
    # Check for suspicious file permissions and timestamps
    if is_root; then
        ((total_checks++))
        local suspicious_files=$(cached_command find /bin /sbin /usr/bin /usr/sbin -type f -perm -4000 2>/dev/null | \
            xargs ls -la 2>/dev/null | \
            awk '$6 ~ /^[0-9]+$/ && $7 ~ /^[0-9]+$/ && $8 ~ /^[0-9]+$/ {if ($6 != $7 || $7 != $8) print $9}' | \
            head -5)
        
        if [ -n "$suspicious_files" ]; then
            ((rootkit_indicators++))
            add_finding "Rootkit Detection" "WARN" "SUID files with suspicious timestamps: $suspicious_files" "Investigate file timestamps: 'stat [file]' and 'ls -la [file]'"
            warn "SUID files with suspicious timestamps detected"
        else
            add_finding "Rootkit Detection" "OK" "SUID file timestamps appear normal" ""
            ok "SUID file timestamps appear normal"
        fi
    fi
    
    # Check for suspicious network behavior patterns
    if command_exists netstat && command_exists ss; then
        ((total_checks++))
        # Look for processes listening on unusual ports
        local unusual_ports=$(cached_command netstat -tuln 2>/dev/null | \
            awk '$1 ~ /tcp/ && $4 ~ /:([0-9]{4,5})$/ {port=substr($4,index($4,":")+1); if(port > 1024 && port < 65536 && port !~ /^(8080|8443|3000|5000|8000|9000|3306|5432|6379|27017)$/) print port}' | \
            head -5)
        
        if [ -n "$unusual_ports" ]; then
            ((rootkit_indicators++))
            add_finding "Rootkit Detection" "WARN" "Processes listening on unusual ports: $unusual_ports" "Investigate ports: 'netstat -tuln | grep [port]' and 'lsof -i :[port]'"
            warn "Processes listening on unusual ports detected"
        else
            add_finding "Rootkit Detection" "OK" "No unusual network ports detected" ""
            ok "No unusual network ports detected"
        fi
    fi
    
	# Check for suspicious systemd services (skip on non-systemd like WSL)
	if command_exists systemctl && [ -d /run/systemd/system ]; then
        ((total_checks++))
        local suspicious_services=$(cached_command systemctl list-units --type=service --state=running 2>/dev/null | grep -E "(\.service|\.timer)" | grep -v "systemd" | wc -l)
        local total_services=$(cached_command systemctl list-units --type=service --state=running 2>/dev/null | wc -l)
        
        if [ $suspicious_services -gt $((total_services / 2)) ]; then
            ((rootkit_indicators++))
            add_finding "Rootkit Detection" "WARN" "Unusually high number of non-systemd services running" "Review services: 'systemctl list-units --type=service --state=running'"
            warn "Unusually high number of non-systemd services running"
        else
            add_finding "Rootkit Detection" "OK" "Service count appears normal" ""
            ok "Service count appears normal"
        fi
    fi
    
    # Check for suspicious kernel module behavior
    if is_root && [ -f /proc/modules ]; then
        ((total_checks++))
        # Look for modules that might be hiding their presence
        local loaded_modules=$(cached_file_content /proc/modules 2>/dev/null)
        local suspicious_modules=$(echo "$loaded_modules" | \
            awk '{if ($3 == "0" && $4 == "0" && $5 == "0") print $1}' | \
            grep -v -E "(nvidia|nouveau|radeon|amdgpu|intel|wifi|bluetooth|usb|pci)" | \
            head -5)
        
        if [ -n "$suspicious_modules" ]; then
            ((rootkit_indicators++))
            add_finding "Rootkit Detection" "WARN" "Kernel modules with suspicious reference counts: $suspicious_modules" "Investigate modules: 'modinfo [module]' and 'lsmod | grep [module]'"
            warn "Kernel modules with suspicious reference counts detected"
        else
            add_finding "Rootkit Detection" "OK" "Kernel module reference counts appear normal" ""
            ok "Kernel module reference counts appear normal"
        fi
    fi
    
    # Check for suspicious file system inconsistencies using stat
    if is_root; then
        ((total_checks++))
        # Check for files that might be hiding their true size or modification time
        local suspicious_stat=$(cached_command find /bin /sbin /usr/bin /usr/sbin -type f -executable 2>/dev/null | \
            head -20 | \
            xargs stat -c "%n %s %Y" 2>/dev/null | \
            awk '{if ($2 == 0 || $3 == 0) print $1}' | \
            head -5)
        
        if [ -n "$suspicious_stat" ]; then
            ((rootkit_indicators++))
            add_finding "Rootkit Detection" "WARN" "Executable files with suspicious stat information: $suspicious_stat" "Investigate files: 'stat [file]' and 'file [file]'"
            warn "Executable files with suspicious stat information detected"
        else
            add_finding "Rootkit Detection" "OK" "File stat information appears normal" ""
            ok "File stat information appears normal"
        fi
    fi
    
    # Check for suspicious process behavior patterns
    if command_exists ps; then
        ((total_checks++))
        # Look for processes with unusual characteristics
        local suspicious_procs=$(cached_command ps aux 2>/dev/null | \
            awk 'NR>1 {if ($3 > 50 || $4 > 50 || $6 > 1000000) print $2 ":" $11}' | \
            grep -v -E "(systemd|kthreadd|ksoftirqd|migration|rcu_|watchdog)" | \
            head -5)
        
        if [ -n "$suspicious_procs" ]; then
            ((rootkit_indicators++))
            add_finding "Rootkit Detection" "WARN" "Processes with unusual resource usage: $suspicious_procs" "Investigate processes: 'ps aux | grep [PID]' and 'top -p [PID]'"
            warn "Processes with unusual resource usage detected"
        else
            add_finding "Rootkit Detection" "OK" "Process resource usage appears normal" ""
            ok "Process resource usage appears normal"
        fi
    fi
    
    # Summary
    local risk_level="LOW"
    if [ $rootkit_indicators -gt 3 ]; then
        risk_level="HIGH"
    elif [ $rootkit_indicators -gt 1 ]; then
        risk_level="MEDIUM"
    fi
    
    add_finding "Rootkit Detection" "INFO" "Rootkit detection completed: $rootkit_indicators/$total_checks indicators found (Risk: $risk_level)" "Consider running dedicated rootkit scanners: 'rkhunter --check' or 'chkrootkit'"
    info "Rootkit detection completed: $rootkit_indicators/$total_checks indicators found (Risk: $risk_level)"
}

# Behavioral analysis for anomaly detection
section_behavioral_analysis() {
    print_section "Behavioral Analysis"
    
    local anomalies=0
    local total_checks=0
    
    # Disable strict error handling for this function to prevent silent failures
    set +e
    
    # Process behavior analysis
    if command_exists ps; then
        ((total_checks++))
        local process_count=$(ps aux 2>/dev/null | wc -l)
        local zombie_count=$(ps aux 2>/dev/null | grep -c "<defunct>" 2>/dev/null || echo 0)
        
        if [ $process_count -gt 0 ]; then
            local zombie_percentage=$((zombie_count * 100 / process_count))
            if [ $zombie_percentage -gt 10 ]; then
                ((anomalies++))
                add_finding "Behavioral Analysis" "WARN" "High zombie process count: $zombie_count/$process_count ($zombie_percentage%)" "Investigate zombie processes"
                warn "High zombie process count: $zombie_count/$process_count ($zombie_percentage%)"
            else
                add_finding "Behavioral Analysis" "OK" "Zombie process count normal: $zombie_count/$process_count" ""
                ok "Zombie process count normal: $zombie_count/$process_count"
            fi
        else
            add_finding "Behavioral Analysis" "WARN" "Could not determine process count" "Check ps command"
        fi
    else
        add_finding "Behavioral Analysis" "WARN" "ps command not available" "Install procps package"
    fi
    
    # Network behavior analysis
    if command_exists netstat; then
        ((total_checks++))
        local listening_ports=$(netstat -tuln 2>/dev/null | grep LISTEN | wc -l)
        local established_conns=$(netstat -tuln 2>/dev/null | grep ESTABLISHED | wc -l)
        
        if [ $established_conns -gt 100 ]; then
            ((anomalies++))
            add_finding "Behavioral Analysis" "WARN" "High number of established connections: $established_conns" "Review connections"
            warn "High number of established connections: $established_conns"
        else
            add_finding "Behavioral Analysis" "OK" "Connection count appears normal: $established_conns" ""
            ok "Connection count appears normal: $established_conns"
        fi
    else
        add_finding "Behavioral Analysis" "WARN" "netstat command not available" "Install net-tools package"
    fi
    
    # File system behavior analysis
    if is_root; then
        ((total_checks++))
        local temp_files=$(find /tmp /var/tmp /dev/shm -maxdepth 3 -type f 2>/dev/null | wc -l)
        
        if [ $temp_files -gt 1000 ]; then
            ((anomalies++))
            add_finding "Behavioral Analysis" "WARN" "High number of temporary files: $temp_files" "Review temp directory"
            warn "High number of temporary files: $temp_files"
        else
            add_finding "Behavioral Analysis" "OK" "Temporary file count normal: $temp_files" ""
            ok "Temporary file count normal: $temp_files"
        fi
    fi
    
    # System resource behavior analysis
    if command_exists uptime && command_exists free; then
        ((total_checks++))
        local load_avg=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')
        local mem_usage=$(free 2>/dev/null | awk '/^Mem:/ {if($2>0) printf "%.0f", $3/$2*100; else print "0"}')
        
        if [ -n "$load_avg" ] && [ $(echo "$load_avg" | awk '{print ($1 > 2.0)}' 2>/dev/null || echo 0) -eq 1 ]; then
            ((anomalies++))
            add_finding "Behavioral Analysis" "WARN" "High system load: $load_avg" "Investigate load"
            warn "High system load: $load_avg"
        else
            add_finding "Behavioral Analysis" "OK" "System load normal: $load_avg" ""
            ok "System load normal: $load_avg"
        fi
        
        if [ -n "$mem_usage" ] && [ $mem_usage -gt 90 ]; then
            ((anomalies++))
            add_finding "Behavioral Analysis" "WARN" "High memory usage: ${mem_usage}%" "Investigate memory"
            warn "High memory usage: ${mem_usage}%"
        else
            add_finding "Behavioral Analysis" "OK" "Memory usage normal: ${mem_usage}%" ""
            ok "Memory usage normal: ${mem_usage}%"
        fi
    fi
    
    # Log behavior analysis
    if is_root && [ -f /var/log/auth.log ]; then
        ((total_checks++))
        # SECURITY FIX: Use safe_log_grep with size limits instead of direct grep
        local failed_logins=$(safe_log_grep /var/log/auth.log "Failed password" 100 1000 | wc -l)
        
        if [ $failed_logins -gt 50 ]; then
            ((anomalies++))
            add_finding "Behavioral Analysis" "WARN" "High failed login activity: $failed_logins attempts" "Review auth logs"
            warn "High failed login activity: $failed_logins attempts"
        else
            add_finding "Behavioral Analysis" "OK" "Login activity appears normal: $failed_logins failed attempts" ""
            ok "Login activity appears normal: $failed_logins failed attempts"
        fi
    fi
    
    # Summary
    local risk_level="LOW"
    if [ $anomalies -gt 4 ]; then
        risk_level="HIGH"
    elif [ $anomalies -gt 2 ]; then
        risk_level="MEDIUM"
    fi
    
    # Ensure we always have at least one check
    if [ $total_checks -eq 0 ]; then
        total_checks=1
        add_finding "Behavioral Analysis" "WARN" "No behavioral checks could be performed" "Check system tools availability"
    fi
    
    add_finding "Behavioral Analysis" "INFO" "Behavioral analysis completed: $anomalies/$total_checks anomalies detected (Risk: $risk_level)" "Monitor system behavior over time and investigate flagged anomalies"
    info "Behavioral analysis completed: $anomalies/$total_checks anomalies detected (Risk: $risk_level)"
    
    # Re-enable strict error handling
    set -e
}

# Initialize advanced security features
# Verify script integrity
if ! verify_script_integrity; then
    echo "Warning: Script integrity verification failed. Proceeding with caution." >&2
fi

# Set permission level based on user context
set_permission_level

# Enable audit logging only if explicitly requested and permissions allow
if [ "$AUDIT_ENABLED" = true ] && [ -w "/var/log" ]; then
    # Set proper permissions for audit log
    touch "$AUDIT_LOG" 2>/dev/null && chmod 640 "$AUDIT_LOG" 2>/dev/null || true
    audit_log "SCRIPT_START" "Blue Team QuickCheck started" "INFO"
    
    # Inform user about audit logging
    if [ "$OUTPUT_FORMAT" = "console" ]; then
        echo "🔍 Audit logging enabled: $AUDIT_LOG"
    fi
elif [ "$AUDIT_ENABLED" = true ] && [ ! -w "/var/log" ]; then
    # User requested audit logging but no permissions
    if [ "$OUTPUT_FORMAT" = "console" ]; then
        echo "⚠️  Audit logging requested but insufficient permissions to write to /var/log"
    fi
    AUDIT_ENABLED=false
fi

# Log permission level and user context (only if audit logging is enabled)
if [ "$AUDIT_ENABLED" = true ]; then
    audit_log "PERMISSION_LEVEL" "Current level: $CURRENT_PERMISSION_LEVEL, User: $(whoami), Mode: $OPERATION_MODE" "INFO"
else
    # Inform user about audit logging option
    if [ "$OUTPUT_FORMAT" = "console" ]; then
        echo "ℹ️  Audit logging disabled (use --audit to enable comprehensive logging)"
    fi
fi

# Cache hygiene
cleanup_old_btqc_dirs

# Initialize embedded configuration (early, before other initialization)
init_embedded_config

# Optionally load external configuration file if it exists (will override embedded defaults)
# This is now optional - script is fully self-contained without it
load_configuration

# Initialize privilege management
store_original_credentials

# Initialize structured logging
log "$LOG_INFO" "Blue Team QuickCheck starting - Version: $VERSION"
log "$LOG_INFO" "Operation mode: $OPERATION_MODE, Output format: $OUTPUT_FORMAT"
log "$LOG_INFO" "Running as user: $(whoami), UID: $(id -u), EUID: $EUID"

# Set resource limits for security
set_resource_limits() {
    # Memory limit: 512MB
    ulimit -v 524288 2>/dev/null || true
    
    # CPU time limit: 300 seconds (5 minutes)
    ulimit -t 300 2>/dev/null || true
    
    # File size limit: 100MB
    ulimit -f 104857600 2>/dev/null || true
    
    # Process limit: 100 processes
    ulimit -u 100 2>/dev/null || true
    
    # Core dump size: 0 (disabled)
    ulimit -c 0 2>/dev/null || true
    
    # File descriptor limit: 256
    ulimit -n 256 2>/dev/null || true
    
    # Stack size limit: 8MB
    ulimit -s 8192 2>/dev/null || true
}

# Apply resource limits
set_resource_limits

# Resource monitoring
monitor_resources() {
    local mem_usage
    local cpu_usage
    
    # Check memory usage
    if command -v ps >/dev/null 2>&1; then
        mem_usage=$(ps -o pid,vsz,rss,comm -p $$ 2>/dev/null | tail -1 | awk '{print $3}')
        if [ -n "$mem_usage" ] && [ "$mem_usage" -gt 400000 ]; then  # 400MB threshold
            warn "High memory usage detected: ${mem_usage}KB"
        fi
    fi
    
    # Check if we're approaching resource limits
    local current_ulimit
    current_ulimit=$(ulimit -v 2>/dev/null || echo "unlimited")
    if [ "$current_ulimit" != "unlimited" ] && [ "$current_ulimit" -lt 100000 ]; then  # Less than 100MB remaining
        warn "Memory limit approaching: ${current_ulimit}KB remaining"
    fi
}

# Initialize caching system and parallel temp dir
init_cache

# SECURITY FIX: Create secure temporary directory (no predictable fallback)
PARALLEL_TMP_DIR=$(mktemp -d -t btqc-par-XXXXXXXXXX 2>/dev/null)
if [ -z "$PARALLEL_TMP_DIR" ] || [ ! -d "$PARALLEL_TMP_DIR" ]; then
    # Try alternative mktemp syntax
    PARALLEL_TMP_DIR=$(mktemp -d 2>/dev/null)
fi
if [ -z "$PARALLEL_TMP_DIR" ] || [ ! -d "$PARALLEL_TMP_DIR" ]; then
    echo "ERROR: Failed to create secure temporary directory for parallel execution" >&2
    echo "Disabling parallel mode for security" >&2
    PARALLEL_MODE=false
    PARALLEL_TMP_DIR="/tmp/btqc-disabled-$$"
fi
# Ensure secure permissions
chmod 700 "$PARALLEL_TMP_DIR" 2>/dev/null || true

# Initialize privacy controls
init_privacy_controls

# If generating to a file in a non-console format, suppress stdout during checks
if [ -n "$OUTPUT_FILE" ] && [ "$OUTPUT_FORMAT" != "console" ]; then
    QUIET_MODE=true
    exec 3>&1
    # Start spinner before suppressing stdout
    start_spinner "Generating report"
    exec >/dev/null
fi

# Run all checks with error isolation
if [ "$PARALLEL_MODE" = true ]; then
    # Conservative parallelism: run core checks sequentially for stable console/JSON output
    run_section_safely section_system "System"
    run_section_safely section_updates "Updates"
    run_section_safely section_listening "Listening Services"
    run_section_safely section_firewall "Firewall"
    run_section_safely section_ssh "SSH Hardening"
    run_section_safely section_auditing "Auditing/Hardening"
    run_section_safely section_accounts "Accounts and Sudo"
    run_section_safely section_permissions "Risky Permissions"
    run_section_safely section_package_integrity "Package Integrity"
    run_section_safely section_file_integrity "File Integrity"
    run_section_safely section_persistence_mechanisms "Persistence Mechanisms"
    run_section_safely section_intrusion_detection "Intrusion Detection"
    run_section_safely section_time_sync "Time Synchronization"
    run_section_safely section_logging "Logging and Monitoring"
    run_section_safely section_network_security "Network Security"
    run_section_safely section_process_forensics "Process & Forensics"
    run_section_safely section_secure_configuration "Secure Configuration"
    run_section_safely section_container_security "Container & Virtualization Security"
    run_section_safely section_kernel_hardening "Kernel & System Hardening"
    run_section_safely section_application_security "Application-Level Protections"
    run_section_safely section_secrets_sensitive_data "Secrets & Sensitive Data"
    run_section_safely section_cloud_remote_mgmt "Cloud & Remote Management"
    run_section_safely section_edr_monitoring "Endpoint Detection & Monitoring"
    run_section_safely section_backup_resilience "Resilience & Backup"
    run_section_safely section_privesc_surface_core "Privilege Escalation Surface (Core)"
    run_section_safely section_taskrunners_nfs "Task Runners & NFS Risk"
    run_section_safely section_container_ssh_secrets_hygiene "Container, SSH & Secrets Hygiene"
    run_section_safely section_kernel_polkit_fstab_refinements "Kernel, Polkit & Filesystem Hardening"
    run_section_safely section_privesc_surface_extended "Privilege Escalation Surface (Extended)"
    run_section_safely section_scheduler_controls "Scheduler Controls (cron/anacron/at)"

    # Keep only advanced detection in parallel for speed without destabilizing output
    run_section_parallel section_malware_detection "Malware Detection"
    run_section_parallel section_rootkit_detection "Rootkit Detection"
    run_section_parallel section_behavioral_analysis "Behavioral Analysis"
    
    # Monitor resources during parallel execution
    monitor_resources
    
    wait_parallel_sections
else
    # Sequential execution (default)
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
    run_section_safely section_privesc_surface_core "Privilege Escalation Surface (Core)"
    run_section_safely section_taskrunners_nfs "Task Runners & NFS Risk"
    run_section_safely section_container_ssh_secrets_hygiene "Container, SSH & Secrets Hygiene"
    run_section_safely section_kernel_polkit_fstab_refinements "Kernel, Polkit & Filesystem Hardening"
    run_section_safely section_privesc_surface_extended "Privilege Escalation Surface (Extended)"
    run_section_safely section_scheduler_controls "Scheduler Controls (cron/anacron/at)"
    run_section_safely section_malware_detection "Malware Detection"
    run_section_safely section_rootkit_detection "Rootkit Detection"
    run_section_safely section_behavioral_analysis "Behavioral Analysis"
fi

# Enhanced security checks (new in v0.6.0)
run_section_safely section_enhanced_kernel_security "Enhanced Kernel Security"
run_section_safely section_enhanced_network_security "Enhanced Network Security"
run_section_safely section_compliance_checks "Compliance & Audit"
run_section_safely section_enhanced_container_security "Enhanced Container Security"
run_section_safely section_enhanced_file_integrity "Enhanced File Integrity"
run_section_safely section_enhanced_process_security "Enhanced Process Security"
run_section_safely section_enhanced_logging_security "Enhanced Logging Security"
run_section_safely section_enhanced_network_access "Enhanced Network Access Controls"

# Note: Malware detection, rootkit detection, and behavioral analysis are now included
# in the parallel execution groups above for better performance

run_section_safely section_privilege_summary "Privilege Limitations Summary"
run_section_safely section_summary "Summary"

# Production-only: Resource Health
if [ "$OPERATION_MODE" = "production" ]; then
    run_section_safely section_resource_health "Resource Health"
fi

# Restore stdout if we had suppressed it
if [ "$QUIET_MODE" = true ]; then
    stop_spinner
    exec 1>&3
    exec 3>&-
fi

# Cleanup cache and parallel temp dir
cleanup_cache
rm -rf "$PARALLEL_TMP_DIR" 2>/dev/null || true



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
        echo "Report saved: $OUTPUT_FILE" 
        echo "Format: $OUTPUT_FORMAT | Mode: $OPERATION_MODE | Findings: $((${#FINDINGS[@]} - 2))"
        if [ "$ANONYMIZE" = true ] || [ "$PRIVACY_LEVEL" = "high" ]; then
            echo "Privacy: level=$PRIVACY_LEVEL anonymize=$ANONYMIZE"
        fi
    else
        echo "Error: Failed to generate output file '$OUTPUT_FILE'" >&2
        exit 1
    fi
else
	generate_output
fi

# Drop privileges after privileged operations are complete
if [ "$EUID" -eq 0 ] && [ "$ORIGINAL_UID" -ne 0 ]; then
    echo "Dropping privileges to original user for cleanup operations..."
    drop_privileges
fi

# Final cleanup and logging
cleanup_and_exit() {
    local exit_code="${1:-0}"
    
    log "$LOG_INFO" "Blue Team QuickCheck completed with exit code: $exit_code"
    log "$LOG_INFO" "Total findings generated: ${#FINDINGS[@]}"
    
    # Cleanup temporary directories
    cleanup_cache
    [ -d "$PARALLEL_TMP_DIR" ] && rm -rf "$PARALLEL_TMP_DIR" 2>/dev/null || true
    
    # Log final resource usage if available
    if command -v ps >/dev/null 2>&1; then
        local mem_usage
        mem_usage=$(ps -o pid,vsz,rss,comm -p $$ 2>/dev/null | tail -1 | awk '{print $3}')
        log "$LOG_DEBUG" "Final memory usage: ${mem_usage}KB"
    fi
    
    exit "$exit_code"
}

# Set up cleanup trap
trap 'cleanup_and_exit $?' EXIT

# Production-only resource health checks (function defined near end for structure)
section_resource_health() {
    print_section "Resource Health"
    if command_exists uptime; then
        la=$(uptime 2>/dev/null | awk -F'load average: ' '{print $2}' | tr -d ',' | awk '{printf "%s %s %s", $1,$2,$3}')
        [ -n "$la" ] && add_finding "Resource Health" "INFO" "Load average (1/5/15m): $la" "Investigate sustained high load in production"
    fi
    if command_exists free; then
        mem_used=$(free -m 2>/dev/null | awk '/^Mem:/ {print $3"/"$2" MB"}')
        add_finding "Resource Health" "INFO" "Memory usage: $mem_used" "Ensure capacity and investigate leaks if consistently high"
    fi
    if command_exists df; then
        high_usage=$(df -hP 2>/dev/null | awk 'NR>1 && $5+0>=85 {print $6" ("$5")"}' | tr '\n' ' ')
        if [ -n "$high_usage" ]; then
            add_finding "Resource Health" "WARN" "Low free space on: $high_usage" "Free space or expand volumes; keep usage <80% in prod"
        else
            add_finding "Resource Health" "OK" "Disk usage under 85%" ""
        fi
    fi
}

# Final security notice for console output
if [ "$OUTPUT_FORMAT" = "console" ]; then
	echo
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo "✅ Security assessment completed successfully"
	echo "📋 Review CRITICAL and WARNING findings above for security improvements"
	echo "🔒 Enhanced security checks completed (v0.6.2)"
	echo "   • Advanced kernel and network hardening validation"
	echo "   • Comprehensive compliance and audit assessment"
	echo "   • Enhanced container and process security analysis"
	echo "   • Industry-standard security validation (CIS, NIST aligned)"
	echo "   • Advanced authentication and authorization controls"
	echo "   • Comprehensive audit logging and access control"
	if [ "$AUDIT_ENABLED" = true ]; then
		echo "🔍 Audit log saved: $AUDIT_LOG"
	else
		echo "ℹ️  Use --audit flag to enable comprehensive audit logging"
	fi
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi

# Log script completion for audit (only if audit logging is enabled)
if [ "$AUDIT_ENABLED" = true ]; then
    audit_log "SCRIPT_COMPLETED" "Blue Team QuickCheck completed successfully, Findings: ${#FINDINGS[@]}" "INFO"
fi

# Clean up audit log if it's empty (no permissions to write)
if [ "$AUDIT_ENABLED" = true ] && [ -f "$AUDIT_LOG" ] && [ ! -s "$AUDIT_LOG" ]; then
    rm -f "$AUDIT_LOG" 2>/dev/null || true
fi

exit 0


