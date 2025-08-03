#!/bin/bash

# Secret WAR - Advanced Git Pre-commit Security Scanner
# "Dread it, Run from it. Destiny Still arrives"
# Version: 1.0.0

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$HOME/.secret-war"
PATTERNS_FILE="$CONFIG_DIR/patterns.conf"
WHITELIST_FILES="$CONFIG_DIR/whitelist-files.conf"
WHITELIST_PATTERNS="$CONFIG_DIR/whitelist-patterns.conf"
BYPASS_FILE="$CONFIG_DIR/bypass.conf"
REPORT_DIR="$CONFIG_DIR/reports"
TEMP_DIR="/tmp/secret-war-$$"
LOADER_PID_FILE="$TEMP_DIR/loader.pid"
MAX_THREADS=8

# Banner
show_banner() {
    echo -e "${PURPLE}"
    cat << 'EOF'
   ██████  ███████  ██████ ██████  ███████ ████████     ██     ██  █████  ████████ 
  ██       ██      ██      ██   ██ ██         ██        ██     ██ ██   ██ ██     ██
  ██████   █████   ██      ██████  █████      ██        ██  █  ██ ███████ ██████  
       ██  ██      ██      ██   ██ ██         ██        ██ ███ ██ ██   ██ ██   ██ 
  ██████   ███████  ██████ ██   ██ ███████    ██         ███ ███  ██   ██ ██   ██ 
                                                                                    
                    Advanced Git Pre-commit Security Scanner
                         "Dread it, Run from it. Destiny Still arrives"
EOF
    echo -e "${NC}"
}

# Cleanup function
cleanup() {
    if [[ -f "$LOADER_PID_FILE" ]]; then
        local loader_pid=$(cat "$LOADER_PID_FILE" 2>/dev/null || echo "")
        if [[ -n "$loader_pid" ]] && kill -0 "$loader_pid" 2>/dev/null; then
            kill "$loader_pid" 2>/dev/null || true
        fi
        rm -f "$LOADER_PID_FILE"
    fi
    
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT

# Show loading animation
show_loader() {
    local message="$1"
    local pid_file="$2"
    
    # GUI loader for desktop environments
    if [[ -n "${DISPLAY:-}" ]] || [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
        if command -v zenity >/dev/null 2>&1; then
            (
                zenity --progress --pulsate --no-cancel --auto-close \
                       --title="Secret WAR" \
                       --text="$message" \
                       --width=400 --height=100 2>/dev/null &
                echo $! > "$pid_file"
                wait
            ) &
            return
        elif command -v kdialog >/dev/null 2>&1; then
            (
                kdialog --progressbar "$message" --title "Secret WAR" &
                echo $! > "$pid_file"
                wait
            ) &
            return
        elif command -v osascript >/dev/null 2>&1; then
            (
                osascript -e "display dialog \"$message\" with title \"Secret WAR\" buttons {\"Cancel\"} default button 1 giving up after 1" &
                echo $! > "$pid_file"
                wait
            ) &
            return
        fi
    fi
    
    # Terminal loader fallback
    (
        local spinner='|/-\'
        local i=0
        echo -e "\n${YELLOW}$message${NC}"
        while true; do
            printf "\r${CYAN}[${spinner:$i:1}] Scanning in progress...${NC}"
            i=$(( (i+1) %4 ))
            sleep 0.2
        done
    ) &
    echo $! > "$pid_file"
}

# Stop loader
stop_loader() {
    if [[ -f "$LOADER_PID_FILE" ]]; then
        local loader_pid=$(cat "$LOADER_PID_FILE" 2>/dev/null || echo "")
        if [[ -n "$loader_pid" ]] && kill -0 "$loader_pid" 2>/dev/null; then
            kill "$loader_pid" 2>/dev/null || true
        fi
        rm -f "$LOADER_PID_FILE"
    fi
    
    # Close any GUI dialogs
    if command -v pkill >/dev/null 2>&1; then
        pkill -f "zenity.*Secret WAR" 2>/dev/null || true
        pkill -f "kdialog.*Secret WAR" 2>/dev/null || true
    fi
    
    # Clear terminal spinner
    printf "\r${NC}%50s\r" " "
}

# Initialize configuration directory
init_config() {
    mkdir -p "$CONFIG_DIR" "$REPORT_DIR" "$TEMP_DIR"
    
    # Create default patterns file
    if [[ ! -f "$PATTERNS_FILE" ]]; then
        cat > "$PATTERNS_FILE" << 'EOF'
# Secret WAR Pattern Configuration
# Add one regex pattern per line

# API Keys and Tokens
[a-zA-Z0-9_-]*api[_-]?key[a-zA-Z0-9_-]*\s*[:=]\s*['"'"'"][a-zA-Z0-9_-]{8,}['"'"'"]
[a-zA-Z0-9_-]*token[a-zA-Z0-9_-]*\s*[:=]\s*['"'"'"][a-zA-Z0-9_-]{8,}['"'"'"]
[a-zA-Z0-9_-]*secret[a-zA-Z0-9_-]*\s*[:=]\s*['"'"'"][a-zA-Z0-9_-]{8,}['"'"'"]

# AWS Credentials
AKIA[0-9A-Z]{16}
aws_access_key_id\s*[:=]\s*['"'"'"]?[A-Z0-9]{20}['"'"'"]?
aws_secret_access_key\s*[:=]\s*['"'"'"]?[A-Za-z0-9/+=]{40}['"'"'"]?

# Google API Keys
AIza[0-9A-Za-z_-]{35}
ya29\.[0-9A-Za-z_-]+

# GitHub Tokens
ghp_[a-zA-Z0-9]{36}
gho_[a-zA-Z0-9]{36}
ghu_[a-zA-Z0-9]{36}
ghs_[a-zA-Z0-9]{36}
ghr_[a-zA-Z0-9]{36}

# Private Keys
-----BEGIN\s+(RSA\s+|DSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----
-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----

# Database Connection Strings
(mongodb|mysql|postgresql|oracle|sqlserver)://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+
jdbc:[a-zA-Z0-9]+://[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_.-]+

# Email and Phone Patterns
[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
\+?[1-9]\d{1,14}

# Credit Card Numbers
4[0-9]{12}(?:[0-9]{3})?
5[1-5][0-9]{14}
3[47][0-9]{13}
3[0-9]{13}
6(?:011|5[0-9]{2})[0-9]{12}

# Social Security Numbers
\b\d{3}-\d{2}-\d{4}\b
\b\d{3}\s\d{2}\s\d{4}\b

# IP Addresses (Private)
\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b
\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b
\b192\.168\.\d{1,3}\.\d{1,3}\b

# JWT Tokens
eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*

# Docker Registry Tokens
[a-zA-Z0-9_-]*docker[a-zA-Z0-9_-]*\s*[:=]\s*['"'"'"][a-zA-Z0-9_-]{20,}['"'"'"]

# Slack Tokens
xox[baprs]-[0-9a-zA-Z-]{10,48}

# Generic Passwords
password\s*[:=]\s*['"'"'"][^'"'"'"]{8,}['"'"'"]
passwd\s*[:=]\s*['"'"'"][^'"'"'"]{8,}['"'"'"]
pwd\s*[:=]\s*['"'"'"][^'"'"'"]{8,}['"'"'"]

# Cryptocurrency Addresses
[13][a-km-zA-HJ-NP-Z1-9]{25,34}
bc1[a-z0-9]{39,59}
0x[a-fA-F0-9]{40}

# Azure Tokens
[a-zA-Z0-9_-]*azure[a-zA-Z0-9_-]*\s*[:=]\s*['"'"'"][a-zA-Z0-9_-]{20,}['"'"'"]

# Twilio
SK[a-z0-9]{32}
AC[a-z0-9]{32}

# SendGrid
SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}

# Stripe
sk_live_[0-9a-zA-Z]{24}
pk_live_[0-9a-zA-Z]{24}

# PayPal
access_token\$production\$[a-z0-9]{16}\$[a-z0-9]{32}

# Square
sq0atp-[0-9A-Za-z_-]{22}
sq0csp-[0-9A-Za-z_-]{43}
EOF
    fi
    
    # Create default whitelist files
    if [[ ! -f "$WHITELIST_FILES" ]]; then
        cat > "$WHITELIST_FILES" << 'EOF'
# Secret WAR File Whitelist
# Add file patterns to ignore (one per line)

# IDE and Editor files
.vscode/
.idea/
*.swp
*.swo
*~

# Build and dependency files
node_modules/
vendor/
target/
build/
dist/
*.class
*.jar
*.war

# Log files
*.log
logs/

# Temporary files
*.tmp
*.temp

# Binary files
*.exe
*.dll
*.so
*.dylib
*.bin
*.dat

# Image files
*.jpg
*.jpeg
*.png
*.gif
*.bmp
*.ico
*.svg

# Archive files
*.zip
*.tar
*.gz
*.rar
*.7z

# Documentation
*.pdf
*.doc
*.docx

# OS generated files
.DS_Store
Thumbs.db
EOF
    fi
    
    # Create default whitelist patterns
    if [[ ! -f "$WHITELIST_PATTERNS" ]]; then
        cat > "$WHITELIST_PATTERNS" << 'EOF'
# Secret WAR Pattern Whitelist
# Add regex patterns to whitelist (one per line)

# Test files and examples
test.*password.*=.*example
.*example.*key.*=.*dummy
.*sample.*token.*=.*fake
.*mock.*secret.*=.*test

# Documentation patterns
#.*api.*key.*in.*documentation
#.*token.*example.*in.*readme

# Environment template files  
.*\.env\.template
.*\.env\.example
.*\.env\.sample
EOF
    fi
    
    # Create bypass configuration
    if [[ ! -f "$BYPASS_FILE" ]]; then
        cat > "$BYPASS_FILE" << 'EOF'
# Secret WAR Bypass Configuration
# Set bypass=true to skip security checks (USE WITH CAUTION!)
# Set bypass_remember=true to remember bypass choice

bypass=false
bypass_remember=false
EOF
    fi
}

# Load configuration
load_config() {
    local config_file="$1"
    local key="$2"
    local default_value="$3"
    
    if [[ -f "$config_file" ]]; then
        local value=$(grep "^${key}=" "$config_file" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        echo "${value:-$default_value}"
    else
        echo "$default_value"
    fi
}

# Save configuration
save_config() {
    local config_file="$1"
    local key="$2"
    local value="$3"
    
    if [[ -f "$config_file" ]]; then
        if grep -q "^${key}=" "$config_file"; then
            sed -i.bak "s/^${key}=.*/${key}=${value}/" "$config_file"
        else
            echo "${key}=${value}" >> "$config_file"
        fi
    else
        echo "${key}=${value}" > "$config_file"
    fi
}

# Check bypass configuration
check_bypass() {
    local bypass=$(load_config "$BYPASS_FILE" "bypass" "false")
    local bypass_remember=$(load_config "$BYPASS_FILE" "bypass_remember" "false")
    
    if [[ "$bypass" == "true" ]]; then
        if [[ "$bypass_remember" == "true" ]]; then
            echo -e "${YELLOW}⚠️  Security scan bypassed (remembered choice)${NC}"
            return 0
        else
            echo -e "${YELLOW}⚠️  Bypass is enabled. Reset bypass? (y/N):${NC}"
            read -r reset_bypass
            if [[ "$reset_bypass" =~ ^[Yy]$ ]]; then
                save_config "$BYPASS_FILE" "bypass" "false"
                save_config "$BYPASS_FILE" "bypass_remember" "false"
                echo -e "${GREEN}✅ Bypass disabled${NC}"
                return 1
            else
                return 0
            fi
        fi
    fi
    return 1
}

# Offer bypass option
offer_bypass() {
    echo -e "${RED}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                    SECURITY ALERT                             ║"
    echo "║            Dread it, Run from it. Destiny Still arrives       ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${YELLOW}Do you want to bypass this security check? (y/N):${NC}"
    read -r bypass_choice
    
    if [[ "$bypass_choice" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Remember this choice? (y/N):${NC}"
        read -r remember_choice
        
        save_config "$BYPASS_FILE" "bypass" "true"
        
        if [[ "$remember_choice" =~ ^[Yy]$ ]]; then
            save_config "$BYPASS_FILE" "bypass_remember" "true"
            echo -e "${YELLOW}⚠️  Security bypass enabled and remembered${NC}"
        else
            save_config "$BYPASS_FILE" "bypass_remember" "false"
            echo -e "${YELLOW}⚠️  Security bypass enabled for this session${NC}"
        fi
        
        return 0
    fi
    
    return 1
}

# Load patterns from config
load_patterns() {
    local patterns=()
    while IFS= read -r line; do
        if [[ ! "$line" =~ ^[[:space:]]*# ]] && [[ -n "${line// }" ]]; then
            patterns+=("$line")
        fi
    done < "$PATTERNS_FILE"
    printf '%s\n' "${patterns[@]}"
}

# Load whitelist files
load_whitelist_files() {
    local files=()
    if [[ -f "$WHITELIST_FILES" ]]; then
        while IFS= read -r line; do
            if [[ ! "$line" =~ ^[[:space:]]*# ]] && [[ -n "${line// }" ]]; then
                files+=("$line")
            fi
        done < "$WHITELIST_FILES"
    fi
    printf '%s\n' "${files[@]}"
}

# Load whitelist patterns
load_whitelist_patterns() {
    local patterns=()
    if [[ -f "$WHITELIST_PATTERNS" ]]; then
        while IFS= read -r line; do
            if [[ ! "$line" =~ ^[[:space:]]*# ]] && [[ -n "${line// }" ]]; then
                patterns+=("$line")
            fi
        done < "$WHITELIST_PATTERNS"
    fi
    printf '%s\n' "${patterns[@]}"
}

# Check if file should be whitelisted
is_file_whitelisted() {
    local file="$1"
    local whitelist_files
    readarray -t whitelist_files < <(load_whitelist_files)
    
    for pattern in "${whitelist_files[@]}"; do
        if [[ "$file" == *"$pattern"* ]]; then
            return 0
        fi
    done
    return 1
}

# Check if match should be whitelisted
is_match_whitelisted() {
    local match="$1"
    local whitelist_patterns
    readarray -t whitelist_patterns < <(load_whitelist_patterns)
    
    for pattern in "${whitelist_patterns[@]}"; do
        if echo "$match" | grep -qE "$pattern"; then
            return 0
        fi
    done
    return 1
}

# Scan file for patterns
scan_file() {
    local file="$1"
    local output_file="$2"
    local patterns
    readarray -t patterns < <(load_patterns)
    
    if is_file_whitelisted "$file"; then
        return 0
    fi
    
    if ! file "$file" | grep -q text; then
        return 0
    fi
    
    local found_issues=0
    
    for pattern in "${patterns[@]}"; do
        if [[ -n "$pattern" ]]; then
            local matches
            matches=$(git grep -n -E "$pattern" -- "$file" 2>/dev/null || true)
            
            if [[ -n "$matches" ]]; then
                while IFS= read -r match; do
                    if ! is_match_whitelisted "$match"; then
                        echo "$match" >> "$output_file"
                        found_issues=1
                    fi
                done <<< "$matches"
            fi
        fi
    done
    
    return $found_issues
}

# Get staged files
get_staged_files() {
    git diff --cached --name-only --diff-filter=ACM | grep -v -E '\.(gitignore|gitattributes)$|\.git/|\.vscode/|\.idea/' || true
}

# Process files in parallel
process_files_parallel() {
    local files=("$@")
    local temp_results=()
    local pids=()
    
    mkdir -p "$TEMP_DIR"
    
    local chunk_size=$(( (${#files[@]} + MAX_THREADS - 1) / MAX_THREADS ))
    local chunk_num=0
    
    for ((i=0; i<${#files[@]}; i+=chunk_size)); do
        local chunk=("${files[@]:i:chunk_size}")
        local result_file="$TEMP_DIR/result_$chunk_num"
        temp_results+=("$result_file")
        
        {
            for file in "${chunk[@]}"; do
                if [[ -f "$file" ]]; then
                    scan_file "$file" "$result_file"
                fi
            done
        } &
        
        pids+=($!)
        ((chunk_num++))
    done
    
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    
    local all_results="$TEMP_DIR/all_results"
    for result_file in "${temp_results[@]}"; do
        if [[ -f "$result_file" ]]; then
            cat "$result_file" >> "$all_results"
        fi
    done
    
    if [[ -f "$all_results" ]]; then
        cat "$all_results"
    fi
}

# Generate HTML report
generate_html_report() {
    local results="$1"
    local timestamp=$(date '+%Y-%m-%d_%H-%M-%S')
    local report_file="$REPORT_DIR/secret-war-report-$timestamp.html"
    
    cat > "$report_file" << 'REPORT_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secret WAR Security Report</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0c0c0c 0%, #1a1a1a 100%);
            color: #00ff00;
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            border: 2px solid #ff0000;
            border-radius: 10px;
            background: rgba(255, 0, 0, 0.1);
        }
        .title {
            font-size: 2.5em;
            color: #ff0000;
            text-shadow: 0 0 10px #ff0000;
            margin-bottom: 10px;
        }
        .subtitle {
            font-size: 1.2em;
            color: #ffff00;
            font-weight: bold;
        }
        .stats {
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
            padding: 15px;
            background: rgba(0, 255, 0, 0.1);
            border: 1px solid #00ff00;
            border-radius: 5px;
        }
        .stat {
            text-align: center;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #ff0000;
        }
        .stat-label {
            color: #00ff00;
        }
        .results {
            margin-top: 20px;
        }
        .file-section {
            margin: 20px 0;
            padding: 15px;
            border: 1px solid #666;
            border-radius: 5px;
            background: rgba(255, 255, 255, 0.05);
        }
        .file-name {
            font-size: 1.3em;
            color: #00ffff;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .match {
            margin: 10px 0;
            padding: 10px;
            background: rgba(255, 0, 0, 0.2);
            border-left: 4px solid #ff0000;
        }
        .line-number {
            color: #ffff00;
            font-weight: bold;
        }
        .code-snippet {
            color: #ffffff;
            background: #333;
            padding: 5px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
        }
        .footer {
            margin-top: 40px;
            text-align: center;
            padding: 20px;
            border-top: 2px solid #666;
            color: #666;
        }
        .warning {
            color: #ff0000;
            font-weight: bold;
            font-size: 1.5em;
            text-align: center;
            margin: 20px 0;
            animation: blink 1s infinite;
        }
        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0.3; }
        }
        .success {
            text-align: center;
            margin: 50px 0;
        }
        .success-icon {
            font-size: 5em;
            color: #00ff00;
            margin-bottom: 20px;
        }
        .success-message {
            font-size: 2.5em;
            color: #00ff00;
            font-weight: bold;
            text-shadow: 0 0 15px #00ff00;
            margin: 20px 0;
        }
        .doom-quote {
            font-size: 1.2em;
            color: #ff0000;
            font-style: italic;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="title">SECRET WAR</div>
        <div class="subtitle">Security Vulnerability Report</div>
        <div style="margin-top: 10px; color: #ff0000;">
            "Dread it, Run from it. Destiny Still arrives"
        </div>
    </div>
REPORT_EOF

    if [[ -n "$results" ]]; then
        local total_issues=$(echo "$results" | wc -l)
        local unique_files=$(echo "$results" | cut -d':' -f1 | sort -u | wc -l)
        
        cat >> "$report_file" << REPORT_ISSUES_EOF
    <div class="warning">⚠️ SECURITY VULNERABILITIES DETECTED ⚠️</div>
    <div class="doom-quote">"Doctor Doom has found vulnerabilities to strike!"</div>
    
    <div class="stats">
        <div class="stat">
            <div class="stat-number">$total_issues</div>
            <div class="stat-label">Total Issues</div>
        </div>
        <div class="stat">
            <div class="stat-number">$unique_files</div>
            <div class="stat-label">Affected Files</div>
        </div>
        <div class="stat">
            <div class="stat-number">$(date '+%Y-%m-%d %H:%M:%S')</div>
            <div class="stat-label">Scan Time</div>
        </div>
    </div>
    
    <div class="results">
REPORT_ISSUES_EOF

        local current_file=""
        while IFS= read -r line; do
            local file=$(echo "$line" | cut -d':' -f1)
            local line_num=$(echo "$line" | cut -d':' -f2)
            local content=$(echo "$line" | cut -d':' -f3-)
            
            if [[ "$file" != "$current_file" ]]; then
                if [[ -n "$current_file" ]]; then
                    echo "        </div>" >> "$report_file"
                fi
                echo "        <div class=\"file-section\">" >> "$report_file"
                echo "            <div class=\"file-name\">📁 $file</div>" >> "$report_file"
                current_file="$file"
            fi
            
            local escaped_content=$(echo "$content" | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g')
            cat >> "$report_file" << MATCH_EOF
            <div class="match">
                <div class="line-number">Line $line_num:</div>
                <div class="code-snippet">$escaped_content</div>
            </div>
MATCH_EOF
        done <<< "$results"
        
        if [[ -n "$current_file" ]]; then
            echo "        </div>" >> "$report_file"
        fi
        echo "    </div>" >> "$report_file"
    else
        cat >> "$report_file" << SUCCESS_EOF
    <div class="success">
        <div class="success-icon">🛡️</div>
        <div class="success-message">We Won Secret War!!!!!!!!</div>
        <div class="success-message">Love you 3000 ❤️</div>
        <div class="doom-quote">"Doctor Doom found no vulnerabilities to exploit!"</div>
        <div style="color: #666; margin-top: 30px;">No security vulnerabilities detected in your commit.</div>
    </div>
SUCCESS_EOF
    fi
    
    cat >> "$report_file" << FOOTER_EOF
    <div class="footer">
        <div>Generated by Secret WAR v1.0.0</div>
        <div>Advanced Git Pre-commit Security Scanner</div>
        <div style="margin-top: 10px;">
            Repository: $(git remote get-url origin 2>/dev/null || echo "Local Repository")
        </div>
        <div>Commit: $(git rev-parse HEAD 2>/dev/null || echo "Pending")</div>
    </div>
</body>
</html>
FOOTER_EOF

    echo "$report_file"
}

# Open report in browser
open_report() {
    local report_file="$1"
    
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$report_file" >/dev/null 2>&1 &
    elif command -v open >/dev/null 2>&1; then
        open "$report_file" >/dev/null 2>&1 &
    elif command -v start >/dev/null 2>&1; then
        start "$report_file" >/dev/null 2>&1 &
    else
        echo -e "${YELLOW}Report generated: $report_file${NC}"
        echo -e "${YELLOW}Please open the file manually in your browser${NC}"
    fi
}

# Show success message
show_success_message() {
    local message="We Won Secret War!!!!!!!! Love you 3000"
    
    if [[ -n "${DISPLAY:-}" ]] || [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
        if command -v notify-send >/dev/null 2>&1; then
            notify-send "Secret WAR" "$message" --icon=dialog-information
        elif command -v osascript >/dev/null 2>&1; then
            osascript -e "display notification \"$message\" with title \"Secret WAR\""
        fi
    fi
    
    echo -e "${GREEN}✅ $message${NC}"
}

# Install pre-commit hook
install_hook() {
    local hook_type="$1"
    local git_dir
    
    if [[ "$hook_type" == "global" ]]; then
        git_dir="$HOME/.git-templates/hooks"
        mkdir -p "$git_dir"
        git config --global init.templateDir "$HOME/.git-templates"
        echo -e "${BLUE}Installing global pre-commit hook...${NC}"
    else
        if ! git rev-parse --git-dir >/dev/null 2>&1; then
            echo -e "${RED}Error: Not in a git repository${NC}"
            exit 1
        fi
        git_dir="$(git rev-parse --git-dir)/hooks"
        echo -e "${BLUE}Installing local pre-commit hook...${NC}"
    fi
    
    local hook_file="$git_dir/pre-commit"
    
    cat > "$hook_file" << 'EOF'
#!/bin/bash

# Secret WAR Pre-commit Hook
set -euo pipefail

CONFIG_DIR="$HOME/.secret-war"
REPORT_DIR="$CONFIG_DIR/reports"
TEMP_DIR="/tmp/secret-war-$"
LOADER_PID_FILE="$TEMP_DIR/loader.pid"
MAX_THREADS=8

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

cleanup() {
    if [[ -f "$LOADER_PID_FILE" ]]; then
        local loader_pid=$(cat "$LOADER_PID_FILE" 2>/dev/null || echo "")
        if [[ -n "$loader_pid" ]] && kill -0 "$loader_pid" 2>/dev/null; then
            kill "$loader_pid" 2>/dev/null || true
        fi
        rm -f "$LOADER_PID_FILE"
    fi
    
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
    
    if command -v pkill >/dev/null 2>&1; then
        pkill -f "zenity.*Secret WAR" 2>/dev/null || true
        pkill -f "kdialog.*Secret WAR" 2>/dev/null || true
    fi
    
    printf "\r${NC}%50s\r" " "
}
trap cleanup EXIT

if [[ -f "$CONFIG_DIR/secret-war-functions.sh" ]]; then
    source "$CONFIG_DIR/secret-war-functions.sh"
else
    echo -e "${RED}Error: Secret WAR functions not found. Please reinstall.${NC}"
    exit 1
fi

main() {
    mkdir -p "$TEMP_DIR"
    
    echo -e "${BLUE}🛡️  Secret WAR Security Scan Starting...${NC}"
    
    # Check bypass configuration
    if check_bypass; then
        echo -e "${YELLOW}⚠️  Security scan bypassed${NC}"
        exit 0
    fi
    
    local staged_files
    readarray -t staged_files < <(get_staged_files)
    
    if [[ ${#staged_files[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No files to scan${NC}"
        exit 0
    fi
    
    echo -e "${BLUE}Scanning ${#staged_files[@]} files with $MAX_THREADS threads...${NC}"
    
    # Start loader
    show_loader "Doctor Doom is Searching Vulnerabilities to Strike..." "$LOADER_PID_FILE"
    
    local results
    results=$(process_files_parallel "${staged_files[@]}")
    
    # Stop loader
    stop_loader
    
    local report_file
    report_file=$(generate_html_report "$results")
    
    if [[ -n "$results" ]]; then
        echo -e "${RED}"
        echo "╔════════════════════════════════════════════════════════════════╗"
        echo "║                    SECURITY ALERT                             ║"
        echo "║            Dread it, Run from it. Destiny Still arrives       ║"
        echo "╚════════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        
        echo -e "${RED}❌ Security vulnerabilities detected!${NC}"
        echo -e "${YELLOW}📊 Report: $report_file${NC}"
        
        open_report "$report_file"
        
        if offer_bypass; then
            echo -e "${YELLOW}⚠️  Proceeding with bypassed security check${NC}"
            exit 0
        else
            echo -e "${RED}Commit blocked for security reasons.${NC}"
            exit 1
        fi
    else
        show_success_message
        open_report "$report_file"
        exit 0
    fi
}

main "$@"
EOF

    chmod +x "$hook_file"
    
    # Copy functions to config directory
    cat > "$CONFIG_DIR/secret-war-functions.sh" << 'FUNCTIONS_EOF'
# Secret WAR Functions Library

load_config() {
    local config_file="$1"
    local key="$2"
    local default_value="$3"
    
    if [[ -f "$config_file" ]]; then
        local value=$(grep "^${key}=" "$config_file" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        echo "${value:-$default_value}"
    else
        echo "$default_value"
    fi
}

save_config() {
    local config_file="$1"
    local key="$2"
    local value="$3"
    
    if [[ -f "$config_file" ]]; then
        if grep -q "^${key}=" "$config_file"; then
            sed -i.bak "s/^${key}=.*/${key}=${value}/" "$config_file"
        else
            echo "${key}=${value}" >> "$config_file"
        fi
    else
        echo "${key}=${value}" > "$config_file"
    fi
}

check_bypass() {
    local bypass_file="$CONFIG_DIR/bypass.conf"
    local bypass=$(load_config "$bypass_file" "bypass" "false")
    local bypass_remember=$(load_config "$bypass_file" "bypass_remember" "false")
    
    if [[ "$bypass" == "true" ]]; then
        if [[ "$bypass_remember" == "true" ]]; then
            echo -e "${YELLOW}⚠️  Security scan bypassed (remembered choice)${NC}"
            return 0
        else
            echo -e "${YELLOW}⚠️  Bypass is enabled. Reset bypass? (y/N):${NC}"
            read -r reset_bypass
            if [[ "$reset_bypass" =~ ^[Yy]$ ]]; then
                save_config "$bypass_file" "bypass" "false"
                save_config "$bypass_file" "bypass_remember" "false"
                echo -e "${GREEN}✅ Bypass disabled${NC}"
                return 1
            else
                return 0
            fi
        fi
    fi
    return 1
}

offer_bypass() {
    local bypass_file="$CONFIG_DIR/bypass.conf"
    
    echo -e "${YELLOW}Do you want to bypass this security check? (y/N):${NC}"
    read -r bypass_choice
    
    if [[ "$bypass_choice" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Remember this choice? (y/N):${NC}"
        read -r remember_choice
        
        save_config "$bypass_file" "bypass" "true"
        
        if [[ "$remember_choice" =~ ^[Yy]$ ]]; then
            save_config "$bypass_file" "bypass_remember" "true"
            echo -e "${YELLOW}⚠️  Security bypass enabled and remembered${NC}"
        else
            save_config "$bypass_file" "bypass_remember" "false"
            echo -e "${YELLOW}⚠️  Security bypass enabled for this session${NC}"
        fi
        
        return 0
    fi
    
    return 1
}

show_loader() {
    local message="$1"
    local pid_file="$2"
    
    if [[ -n "${DISPLAY:-}" ]] || [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
        if command -v zenity >/dev/null 2>&1; then
            (
                zenity --progress --pulsate --no-cancel --auto-close \
                       --title="Secret WAR" \
                       --text="$message" \
                       --width=400 --height=100 2>/dev/null &
                echo $! > "$pid_file"
                wait
            ) &
            return
        elif command -v kdialog >/dev/null 2>&1; then
            (
                kdialog --progressbar "$message" --title "Secret WAR" &
                echo $! > "$pid_file"
                wait
            ) &
            return
        elif command -v osascript >/dev/null 2>&1; then
            (
                osascript -e "display dialog \"$message\" with title \"Secret WAR\" buttons {\"Please Wait...\"} default button 1 giving up after 30" &
                echo $! > "$pid_file"
                wait
            ) &
            return
        fi
    fi
    
    (
        local spinner='|/-\'
        local i=0
        echo -e "\n${YELLOW}$message${NC}"
        while true; do
            printf "\r${CYAN}[${spinner:$i:1}] Scanning in progress...${NC}"
            i=$(( (i+1) %4 ))
            sleep 0.2
        done
    ) &
    echo $! > "$pid_file"
}

stop_loader() {
    if [[ -f "$LOADER_PID_FILE" ]]; then
        local loader_pid=$(cat "$LOADER_PID_FILE" 2>/dev/null || echo "")
        if [[ -n "$loader_pid" ]] && kill -0 "$loader_pid" 2>/dev/null; then
            kill "$loader_pid" 2>/dev/null || true
        fi
        rm -f "$LOADER_PID_FILE"
    fi
    
    if command -v pkill >/dev/null 2>&1; then
        pkill -f "zenity.*Secret WAR" 2>/dev/null || true
        pkill -f "kdialog.*Secret WAR" 2>/dev/null || true
    fi
    
    printf "\r${NC}%50s\r" " "
}

load_patterns() {
    local patterns=()
    while IFS= read -r line; do
        if [[ ! "$line" =~ ^[[:space:]]*# ]] && [[ -n "${line// }" ]]; then
            patterns+=("$line")
        fi
    done < "$CONFIG_DIR/patterns.conf"
    printf '%s\n' "${patterns[@]}"
}

load_whitelist_files() {
    local files=()
    if [[ -f "$CONFIG_DIR/whitelist-files.conf" ]]; then
        while IFS= read -r line; do
            if [[ ! "$line" =~ ^[[:space:]]*# ]] && [[ -n "${line// }" ]]; then
                files+=("$line")
            fi
        done < "$CONFIG_DIR/whitelist-files.conf"
    fi
    printf '%s\n' "${files[@]}"
}

load_whitelist_patterns() {
    local patterns=()
    if [[ -f "$CONFIG_DIR/whitelist-patterns.conf" ]]; then
        while IFS= read -r line; do
            if [[ ! "$line" =~ ^[[:space:]]*# ]] && [[ -n "${line// }" ]]; then
                patterns+=("$line")
            fi
        done < "$CONFIG_DIR/whitelist-patterns.conf"
    fi
    printf '%s\n' "${patterns[@]}"
}

is_file_whitelisted() {
    local file="$1"
    local whitelist_files
    readarray -t whitelist_files < <(load_whitelist_files)
    
    for pattern in "${whitelist_files[@]}"; do
        if [[ "$file" == *"$pattern"* ]]; then
            return 0
        fi
    done
    return 1
}

is_match_whitelisted() {
    local match="$1"
    local whitelist_patterns
    readarray -t whitelist_patterns < <(load_whitelist_patterns)
    
    for pattern in "${whitelist_patterns[@]}"; do
        if echo "$match" | grep -qE "$pattern"; then
            return 0
        fi
    done
    return 1
}

scan_file() {
    local file="$1"
    local output_file="$2"
    local patterns
    readarray -t patterns < <(load_patterns)
    
    if is_file_whitelisted "$file"; then
        return 0
    fi
    
    if ! file "$file" | grep -q text; then
        return 0
    fi
    
    local found_issues=0
    
    for pattern in "${patterns[@]}"; do
        if [[ -n "$pattern" ]]; then
            local matches
            matches=$(git grep -n -E "$pattern" -- "$file" 2>/dev/null || true)
            
            if [[ -n "$matches" ]]; then
                while IFS= read -r match; do
                    if ! is_match_whitelisted "$match"; then
                        echo "$match" >> "$output_file"
                        found_issues=1
                    fi
                done <<< "$matches"
            fi
        fi
    done
    
    return $found_issues
}

get_staged_files() {
    git diff --cached --name-only --diff-filter=ACM | grep -v -E '\.(gitignore|gitattributes)$|\.git/|\.vscode/|\.idea/' || true
}

process_files_parallel() {
    local files=("$@")
    local temp_results=()
    local pids=()
    
    mkdir -p "$TEMP_DIR"
    
    local chunk_size=$(( (${#files[@]} + MAX_THREADS - 1) / MAX_THREADS ))
    local chunk_num=0
    
    for ((i=0; i<${#files[@]}; i+=chunk_size)); do
        local chunk=("${files[@]:i:chunk_size}")
        local result_file="$TEMP_DIR/result_$chunk_num"
        temp_results+=("$result_file")
        
        {
            for file in "${chunk[@]}"; do
                if [[ -f "$file" ]]; then
                    scan_file "$file" "$result_file"
                fi
            done
        } &
        
        pids+=($!)
        ((chunk_num++))
    done
    
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    
    local all_results="$TEMP_DIR/all_results"
    for result_file in "${temp_results[@]}"; do
        if [[ -f "$result_file" ]]; then
            cat "$result_file" >> "$all_results"
        fi
    done
    
    if [[ -f "$all_results" ]]; then
        cat "$all_results"
    fi
}

generate_html_report() {
    local results="$1"
    local timestamp=$(date '+%Y-%m-%d_%H-%M-%S')
    local report_file="$REPORT_DIR/secret-war-report-$timestamp.html"
    
    cat > "$report_file" << 'REPORT_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secret WAR Security Report</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0c0c0c 0%, #1a1a1a 100%);
            color: #00ff00;
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            border: 2px solid #ff0000;
            border-radius: 10px;
            background: rgba(255, 0, 0, 0.1);
        }
        .title {
            font-size: 2.5em;
            color: #ff0000;
            text-shadow: 0 0 10px #ff0000;
            margin-bottom: 10px;
        }
        .subtitle {
            font-size: 1.2em;
            color: #ffff00;
            font-weight: bold;
        }
        .stats {
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
            padding: 15px;
            background: rgba(0, 255, 0, 0.1);
            border: 1px solid #00ff00;
            border-radius: 5px;
        }
        .stat {
            text-align: center;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #ff0000;
        }
        .stat-label {
            color: #00ff00;
        }
        .results {
            margin-top: 20px;
        }
        .file-section {
            margin: 20px 0;
            padding: 15px;
            border: 1px solid #666;
            border-radius: 5px;
            background: rgba(255, 255, 255, 0.05);
        }
        .file-name {
            font-size: 1.3em;
            color: #00ffff;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .match {
            margin: 10px 0;
            padding: 10px;
            background: rgba(255, 0, 0, 0.2);
            border-left: 4px solid #ff0000;
        }
        .line-number {
            color: #ffff00;
            font-weight: bold;
        }
        .code-snippet {
            color: #ffffff;
            background: #333;
            padding: 5px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
        }
        .footer {
            margin-top: 40px;
            text-align: center;
            padding: 20px;
            border-top: 2px solid #666;
            color: #666;
        }
        .warning {
            color: #ff0000;
            font-weight: bold;
            font-size: 1.5em;
            text-align: center;
            margin: 20px 0;
            animation: blink 1s infinite;
        }
        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0.3; }
        }
        .success {
            text-align: center;
            margin: 50px 0;
        }
        .success-icon {
            font-size: 5em;
            color: #00ff00;
            margin-bottom: 20px;
        }
        .success-message {
            font-size: 2.5em;
            color: #00ff00;
            font-weight: bold;
            text-shadow: 0 0 15px #00ff00;
            margin: 20px 0;
        }
        .doom-quote {
            font-size: 1.2em;
            color: #ff0000;
            font-style: italic;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="title">SECRET WAR</div>
        <div class="subtitle">Security Vulnerability Report</div>
        <div style="margin-top: 10px; color: #ff0000;">
            "Dread it, Run from it. Destiny Still arrives"
        </div>
    </div>
REPORT_EOF

    if [[ -n "$results" ]]; then
        local total_issues=$(echo "$results" | wc -l)
        local unique_files=$(echo "$results" | cut -d':' -f1 | sort -u | wc -l)
        
        cat >> "$report_file" << REPORT_ISSUES_EOF
    <div class="warning">⚠️ SECURITY VULNERABILITIES DETECTED ⚠️</div>
    <div class="doom-quote">"Doctor Doom has found vulnerabilities to strike!"</div>
    
    <div class="stats">
        <div class="stat">
            <div class="stat-number">$total_issues</div>
            <div class="stat-label">Total Issues</div>
        </div>
        <div class="stat">
            <div class="stat-number">$unique_files</div>
            <div class="stat-label">Affected Files</div>
        </div>
        <div class="stat">
            <div class="stat-number">$(date '+%Y-%m-%d %H:%M:%S')</div>
            <div class="stat-label">Scan Time</div>
        </div>
    </div>
    
    <div class="results">
REPORT_ISSUES_EOF

        local current_file=""
        while IFS= read -r line; do
            local file=$(echo "$line" | cut -d':' -f1)
            local line_num=$(echo "$line" | cut -d':' -f2)
            local content=$(echo "$line" | cut -d':' -f3-)
            
            if [[ "$file" != "$current_file" ]]; then
                if [[ -n "$current_file" ]]; then
                    echo "        </div>" >> "$report_file"
                fi
                echo "        <div class=\"file-section\">" >> "$report_file"
                echo "            <div class=\"file-name\">📁 $file</div>" >> "$report_file"
                current_file="$file"
            fi
            
            local escaped_content=$(echo "$content" | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g')
            cat >> "$report_file" << MATCH_EOF
            <div class="match">
                <div class="line-number">Line $line_num:</div>
                <div class="code-snippet">$escaped_content</div>
            </div>
MATCH_EOF
        done <<< "$results"
        
        if [[ -n "$current_file" ]]; then
            echo "        </div>" >> "$report_file"
        fi
        echo "    </div>" >> "$report_file"
    else
        cat >> "$report_file" << SUCCESS_EOF
    <div class="success">
        <div class="success-icon">🛡️</div>
        <div class="success-message">We Won Secret War!!!!!!!!</div>
        <div class="success-message">Love you 3000 ❤️</div>
        <div class="doom-quote">"Doctor Doom found no vulnerabilities to exploit!"</div>
        <div style="color: #666; margin-top: 30px;">No security vulnerabilities detected in your commit.</div>
    </div>
SUCCESS_EOF
    fi
    
    cat >> "$report_file" << FOOTER_EOF
    <div class="footer">
        <div>Generated by Secret WAR v1.0.0</div>
        <div>Advanced Git Pre-commit Security Scanner</div>
        <div style="margin-top: 10px;">
            Repository: $(git remote get-url origin 2>/dev/null || echo "Local Repository")
        </div>
        <div>Commit: $(git rev-parse HEAD 2>/dev/null || echo "Pending")</div>
    </div>
</body>
</html>
FOOTER_EOF

    echo "$report_file"
}

open_report() {
    local report_file="$1"
    
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$report_file" >/dev/null 2>&1 &
    elif command -v open >/dev/null 2>&1; then
        open "$report_file" >/dev/null 2>&1 &
    elif command -v start >/dev/null 2>&1; then
        start "$report_file" >/dev/null 2>&1 &
    fi
}

show_success_message() {
    local message="We Won Secret War!!!!!!!! Love you 3000"
    
    if [[ -n "${DISPLAY:-}" ]] || [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
        if command -v notify-send >/dev/null 2>&1; then
            notify-send "Secret WAR" "$message" --icon=dialog-information
        elif command -v osascript >/dev/null 2>&1; then
            osascript -e "display notification \"$message\" with title \"Secret WAR\""
        fi
    fi
    
    echo -e "${GREEN}✅ $message${NC}"
}
FUNCTIONS_EOF

    if [[ "$hook_type" == "global" ]]; then
        echo -e "${GREEN}✅ Global pre-commit hook installed successfully${NC}"
        echo -e "${CYAN}All new repositories will have Secret WAR protection${NC}"
    else
        echo -e "${GREEN}✅ Local pre-commit hook installed successfully${NC}"
        echo -e "${CYAN}This repository now has Secret WAR protection${NC}"
    fi
    
    echo -e "${GREEN}🛡️  We are ready for Secret War!${NC}"
}

# Uninstall pre-commit hook
uninstall_hook() {
    local hook_type="$1"
    local git_dir
    
    if [[ "$hook_type" == "global" ]]; then
        git_dir="$HOME/.git-templates/hooks"
        echo -e "${BLUE}Uninstalling global pre-commit hook...${NC}"
    else
        if ! git rev-parse --git-dir >/dev/null 2>&1; then
            echo -e "${RED}Error: Not in a git repository${NC}"
            exit 1
        fi
        git_dir="$(git rev-parse --git-dir)/hooks"
        echo -e "${BLUE}Uninstalling local pre-commit hook...${NC}"
    fi
    
    local hook_file="$git_dir/pre-commit"
    
    if [[ -f "$hook_file" ]] && grep -q "Secret WAR" "$hook_file"; then
        rm -f "$hook_file"
        if [[ "$hook_type" == "global" ]]; then
            echo -e "${GREEN}✅ Global pre-commit hook uninstalled successfully${NC}"
        else
            echo -e "${GREEN}✅ Local pre-commit hook uninstalled successfully${NC}"
        fi
    else
        echo -e "${YELLOW}No Secret WAR hook found to uninstall${NC}"
    fi
}

# Reset bypass configuration
reset_bypass() {
    if [[ -f "$BYPASS_FILE" ]]; then
        save_config "$BYPASS_FILE" "bypass" "false"
        save_config "$BYPASS_FILE" "bypass_remember" "false"
        echo -e "${GREEN}✅ Bypass configuration reset${NC}"
    else
        echo -e "${YELLOW}No bypass configuration found${NC}"
    fi
}

# Show configuration
show_config() {
    echo -e "${CYAN}Secret WAR Configuration:${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "Config Directory: ${GREEN}$CONFIG_DIR${NC}"
    echo -e "Reports Directory: ${GREEN}$REPORT_DIR${NC}"
    echo -e "Max Threads: ${GREEN}$MAX_THREADS${NC}"
    
    if [[ -f "$BYPASS_FILE" ]]; then
        local bypass=$(load_config "$BYPASS_FILE" "bypass" "false")
        local bypass_remember=$(load_config "$BYPASS_FILE" "bypass_remember" "false")
        echo -e "Bypass Enabled: ${GREEN}$bypass${NC}"
        echo -e "Bypass Remember: ${GREEN}$bypass_remember${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}Configuration Files:${NC}"
    echo -e "Patterns: ${GREEN}$PATTERNS_FILE${NC}"
    echo -e "Whitelist Files: ${GREEN}$WHITELIST_FILES${NC}"
    echo -e "Whitelist Patterns: ${GREEN}$WHITELIST_PATTERNS${NC}"
    echo -e "Bypass Config: ${GREEN}$BYPASS_FILE${NC}"
    
    echo ""
    echo -e "${BLUE}Hook Status:${NC}"
    if git rev-parse --git-dir >/dev/null 2>&1; then
        local local_hook="$(git rev-parse --git-dir)/hooks/pre-commit"
        if [[ -f "$local_hook" ]] && grep -q "Secret WAR" "$local_hook"; then
            echo -e "Local Hook: ${GREEN}Installed${NC}"
        else
            echo -e "Local Hook: ${RED}Not Installed${NC}"
        fi
    fi
    
    local global_hook="$HOME/.git-templates/hooks/pre-commit"
    if [[ -f "$global_hook" ]] && grep -q "Secret WAR" "$global_hook"; then
        echo -e "Global Hook: ${GREEN}Installed${NC}"
    else
        echo -e "Global Hook: ${RED}Not Installed${NC}"
    fi
}

# Manual scan
manual_scan() {
    echo -e "${BLUE}🛡️  Starting Manual Security Scan...${NC}"
    
    # Check if in git repository
    if ! git rev-parse --git-dir >/dev/null 2>&1; then
        echo -e "${RED}Error: Not in a git repository${NC}"
        exit 1
    fi
    
    # Get all files in repository
    local all_files
    readarray -t all_files < <(git ls-files)
    
    if [[ ${#all_files[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No files to scan${NC}"
        exit 0
    fi
    
    echo -e "${BLUE}Scanning ${#all_files[@]} files with $MAX_THREADS threads...${NC}"
    
    # Start loader
    show_loader "Doctor Doom is Searching Vulnerabilities to Strike..." "$LOADER_PID_FILE"
    
    # Process files in parallel
    local results
    results=$(process_files_parallel "${all_files[@]}")
    
    # Stop loader
    stop_loader
    
    # Generate report
    local report_file
    report_file=$(generate_html_report "$results")
    
    if [[ -n "$results" ]]; then
        echo -e "${RED}❌ Security vulnerabilities detected!${NC}"
        echo -e "${YELLOW}📊 Report: $report_file${NC}"
        open_report "$report_file"
    else
        show_success_message
        open_report "$report_file"
    fi
}

# Show usage information
show_usage() {
    echo -e "${CYAN}Secret WAR - Advanced Git Pre-commit Security Scanner${NC}"
    echo -e "${YELLOW}Usage: $0 [COMMAND] [OPTIONS]${NC}"
    echo ""
    echo -e "${BLUE}Commands:${NC}"
    echo -e "  ${GREEN}install${NC}              Install local pre-commit hook"
    echo -e "  ${GREEN}install --global${NC}     Install global pre-commit hook"
    echo -e "  ${GREEN}uninstall${NC}            Uninstall local pre-commit hook"
    echo -e "  ${GREEN}uninstall --global${NC}   Uninstall global pre-commit hook"
    echo -e "  ${GREEN}scan${NC}                 Run manual security scan"
    echo -e "  ${GREEN}config${NC}               Show configuration"
    echo -e "  ${GREEN}reset-bypass${NC}         Reset bypass configuration"
    echo -e "  ${GREEN}help${NC}                 Show this help message"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo -e "  $0 install              # Install hook for current repository"
    echo -e "  $0 install --global     # Install hook for all repositories"
    echo -e "  $0 scan                 # Run manual scan on current repository"
    echo -e "  $0 config               # Show current configuration"
    echo ""
    echo -e "${PURPLE}\"Dread it, Run from it. Destiny Still arrives\"${NC}"
}

# Main function
main() {
    # Initialize configuration
    init_config
    
    # Handle command line arguments
    case "${1:-help}" in
        "install")
            if [[ "${2:-}" == "--global" ]]; then
                install_hook "global"
            else
                install_hook "local"
            fi
            ;;
        "uninstall")
            if [[ "${2:-}" == "--global" ]]; then
                uninstall_hook "global"
            else
                uninstall_hook "local"
            fi
            ;;
        "scan")
            manual_scan
            ;;
        "config")
            show_config
            ;;
        "reset-bypass")
            reset_bypass
            ;;
        "help"|"-h"|"--help")
            show_banner
            show_usage
            ;;
        *)
            show_banner
            echo -e "${RED}Unknown command: $1${NC}"
            echo ""
            show_usage
            exit 1
            ;;
    esac
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi