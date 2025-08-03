#!/bin/bash

# Secret WAR - Advanced Git Pre-commit Security Scanner
# Complete Installation Script with Cross-Platform Thread Management
# "Dread it, Run from it. Destiny Still arrives"
# Version: 1.0.2

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR=""  # Will be set based on installation type
INSTALL_TYPE=""
VERBOSE=false
FORCE_INSTALL=false
VERSION="1.0.2"

# Installation banner
show_banner() {
    clear
    echo -e "${PURPLE}${BOLD}"
    cat << 'EOF'
   ██████  ███████  ██████ ██████  ███████ ████████     ██     ██  █████  ████████ 
  ██       ██      ██      ██   ██ ██         ██        ██     ██ ██   ██ ██     ██
  ██████   █████   ██      ██████  █████      ██        ██  █  ██ ███████ ██████  
       ██  ██      ██      ██   ██ ██         ██        ██ ███ ██ ██   ██ ██   ██ 
  ██████   ███████  ██████ ██   ██ ███████    ██         ███ ███  ██   ██ ██   ██ 
                                                                                    
                      Advanced Git Pre-commit Security Scanner
                   "Dread it, Run from it. Destiny Still arrives"
                            Installer v1.0.2
EOF
    echo -e "${NC}"
    echo -e "${CYAN}🛡️  Protecting your repositories from security vulnerabilities${NC}"
    echo -e "${CYAN}⚡ Cross-platform thread management | 100+ security patterns | HTML reports${NC}"
    echo ""
}

# Print colored output
print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_step() { echo -e "${PURPLE}🔄 $1${NC}"; }

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Set configuration directory based on installation type
set_config_dir() {
    case $INSTALL_TYPE in
        "global"|"advanced")
            CONFIG_DIR="$HOME/.secret-war"
            ;;
        "local")
            if git rev-parse --git-dir >/dev/null 2>&1; then
                CONFIG_DIR="$(git rev-parse --show-toplevel)/.secret-war"
            else
                print_error "Not in a git repository for local installation!"
                exit 1
            fi
            ;;
        "update")
            # For updates, check both locations
            if [[ -d "$HOME/.secret-war" ]]; then
                CONFIG_DIR="$HOME/.secret-war"
            elif git rev-parse --git-dir >/dev/null 2>&1 && [[ -d "$(git rev-parse --show-toplevel)/.secret-war" ]]; then
                CONFIG_DIR="$(git rev-parse --show-toplevel)/.secret-war"
            else
                print_error "No existing Secret WAR installation found!"
                exit 1
            fi
            ;;
        *)
            CONFIG_DIR="$HOME/.secret-war"
            ;;
    esac
}

# Check system requirements
check_requirements() {
    print_step "Checking system requirements..."
    
    local missing_deps=()
    
    # Check required commands
    if ! command_exists git; then
        missing_deps+=("git")
    fi
    
    if ! command_exists grep; then
        missing_deps+=("grep")
    fi
    
    if ! command_exists sed; then
        missing_deps+=("sed")
    fi
    
    if ! command_exists awk; then
        missing_deps+=("awk")
    fi
    
    if ! command_exists file; then
        missing_deps+=("file")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"
        echo ""
        echo "Please install the missing dependencies and run the installer again."
        exit 1
    fi
    
    # Check Git version
    local git_version
    git_version=$(git --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    local git_major
    git_major=$(echo "$git_version" | cut -d. -f1)
    local git_minor
    git_minor=$(echo "$git_version" | cut -d. -f2)
    
    if [[ $git_major -lt 2 ]] || [[ $git_major -eq 2 && $git_minor -lt 9 ]]; then
        print_warning "Git version $git_version detected. Recommended: 2.9 or higher"
    fi
    
    print_success "System requirements satisfied"
}

# Show installation options menu
show_menu() {
    echo -e "${BOLD}${CYAN}Installation Options:${NC}"
    echo ""
    echo -e "${GREEN}1)${NC} 🌍 Global Installation    - Protect all repositories (Home config)"
    echo -e "${GREEN}2)${NC} 📁 Local Installation     - Protect current repository (Local config)"
    echo -e "${GREEN}3)${NC} ⚙️  Advanced Installation  - Custom configuration"
    echo -e "${GREEN}4)${NC} 🔄 Update Installation    - Update existing installation"
    echo -e "${GREEN}5)${NC} 🗑️  Uninstall             - Remove Secret WAR"
    echo -e "${GREEN}6)${NC} ❓ Help                   - Show usage information"
    echo -e "${GREEN}0)${NC} 🚪 Exit                   - Exit installer"
    echo ""
}

# Get user choice
get_user_choice() {
    local choice
    while true; do
        echo -ne "${CYAN}Choose an option [1-6, 0 to exit]: ${NC}"
        read -r choice
        
        case $choice in
            1)
                INSTALL_TYPE="global"
                break
                ;;
            2) 
                INSTALL_TYPE="local"
                break
                ;;
            3)
                INSTALL_TYPE="advanced"
                break
                ;;
            4)
                INSTALL_TYPE="update"
                break
                ;;
            5)
                INSTALL_TYPE="uninstall"
                break
                ;;
            6)
                show_help
                continue
                ;;
            0)
                print_info "Installation cancelled by user"
                exit 0
                ;;
            *)
                print_error "Invalid choice. Please select 1-6 or 0 to exit."
                continue
                ;;
        esac
    done
}

# Show help information
show_help() {
    echo ""
    echo -e "${BOLD}${CYAN}Secret WAR Installation Help${NC}"
    echo ""
    echo -e "${YELLOW}Installation Types:${NC}"
    echo ""
    echo -e "${GREEN}Global Installation:${NC}"
    echo "  • Installs hooks for all repositories (current and future)"
    echo "  • Uses Git template directory (~/.git-templates)"
    echo "  • Configuration stored in ~/.secret-war"
    echo "  • Automatically applies to new repositories via 'git init' or 'git clone'"
    echo "  • Recommended for most users"
    echo ""
    echo -e "${GREEN}Local Installation:${NC}"
    echo "  • Installs hook only in current repository"
    echo "  • Configuration stored in .secret-war/ (repository root)"
    echo "  • Must be run from within a Git repository"
    echo "  • Repository-specific configuration"
    echo "  • Useful for project-specific security requirements"
    echo ""
    echo -e "${GREEN}Advanced Installation:${NC}"
    echo "  • Custom configuration options"
    echo "  • Choose thread count, patterns, and whitelisting"
    echo "  • Custom report directory and configuration"
    echo ""
    echo -e "${YELLOW}Command Line Options:${NC}"
    echo "  --global          Global installation"
    echo "  --local           Local installation"
    echo "  --advanced        Advanced installation"
    echo "  --update          Update existing installation"
    echo "  --uninstall       Remove Secret WAR"
    echo "  --force           Force installation (overwrite existing)"
    echo "  --verbose         Verbose output"
    echo "  --help            Show this help"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  ./install.sh --global          # Quick global install"
    echo "  ./install.sh --local --force   # Force local install"
    echo "  ./install.sh --advanced        # Interactive advanced setup"
    echo ""
    read -p "Press Enter to continue..."
    echo ""
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --global)
                INSTALL_TYPE="global"
                shift
                ;;
            --local)
                INSTALL_TYPE="local"
                shift
                ;;
            --advanced)
                INSTALL_TYPE="advanced"
                shift
                ;;
            --update)
                INSTALL_TYPE="update"
                shift
                ;;
            --uninstall)
                INSTALL_TYPE="uninstall"
                shift
                ;;
            --force)
                FORCE_INSTALL=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Create configuration directory and files
setup_config() {
    print_step "Setting up configuration..."
    
    if [[ "$INSTALL_TYPE" == "local" ]]; then
        print_info "Using local configuration directory: $CONFIG_DIR"
        # Add .secret-war to .gitignore for local installations
        local gitignore_file="$(git rev-parse --show-toplevel)/.gitignore"
        if [[ -f "$gitignore_file" ]]; then
            if ! grep -q "^\.secret-war/" "$gitignore_file" 2>/dev/null; then
                echo "" >> "$gitignore_file"
                echo "# Secret WAR configuration" >> "$gitignore_file"
                echo ".secret-war/" >> "$gitignore_file"
                print_info "Added .secret-war/ to .gitignore"
            fi
        else
            echo "# Secret WAR configuration" > "$gitignore_file"
            echo ".secret-war/" >> "$gitignore_file"
            print_info "Created .gitignore with .secret-war/ entry"
        fi
    else
        print_info "Using global configuration directory: $CONFIG_DIR"
    fi
    
    mkdir -p "$CONFIG_DIR" "$CONFIG_DIR/reports"
    
    # Copy main script (this is not needed for installation, only for reference)
    # The main functionality is embedded in the pre-commit hook
    
    # Create default patterns file if it doesn't exist
    if [[ ! -f "$CONFIG_DIR/patterns.conf" ]] || [[ "$FORCE_INSTALL" == true ]]; then
        create_patterns_config
    fi
    
    # Create whitelist files if they don't exist
    if [[ ! -f "$CONFIG_DIR/whitelist-files.conf" ]] || [[ "$FORCE_INSTALL" == true ]]; then
        create_whitelist_files_config
    fi
    
    if [[ ! -f "$CONFIG_DIR/whitelist-patterns.conf" ]] || [[ "$FORCE_INSTALL" == true ]]; then
        create_whitelist_patterns_config
    fi
    
    # Create functions library
    create_functions_library
    
    print_success "Configuration setup completed"
}

# Create patterns configuration
create_patterns_config() {
    cat > "$CONFIG_DIR/patterns.conf" << 'EOF'
# Secret WAR Pattern Configuration
# Add one regex pattern per line
# Lines starting with # are comments

# API Keys and Secrets
(?i)(password|pwd|pass|key|token|secret|auth)\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?

# Social Security Numbers
\b\d{3}-\d{2}-\d{4}\b
\b\d{3}\s\d{2}\s\d{4}\b

# Email and Phone Patterns
[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
\+?[1-9]\d{1,14}

# AWS Keys
AKIA[0-9A-Z]{16}
[A-Za-z0-9/+=]{40}

# Azure Tokens
[a-zA-Z0-9_-]*azure[a-zA-Z0-9_-]*\s*[:=]\s*['"'"'"][a-zA-Z0-9_-]{20,}['"'"'"]

# Google API Keys
AIza[0-9A-Za-z_-]{35}

# GitHub Tokens
ghp_[A-Za-z0-9]{36}
gho_[A-Za-z0-9]{36}
ghu_[A-Za-z0-9]{36}
ghs_[A-Za-z0-9]{36}
ghr_[A-Za-z0-9]{36}

# Slack Tokens
xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}

# Twilio
SK[a-z0-9]{32}
AC[a-z0-9]{32}

# SendGrid
SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}

# Stripe
sk_live_[0-9a-zA-Z]{24}
pk_live_[0-9a-zA-Z]{24}
sk_test_[0-9a-zA-Z]{24}
pk_test_[0-9a-zA-Z]{24}

# PayPal
access_token\$production\$[a-z0-9]{16}\$[a-z0-9]{32}

# Square
sq0atp-[0-9A-Za-z_-]{22}
sq0csp-[0-9A-Za-z_-]{43}

# JWT Tokens
eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*

# Private Keys
-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----
-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----

# Database URLs
(mongodb|mysql|postgres|redis)://[^\s"']+
//\s*(?i)(password|pwd|pass|key|token|secret|auth)\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?
#\s*(?i)(password|pwd|pass|key|token|secret|auth)\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?
/\*\s*(?i)(password|pwd|pass|key|token|secret|auth)\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?\s*\*/

# TODO/FIXME comments with credentials
(?i)(?:todo|fixme|hack|temp|temporary)\s*[:]*\s*(?:password|pwd|pass|key|token|secret|auth)\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?

# Commented out credentials
//\s*(?i)[a-z0-9_-]*(?:api[_-]?key|token|secret|password)[a-z0-9_-]*\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?
#\s*(?i)[a-z0-9_-]*(?:api[_-]?key|token|secret|password)[a-z0-9_-]*\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?

# Multi-line comment blocks with secrets
/\*[\s\S]*?(?i)(password|key|token|secret|auth)[\s\S]*?[a-z0-9_-]{12,}[\s\S]*?\*/

# XML/HTML comments with secrets
<!--\s*(?i)(password|pwd|pass|key|token|secret|auth)\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?\s*-->

# Python docstring secrets
"""\s*(?i)(password|pwd|pass|key|token|secret|auth)\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?\s*"""
'''\s*(?i)(password|pwd|pass|key|token|secret|auth)\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?\s*'''

# Shell script comments
#!\s*/bin/(?:bash|sh)[\s\S]*?#\s*(?i)(password|pwd|pass|key|token|secret|auth)\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?


# Development notes with credentials
(?i)note\s*[:]*\s*(?:password|pwd|pass|key|token|secret|auth)\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?
(?i)remember\s*[:]*\s*(?:password|pwd|pass|key|token|secret|auth)\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?
(?i)default\s*[:]*\s*(?:password|pwd|pass|key|token|secret|auth)\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?

# Debug comments with sensitive info
(?i)debug\s*[:]*\s*(?:password|pwd|pass|key|token|secret|auth)\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?
(?i)test\s*[:]*\s*(?:password|pwd|pass|key|token|secret|auth)\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?

# Active API keys
(?i)[a-z0-9_-]*api[_-]?key[a-z0-9_-]*\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?
(?i)[a-z0-9_-]*token[a-z0-9_-]*\s*[:=]\s*['""]?[a-z0-9_-]{12,}['""]?
(?i)[a-z0-9_-]*secret[a-z0-9_-]*\s*[:=]\s*['""]?[a-z0-9_-]{12,}['""]?
(?i)[a-z0-9_-]*auth[a-z0-9_-]*\s*[:=]\s*['""]?[a-z0-9_-]{12,}['""]?
(?i)bearer\s+[a-z0-9_-]{12,}

# Commented API keys
//\s*(?i)[a-z0-9_-]*api[_-]?key[a-z0-9_-]*\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?
#\s*(?i)[a-z0-9_-]*api[_-]?key[a-z0-9_-]*\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?

# Environment variable patterns
(?i)export\s+[A-Z_]*(?:API|TOKEN|SECRET|KEY)[A-Z_]*\s*=\s*['""]?[a-z0-9_-]{8,}['""]?
(?i)set\s+[A-Z_]*(?:API|TOKEN|SECRET|KEY)[A-Z_]*\s*=\s*['""]?[a-z0-9_-]{8,}['""]?

# JSON/YAML configurations
"(?i)[a-z0-9_-]*(?:api[_-]?key|token|secret|auth)[a-z0-9_-]*"\s*:\s*"[a-z0-9_-]{8,}"
(?i)[a-z0-9_-]*(?:api[_-]?key|token|secret|auth)[a-z0-9_-]*\s*:\s*['""]?[a-z0-9_-]{8,}['""]?
# AWS Access Keys
AKIA[0-9A-Z]{16}
ASIA[0-9A-Z]{16}
AROA[0-9A-Z]{16}
AIDA[0-9A-Z]{16}
AIPA[0-9A-Z]{16}
ANPA[0-9A-Z]{16}
ANVA[0-9A-Z]{16}
AGPA[0-9A-Z]{16}

# AWS Secret Keys
(?i)aws_secret_access_key\s*[:=]\s*['""]?[a-z0-9/+=]{40}['""]?
(?i)aws_access_key_id\s*[:=]\s*['""]?[a-z0-9]{20}['""]?
(?i)aws_session_token\s*[:=]\s*['""]?[a-z0-9/+=]{16,}['""]?

# AWS in comments
//\s*(?i)aws[_-]?(?:secret|access|session)[_-]?(?:key|token)[_-]?(?:id)?\s*[:=]\s*['""]?[a-z0-9/+=]{20,}['""]?
#\s*(?i)aws[_-]?(?:secret|access|session)[_-]?(?:key|token)[_-]?(?:id)?\s*[:=]\s*['""]?[a-z0-9/+=]{20,}['""]?

# AWS CLI configuration
\[(?:default|profile\s+[a-z0-9_-]+)\][\s\S]*?aws_access_key_id\s*=\s*[a-z0-9]{20}
\[(?:default|profile\s+[a-z0-9_-]+)\][\s\S]*?aws_secret_access_key\s*=\s*[a-z0-9/+=]{40}

# AWS Lambda environment variables
(?i)AWS_LAMBDA_FUNCTION_[A-Z_]*\s*[:=]\s*['""]?[a-z0-9_-]{8,}['""]?

# AWS RDS connection strings
(?i)rds[.-][a-z0-9-]+\.amazonaws\.com
(?i)rds[.-][a-z0-9-]+\.amazonaws\.com[:/][0-9]+/[a-z0-9_-]+
# AWS S3 bucket names
(?i)s3://[a-z0-9._-]+/[a-z0-9._-]+
# AWS S3 access keys
(?i)s3_access_key_id\s*[:=]\s*['""]?[a-z0-9]{20}['""]?
(?i)s3_secret_access_key\s*[:=]\s*['""]?[a-z0-9/+=]{40}['""]?
# Azure Keys
(?i)azure[_-]?client[_-]?secret\s*[:=]\s*['""]?[a-z0-9_~.-]{34,}['""]?
(?i)azure[_-]?tenant[_-]?id\s*[:=]\s*['""]?[a-f0-9-]{36}['""]?
(?i)azure[_-]?client[_-]?id\s*[:=]\s*['""]?[a-f0-9-]{36}['""]?
(?i)azure[_-]?subscription[_-]?id\s*[:=]\s*['""]?[a-f0-9-]{36}['""]?

# Azure Storage Account Keys
(?i)azure[_-]?storage[_-]?(?:account|connection)[_-]?(?:key|string)\s*[:=]\s*['""]?[a-z0-9+/=]{88}['""]?
DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]{88};

# Azure in comments
//\s*(?i)azure[_-]?(?:client|tenant|subscription)[_-]?(?:secret|id)\s*[:=]\s*['""]?[a-f0-9_~.-]{34,}['""]?
#\s*(?i)azure[_-]?(?:client|tenant|subscription)[_-]?(?:secret|id)\s*[:=]\s*['""]?[a-f0-9_~.-]{34,}['""]?
# GitHub Personal Access Tokens
ghp_[a-zA-Z0-9]{36}
gho_[a-zA-Z0-9]{36}
ghu_[a-zA-Z0-9]{36}
ghs_[a-zA-Z0-9]{36}
ghr_[a-zA-Z0-9]{36}
github_pat_[a-zA-Z0-9_]{82}

# GitHub App Tokens
(?i)github[_-]?token\s*[:=]\s*['""]?[a-z0-9]{40}['""]?
(?i)gh[_-]?token\s*[:=]\s*['""]?gh[a-z]_[a-zA-Z0-9]{36}['""]?

# GitHub in comments
//\s*(?i)github[_-]?(?:token|pat|key)\s*[:=]\s*['""]?gh[a-z]_[a-zA-Z0-9]{36}['""]?
#\s*(?i)github[_-]?(?:token|pat|key)\s*[:=]\s*['""]?gh[a-z]_[a-zA-Z0-9]{36}['""]?

# GitHub CLI authentication
gh auth login --with-token <<< [a-zA-Z0-9]{40}
# GitLab Tokens
glpat-[a-zA-Z0-9_-]{20}
(?i)gitlab[_-]?token\s*[:=]\s*['""]?[a-z0-9_-]{20,}['""]?
(?i)gitlab[_-]?private[_-]?token\s*[:=]\s*['""]?[a-z0-9_-]{20,}['""]?

# GitLab CI variables
(?i)CI_JOB_TOKEN\s*[:=]\s*['""]?[a-z0-9_-]{20,}['""]?
(?i)GITLAB_TOKEN\s*[:=]\s*['""]?[a-z0-9_-]{20,}['""]?

# GitLab in comments
//\s*(?i)gitlab[_-]?(?:token|private[_-]?token)\s*[:=]\s*['""]?[a-z0-9_-]{20,}['""]?
#\s*(?i)gitlab[_-]?(?:token|private[_-]?token)\s*[:=]\s*['""]?[a-z0-9_-]{20,}['""]?

# MySQL
mysql://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_.-]+
(?i)mysql[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)mysql[_-]?host\s*[:=]\s*['""]?[a-z0-9.-]+['""]?
(?i)mysql[_-]?user\s*[:=]\s*['""]?[a-z0-9_-]+['""]?

# MySQL in comments
//\s*(?i)mysql[_-]?(?:password|user|host|database)\s*[:=]\s*['""]?[^\s'"";]{4,}['""]?
#\s*(?i)mysql[_-]?(?:password|user|host|database)\s*[:=]\s*['""]?[^\s'"";]{4,}['""]?

# PostgreSQL
postgresql://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_.-]+
postgres://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_.-]+
(?i)postgres[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# SQL Server
sqlserver://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+;database=[a-zA-Z0-9_.-]+
mssql://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_.-]+
(?i)(?:mssql|sqlserver)[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# Oracle
oracle://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_.-]+
jdbc:oracle:thin:@[a-zA-Z0-9_.-]+:[0-9]+:[a-zA-Z0-9_.-]+
(?i)oracle[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# SQLite with passwords
(?i)sqlite[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# JDBC Connection Strings
jdbc:[a-z]+://[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_.-]+\?user=[a-zA-Z0-9_.-]+&password=[a-zA-Z0-9_.-]+


# MySQL
mysql://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_.-]+
(?i)mysql[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)mysql[_-]?host\s*[:=]\s*['""]?[a-z0-9.-]+['""]?
(?i)mysql[_-]?user\s*[:=]\s*['""]?[a-z0-9_-]+['""]?

# MySQL in comments
//\s*(?i)mysql[_-]?(?:password|user|host|database)\s*[:=]\s*['""]?[^\s'"";]{4,}['""]?
#\s*(?i)mysql[_-]?(?:password|user|host|database)\s*[:=]\s*['""]?[^\s'"";]{4,}['""]?

# PostgreSQL
postgresql://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_.-]+
postgres://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_.-]+
(?i)postgres[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# SQL Server
sqlserver://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+;database=[a-zA-Z0-9_.-]+
mssql://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_.-]+
(?i)(?:mssql|sqlserver)[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# Oracle
oracle://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_.-]+
jdbc:oracle:thin:@[a-zA-Z0-9_.-]+:[0-9]+:[a-zA-Z0-9_.-]+
(?i)oracle[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# SQLite with passwords
(?i)sqlite[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# JDBC Connection Strings
jdbc:[a-z]+://[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_.-]+\?user=[a-zA-Z0-9_.-]+&password=[a-zA-Z0-9_.-]+


# MongoDB
mongodb://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_.-]+
mongodb\+srv://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+
(?i)mongo[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)mongodb[_-]?uri\s*[:=]\s*['""]?mongodb(?:\+srv)?://[^\s'"";]+['""]?

# MongoDB in comments
//\s*(?i)mongo(?:db)?[_-]?(?:password|uri|connection)\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
#\s*(?i)mongo(?:db)?[_-]?(?:password|uri|connection)\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# Redis
redis://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+
rediss://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+
(?i)redis[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)redis[_-]?auth\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# Elasticsearch
(?i)elastic[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)elasticsearch[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# CouchDB
(?i)couchdb[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
http://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+

# Cassandra
(?i)cassandra[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# RSA Private Keys
-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----[^-]*-----END\s+RSA\s+PRIVATE\s+KEY-----
-----BEGIN\s+PRIVATE\s+KEY-----[^-]*-----END\s+PRIVATE\s+KEY-----
-----BEGIN\s+EC\s+PRIVATE\s+KEY-----[^-]*-----END\s+EC\s+PRIVATE\s+KEY-----
-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----[^-]*-----END\s+DSA\s+PRIVATE\s+KEY-----
-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[^-]*-----END\s+OPENSSH\s+PRIVATE\s+KEY-----

# PGP Private Keys
-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----[^-]*-----END\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----

# SSH Private Keys
ssh-rsa\s+[A-Za-z0-9+/=]+
ssh-ed25519\s+[A-Za-z0-9+/=]+
ssh-dss\s+[A-Za-z0-9+/=]+

# Private keys in comments
//\s*-----BEGIN[^-]*PRIVATE[^-]*KEY-----
#\s*-----BEGIN[^-]*PRIVATE[^-]*KEY-----

# Environment variables with private keys
(?i)(?:export\s+|set\s+)?[A-Z_]*PRIVATE[_]?KEY[A-Z_]*\s*=\s*['""]?-----BEGIN[^"']*-----['""]?

# SSH key files
id_rsa\s*[:=]\s*['""]?-----BEGIN[^"']*PRIVATE[^"']*KEY-----[^"']*-----END[^"']*PRIVATE[^"']*KEY-----['""]?
id_ed25519\s*[:=]\s*['""]?-----BEGIN[^"']*PRIVATE[^"']*KEY-----[^"']*-----END[^"']*PRIVATE[^"']*KEY-----['""]?

# SSL/TLS Certificates
-----BEGIN\s+CERTIFICATE-----[^-]*-----END\s+CERTIFICATE-----
-----BEGIN\s+X509\s+CERTIFICATE-----[^-]*-----END\s+X509\s+CERTIFICATE-----
-----BEGIN\s+TRUSTED\s+CERTIFICATE-----[^-]*-----END\s+TRUSTED\s+CERTIFICATE-----

# Certificate Signing Requests
-----BEGIN\s+CERTIFICATE\s+REQUEST-----[^-]*-----END\s+CERTIFICATE\s+REQUEST-----
-----BEGIN\s+NEW\s+CERTIFICATE\s+REQUEST-----[^-]*-----END\s+NEW\s+CERTIFICATE\s+REQUEST-----

# Public Keys
-----BEGIN\s+PUBLIC\s+KEY-----[^-]*-----END\s+PUBLIC\s+KEY-----
-----BEGIN\s+RSA\s+PUBLIC\s+KEY-----[^-]*-----END\s+RSA\s+PUBLIC\s+KEY-----

# Certificate in environment variables
(?i)(?:export\s+|set\s+)?[A-Z_]*(?:CERT|CERTIFICATE)[A-Z_]*\s*=\s*['""]?-----BEGIN[^"']*CERTIFICATE-----[^"']*-----END[^"']*CERTIFICATE-----['""]?

# SSL/TLS Certificates
-----BEGIN\s+CERTIFICATE-----[^-]*-----END\s+CERTIFICATE-----
-----BEGIN\s+X509\s+CERTIFICATE-----[^-]*-----END\s+X509\s+CERTIFICATE-----
-----BEGIN\s+TRUSTED\s+CERTIFICATE-----[^-]*-----END\s+TRUSTED\s+CERTIFICATE-----

# Certificate Signing Requests
-----BEGIN\s+CERTIFICATE\s+REQUEST-----[^-]*-----END\s+CERTIFICATE\s+REQUEST-----
-----BEGIN\s+NEW\s+CERTIFICATE\s+REQUEST-----[^-]*-----END\s+NEW\s+CERTIFICATE\s+REQUEST-----

# Public Keys
-----BEGIN\s+PUBLIC\s+KEY-----[^-]*-----END\s+PUBLIC\s+KEY-----
-----BEGIN\s+RSA\s+PUBLIC\s+KEY-----[^-]*-----END\s+RSA\s+PUBLIC\s+KEY-----

# Certificate in environment variables
(?i)(?:export\s+|set\s+)?[A-Z_]*(?:CERT|CERTIFICATE)[A-Z_]*\s*=\s*['""]?-----BEGIN[^"']*CERTIFICATE-----[^"']*-----END[^"']*CERTIFICATE-----['""]?

# JWT Tokens
eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*

# JWT in various contexts
(?i)jwt[_-]?token\s*[:=]\s*['""]?eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*['""]?
(?i)bearer\s+eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*
Authorization:\s*Bearer\s+eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*

# JWT in comments
//\s*(?i)jwt[_-]?token\s*[:=]\s*['""]?eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*['""]?
#\s*(?i)jwt[_-]?token\s*[:=]\s*['""]?eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*['""]?

# Session IDs
(?i)session[_-]?id\s*[:=]\s*['""]?[a-z0-9]{16,}['""]?
(?i)jsessionid\s*[:=]\s*['""]?[a-z0-9]{16,}['""]?
(?i)phpsessid\s*[:=]\s*['""]?[a-z0-9]{16,}['""]?
(?i)asp\.net[_-]?sessionid\s*[:=]\s*['""]?[a-z0-9]{16,}['""]?

# Session tokens in cookies
Set-Cookie:\s*[a-zA-Z0-9_-]*(?:session|token|auth)[a-zA-Z0-9_-]*=[a-zA-Z0-9+/=]{16,}
Cookie:\s*[a-zA-Z0-9_-]*(?:session|token|auth)[a-zA-Z0-9_-]*=[a-zA-Z0-9+/=]{16,}

# Slack Tokens
xox[baprs]-[0-9a-zA-Z-]{10,48}
xoxe.xox[bp]-[0-9]-[a-zA-Z0-9-]+

# Slack webhooks
https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+

# Slack in comments
//\s*(?i)slack[_-]?(?:token|webhook|bot[_-]?token)\s*[:=]\s*['""]?xox[a-z]-[0-9a-zA-Z-]{10,48}['""]?
#\s*(?i)slack[_-]?(?:token|webhook|bot[_-]?token)\s*[:=]\s*['""]?xox[a-z]-[0-9a-zA-Z-]{10,48}['""]?

# Discord Tokens
[MN][A-Za-z\d]{23}\.[A-Za-z\d-_]{6}\.[A-Za-z\d-_]{27}
mfa\.[a-z0-9_-]{84}

# Discord webhooks
https://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+
https://discordapp\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+

# Discord in comments
//\s*(?i)discord[_-]?(?:token|webhook|bot[_-]?token)\s*[:=]\s*['""]?[MN][A-Za-z\d]{23}\.[A-Za-z\d-_]{6}\.[A-Za-z\d-_]{27}['""]?
#\s*(?i)discord[_-]?(?:token|webhook|bot[_-]?token)\s*[:=]\s*['""]?[MN][A-Za-z\d]{23}\.[A-Za-z\d-_]{6}\.[A-Za-z\d-_]{27}['""]?

# Telegram Bot Tokens
[0-9]{8,10}:[a-zA-Z0-9_-]{35}

# Telegram in comments
//\s*(?i)telegram[_-]?(?:token|bot[_-]?token)\s*[:=]\s*['""]?[0-9]{8,10}:[a-zA-Z0-9_-]{35}['""]?
#\s*(?i)telegram[_-]?(?:token|bot[_-]?token)\s*[:=]\s*['""]?[0-9]{8,10}:[a-zA-Z0-9_-]{35}['""]?

# Twilio
SK[a-z0-9]{32}
AC[a-z0-9]{32}
(?i)twilio[_-]?auth[_-]?token\s*[:=]\s*['""]?[a-z0-9]{32}['""]?
(?i)twilio[_-]?account[_-]?sid\s*[:=]\s*['""]?AC[a-z0-9]{32}['""]?

# Twilio in comments
//\s*(?i)twilio[_-]?(?:auth[_-]?token|account[_-]?sid)\s*[:=]\s*['""]?[AS][CK][a-z0-9]{32}['""]?
#\s*(?i)twilio[_-]?(?:auth[_-]?token|account[_-]?sid)\s*[:=]\s*['""]?[AS][CK][a-z0-9]{32}['""]?

# SendGrid
SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}
(?i)sendgrid[_-]?api[_-]?key\s*[:=]\s*['""]?SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}['""]?

# SendGrid in comments
//\s*(?i)sendgrid[_-]?api[_-]?key\s*[:=]\s*['""]?SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}['""]?
#\s*(?i)sendgrid[_-]?api[_-]?key\s*[:=]\s*['""]?SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}['""]?

# Mailgun
key-[a-z0-9]{32}
(?i)mailgun[_-]?api[_-]?key\s*[:=]\s*['""]?key-[a-z0-9]{32}['""]?
(?i)mailgun[_-]?domain\s*[:=]\s*['""]?[a-z0-9.-]+['""]?

# Mailgun in comments
//\s*(?i)mailgun[_-]?api[_-]?key\s*[:=]\s*['""]?key-[a-z0-9]{32}['""]?
#\s*(?i)mailgun[_-]?api[_-]?key\s*[:=]\s*['""]?key-[a-z0-9]{32}['""]?

# Mailchimp
[a-f0-9]{32}-us[0-9]{1,2}
(?i)mailchimp[_-]?api[_-]?key\s*[:=]\s*['""]?[a-f0-9]{32}-us[0-9]{1,2}['""]?

# AWS SES
(?i)ses[_-]?(?:access[_-]?key|secret[_-]?key)\s*[:=]\s*['""]?[a-zA-Z0-9+/=]{20,}['""]?

# Postmark
[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}
(?i)postmark[_-]?(?:server[_-]?token|api[_-]?key)\s*[:=]\s*['""]?[a-f0-9-]{36}['""]?

# SendGrid
SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}
(?i)sendgrid[_-]?api[_-]?key\s*[:=]\s*['""]?SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}['""]?

# SendGrid in comments
//\s*(?i)sendgrid[_-]?api[_-]?key\s*[:=]\s*['""]?SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}['""]?
#\s*(?i)sendgrid[_-]?api[_-]?key\s*[:=]\s*['""]?SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}['""]?

# Mailgun
key-[a-z0-9]{32}
(?i)mailgun[_-]?api[_-]?key\s*[:=]\s*['""]?key-[a-z0-9]{32}['""]?
(?i)mailgun[_-]?domain\s*[:=]\s*['""]?[a-z0-9.-]+['""]?

# Mailgun in comments
//\s*(?i)mailgun[_-]?api[_-]?key\s*[:=]\s*['""]?key-[a-z0-9]{32}['""]?
#\s*(?i)mailgun[_-]?api[_-]?key\s*[:=]\s*['""]?key-[a-z0-9]{32}['""]?

# Mailchimp
[a-f0-9]{32}-us[0-9]{1,2}
(?i)mailchimp[_-]?api[_-]?key\s*[:=]\s*['""]?[a-f0-9]{32}-us[0-9]{1,2}['""]?

# AWS SES
(?i)ses[_-]?(?:access[_-]?key|secret[_-]?key)\s*[:=]\s*['""]?[a-zA-Z0-9+/=]{20,}['""]?

# Postmark
[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}
(?i)postmark[_-]?(?:server[_-]?token|api[_-]?key)\s*[:=]\s*['""]?[a-f0-9-]{36}['""]?

# Stripe
sk_live_[0-9a-zA-Z]{24}
pk_live_[0-9a-zA-Z]{24}
sk_test_[0-9a-zA-Z]{24}
pk_test_[0-9a-zA-Z]{24}
rk_live_[0-9a-zA-Z]{24}
rk_test_[0-9a-zA-Z]{24}

# Stripe webhooks
whsec_[a-zA-Z0-9]{32,}

# Stripe in comments
//\s*(?i)stripe[_-]?(?:secret|publishable|restricted)[_-]?key\s*[:=]\s*['""]?[sp]k_(?:live|test)_[0-9a-zA-Z]{24}['""]?
#\s*(?i)stripe[_-]?(?:secret|publishable|restricted)[_-]?key\s*[:=]\s*['""]?[sp]k_(?:live|test)_[0-9a-zA-Z]{24}['""]?

# PayPal
access_token\$production\$[a-z0-9]{16}\$[a-z0-9]{32}
access_token\$sandbox\$[a-z0-9]{16}\$[a-z0-9]{32}
(?i)paypal[_-]?(?:client[_-]?id|client[_-]?secret)\s*[:=]\s*['""]?[a-zA-Z0-9_-]{80}['""]?

# PayPal in comments
//\s*(?i)paypal[_-]?(?:client[_-]?id|client[_-]?secret|access[_-]?token)\s*[:=]\s*['""]?[a-zA-Z0-9_$-]{32,}['""]?
#\s*(?i)paypal[_-]?(?:client[_-]?id|client[_-]?secret|access[_-]?token)\s*[:=]\s*['""]?[a-zA-Z0-9_$-]{32,}['""]?

# Square
sq0atp-[0-9A-Za-z_-]{22}
sq0csp-[0-9A-Za-z_-]{43}
sq0idb-[0-9A-Za-z_-]{22}

# Square in comments
//\s*(?i)square[_-]?(?:access[_-]?token|application[_-]?id)\s*[:=]\s*['""]?sq0[a-z]{3}-[0-9A-Za-z_-]{22,43}['""]?
#\s*(?i)square[_-]?(?:access[_-]?token|application[_-]?id)\s*[:=]\s*['""]?sq0[a-z]{3}-[0-9A-Za-z_-]{22,43}['""]?

# Braintree
(?i)braintree[_-]?(?:merchant[_-]?id|public[_-]?key|private[_-]?key)\s*[:=]\s*['""]?[a-zA-Z0-9]{16,}['""]?

# Facebook/Meta
(?i)facebook[_-]?(?:app[_-]?id|app[_-]?secret|access[_-]?token)\s*[:=]\s*['""]?[a-zA-Z0-9]{15,}['""]?
(?i)fb[_-]?(?:app[_-]?id|app[_-]?secret|access[_-]?token)\s*[:=]\s*['""]?[a-zA-Z0-9]{15,}['""]?

# Facebook in comments
//\s*(?i)(?:facebook|fb)[_-]?(?:app[_-]?id|app[_-]?secret|access[_-]?token)\s*[:=]\s*['""]?[a-zA-Z0-9]{15,}['""]?
#\s*(?i)(?:facebook|fb)[_-]?(?:app[_-]?id|app[_-]?secret|access[_-]?token)\s*[:=]\s*['""]?[a-zA-Z0-9]{15,}['""]?

# Twitter/X API
(?i)twitter[_-]?(?:consumer[_-]?key|consumer[_-]?secret|access[_-]?token|access[_-]?token[_-]?secret)\s*[:=]\s*['""]?[a-zA-Z0-9]{25,}['""]?
(?i)x[_-]?(?:consumer[_-]?key|consumer[_-]?secret|access[_-]?token|bearer[_-]?token)\s*[:=]\s*['""]?[a-zA-Z0-9]{25,}['""]?

# Google Analytics
UA-[0-9]{4,9}-[0-9]{1,4}
G-[A-Z0-9]{10}
(?i)google[_-]?analytics[_-]?(?:tracking[_-]?id|measurement[_-]?id)\s*[:=]\s*['""]?(?:UA-[0-9-]+|G-[A-Z0-9]{10})['""]?

# Google Analytics in comments
//\s*(?i)(?:ga|google[_-]?analytics)[_-]?(?:tracking[_-]?id|measurement[_-]?id)\s*[:=]\s*['""]?(?:UA-[0-9-]+|G-[A-Z0-9]{10})['""]?
#\s*(?i)(?:ga|google[_-]?analytics)[_-]?(?:tracking[_-]?id|measurement[_-]?id)\s*[:=]\s*['""]?(?:UA-[0-9-]+|G-[A-Z0-9]{10})['""]?

# LinkedIn API
(?i)linkedin[_-]?(?:client[_-]?id|client[_-]?secret|access[_-]?token)\s*[:=]\s*['""]?[a-zA-Z0-9]{10,}['""]?

# Instagram API
(?i)instagram[_-]?(?:client[_-]?id|client[_-]?secret|access[_-]?token)\s*[:=]\s*['""]?[a-zA-Z0-9]{15,}['""]?

# Generic password patterns
(?i)password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)passwd\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)pwd\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)pass\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# Passwords in comments
//\s*(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
#\s*(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# Database passwords
(?i)db[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)database[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)db[_-]?pass\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# Admin passwords
(?i)admin[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)root[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)superuser[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# Application-specific passwords
(?i)(?:app|application)[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)user[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)login[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# Service passwords
(?i)service[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)auth[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# FTP/SFTP passwords
(?i)ftp[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)sftp[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# Email passwords
(?i)email[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)smtp[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)imap[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)pop3[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# WiFi passwords
(?i)wifi[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)wpa[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?
(?i)network[_-]?password\s*[:=]\s*['""]?[^\s'"";]{8,}['""]?

# Default passwords (commonly used)
(?i)password\s*[:=]\s*['""]?(?:password|123456|admin|root|default|guest|user)['""]?
(?i)(?:user|admin|root)\s*[:=]\s*['""]?[a-zA-Z0-9_-]+['""]?\s*[,;]\s*(?i)(?:password|pass|pwd)\s*[:=]\s*['""]?[^\s'"";]{4,}['""]?
# Admin panels
/admin[/]?
/administrator[/]?
/wp-admin[/]?
/phpmyadmin[/]?
/cpanel[/]?
/webmin[/]?
/manager[/]?
/console[/]?
/dashboard[/]?

# API endpoints with potential secrets
/api/v[0-9]+/keys
/api/v[0-9]+/tokens
/api/v[0-9]+/secrets
/api/v[0-9]+/config
/api/v[0-9]+/admin
/.env
/config/
/.git/config
/.svn/
/.htaccess
/.htpasswd

# Database admin interfaces
/phpMyAdmin[/]?
/adminer[/]?
/mysql[/]?
/postgres[/]?
/mongodb[/]?

# Cloud service endpoints
/aws/credentials
/azure/config
/gcp/service-account
/.aws/credentials
/.azure/credentials

# Debug and development endpoints
/debug[/]?
/test[/]?
/dev[/]?
/trace[/]?
/health[/]?
/metrics[/]?
/status[/]?

# Endpoints in comments
//\s*/(?:admin|api|config|debug|test)[^\s]*
#\s*/(?:admin|api|config|debug|test)[^\s]*
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

# Credit Card Numbers
4[0-9]{12}(?:[0-9]{3})?
5[1-5][0-9]{14}
3[47][0-9]{13}

# Social Security Numbers
\b\d{3}-\d{2}-\d{4}\b
\b\d{3}\s\d{2}\s\d{4}\b

# Email and Phone Patterns
[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
\+?[1-9]\d{1,14}

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
# Credit Card Numbers (basic pattern)
\b(?:\d{4}[-\s]?){3}\d{4}\b
EOF
}

# Create whitelist files configuration
create_whitelist_files_config() {
    cat > "$CONFIG_DIR/whitelist-files.conf" << 'EOF'
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
*.min.js
*.min.css

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
*.webp

# Archive files
*.zip
*.tar
*.gz
*.rar
*.7z
*.bz2
*.xz

# Documentation
*.pdf
*.doc
*.docx

# OS generated files
.DS_Store
Thumbs.db

# Version control
.git/
.svn/
.hg/

# Secret WAR files
.secret-war/
secret-war.sh
install.sh
Secret_WAR_Install_v3.sh

# Package lock files
package-lock.json
yarn.lock
composer.lock
Pipfile.lock
EOF
}

# Create whitelist patterns configuration
create_whitelist_patterns_config() {
    cat > "$CONFIG_DIR/whitelist-patterns.conf" << 'EOF'
# Secret WAR Pattern Whitelist
# Add regex patterns to whitelist (one per line)

# Test files and examples
test.*password.*=.*example
.*example.*key.*=.*dummy
.*sample.*token.*=.*fake
.*mock.*secret.*=.*test
.*placeholder.*
.*your.*key.*here.*
.*insert.*key.*
.*replace.*with.*

# Documentation patterns
.*api.*key.*documentation
.*token.*example.*readme
.*secret.*description

# Environment template files  
.*\.env\.template
.*\.env\.example
.*\.env\.sample
.*\.env\.local\.example

# Common false positives
.*lorem.*ipsum.*
.*demo.*data.*
.*test.*data.*
.*123456.*
.*password.*password.*
.*secret.*secret.*
EOF
}

# Create functions library
create_functions_library() {
    local functions_file="$CONFIG_DIR/secret-war-functions.sh"
    
    cat > "$functions_file" << 'FUNCTIONS_EOF'
# Secret WAR Functions Library

# Determine config directory based on context
get_config_dir() {
    # Check if we're in a git repo with local config
    if git rev-parse --git-dir >/dev/null 2>&1; then
        local repo_root="$(git rev-parse --show-toplevel)"
        if [[ -d "$repo_root/.secret-war" ]]; then
            echo "$repo_root/.secret-war"
            return 0
        fi
    fi
    
    # Fallback to global config
    echo "$HOME/.secret-war"
}

# Initialize config directory variable
CONFIG_DIR="$(get_config_dir)"

# Load patterns from config
load_patterns() {
    local patterns=()
    if [[ -f "$CONFIG_DIR/patterns.conf" ]]; then
        while IFS= read -r line; do
            if [[ ! "$line" =~ ^[[:space:]]*# ]] && [[ -n "${line// }" ]]; then
                patterns+=("$line")
            fi
        done < "$CONFIG_DIR/patterns.conf"
    fi
    printf '%s\n' "${patterns[@]}"
}

# Load whitelist files
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

# Load whitelist patterns
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

# Get staged files
get_staged_files() {
    git diff --cached --name-only --diff-filter=ACM | grep -v -E '\.(gitignore|gitattributes)$|\.git/|\.vscode/|\.idea/|\.secret-war/' || true
}
FUNCTIONS_EOF
}

# Install global pre-commit hook
install_global_hook() {
    print_step "Installing global pre-commit hook..."
    
    local git_template_dir="$HOME/.git-templates"
    local hooks_dir="$git_template_dir/hooks"
    
    # Create template directory
    mkdir -p "$hooks_dir"
    
    # Set global template directory
    git config --global init.templateDir "$git_template_dir"
    
    # Create pre-commit hook
    create_precommit_hook "$hooks_dir/pre-commit"
    
    print_success "Global hook installed successfully"
    print_info "All new repositories will automatically use Secret WAR"
    
    # Ask if user wants to apply to existing repositories
    echo ""
    echo -ne "${CYAN}Apply to existing repositories? [y/N]: ${NC}"
    read -r apply_existing
    
    if [[ "$apply_existing" =~ ^[Yy]$ ]]; then
        apply_to_existing_repos
    fi
}

# Install local pre-commit hook
install_local_hook() {
    print_step "Installing local pre-commit hook..."
    
    # Check if we're in a git repository
    if ! git rev-parse --git-dir >/dev/null 2>&1; then
        print_error "Not in a git repository!"
        echo "Please run this command from within a git repository."
        exit 1
    fi
    
    local git_dir
    git_dir="$(git rev-parse --git-dir)"
    local hooks_dir="$git_dir/hooks"
    
    # Create hooks directory if it doesn't exist
    mkdir -p "$hooks_dir"
    
    # Create pre-commit hook
    create_precommit_hook "$hooks_dir/pre-commit"
    
    local repo_name
    repo_name=$(basename "$(git rev-parse --show-toplevel)")
    
    print_success "Local hook installed for repository: $repo_name"
    print_info "Configuration stored locally in: $CONFIG_DIR"
}

# Create pre-commit hook file with enhanced cross-platform thread management
create_precommit_hook() {
    local hook_file="$1"
    
    # Backup existing hook if it exists
    if [[ -f "$hook_file" ]] && [[ "$FORCE_INSTALL" != true ]]; then
        if ! grep -q "Secret WAR" "$hook_file" 2>/dev/null; then
            print_warning "Existing pre-commit hook found"
            echo -ne "${CYAN}Backup and replace? [y/N]: ${NC}"
            read -r backup_choice
            
            if [[ "$backup_choice" =~ ^[Yy]$ ]]; then
                cp "$hook_file" "$hook_file.backup.$(date +%s)"
                print_info "Existing hook backed up"
            else
                print_error "Installation cancelled"
                exit 1
            fi
        fi
    fi
    
    cat > "$hook_file" << 'HOOK_EOF'
#!/bin/bash

# Secret WAR Pre-commit Hook with Cross-Platform Thread Management
# This hook is automatically installed by Secret WAR installer
# "Dread it, Run from it. Destiny Still arrives"

set -euo pipefail

# Determine config directory (local takes precedence over global)
get_config_dir() {
    if git rev-parse --git-dir >/dev/null 2>&1; then
        local repo_root="$(git rev-parse --show-toplevel)"
        if [[ -d "$repo_root/.secret-war" ]]; then
            echo "$repo_root/.secret-war"
            return 0
        fi
    fi
    echo "$HOME/.secret-war"
}

CONFIG_DIR="$(get_config_dir)"
REPORT_DIR="$CONFIG_DIR/reports"
TEMP_DIR="/tmp/secret-war-$$"
MAX_THREADS=8

# Thread management variables
THREAD_POOL_SIZE=8
FILE_QUEUE="$TEMP_DIR/file_queue"
RESULTS_DIR="$TEMP_DIR/results"
THREAD_STATUS_DIR="$TEMP_DIR/thread_status"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Cleanup function
cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Check if Secret WAR is installed
if [[ ! -f "$CONFIG_DIR/secret-war-functions.sh" ]]; then
    echo -e "${RED}❌ Secret WAR not properly installed!${NC}"
    echo -e "${YELLOW}Configuration directory: $CONFIG_DIR${NC}"
    echo -e "${YELLOW}Please run the installer to set up Secret WAR${NC}"
    exit 1
fi

# Source the main Secret WAR functions
source "$CONFIG_DIR/secret-war-functions.sh"

# Cross-platform file locking using directory-based atomic operations
acquire_lock() {
    local lock_name="$1"
    local lock_dir="$TEMP_DIR/locks/$lock_name"
    local timeout=10
    local waited=0
    
    while ! mkdir "$lock_dir" 2>/dev/null; do
        sleep 0.1
        waited=$((waited + 1))
        if [[ $waited -gt $((timeout * 10)) ]]; then
            return 1  # Lock acquisition failed
        fi
    done
    return 0
}

release_lock() {
    local lock_name="$1"
    local lock_dir="$TEMP_DIR/locks/$lock_name"
    rmdir "$lock_dir" 2>/dev/null || true
}

# Initialize thread management with cross-platform locks
init_thread_management() {
    mkdir -p "$TEMP_DIR" "$RESULTS_DIR" "$THREAD_STATUS_DIR" "$TEMP_DIR/locks"
    touch "$FILE_QUEUE"
    
    # Ensure clean state
    rm -rf "$TEMP_DIR/locks"/* 2>/dev/null || true
}

# Thread-safe file dequeue function using directory locks
dequeue_file() {
    local thread_id="$1"
    local file=""
    
    # Acquire exclusive lock for file queue access
    if acquire_lock "file_queue"; then
        if [[ -s "$FILE_QUEUE" ]]; then
            file=$(head -n1 "$FILE_QUEUE" 2>/dev/null || true)
            if [[ -n "$file" ]]; then
                # Use a more robust approach to remove first line
                local temp_file="${FILE_QUEUE}.tmp.$$"
                if tail -n +2 "$FILE_QUEUE" > "$temp_file" 2>/dev/null; then
                    mv "$temp_file" "$FILE_QUEUE" 2>/dev/null || {
                        # Fallback: recreate file without first line
                        rm -f "$temp_file"
                        tail -n +2 "$FILE_QUEUE" > "$FILE_QUEUE.new" 2>/dev/null && mv "$FILE_QUEUE.new" "$FILE_QUEUE"
                    }
                else
                    # If tail fails, manually recreate the file
                    rm -f "$temp_file"
                    if [[ $(wc -l < "$FILE_QUEUE" 2>/dev/null || echo "0") -le 1 ]]; then
                        > "$FILE_QUEUE"  # Empty the file if only one line
                    else
                        sed '1d' "$FILE_QUEUE" > "$FILE_QUEUE.new" 2>/dev/null && mv "$FILE_QUEUE.new" "$FILE_QUEUE"
                    fi
                fi
            fi
        fi
        release_lock "file_queue"
    fi
    
    echo "$file"
}

# Enhanced thread-safe status management
set_thread_status() {
    local thread_id="$1"
    local status="$2"  # active|idle|completed
    local status_file="$THREAD_STATUS_DIR/thread_$thread_id"
    
    # Use atomic write operation
    echo "$status" > "${status_file}.tmp" && mv "${status_file}.tmp" "$status_file"
}

# Check if all threads are idle or completed with better error handling
all_threads_idle() {
    local active_threads=0
    local total_threads=0
    
    for status_file in "$THREAD_STATUS_DIR"/thread_*; do
        if [[ -f "$status_file" ]]; then
            local status=$(cat "$status_file" 2>/dev/null || echo "unknown")
            ((total_threads++))
            if [[ "$status" == "active" ]]; then
                ((active_threads++))
            fi
        fi
    done
    
    # If no threads found or all are idle/completed
    [[ $active_threads -eq 0 && $total_threads -gt 0 ]]
}

# Enhanced scan file function with thread safety
scan_file_threaded() {
    local file="$1"
    local thread_id="$2"
    local thread_result_file="$RESULTS_DIR/thread_${thread_id}_results"
    local patterns
    readarray -t patterns < <(load_patterns)
    
    # Skip if file is whitelisted
    if is_file_whitelisted "$file"; then
        return 0
    fi
    
    # Skip binary files
    if ! file "$file" 2>/dev/null | grep -q text; then
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
                        echo "$match" >> "$thread_result_file"
                        found_issues=1
                    fi
                done <<< "$matches"
            fi
        fi
    done
    
    return $found_issues
}

# Worker thread function with improved error handling and cross-platform compatibility
worker_thread() {
    local thread_id="$1"
    local thread_result_file="$RESULTS_DIR/thread_${thread_id}_results"
    local max_idle_cycles=50
    local idle_cycles=0
    
    set_thread_status "$thread_id" "active"
    
    while true; do
        local file
        file=$(dequeue_file "$thread_id")
        
        if [[ -z "$file" ]]; then
            set_thread_status "$thread_id" "idle"
            ((idle_cycles++))
            
            # Wait a bit and check again
            sleep 0.1
            
            # If no file for too long and other threads are also idle, exit
            if [[ $idle_cycles -gt $max_idle_cycles ]] && all_threads_idle; then
                set_thread_status "$thread_id" "completed"
                break
            fi
            continue
        fi
        
        # Reset idle cycles when we get work
        idle_cycles=0
        set_thread_status "$thread_id" "active"
        
        if [[ -f "$file" ]]; then
            scan_file_threaded "$file" "$thread_id" || true
        fi
    done
}

# Enhanced parallel processing with better error handling and cross-platform compatibility
process_files_with_thread_pool() {
    local files=("$@")
    local pids=()
    
    if [[ ${#files[@]} -eq 0 ]]; then
        return 0
    fi
    
    init_thread_management
    
    # Populate file queue
    for file in "${files[@]}"; do
        echo "$file" >> "$FILE_QUEUE"
    done
    
    # Adjust thread pool size based on number of files
    local optimal_threads=$THREAD_POOL_SIZE
    if [[ ${#files[@]} -lt $THREAD_POOL_SIZE ]]; then
        optimal_threads=${#files[@]}
    fi
    
    echo -e "${BLUE}Starting $optimal_threads worker threads for ${#files[@]} files...${NC}" >&2
    
    # Start worker threads
    for ((i=1; i<=optimal_threads; i++)); do
        worker_thread "$i" &
        pids+=($!)
    done
    
    # Wait for all threads to complete with timeout
    local timeout=300  # 5 minutes timeout
    local elapsed=0
    
    for pid in "${pids[@]}"; do
        local wait_start=$(date +%s)
        while kill -0 "$pid" 2>/dev/null; do
            sleep 1
            elapsed=$(($(date +%s) - wait_start))
            if [[ $elapsed -gt $timeout ]]; then
                echo -e "${YELLOW}Warning: Thread $pid timed out, terminating...${NC}" >&2
                kill "$pid" 2>/dev/null || true
                break
            fi
        done
        wait "$pid" 2>/dev/null || true
    done
    
    # Combine all results into single output
    local all_results="$TEMP_DIR/combined_results"
    for result_file in "$RESULTS_DIR"/thread_*_results; do
        if [[ -f "$result_file" && -s "$result_file" ]]; then
            cat "$result_file" >> "$all_results" 2>/dev/null || true
        fi
    done
    
    # Remove duplicates and sort if results exist
    if [[ -f "$all_results" && -s "$all_results" ]]; then
        sort -u "$all_results" 2>/dev/null || cat "$all_results"
    fi
}

# Generate HTML report
generate_html_report() {
    local results="$1"
    local timestamp=$(date '+%Y-%m-%d_%H-%M-%S')
    local report_file="$REPORT_DIR/secret-war-report-$timestamp.html"
    
    mkdir -p "$REPORT_DIR"
    
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
        .stats {
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
            padding: 15px;
            background: rgba(0, 255, 0, 0.1);
            border: 1px solid #00ff00;
            border-radius: 5px;
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
            font-size: 2em;
            color: #00ff00;
        }
        .config-info {
            text-align: center;
            margin: 10px 0;
            color: #00ffff;
            font-size: 0.9em;
        }
        .thread-info {
            text-align: center;
            margin: 10px 0;
            color: #ffff00;
            font-size: 0.8em;
        }
        .results {
            background: rgba(0, 0, 0, 0.5);
            padding: 20px;
            border: 1px solid #ff0000;
            border-radius: 5px;
            white-space: pre-wrap;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #ff6666;
            max-height: 500px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="title">SECRET WAR</div>
        <div style="color: #ff0000;">Dread it, Run from it. Destiny Still arrives</div>
        <div class="config-info">Config: CONFIG_DIR_PLACEHOLDER</div>
        <div class="thread-info">Cross-Platform Thread Pool: THREAD_COUNT_PLACEHOLDER threads</div>
    </div>
REPORT_EOF

    # Replace config directory and thread count placeholders
    sed -i.bak "s|CONFIG_DIR_PLACEHOLDER|$CONFIG_DIR|g" "$report_file" && rm -f "$report_file.bak"
    sed -i.bak "s|THREAD_COUNT_PLACEHOLDER|$THREAD_POOL_SIZE|g" "$report_file" && rm -f "$report_file.bak"

    if [[ -n "$results" ]]; then
        local total_issues=$(echo "$results" | wc -l | tr -d ' ')
        cat >> "$report_file" << ISSUES_EOF
    <div class="warning">⚠️ OOPS! We Lost WAR..SECURITY VULNERABILITIES DETECTED ⚠️</div>
    <div class="stats">
        <div>Issues Found: $total_issues</div>
        <div>Threads Used: $THREAD_POOL_SIZE</div>
        <div>Scan Time: $(date '+%Y-%m-%d %H:%M:%S')</div>
    </div>
    <div class="results">$results</div>
ISSUES_EOF
    else
        cat >> "$report_file" << SUCCESS_EOF
    <div class="success">
        ✅ We Won Secret War!!!!!!!! Love you 3000
        <br><small>No security vulnerabilities detected</small>
        <br><small>Scanned with $THREAD_POOL_SIZE threads</small>
    </div>
SUCCESS_EOF
    fi
    
    echo "</body></html>" >> "$report_file"
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
    fi
}

# Show success message
show_success_message() {
    local message="We Won Secret War!!!!!!!! Love you 3000"
    
    if [[ -n "${DISPLAY:-}" ]] || [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
        if command -v notify-send >/dev/null 2>&1; then
            notify-send "Secret WAR" "$message" --icon=dialog-information 2>/dev/null || true
        elif command -v osascript >/dev/null 2>&1; then
            osascript -e "display notification \"$message\" with title \"Secret WAR\"" 2>/dev/null || true
        fi
    fi
    
    echo -e "${GREEN}✅ $message${NC}"
}

# Main execution with enhanced thread management
main() {
    echo -e "${YELLOW}🛡️  Secret WAR Security Scan Starting...${NC}"
    echo -e "${BLUE}Using configuration: $CONFIG_DIR${NC}"
    echo -e "${PURPLE}Thread Pool Size: $THREAD_POOL_SIZE${NC}"
    
    local staged_files
    readarray -t staged_files < <(get_staged_files)
    
    if [[ ${#staged_files[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No files to scan${NC}"
        exit 0
    fi
    
    echo -e "${BLUE}Doctor Scanning Vulnerabilities to Strike!!....Scanning.... ${#staged_files[@]} files with $THREAD_POOL_SIZE threads...${NC}"
    
    local start_time=$(date +%s)
    local results
    results=$(process_files_with_thread_pool "${staged_files[@]}")
    local end_time=$(date +%s)
    local scan_duration=$((end_time - start_time))
    
    echo -e "${BLUE}Scan completed in ${scan_duration} seconds${NC}"
    
    local report_file
    report_file=$(generate_html_report "$results")
    
    if [[ -n "$results" ]]; then
        echo -e "${RED}"
        echo "╔════════════════════════════════════════════════════════════════╗"
        echo "║                    SECURITY ALERT                              ║"
        echo "║            Dread it, Run from it. Destiny Still arrives        ║"
        echo "╚════════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        
        echo -e "${RED}❌ Doctor Doom Striked! ----Security vulnerabilities detected!${NC}"
        echo -e "${YELLOW}📊 Report: $report_file${NC}"
        echo -e "${BLUE}⚡ Processed with $THREAD_POOL_SIZE threads in ${scan_duration}s${NC}"
        
        open_report "$report_file"
        
        echo -e "${RED}Commit blocked for security reasons.${NC}"
        exit 1
    else
        show_success_message
        echo -e "${BLUE}⚡ Scanned ${#staged_files[@]} files with $THREAD_POOL_SIZE threads in ${scan_duration}s${NC}"
        open_report "$report_file"
        exit 0
    fi
}

main "$@"
HOOK_EOF

    chmod +x "$hook_file"
}

# Apply to existing repositories
apply_to_existing_repos() {
    print_step "Applying to existing repositories..."
    
    local repos_found=0
    local repos_updated=0
    
    # Find git repositories in common locations
    local search_paths=("$HOME/Projects" "$HOME/Code" "$HOME/Development" "$HOME/src" "$HOME/git" "$HOME")
    
    for search_path in "${search_paths[@]}"; do
        if [[ -d "$search_path" ]]; then
            while IFS= read -r -d '' repo_path; do
                if [[ -d "$repo_path/.git" ]]; then
                    ((repos_found++))
                    
                    local repo_name
                    repo_name=$(basename "$repo_path")
                    
                    if [[ "$VERBOSE" == true ]]; then
                        print_info "Found repository: $repo_name"
                    fi
                    
                    # Apply template to existing repo
                    (
                        cd "$repo_path"
                        git init >/dev/null 2>&1 || true
                        ((repos_updated++))
                    )
                fi
            done < <(find "$search_path" -maxdepth 3 -type d -name ".git" -print0 2>/dev/null)
        fi
    done
    
    if [[ $repos_found -gt 0 ]]; then
        print_success "Applied to $repos_updated of $repos_found repositories found"
    else
        print_info "No existing repositories found in common locations"
    fi
}

# Advanced installation with custom options
install_advanced() {
    echo ""
    echo -e "${BOLD}${CYAN}Advanced Installation Configuration${NC}"
    echo ""
    
    # Choose installation type
    echo -e "${YELLOW}1. Installation Type:${NC}"
    echo "1) Global (config in ~/.secret-war)"
    echo "2) Local (config in ./.secret-war)"
    echo -ne "${CYAN}Choose [1-2]: ${NC}"
    read -r install_choice
    
    case $install_choice in
        1) local_install_type="global" ;;
        2) local_install_type="local" ;;
        *) local_install_type="global" ;;
    esac
    
    # Thread configuration
    echo ""
    echo -e "${YELLOW}2. Thread Configuration:${NC}"
    echo -ne "${CYAN}Number of threads [1-16, default 8]: ${NC}"
    read -r thread_count
    
    if [[ ! "$thread_count" =~ ^[0-9]+$ ]] || [[ $thread_count -lt 1 ]] || [[ $thread_count -gt 16 ]]; then
        thread_count=8
    fi
    
    # Custom patterns
    echo ""
    echo -e "${YELLOW}3. Pattern Configuration:${NC}"
    echo -ne "${CYAN}Add custom patterns file? [y/N]: ${NC}"
    read -r custom_patterns
    
    # Report configuration
    echo ""
    echo -e "${YELLOW}4. Report Configuration:${NC}"
    if [[ "$local_install_type" == "local" ]]; then
        echo -ne "${CYAN}Custom report directory [default: ./.secret-war/reports]: ${NC}"
    else
        echo -ne "${CYAN}Custom report directory [default: ~/.secret-war/reports]: ${NC}"
    fi
    read -r report_dir
    
    # Auto-open reports
    echo ""
    echo -ne "${CYAN}Auto-open reports in browser? [Y/n]: ${NC}"
    read -r auto_open
    
    # Summary
    echo ""
    echo -e "${BOLD}${CYAN}Configuration Summary:${NC}"
    echo "Installation Type: $local_install_type"
    echo "Thread Count: $thread_count"
    echo "Custom Patterns: ${custom_patterns:-N}"
    if [[ -n "$report_dir" ]]; then
        echo "Report Directory: $report_dir"
    else
        if [[ "$local_install_type" == "local" ]]; then
            echo "Report Directory: ./.secret-war/reports"
        else
            echo "Report Directory: ~/.secret-war/reports"
        fi
    fi
    echo "Auto-open Reports: ${auto_open:-Y}"
    echo ""
    
    echo -ne "${CYAN}Proceed with installation? [Y/n]: ${NC}"
    read -r proceed
    
    if [[ "$proceed" =~ ^[Nn]$ ]]; then
        print_info "Installation cancelled"
        exit 0
    fi
    
    # Set installation type for the rest of the process
    INSTALL_TYPE="$local_install_type"
    
    # Set config directory based on installation type
    set_config_dir
    
    # Apply configuration
    export MAX_THREADS="$thread_count"
    if [[ -n "$report_dir" ]]; then
        mkdir -p "$report_dir"
    fi
    
    # Perform installation
    if [[ "$local_install_type" == "global" ]]; then
        install_global_hook
    else
        install_local_hook
    fi
    
    # Handle custom patterns
    if [[ "$custom_patterns" =~ ^[Yy]$ ]]; then
        echo ""
        print_info "Custom patterns file created at: $CONFIG_DIR/patterns.conf"
        print_info "Edit this file to add your custom detection patterns"
    fi
}

# Update existing installation
update_installation() {
    print_step "Updating Secret WAR installation..."
    
    # Set config directory for updates
    set_config_dir
    
    if [[ ! -d "$CONFIG_DIR" ]]; then
        print_error "Secret WAR not installed at: $CONFIG_DIR"
        print_info "Use --global or --local to install."
        exit 1
    fi
    
    print_info "Updating installation at: $CONFIG_DIR"
    
    # Backup existing configuration
    local backup_dir="$CONFIG_DIR/backup-$(date +%s)"
    mkdir -p "$backup_dir"
    
    if [[ -f "$CONFIG_DIR/patterns.conf" ]]; then
        cp "$CONFIG_DIR/patterns.conf" "$backup_dir/"
    fi
    if [[ -f "$CONFIG_DIR/whitelist-files.conf" ]]; then
        cp "$CONFIG_DIR/whitelist-files.conf" "$backup_dir/"
    fi
    if [[ -f "$CONFIG_DIR/whitelist-patterns.conf" ]]; then
        cp "$CONFIG_DIR/whitelist-patterns.conf" "$backup_dir/"
    fi
    
    print_info "Configuration backed up to: $backup_dir"
    
    # Update configuration
    FORCE_INSTALL=true
    setup_config
    
    # Update hooks
    if git config --global --get init.templateDir >/dev/null 2>&1; then
        install_global_hook
    fi
    
    # Check for local installation
    if git rev-parse --git-dir >/dev/null 2>&1; then
        local git_dir
        git_dir="$(git rev-parse --git-dir)"
        if [[ -f "$git_dir/hooks/pre-commit" ]] && grep -q "Secret WAR" "$git_dir/hooks/pre-commit" 2>/dev/null; then
            install_local_hook
        fi
    fi
    
    print_success "Secret WAR updated successfully"
}

# Uninstall Secret WAR
uninstall() {
    echo ""
    print_warning "This will remove Secret WAR from your system"
    echo -ne "${CYAN}Are you sure? [y/N]: ${NC}"
    read -r confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_info "Uninstall cancelled"
        exit 0
    fi
    
    print_step "Uninstalling Secret WAR..."
    
    # Remove global template
    if git config --global --get init.templateDir >/dev/null 2>&1; then
        local template_dir
        template_dir=$(git config --global --get init.templateDir)
        if [[ "$template_dir" == "$HOME/.git-templates" ]]; then
            git config --global --unset init.templateDir
            rm -rf "$HOME/.git-templates"
            print_info "Global template removed"
        fi
    fi
    
    # Remove global configuration
    if [[ -d "$HOME/.secret-war" ]]; then
        rm -rf "$HOME/.secret-war"
        print_info "Global configuration directory removed"
    fi
    
    # Remove local configuration if in a git repo
    if git rev-parse --git-dir >/dev/null 2>&1; then
        local repo_root
        repo_root="$(git rev-parse --show-toplevel)"
        if [[ -d "$repo_root/.secret-war" ]]; then
            echo -ne "${CYAN}Remove local configuration from current repository? [y/N]: ${NC}"
            read -r remove_local
            if [[ "$remove_local" =~ ^[Yy]$ ]]; then
                rm -rf "$repo_root/.secret-war"
                print_info "Local configuration directory removed"
            fi
        fi
    fi
    
    print_success "Secret WAR uninstalled successfully"
    print_info "Local repository hooks need to be removed manually if needed"
}

# Installation summary and next steps
show_installation_summary() {
    echo ""
    echo -e "${BOLD}${GREEN}🎉 Secret WAR Installation Complete!${NC}"
    echo ""
    echo -e "${CYAN}What's Next:${NC}"
    
    case $INSTALL_TYPE in
        "global")
            echo "✅ Global hooks installed - all repositories are now protected"
            echo "✅ New repositories will automatically use Secret WAR"
            echo "📁 Configuration: $CONFIG_DIR"
            echo "⚡ Cross-platform thread management: TestNG-like parallel processing"
            ;;
        "local")
            echo "✅ Local hook installed for current repository"
            echo "✅ Repository-specific configuration created"
            echo "📁 Configuration: $CONFIG_DIR"
            echo "⚡ Cross-platform thread management: TestNG-like parallel processing"
            echo "💡 Run with --global to protect all repositories"
            ;;
        "advanced")
            echo "✅ Advanced configuration applied"
            echo "⚙️  Configuration files available in $CONFIG_DIR"
            echo "⚡ Cross-platform thread management: TestNG-like parallel processing"
            ;;
    esac
    
    echo ""
    echo -e "${YELLOW}Configuration Files:${NC}"
    echo "📁 Config Directory: $CONFIG_DIR"
    echo "🎯 Patterns: $CONFIG_DIR/patterns.conf"
    echo "📋 File Whitelist: $CONFIG_DIR/whitelist-files.conf"
    echo "🔍 Pattern Whitelist: $CONFIG_DIR/whitelist-patterns.conf"
    echo "📊 Reports: $CONFIG_DIR/reports/"
    
    echo ""
    echo -e "${YELLOW}Cross-Platform Thread Management Features:${NC}"
    echo "⚡ Directory-based locking (no flock dependency)"
    echo "🔒 Thread-safe file processing across Linux/macOS/BSD"
    echo "📊 No duplicate file processing across threads"
    echo "🔄 Unified report generation from all threads"
    echo "⏱️  Performance timing and thread statistics"
    echo "🛡️  Timeout protection and graceful error handling"
    
    if [[ "$INSTALL_TYPE" == "local" ]]; then
        echo ""
        echo -e "${YELLOW}Local Installation Notes:${NC}"
        echo "• Configuration is stored locally in the repository"
        echo "• .secret-war/ has been added to .gitignore"
        echo "• Each team member needs to run the installer"
        echo "• Configuration can be customized per repository"
    fi
    
    echo ""
    echo -e "${YELLOW}Testing Your Installation:${NC}"
    echo "1. Create a test file with a fake API key:"
    echo "   echo 'api_key=\"sk-1234567890abcdef\"' > test-secret.txt"
    echo "2. Try to commit it:"
    echo "   git add test-secret.txt && git commit -m 'test'"
    echo "3. Secret WAR should block the commit and show a report"
    
    echo ""
    echo -e "${YELLOW}Need Help?${NC}"
    echo "🆘 Documentation: README.md"
    echo "⚙️  Edit patterns: vim $CONFIG_DIR/patterns.conf"
    echo "🔧 Troubleshooting: Check hook logs or reinstall"
    
    echo ""
    echo -e "${GREEN} You are Ready for Secret War.🛡️${NC}"
    echo -e "${GREEN} Great code Comes with Great Responsibility🛡️${NC}"
    echo -e "${GREEN} Happy secure coding! 🛡️${NC}"
}

# Main installation flow
main() {
    show_banner
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Check system requirements
    check_requirements
    
    # If no installation type specified, show menu
    if [[ -z "$INSTALL_TYPE" ]]; then
        show_menu
        get_user_choice
    fi
    
    # Set configuration directory based on installation type
    set_config_dir
    
    # Setup configuration
    setup_config
    
    # Execute installation based on type
    case $INSTALL_TYPE in
        "global")
            install_global_hook
            ;;
        "local")
            install_local_hook
            ;;
        "advanced")
            install_advanced
            ;;
        "update")
            update_installation
            ;;
        "uninstall")
            uninstall
            exit 0
            ;;
        *)
            print_error "Invalid installation type: $INSTALL_TYPE"
            exit 1
            ;;
    esac
    
    # Show installation summary
    show_installation_summary
}

# Handle script interruption
trap 'echo -e "\n${YELLOW}Installation interrupted by user${NC}"; exit 130' INT TERM

# Run main function with all arguments
main "$@"