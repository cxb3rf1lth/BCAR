#!/bin/bash

# BlackCell Auto Recon (BCAR) - Automated Reconnaissance Tool
# Author: BlackCell Security
# Description: Comprehensive automated reconnaissance tool for security assessments
# Version: 1.0.0

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# ASCII Banner
print_banner() {
    echo -e "${RED}"
    cat << "EOF"
██████╗  ██████╗ █████╗ ██████╗ 
██╔══██╗██╔════╝██╔══██╗██╔══██╗
██████╔╝██║     ███████║██████╔╝
██╔══██╗██║     ██╔══██║██╔══██╗
██████╔╝╚██████╗██║  ██║██║  ██║
╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝
EOF
    echo -e "${WHITE}BlackCell Auto Recon v1.0.0${NC}"
    echo -e "${CYAN}Automated Reconnaissance Framework${NC}"
    echo -e "${YELLOW}==========================================${NC}"
    echo
}

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly DEFAULT_WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
readonly DEFAULT_ALT_WORDLIST="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"

OUTPUT_DIR="bcar_results_$(date +%Y%m%d_%H%M%S)"
TARGET=""
THREADS=50
WORDLIST="$DEFAULT_WORDLIST"
NMAP_SCRIPTS="default,vuln"
STEALTH_MODE=false
TIMING="normal"
OUTPUT_FORMAT="txt"
DOM_SCAN_ENABLED=true
DOM_HEADLESS=true
DOM_PARAMETERS=true

# Input validation function
validate_input() {
    local input="$1"
    local type="$2"
    
    case "$type" in
        "target")
            # Basic validation for IP addresses and domain names
            if [[ ! "$input" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,61}[a-zA-Z0-9])?$ ]] && 
               [[ ! "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                log "ERROR" "Invalid target format: $input"
                return 1
            fi
            ;;
        "threads")
            if [[ ! "$input" =~ ^[0-9]+$ ]] || [[ "$input" -lt 1 ]] || [[ "$input" -gt 1000 ]]; then
                log "ERROR" "Invalid thread count: $input (must be 1-1000)"
                return 1
            fi
            ;;
        "path")
            # Basic path traversal protection
            if [[ "$input" =~ \.\./|\.\.\\ ]]; then
                log "ERROR" "Path traversal detected in: $input"
                return 1
            fi
            ;;
        *)
            log "ERROR" "Unknown validation type: $type"
            return 1
            ;;
    esac
    return 0
}

# Usage function
usage() {
    echo -e "${WHITE}Usage: $0 [OPTIONS] TARGET${NC}"
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  -t, --target      Target IP address or domain"
    echo -e "  -o, --output      Output directory (default: bcar_results_timestamp)"
    echo -e "  -T, --threads     Number of threads (default: 50)"
    echo -e "  -w, --wordlist    Wordlist for directory brute force"
    echo -e "  -s, --scripts     Nmap scripts to use (default: default,vuln)"
    echo -e "  --stealth         Enable stealth mode (slower but more evasive)"
    echo -e "  --timing          Timing mode: slow, normal, fast (default: normal)"
    echo -e "  --format          Output format: txt, json, both (default: txt)"
    echo -e "  --no-dom          Disable DOM-based XSS and Open Redirect scanning"
    echo -e "  --dom-gui         Run DOMscan with visible browser (default: headless)"
    echo -e "  -h, --help        Show this help message"
    echo
    echo -e "${YELLOW}Examples:${NC}"
    echo -e "  $0 -t 192.168.1.100"
    echo -e "  $0 -t example.com -o custom_output -T 100"
    echo -e "  $0 --target 10.0.0.1 --wordlist /path/to/wordlist.txt --no-dom"
    echo -e "  $0 -t example.com --stealth --timing slow --format both"
}

# Logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    # Create output directory if it doesn't exist and we need to log to file
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        mkdir -p "$OUTPUT_DIR" 2>/dev/null || true
    fi
    
    case "$level" in
        "INFO")
            if [[ -d "$OUTPUT_DIR" ]]; then
                echo -e "${CYAN}[INFO]${NC} ${timestamp} - $message" | tee -a "$OUTPUT_DIR/bcar.log"
            else
                echo -e "${CYAN}[INFO]${NC} ${timestamp} - $message"
            fi
            ;;
        "SUCCESS")
            if [[ -d "$OUTPUT_DIR" ]]; then
                echo -e "${GREEN}[SUCCESS]${NC} ${timestamp} - $message" | tee -a "$OUTPUT_DIR/bcar.log"
            else
                echo -e "${GREEN}[SUCCESS]${NC} ${timestamp} - $message"
            fi
            ;;
        "WARNING")
            if [[ -d "$OUTPUT_DIR" ]]; then
                echo -e "${YELLOW}[WARNING]${NC} ${timestamp} - $message" | tee -a "$OUTPUT_DIR/bcar.log"
            else
                echo -e "${YELLOW}[WARNING]${NC} ${timestamp} - $message"
            fi
            ;;
        "ERROR")
            if [[ -d "$OUTPUT_DIR" ]]; then
                echo -e "${RED}[ERROR]${NC} ${timestamp} - $message" | tee -a "$OUTPUT_DIR/bcar.log"
            else
                echo -e "${RED}[ERROR]${NC} ${timestamp} - $message"
            fi
            ;;
        *)
            if [[ -d "$OUTPUT_DIR" ]]; then
                echo -e "${RED}[UNKNOWN]${NC} ${timestamp} - $message" | tee -a "$OUTPUT_DIR/bcar.log"
            else
                echo -e "${RED}[UNKNOWN]${NC} ${timestamp} - $message"
            fi
            ;;
    esac
}

# Automatic dependency installation
install_dependencies() {
    local missing_tools=("$@")
    log "INFO" "Attempting automatic dependency installation..."
    
    # Detect package manager and install dependencies
    if command -v apt-get &> /dev/null; then
        log "INFO" "Using apt package manager..."
        sudo apt-get update -qq 2>/dev/null || log "WARNING" "Could not update package lists"
        for tool in "${missing_tools[@]}"; do
            case "$tool" in
                "dig") sudo apt-get install -y dnsutils 2>/dev/null || log "WARNING" "Failed to install dnsutils" ;;
                "node") sudo apt-get install -y nodejs 2>/dev/null || log "WARNING" "Failed to install nodejs" ;;
                "npm") sudo apt-get install -y npm 2>/dev/null || log "WARNING" "Failed to install npm" ;;
                *) sudo apt-get install -y "$tool" 2>/dev/null || log "WARNING" "Failed to install $tool" ;;
            esac
        done
    elif command -v yum &> /dev/null; then
        log "INFO" "Using yum package manager..."
        for tool in "${missing_tools[@]}"; do
            case "$tool" in
                "dig") sudo yum install -y bind-utils 2>/dev/null || log "WARNING" "Failed to install bind-utils" ;;
                "node") sudo yum install -y nodejs 2>/dev/null || log "WARNING" "Failed to install nodejs" ;;
                "npm") sudo yum install -y npm 2>/dev/null || log "WARNING" "Failed to install npm" ;;
                *) sudo yum install -y "$tool" 2>/dev/null || log "WARNING" "Failed to install $tool" ;;
            esac
        done
    elif command -v dnf &> /dev/null; then
        log "INFO" "Using dnf package manager..."
        for tool in "${missing_tools[@]}"; do
            case "$tool" in
                "dig") sudo dnf install -y bind-utils 2>/dev/null || log "WARNING" "Failed to install bind-utils" ;;
                "node") sudo dnf install -y nodejs 2>/dev/null || log "WARNING" "Failed to install nodejs" ;;
                "npm") sudo dnf install -y npm 2>/dev/null || log "WARNING" "Failed to install npm" ;;
                *) sudo dnf install -y "$tool" 2>/dev/null || log "WARNING" "Failed to install $tool" ;;
            esac
        done
    elif command -v pacman &> /dev/null; then
        log "INFO" "Using pacman package manager..."
        sudo pacman -Sy --noconfirm 2>/dev/null || log "WARNING" "Could not update package database"
        for tool in "${missing_tools[@]}"; do
            case "$tool" in
                "dig") sudo pacman -S --noconfirm dnsutils 2>/dev/null || log "WARNING" "Failed to install dnsutils" ;;
                "node") sudo pacman -S --noconfirm nodejs 2>/dev/null || log "WARNING" "Failed to install nodejs" ;;
                "npm") sudo pacman -S --noconfirm npm 2>/dev/null || log "WARNING" "Failed to install npm" ;;
                *) sudo pacman -S --noconfirm "$tool" 2>/dev/null || log "WARNING" "Failed to install $tool" ;;
            esac
        done
    elif command -v brew &> /dev/null; then
        log "INFO" "Using Homebrew package manager..."
        for tool in "${missing_tools[@]}"; do
            case "$tool" in
                "node") brew install node 2>/dev/null || log "WARNING" "Failed to install node" ;;
                *) brew install "$tool" 2>/dev/null || log "WARNING" "Failed to install $tool" ;;
            esac
        done
    else
        log "WARNING" "No supported package manager found. Please install dependencies manually."
        return 1
    fi
}

# DOMscan installation and setup
setup_domscan() {
    log "INFO" "Checking DOMscan installation..."
    
    # Check if DOMscan is already installed globally
    if command -v domscan &> /dev/null; then
        log "SUCCESS" "DOMscan is already installed"
        return 0
    fi
    
    # Try to install DOMscan globally
    log "INFO" "Installing DOMscan..."
    if npm install -g https://github.com/lauritzh/domscan.git 2>/dev/null; then
        log "SUCCESS" "DOMscan installed successfully"
        return 0
    else
        log "WARNING" "Failed to install DOMscan globally, trying local installation"
        
        # Create a local DOMscan directory in the script directory
        local domscan_dir="$SCRIPT_DIR/domscan"
        if [[ ! -d "$domscan_dir" ]]; then
            git clone https://github.com/lauritzh/domscan.git "$domscan_dir" 2>/dev/null || {
                log "ERROR" "Failed to clone DOMscan repository"
                return 1
            }
        fi
        
        # Install DOMscan dependencies locally
        cd "$domscan_dir" || {
            log "ERROR" "Failed to change to DOMscan directory"
            return 1
        }
        
        if npm install 2>/dev/null; then
            log "SUCCESS" "DOMscan installed locally at $domscan_dir"
            cd "$SCRIPT_DIR"
            return 0
        else
            log "ERROR" "Failed to install DOMscan dependencies"
            cd "$SCRIPT_DIR"
            return 1
        fi
    fi
}

# Check if DOMscan is available
check_domscan() {
    # Check global installation first
    if command -v domscan &> /dev/null; then
        echo "domscan"
        return 0
    fi
    
    # Check local installation
    local domscan_dir="$SCRIPT_DIR/domscan"
    if [[ -f "$domscan_dir/domscan.js" ]]; then
        echo "node $domscan_dir/domscan.js"
        return 0
    fi
    
    return 1
}
check_dependencies() {
    log "INFO" "Checking dependencies..."
    
    local tools=("nmap" "gobuster" "nikto" "whatweb" "dig" "whois" "curl" "node" "npm")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -ne 0 ]]; then
        log "ERROR" "Missing required tools: ${missing_tools[*]}"
        log "INFO" "Attempting to install missing dependencies..."
        install_dependencies "${missing_tools[@]}"
        
        # Re-check after installation attempt
        local still_missing=()
        for tool in "${missing_tools[@]}"; do
            if ! command -v "$tool" &> /dev/null; then
                still_missing+=("$tool")
            fi
        done
        
        if [[ ${#still_missing[@]} -ne 0 ]]; then
            log "ERROR" "Failed to install: ${still_missing[*]}"
            echo -e "${RED}Please manually install the missing tools before running BCAR${NC}"
            exit 1
        fi
    fi
    
    log "SUCCESS" "All dependencies are available"
    
    # Setup DOMscan after basic dependencies are confirmed
    setup_domscan || log "WARNING" "DOMscan setup failed - DOM security scanning will be unavailable"
}

# DNS enumeration
dns_enumeration() {
    log "INFO" "Starting DNS enumeration for $TARGET"
    
    mkdir -p "$OUTPUT_DIR/dns"
    
    # Basic DNS lookups
    dig +short "$TARGET" > "$OUTPUT_DIR/dns/a_records.txt" 2>/dev/null || true
    dig +short MX "$TARGET" > "$OUTPUT_DIR/dns/mx_records.txt" 2>/dev/null || true
    dig +short NS "$TARGET" > "$OUTPUT_DIR/dns/ns_records.txt" 2>/dev/null || true
    dig +short TXT "$TARGET" > "$OUTPUT_DIR/dns/txt_records.txt" 2>/dev/null || true
    
    # Zone transfer attempt
    local nameservers
    nameservers="$(dig +short NS "$TARGET" 2>/dev/null)"
    if [[ -n "$nameservers" ]]; then
        while IFS= read -r ns; do
            [[ -n "$ns" ]] || continue
            log "INFO" "Attempting zone transfer from $ns"
            dig AXFR "$TARGET" @"$ns" > "$OUTPUT_DIR/dns/zone_transfer_${ns}.txt" 2>/dev/null || true
        done <<< "$nameservers"
    fi
    
    log "SUCCESS" "DNS enumeration completed"
}

# WHOIS lookup
whois_lookup() {
    log "INFO" "Performing WHOIS lookup for $TARGET"
    
    mkdir -p "$OUTPUT_DIR/whois"
    whois "$TARGET" > "$OUTPUT_DIR/whois/whois_info.txt" 2>/dev/null || true
    
    log "SUCCESS" "WHOIS lookup completed"
}

# Port scanning with Nmap
port_scanning() {
    log "INFO" "Starting port scan for $TARGET"
    
    mkdir -p "$OUTPUT_DIR/nmap"
    
    # Determine timing template based on settings
    local nmap_timing="-T4"
    if [[ "$STEALTH_MODE" == "true" ]]; then
        nmap_timing="-T1"
    elif [[ "$TIMING" == "slow" ]]; then
        nmap_timing="-T2"
    elif [[ "$TIMING" == "fast" ]]; then
        nmap_timing="-T5"
    fi
    
    # Quick scan for top ports
    log "INFO" "Running quick port scan (top 1000 ports)"
    nmap "$nmap_timing" -top-ports 1000 --open "$TARGET" -oN "$OUTPUT_DIR/nmap/quick_scan.txt" -oX "$OUTPUT_DIR/nmap/quick_scan.xml" &>/dev/null || true
    
    # Full TCP scan (conditional based on stealth mode)
    if [[ "$STEALTH_MODE" != "true" ]]; then
        log "INFO" "Running comprehensive TCP scan"
        nmap -sS "$nmap_timing" -p- --open "$TARGET" -oN "$OUTPUT_DIR/nmap/full_tcp.txt" -oX "$OUTPUT_DIR/nmap/full_tcp.xml" &>/dev/null || true
    else
        log "INFO" "Skipping full TCP scan in stealth mode"
    fi
    
    # Service version detection
    local open_ports
    open_ports="$(grep -oP '\d+/tcp' "$OUTPUT_DIR/nmap/quick_scan.txt" 2>/dev/null | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')"
    if [[ -n "$open_ports" ]]; then
        log "INFO" "Running service version detection on open ports: $open_ports"
        nmap -sV -sC --script="$NMAP_SCRIPTS" "$nmap_timing" -p"$open_ports" "$TARGET" -oN "$OUTPUT_DIR/nmap/service_scan.txt" -oX "$OUTPUT_DIR/nmap/service_scan.xml" &>/dev/null || true
    fi
    
    # UDP scan (top ports only) - skip in stealth mode
    if [[ "$STEALTH_MODE" != "true" ]]; then
        log "INFO" "Running UDP scan (top 100 ports)"
        nmap -sU "$nmap_timing" --top-ports 100 --open "$TARGET" -oN "$OUTPUT_DIR/nmap/udp_scan.txt" -oX "$OUTPUT_DIR/nmap/udp_scan.xml" &>/dev/null || true
    else
        log "INFO" "Skipping UDP scan in stealth mode"
    fi
    
    log "SUCCESS" "Port scanning completed"
}

# Web application scanning
web_scanning() {
    log "INFO" "Starting web application scanning"
    
    mkdir -p "$OUTPUT_DIR/web"
    
    # Check for HTTP services
    local http_ports=()
    if [[ -f "$OUTPUT_DIR/nmap/service_scan.txt" ]]; then
        mapfile -t http_ports < <(grep -E "(http|https)" "$OUTPUT_DIR/nmap/service_scan.txt" | grep -oP '\d+/tcp' | cut -d'/' -f1)
    fi
    
    if [[ ${#http_ports[@]} -eq 0 ]]; then
        # Default HTTP/HTTPS ports
        http_ports=(80 443 8080 8443)
    fi
    
    for port in "${http_ports[@]}"; do
        local scheme="http"
        if [[ "$port" =~ ^(443|8443)$ ]]; then
            scheme="https"
        fi
        
        local url="${scheme}://${TARGET}:${port}"
        
        # Check if service is actually running
        if curl -s --connect-timeout 5 --max-time 10 "$url" &>/dev/null; then
            log "INFO" "Scanning web service on port $port"
            
            # WhatWeb
            whatweb -a 3 "$url" > "$OUTPUT_DIR/web/whatweb_${port}.txt" 2>/dev/null || true
            
            # Directory brute force with Gobuster
            if [[ -f "$WORDLIST" ]]; then
                log "INFO" "Running directory brute force on port $port"
                gobuster dir -u "$url" -w "$WORDLIST" -t "$THREADS" -x php,html,js,txt,xml -o "$OUTPUT_DIR/web/gobuster_${port}.txt" &>/dev/null || true
            elif [[ -f "$DEFAULT_ALT_WORDLIST" ]]; then
                log "INFO" "Using alternative wordlist for directory brute force on port $port"
                gobuster dir -u "$url" -w "$DEFAULT_ALT_WORDLIST" -t "$THREADS" -x php,html,js,txt,xml -o "$OUTPUT_DIR/web/gobuster_${port}.txt" &>/dev/null || true
            else
                log "WARNING" "No suitable wordlist found for directory brute force"
            fi
            
            # Nikto scan
            log "INFO" "Running Nikto scan on port $port"
            nikto -h "$url" -output "$OUTPUT_DIR/web/nikto_${port}.txt" &>/dev/null || true
        fi
    done
    
    log "SUCCESS" "Web application scanning completed"
}

# DOM-based XSS and Open Redirect scanning with DOMscan
dom_security_scan() {
    if [[ "$DOM_SCAN_ENABLED" != "true" ]]; then
        log "INFO" "DOM security scanning disabled, skipping"
        return 0
    fi
    
    log "INFO" "Starting DOM security analysis with DOMscan"
    
    mkdir -p "$OUTPUT_DIR/dom_security"
    
    # Get DOMscan command
    local domscan_cmd
    domscan_cmd="$(check_domscan)" || {
        log "WARNING" "DOMscan not available, skipping DOM security scanning"
        return 0
    }
    
    # Check for HTTP services
    local http_ports=()
    if [[ -f "$OUTPUT_DIR/nmap/service_scan.txt" ]]; then
        mapfile -t http_ports < <(grep -E "(http|https)" "$OUTPUT_DIR/nmap/service_scan.txt" | grep -oP '\d+/tcp' | cut -d'/' -f1)
    fi
    
    if [[ ${#http_ports[@]} -eq 0 ]]; then
        # Default HTTP/HTTPS ports
        http_ports=(80 443 8080 8443)
    fi
    
    for port in "${http_ports[@]}"; do
        local scheme="http"
        if [[ "$port" =~ ^(443|8443)$ ]]; then
            scheme="https"
        fi
        
        local url="${scheme}://${TARGET}:${port}"
        
        # Check if service is actually running
        if curl -s --connect-timeout 5 --max-time 10 "$url" &>/dev/null; then
            log "INFO" "Running DOMscan security analysis on port $port"
            
            # Prepare DOMscan options based on configuration
            local domscan_opts=""
            if [[ "$DOM_HEADLESS" == "true" ]]; then
                domscan_opts="--headless true"
            else
                domscan_opts="--headless false"
            fi
            
            # Run DOMscan with different configurations based on mode
            if [[ "$STEALTH_MODE" == "true" ]]; then
                # Stealth mode - more conservative scanning
                $domscan_cmd "$url" "$domscan_opts" --throttle > "$OUTPUT_DIR/dom_security/domscan_${port}.txt" 2>/dev/null || {
                    log "WARNING" "DOMscan failed for $url"
                    continue
                }
            else
                # Normal mode - comprehensive scanning
                $domscan_cmd -g -G "$url" "$domscan_opts" > "$OUTPUT_DIR/dom_security/domscan_${port}.txt" 2>/dev/null || {
                    log "WARNING" "DOMscan failed for $url"
                    continue
                }
            fi
            
            # Parse discovered endpoints from Gobuster for additional DOMscan testing
            local gobuster_file="$OUTPUT_DIR/web/gobuster_${port}.txt"
            if [[ -f "$gobuster_file" ]]; then
                log "INFO" "Testing discovered endpoints with DOMscan on port $port"
                
                # Extract successful endpoints (Status: 200, 301, 302, etc.)
                local endpoints
                endpoints="$(grep -E "Status: (200|301|302|403)" "$gobuster_file" 2>/dev/null | awk '{print $1}' | head -5)" || true
                
                if [[ -n "$endpoints" ]]; then
                    while IFS= read -r endpoint; do
                        if [[ -n "$endpoint" ]]; then
                            local test_url="${url}${endpoint}?test=BCAR_TEST"
                            log "INFO" "DOMscan testing endpoint: $endpoint"
                            
                            $domscan_cmd "$test_url" "$domscan_opts" > "$OUTPUT_DIR/dom_security/domscan_${port}_${endpoint//\//_}.txt" 2>/dev/null || true
                        fi
                    done <<< "$endpoints"
                fi
            fi
        fi
    done
    
    log "SUCCESS" "DOM security analysis completed"
}

# SSL/TLS analysis
ssl_analysis() {
    log "INFO" "Starting SSL/TLS analysis"
    
    mkdir -p "$OUTPUT_DIR/ssl"
    
    # Check for HTTPS services
    local https_ports=(443 8443)
    
    for port in "${https_ports[@]}"; do
        if nmap -p"$port" --script ssl-cert,ssl-enum-ciphers "$TARGET" &>/dev/null; then
            log "INFO" "Analyzing SSL/TLS on port $port"
            nmap -p"$port" --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle "$TARGET" -oN "$OUTPUT_DIR/ssl/ssl_analysis_${port}.txt" &>/dev/null || true
        fi
    done
    
    log "SUCCESS" "SSL/TLS analysis completed"
}

# Generate summary report
generate_report() {
    log "INFO" "Generating summary report"
    
    local report_file="$OUTPUT_DIR/BCAR_Report.txt"
    local scan_date
    scan_date="$(date)"
    
    {
        echo "========================================"
        echo "BlackCell Auto Recon (BCAR) Report"
        echo "========================================"
        echo "Target: $TARGET"
        echo "Scan Date: $scan_date"
        echo "Output Directory: $OUTPUT_DIR"
        echo "========================================"
        echo
        
        echo "DNS INFORMATION:"
        echo "=================="
        if [[ -f "$OUTPUT_DIR/dns/a_records.txt" ]]; then
            echo "A Records:"
            head -10 < "$OUTPUT_DIR/dns/a_records.txt"
            echo
        fi
        
        echo "OPEN PORTS:"
        echo "============"
        if [[ -f "$OUTPUT_DIR/nmap/quick_scan.txt" ]]; then
            grep -E "^\d+/tcp.*open" "$OUTPUT_DIR/nmap/quick_scan.txt" || echo "No open ports found in quick scan"
            echo
        fi
        
        echo "WEB SERVICES:"
        echo "=============="
        if find "$OUTPUT_DIR/web" -name "whatweb_*.txt" -type f &>/dev/null; then
            find "$OUTPUT_DIR/web" -name "whatweb_*.txt" -exec sh -c 'echo "Port $(basename "$1" .txt | cut -d_ -f2):"; head -3 "$1"' _ {} \; 2>/dev/null
        else
            echo "No web services analyzed"
        fi
        echo
        
        echo "DIRECTORIES FOUND:"
        echo "=================="
        if find "$OUTPUT_DIR/web" -name "gobuster_*.txt" -type f &>/dev/null; then
            find "$OUTPUT_DIR/web" -name "gobuster_*.txt" -exec sh -c 'echo "Port $(basename "$1" .txt | cut -d_ -f2):"; grep -E "Status: 200|Status: 301|Status: 302" "$1"' _ {} \; 2>/dev/null | head -20
        else
            echo "No directories found"
        fi
        echo
        
        echo "DOM SECURITY FINDINGS:"
        echo "======================"
        if [[ -d "$OUTPUT_DIR/dom_security" ]] && find "$OUTPUT_DIR/dom_security" -name "domscan_*.txt" -type f &>/dev/null; then
            find "$OUTPUT_DIR/dom_security" -name "domscan_*.txt" -exec sh -c '
                port=$(basename "$1" .txt | cut -d_ -f2)
                echo "Port $port:"
                if [[ -s "$1" ]]; then
                    grep -E "(XSS|Redirect|DOM|Alert|Execution)" "$1" 2>/dev/null | head -5 || echo "  No security issues detected"
                else
                    echo "  Scan completed - no output recorded"
                fi
                echo
            ' _ {} \; 2>/dev/null
        else
            echo "No DOM security analysis performed"
        fi
        echo
        
    } > "$report_file"
    
    log "SUCCESS" "Summary report generated: $report_file"
}

# Generate JSON report
generate_json_report() {
    log "INFO" "Generating JSON report"
    
    local json_file="$OUTPUT_DIR/BCAR_Report.json"
    local scan_date
    scan_date="$(date -Iseconds)"
    
    cat > "$json_file" << EOF
{
  "scan_info": {
    "target": "$TARGET",
    "scan_date": "$scan_date",
    "output_directory": "$OUTPUT_DIR",
    "version": "1.0.0",
    "threads": $THREADS
  },
  "dns": {
EOF

    if [[ -f "$OUTPUT_DIR/dns/a_records.txt" ]]; then
        echo '    "a_records": [' >> "$json_file"
        while IFS= read -r record; do
            [[ -n "$record" ]] && echo "      \"$record\"," >> "$json_file"
        done < "$OUTPUT_DIR/dns/a_records.txt"
        sed -i '$ s/,$//' "$json_file"  # Remove last comma
        echo '    ],' >> "$json_file"
    else
        echo '    "a_records": [],' >> "$json_file"
    fi
    
    {
        echo '    "zone_transfers": []'
        echo '  },'
    } >> "$json_file"
    
    # Add ports section
    {
        echo '  "ports": {'
        echo '    "open_tcp": [],'
        echo '    "open_udp": []'
        echo '  },'
    } >> "$json_file"
    
    # Add web services section
    echo '  "web_services": [],' >> "$json_file"
    
    # Add DOM security section
    {
        echo '  "dom_security": {'
        echo '    "findings": [],'
    } >> "$json_file"
    if [[ -d "$OUTPUT_DIR/dom_security" ]]; then
        echo '    "scanned_urls": [' >> "$json_file"
        find "$OUTPUT_DIR/dom_security" -name "domscan_*.txt" -type f 2>/dev/null | while read -r file; do
            local port
            port=$(basename "$file" .txt | cut -d_ -f2)
            local scheme="http"
            if [[ "$port" =~ ^(443|8443)$ ]]; then
                scheme="https"
            fi
            echo "      \"${scheme}://${TARGET}:${port}\"," >> "$json_file"
        done 2>/dev/null || true
        sed -i '$ s/,$//' "$json_file" 2>/dev/null || true  # Remove last comma
        echo '    ]' >> "$json_file"
    else
        echo '    "scanned_urls": []' >> "$json_file"
    fi
    
    # Close DOM security and add vulnerabilities section
    {
        echo '  },'
        echo '  "vulnerabilities": []'
        echo '}'
    } >> "$json_file"
    
    log "SUCCESS" "JSON report generated: $json_file"
}

# Configuration file support
load_config() {
    local config_file="${SCRIPT_DIR}/bcar.conf"
    if [[ -f "$config_file" ]]; then
        log "INFO" "Loading configuration from $config_file"
        # shellcheck source=/dev/null
        source "$config_file"
    fi
}

# Interactive main menu
show_main_menu() {
    clear
    print_banner
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}                 MAIN MENU${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
    echo -e "${CYAN}Current Configuration:${NC}"
    echo -e "  Target: ${YELLOW}${TARGET:-"Not set"}${NC}"
    echo -e "  Output Dir: ${YELLOW}$OUTPUT_DIR${NC}"
    echo -e "  Threads: ${YELLOW}$THREADS${NC}"
    echo -e "  Timing: ${YELLOW}$TIMING${NC}"
    echo -e "  Stealth Mode: ${YELLOW}$(if [[ "$STEALTH_MODE" == "true" ]]; then echo "Enabled"; else echo "Disabled"; fi)${NC}"
    echo -e "  DOM Scanning: ${YELLOW}$(if [[ "$DOM_SCAN_ENABLED" == "true" ]]; then echo "Enabled"; else echo "Disabled"; fi)${NC}"
    echo -e "  Output Format: ${YELLOW}$OUTPUT_FORMAT${NC}"
    echo
    echo -e "${WHITE}Options:${NC}"
    echo -e "  ${GREEN}1)${NC} Set Target (IP/Domain)"
    echo -e "  ${GREEN}2)${NC} Configure Scan Options"
    echo -e "  ${GREEN}3)${NC} Start Reconnaissance Scan"
    echo -e "  ${GREEN}4)${NC} View Configuration"
    echo -e "  ${GREEN}5)${NC} Reset to Defaults"
    echo -e "  ${GREEN}6)${NC} Help"
    echo -e "  ${RED}0)${NC} Exit"
    echo
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -en "${WHITE}Enter your choice [0-6]: ${NC}"
}

# Interactive target input
set_target_interactive() {
    echo
    echo -e "${CYAN}═══ Target Configuration ═══${NC}"
    echo -e "${YELLOW}Enter target IP address or domain name:${NC}"
    echo -e "${WHITE}Examples: 192.168.1.100, example.com, subdomain.target.org${NC}"
    echo
    echo -en "${WHITE}Target: ${NC}"
    read -r user_target
    
    if [[ -n "$user_target" ]]; then
        if validate_input "$user_target" "target"; then
            TARGET="$user_target"
            echo -e "${GREEN}✓ Target set to: $TARGET${NC}"
        else
            echo -e "${RED}✗ Invalid target format${NC}"
            echo -en "${YELLOW}Press Enter to continue...${NC}"
            read -r _
            return 1
        fi
    else
        echo -e "${YELLOW}No target entered${NC}"
    fi
    
    # Only pause for user input if we're truly interactive (not automated)
    if [[ -t 0 ]]; then
        echo -en "${YELLOW}Press Enter to continue...${NC}"
        read -r _
    fi
}

# Interactive options configuration
configure_options() {
    while true; do
        clear
        echo -e "${CYAN}═══ Scan Options Configuration ═══${NC}"
        echo
        echo -e "${WHITE}Current Settings:${NC}"
        echo -e "  ${GREEN}1)${NC} Threads: ${YELLOW}$THREADS${NC}"
        echo -e "  ${GREEN}2)${NC} Timing: ${YELLOW}$TIMING${NC} (slow/normal/fast)"
        echo -e "  ${GREEN}3)${NC} Stealth Mode: ${YELLOW}$(if [[ "$STEALTH_MODE" == "true" ]]; then echo "Enabled"; else echo "Disabled"; fi)${NC}"
        echo -e "  ${GREEN}4)${NC} Output Format: ${YELLOW}$OUTPUT_FORMAT${NC} (txt/json/both)"
        echo -e "  ${GREEN}5)${NC} DOM Scanning: ${YELLOW}$(if [[ "$DOM_SCAN_ENABLED" == "true" ]]; then echo "Enabled"; else echo "Disabled"; fi)${NC}"
        echo -e "  ${GREEN}6)${NC} DOM Mode: ${YELLOW}$(if [[ "$DOM_HEADLESS" == "true" ]]; then echo "Headless"; else echo "GUI"; fi)${NC}"
        echo -e "  ${GREEN}7)${NC} Output Directory: ${YELLOW}$OUTPUT_DIR${NC}"
        echo -e "  ${GREEN}8)${NC} Wordlist: ${YELLOW}${WORDLIST:-"Default"}${NC}"
        echo -e "  ${GREEN}9)${NC} Nmap Scripts: ${YELLOW}$NMAP_SCRIPTS${NC}"
        echo
        echo -e "  ${RED}0)${NC} Back to Main Menu"
        echo
        echo -en "${WHITE}Select option to configure [0-9]: ${NC}"
        read -r choice
        
        case $choice in
            1)
                echo -en "${WHITE}Enter number of threads (1-1000) [$THREADS]: ${NC}"
                read -r new_threads
                if [[ -n "$new_threads" ]] && validate_input "$new_threads" "threads"; then
                    THREADS="$new_threads"
                    echo -e "${GREEN}✓ Threads set to: $THREADS${NC}"
                else
                    echo -e "${RED}✗ Invalid thread count${NC}"
                fi
                echo -en "${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            2)
                echo -e "${WHITE}Timing options:${NC}"
                echo -e "  ${GREEN}1)${NC} slow (stealthy, T1-T2)"
                echo -e "  ${GREEN}2)${NC} normal (balanced, T4)"
                echo -e "  ${GREEN}3)${NC} fast (aggressive, T5)"
                echo -en "${WHITE}Select timing [1-3]: ${NC}"
                read -r timing_choice
                case $timing_choice in
                    1) TIMING="slow"; echo -e "${GREEN}✓ Timing set to: slow${NC}" ;;
                    2) TIMING="normal"; echo -e "${GREEN}✓ Timing set to: normal${NC}" ;;
                    3) TIMING="fast"; echo -e "${GREEN}✓ Timing set to: fast${NC}" ;;
                    *) echo -e "${RED}✗ Invalid choice${NC}" ;;
                esac
                echo -en "${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            3)
                if [[ "$STEALTH_MODE" == "true" ]]; then
                    STEALTH_MODE="false"
                    echo -e "${GREEN}✓ Stealth mode disabled${NC}"
                else
                    STEALTH_MODE="true"
                    TIMING="slow"
                    THREADS=10
                    echo -e "${GREEN}✓ Stealth mode enabled (timing and threads adjusted)${NC}"
                fi
                echo -en "${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            4)
                echo -e "${WHITE}Output format options:${NC}"
                echo -e "  ${GREEN}1)${NC} txt (text format)"
                echo -e "  ${GREEN}2)${NC} json (JSON format)"
                echo -e "  ${GREEN}3)${NC} both (text and JSON)"
                echo -en "${WHITE}Select format [1-3]: ${NC}"
                read -r format_choice
                case $format_choice in
                    1) OUTPUT_FORMAT="txt"; echo -e "${GREEN}✓ Output format set to: txt${NC}" ;;
                    2) OUTPUT_FORMAT="json"; echo -e "${GREEN}✓ Output format set to: json${NC}" ;;
                    3) OUTPUT_FORMAT="both"; echo -e "${GREEN}✓ Output format set to: both${NC}" ;;
                    *) echo -e "${RED}✗ Invalid choice${NC}" ;;
                esac
                echo -en "${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            5)
                if [[ "$DOM_SCAN_ENABLED" == "true" ]]; then
                    DOM_SCAN_ENABLED="false"
                    echo -e "${GREEN}✓ DOM scanning disabled${NC}"
                else
                    DOM_SCAN_ENABLED="true"
                    echo -e "${GREEN}✓ DOM scanning enabled${NC}"
                fi
                echo -en "${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            6)
                if [[ "$DOM_HEADLESS" == "true" ]]; then
                    DOM_HEADLESS="false"
                    echo -e "${GREEN}✓ DOM mode set to GUI${NC}"
                else
                    DOM_HEADLESS="true"
                    echo -e "${GREEN}✓ DOM mode set to headless${NC}"
                fi
                echo -en "${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            7)
                echo -en "${WHITE}Enter output directory [$OUTPUT_DIR]: ${NC}"
                read -r new_output
                if [[ -n "$new_output" ]]; then
                    if validate_input "$new_output" "path"; then
                        OUTPUT_DIR="$new_output"
                        echo -e "${GREEN}✓ Output directory set to: $OUTPUT_DIR${NC}"
                    else
                        echo -e "${RED}✗ Invalid directory path${NC}"
                    fi
                fi
                echo -en "${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            8)
                echo -en "${WHITE}Enter wordlist path [current: ${WORDLIST:-"default"}]: ${NC}"
                read -r new_wordlist
                if [[ -n "$new_wordlist" ]]; then
                    if [[ -f "$new_wordlist" ]]; then
                        WORDLIST="$new_wordlist"
                        echo -e "${GREEN}✓ Wordlist set to: $WORDLIST${NC}"
                    else
                        echo -e "${RED}✗ Wordlist file not found${NC}"
                    fi
                fi
                echo -en "${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            9)
                echo -en "${WHITE}Enter Nmap scripts [$NMAP_SCRIPTS]: ${NC}"
                read -r new_scripts
                if [[ -n "$new_scripts" ]]; then
                    NMAP_SCRIPTS="$new_scripts"
                    echo -e "${GREEN}✓ Nmap scripts set to: $NMAP_SCRIPTS${NC}"
                fi
                echo -en "${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            0)
                return 0
                ;;
            *)
                echo -e "${RED}✗ Invalid option${NC}"
                echo -en "${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
        esac
    done
}

# View current configuration
view_configuration() {
    clear
    echo -e "${CYAN}═══ Current Configuration ═══${NC}"
    echo
    echo -e "${WHITE}Target Settings:${NC}"
    echo -e "  Target: ${YELLOW}${TARGET:-"Not set"}${NC}"
    echo -e "  Output Directory: ${YELLOW}$OUTPUT_DIR${NC}"
    echo
    echo -e "${WHITE}Scan Settings:${NC}"
    echo -e "  Threads: ${YELLOW}$THREADS${NC}"
    echo -e "  Timing Mode: ${YELLOW}$TIMING${NC}"
    echo -e "  Stealth Mode: ${YELLOW}$(if [[ "$STEALTH_MODE" == "true" ]]; then echo "Enabled"; else echo "Disabled"; fi)${NC}"
    echo -e "  DOM Scanning: ${YELLOW}$(if [[ "$DOM_SCAN_ENABLED" == "true" ]]; then echo "Enabled"; else echo "Disabled"; fi)${NC}"
    echo -e "  DOM Mode: ${YELLOW}$(if [[ "$DOM_HEADLESS" == "true" ]]; then echo "Headless"; else echo "GUI"; fi)${NC}"
    echo -e "  Nmap Scripts: ${YELLOW}$NMAP_SCRIPTS${NC}"
    echo
    echo -e "${WHITE}Output Settings:${NC}"
    echo -e "  Format: ${YELLOW}$OUTPUT_FORMAT${NC}"
    echo
    echo -e "${WHITE}Wordlist:${NC}"
    echo -e "  Path: ${YELLOW}${WORDLIST:-"Using default"}${NC}"
    if [[ -n "$WORDLIST" ]] && [[ -f "$WORDLIST" ]]; then
        local wordcount
        wordcount=$(wc -l < "$WORDLIST" 2>/dev/null || echo "unknown")
        echo -e "  Entries: ${YELLOW}$wordcount${NC}"
    fi
    echo
    echo -en "${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# Reset configuration to defaults
reset_configuration() {
    echo
    echo -e "${YELLOW}Reset all settings to defaults? [y/N]: ${NC}"
    read -r confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        OUTPUT_DIR="bcar_results_$(date +%Y%m%d_%H%M%S)"
        TARGET=""
        THREADS=50
        WORDLIST="$DEFAULT_WORDLIST"
        NMAP_SCRIPTS="default,vuln"
        STEALTH_MODE=false
        TIMING="normal"
        OUTPUT_FORMAT="txt"
        DOM_SCAN_ENABLED=true
        DOM_HEADLESS=true
        echo -e "${GREEN}✓ Configuration reset to defaults${NC}"
    else
        echo -e "${YELLOW}Reset cancelled${NC}"
    fi
    echo -en "${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# Start scan from menu
start_scan_interactive() {
    if [[ -z "$TARGET" ]]; then
        echo
        echo -e "${RED}✗ No target configured!${NC}"
        echo -e "${YELLOW}Please set a target first (option 1)${NC}"
        echo -en "${YELLOW}Press Enter to continue...${NC}"
        read -r
        return 1
    fi
    
    echo
    echo -e "${CYAN}═══ Scan Summary ═══${NC}"
    echo -e "${WHITE}Target: ${GREEN}$TARGET${NC}"
    echo -e "${WHITE}Output: ${GREEN}$OUTPUT_DIR${NC}"
    echo -e "${WHITE}Threads: ${GREEN}$THREADS${NC}"
    echo -e "${WHITE}Timing: ${GREEN}$TIMING${NC}"
    echo -e "${WHITE}Stealth: ${GREEN}$(if [[ "$STEALTH_MODE" == "true" ]]; then echo "Enabled"; else echo "Disabled"; fi)${NC}"
    echo
    echo -e "${YELLOW}Start reconnaissance scan? [Y/n]: ${NC}"
    read -r confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        echo -e "${YELLOW}Scan cancelled${NC}"
        echo -en "${YELLOW}Press Enter to continue...${NC}"
        read -r
        return 1
    fi
    
    echo
    echo -e "${GREEN}Starting BCAR reconnaissance scan...${NC}"
    echo
    run_scan
    
    echo
    echo -e "${GREEN}✓ Scan completed!${NC}"
    echo -e "${CYAN}Results saved to: $OUTPUT_DIR${NC}"
    if [[ -t 0 ]]; then
        echo -en "${YELLOW}Press Enter to return to main menu...${NC}"
        read -r _
    fi
}

# Interactive main menu loop
main_menu() {
    # Initialize output directory for menu usage
    OUTPUT_DIR="bcar_results_$(date +%Y%m%d_%H%M%S)"
    
    while true; do
        show_main_menu
        read -r choice
        
        case $choice in
            1)
                set_target_interactive
                ;;
            2)
                configure_options
                ;;
            3)
                start_scan_interactive
                ;;
            4)
                view_configuration
                ;;
            5)
                reset_configuration
                ;;
            6)
                clear
                print_banner
                usage
                echo -en "${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            0)
                echo
                echo -e "${CYAN}Thank you for using BCAR!${NC}"
                exit 0
                ;;
            *)
                echo
                echo -e "${RED}✗ Invalid option. Please try again.${NC}"
                echo -en "${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
        esac
    done
}
show_progress() {
    local current="$1"
    local total="$2"
    local description="$3"
    local percentage=$((current * 100 / total))
    local bar_length=50
    local filled_length=$((percentage * bar_length / 100))
    
    local bar=""
    for ((i=0; i<filled_length; i++)); do bar+="█"; done
    for ((i=filled_length; i<bar_length; i++)); do bar+="░"; done
    
    printf "\r${CYAN}[%s]${NC} %3d%% %s - %s" "$bar" "$percentage" "$description" "$(date '+%H:%M:%S')"
    if [[ $current -eq $total ]]; then
        echo
    fi
}

# Enhanced run scan with progress tracking
run_scan() {
    log "INFO" "Starting BlackCell Auto Recon scan against $TARGET"
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    local total_phases=6
    local current_phase=0
    
    # Run reconnaissance modules with progress tracking
    ((current_phase++))
    show_progress "$current_phase" "$total_phases" "DNS Enumeration"
    dns_enumeration
    
    ((current_phase++))
    show_progress "$current_phase" "$total_phases" "WHOIS Lookup"
    whois_lookup
    
    ((current_phase++))
    show_progress "$current_phase" "$total_phases" "Port Scanning"
    port_scanning
    
    ((current_phase++))
    show_progress "$current_phase" "$total_phases" "Web Application Scanning"
    web_scanning
    
    ((current_phase++))
    show_progress "$current_phase" "$total_phases" "DOM Security Analysis"
    dom_security_scan
    
    ((current_phase++))
    show_progress "$current_phase" "$total_phases" "SSL Analysis & Report Generation"
    ssl_analysis
    
    # Generate final reports based on format selection
    case "$OUTPUT_FORMAT" in
        "txt")
            generate_report
            ;;
        "json")
            generate_json_report
            ;;
        "both")
            generate_report
            generate_json_report
            ;;
        *)
            log "WARNING" "Unknown output format: $OUTPUT_FORMAT, defaulting to txt"
            generate_report
            ;;
    esac
    
    log "SUCCESS" "BCAR scan completed successfully!"
    echo -e "${GREEN}Results saved to: $OUTPUT_DIR${NC}"
    echo -e "${CYAN}Summary report: $OUTPUT_DIR/BCAR_Report.txt${NC}"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--target)
            TARGET="$2"
            validate_input "$TARGET" "target" || exit 1
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            validate_input "$OUTPUT_DIR" "path" || exit 1
            shift 2
            ;;
        -T|--threads)
            THREADS="$2"
            validate_input "$THREADS" "threads" || exit 1
            shift 2
            ;;
        -w|--wordlist)
            WORDLIST="$2"
            validate_input "$WORDLIST" "path" || exit 1
            shift 2
            ;;
        -s|--scripts)
            NMAP_SCRIPTS="$2"
            shift 2
            ;;
        --stealth)
            STEALTH_MODE=true
            TIMING="slow"
            THREADS=10
            shift
            ;;
        --timing)
            TIMING="$2"
            shift 2
            ;;
        --format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --no-dom)
            DOM_SCAN_ENABLED=false
            shift
            ;;
        --dom-gui)
            DOM_HEADLESS=false
            shift
            ;;
        -h|--help)
            print_banner
            usage
            exit 0
            ;;
        *)
            if [[ -z "$TARGET" ]]; then
                TARGET="$1"
                validate_input "$TARGET" "target" || exit 1
            else
                echo -e "${RED}Unknown option: $1${NC}"
                usage
                exit 1
            fi
            shift
            ;;
    esac
done

# Main execution
# If no arguments provided, launch interactive menu
if [[ $# -eq 0 ]]; then
    # Load configuration if available
    load_config
    
    # Check dependencies before starting menu
    check_dependencies
    
    # Launch interactive menu
    main_menu
else
    # Command-line mode (existing behavior)
    print_banner
    
    # Load configuration if available
    load_config
    
    # Validate input
    if [[ -z "$TARGET" ]]; then
        echo -e "${RED}Error: Target is required${NC}"
        usage
        exit 1
    fi
    
    # Check dependencies
    check_dependencies
    
    # Start scanning
    run_scan
fi