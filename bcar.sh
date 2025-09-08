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
OUTPUT_DIR="bcar_results_$(date +%Y%m%d_%H%M%S)"
TARGET=""
THREADS=50
WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
NMAP_SCRIPTS="default,vuln"

# Usage function
usage() {
    echo -e "${WHITE}Usage: $0 [OPTIONS] TARGET${NC}"
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  -t, --target      Target IP address or domain"
    echo -e "  -o, --output      Output directory (default: bcar_results_timestamp)"
    echo -e "  -T, --threads     Number of threads (default: 50)"
    echo -e "  -w, --wordlist    Wordlist for directory brute force"
    echo -e "  -s, --scripts     Nmap scripts to use (default: default,vuln)"
    echo -e "  -h, --help        Show this help message"
    echo
    echo -e "${YELLOW}Examples:${NC}"
    echo -e "  $0 -t 192.168.1.100"
    echo -e "  $0 -t example.com -o custom_output -T 100"
    echo -e "  $0 --target 10.0.0.1 --wordlist /path/to/wordlist.txt"
}

# Logging function
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "${CYAN}[INFO]${NC} ${timestamp} - $message" | tee -a "$OUTPUT_DIR/bcar.log"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} ${timestamp} - $message" | tee -a "$OUTPUT_DIR/bcar.log"
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING]${NC} ${timestamp} - $message" | tee -a "$OUTPUT_DIR/bcar.log"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} ${timestamp} - $message" | tee -a "$OUTPUT_DIR/bcar.log"
            ;;
    esac
}

# Check if required tools are installed
check_dependencies() {
    log "INFO" "Checking dependencies..."
    
    local tools=("nmap" "gobuster" "nikto" "whatweb" "dig" "whois" "curl")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log "ERROR" "Missing required tools: ${missing_tools[*]}"
        echo -e "${RED}Please install the missing tools before running BCAR${NC}"
        exit 1
    fi
    
    log "SUCCESS" "All dependencies are available"
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
    local nameservers=$(dig +short NS "$TARGET" 2>/dev/null)
    if [ -n "$nameservers" ]; then
        while IFS= read -r ns; do
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
    
    # Quick scan for top ports
    log "INFO" "Running quick port scan (top 1000 ports)"
    nmap -T4 -top-ports 1000 --open "$TARGET" -oN "$OUTPUT_DIR/nmap/quick_scan.txt" -oX "$OUTPUT_DIR/nmap/quick_scan.xml" &>/dev/null || true
    
    # Full TCP scan
    log "INFO" "Running comprehensive TCP scan"
    nmap -sS -T4 -p- --open "$TARGET" -oN "$OUTPUT_DIR/nmap/full_tcp.txt" -oX "$OUTPUT_DIR/nmap/full_tcp.xml" &>/dev/null || true
    
    # Service version detection
    local open_ports=$(grep -oP '\d+/tcp' "$OUTPUT_DIR/nmap/quick_scan.txt" 2>/dev/null | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
    if [ -n "$open_ports" ]; then
        log "INFO" "Running service version detection on open ports: $open_ports"
        nmap -sV -sC --script="$NMAP_SCRIPTS" -p"$open_ports" "$TARGET" -oN "$OUTPUT_DIR/nmap/service_scan.txt" -oX "$OUTPUT_DIR/nmap/service_scan.xml" &>/dev/null || true
    fi
    
    # UDP scan (top ports only)
    log "INFO" "Running UDP scan (top 100 ports)"
    nmap -sU -T4 --top-ports 100 --open "$TARGET" -oN "$OUTPUT_DIR/nmap/udp_scan.txt" -oX "$OUTPUT_DIR/nmap/udp_scan.xml" &>/dev/null || true
    
    log "SUCCESS" "Port scanning completed"
}

# Web application scanning
web_scanning() {
    log "INFO" "Starting web application scanning"
    
    mkdir -p "$OUTPUT_DIR/web"
    
    # Check for HTTP services
    local http_ports=()
    if [ -f "$OUTPUT_DIR/nmap/service_scan.txt" ]; then
        http_ports=($(grep -E "(http|https)" "$OUTPUT_DIR/nmap/service_scan.txt" | grep -oP '\d+/tcp' | cut -d'/' -f1))
    fi
    
    if [ ${#http_ports[@]} -eq 0 ]; then
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
            if [ -f "$WORDLIST" ]; then
                log "INFO" "Running directory brute force on port $port"
                gobuster dir -u "$url" -w "$WORDLIST" -t "$THREADS" -x php,html,js,txt,xml -o "$OUTPUT_DIR/web/gobuster_${port}.txt" &>/dev/null || true
            fi
            
            # Nikto scan
            log "INFO" "Running Nikto scan on port $port"
            nikto -h "$url" -output "$OUTPUT_DIR/web/nikto_${port}.txt" &>/dev/null || true
        fi
    done
    
    log "SUCCESS" "Web application scanning completed"
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
    
    {
        echo "========================================"
        echo "BlackCell Auto Recon (BCAR) Report"
        echo "========================================"
        echo "Target: $TARGET"
        echo "Scan Date: $(date)"
        echo "Output Directory: $OUTPUT_DIR"
        echo "========================================"
        echo
        
        echo "DNS INFORMATION:"
        echo "=================="
        if [ -f "$OUTPUT_DIR/dns/a_records.txt" ]; then
            echo "A Records:"
            cat "$OUTPUT_DIR/dns/a_records.txt" | head -10
            echo
        fi
        
        echo "OPEN PORTS:"
        echo "============"
        if [ -f "$OUTPUT_DIR/nmap/quick_scan.txt" ]; then
            grep -E "^\d+/tcp.*open" "$OUTPUT_DIR/nmap/quick_scan.txt" || echo "No open ports found in quick scan"
            echo
        fi
        
        echo "WEB SERVICES:"
        echo "=============="
        find "$OUTPUT_DIR/web" -name "whatweb_*.txt" -exec echo "Port $(basename {} .txt | cut -d'_' -f2):" \; -exec head -3 {} \; 2>/dev/null || echo "No web services analyzed"
        echo
        
        echo "DIRECTORIES FOUND:"
        echo "=================="
        find "$OUTPUT_DIR/web" -name "gobuster_*.txt" -exec echo "Port $(basename {} .txt | cut -d'_' -f2):" \; -exec grep -E "Status: 200|Status: 301|Status: 302" {} \; 2>/dev/null | head -20 || echo "No directories found"
        echo
        
    } > "$report_file"
    
    log "SUCCESS" "Summary report generated: $report_file"
}

# Main scanning function
run_scan() {
    log "INFO" "Starting BlackCell Auto Recon scan against $TARGET"
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Run reconnaissance modules
    dns_enumeration
    whois_lookup
    port_scanning
    web_scanning
    ssl_analysis
    
    # Generate final report
    generate_report
    
    log "SUCCESS" "BCAR scan completed successfully!"
    echo -e "${GREEN}Results saved to: $OUTPUT_DIR${NC}"
    echo -e "${CYAN}Summary report: $OUTPUT_DIR/BCAR_Report.txt${NC}"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--target)
            TARGET="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -T|--threads)
            THREADS="$2"
            shift 2
            ;;
        -w|--wordlist)
            WORDLIST="$2"
            shift 2
            ;;
        -s|--scripts)
            NMAP_SCRIPTS="$2"
            shift 2
            ;;
        -h|--help)
            print_banner
            usage
            exit 0
            ;;
        *)
            if [ -z "$TARGET" ]; then
                TARGET="$1"
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
print_banner

# Validate input
if [ -z "$TARGET" ]; then
    echo -e "${RED}Error: Target is required${NC}"
    usage
    exit 1
fi

# Check dependencies
check_dependencies

# Start scanning
run_scan