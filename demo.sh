#!/bin/bash

# BCAR Demo Script
# Demonstrates BCAR functionality with safe examples

echo "========================================"
echo "BCAR - BlackCell Auto Recon Demo"
echo "========================================"
echo

# Show help
echo "1. Displaying help information:"
echo "-------------------------------"
./bcar.sh --help
echo

# Show version and banner
echo "2. Showing script banner:"
echo "------------------------"
echo "Example command: ./bcar.sh -t example.com"
echo

echo "3. Available features:"
echo "---------------------"
echo "- DNS enumeration and zone transfer testing"
echo "- WHOIS lookup and domain analysis"  
echo "- Comprehensive port scanning with Nmap"
echo "- Web application discovery and fingerprinting"
echo "- Directory and file brute forcing"
echo "- SSL/TLS security analysis"
echo "- Automated vulnerability scanning"
echo "- Structured output and reporting"
echo

echo "4. Sample usage patterns:"
echo "------------------------"
echo "Basic scan:     ./bcar.sh -t target.com"
echo "Custom output:  ./bcar.sh -t target.com -o my_assessment"
echo "High threads:   ./bcar.sh -t target.com -T 100"
echo "Custom wordlist: ./bcar.sh -t target.com -w /path/to/wordlist.txt"
echo

echo "========================================"
echo "Demo completed. Use './bcar.sh -h' for detailed options."
echo "========================================"