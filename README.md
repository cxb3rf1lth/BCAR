# BCAR - BlackCell Auto Recon

A comprehensive automated reconnaissance framework designed for security professionals and penetration testers. BCAR streamlines the reconnaissance phase of security assessments by automating multiple discovery and enumeration techniques in a single, efficient workflow.

## Overview

BlackCell Auto Recon (BCAR) is a powerful bash-based reconnaissance tool that combines multiple industry-standard tools and techniques to provide comprehensive target analysis. Built for efficiency and thoroughness, BCAR automates the tedious aspects of information gathering while maintaining the flexibility for manual analysis.

## Features

### Core Capabilities
- **DNS Enumeration**: Comprehensive DNS record analysis including A, MX, NS, and TXT records
- **Zone Transfer Testing**: Automated attempts to identify misconfigured DNS servers
- **WHOIS Analysis**: Complete domain registration and ownership information gathering
- **Port Scanning**: Multi-phase port discovery using Nmap with intelligent service detection
- **Web Application Discovery**: Automated web service identification and analysis
- **Directory Brute Force**: Comprehensive directory and file discovery using Gobuster
- **SSL/TLS Analysis**: Security assessment of encrypted services
- **Vulnerability Scanning**: Automated vulnerability detection using Nmap scripts
- **Service Fingerprinting**: Detailed service version and technology identification

### Technical Features
- **Multi-threaded Execution**: Configurable thread counts for optimal performance
- **Modular Architecture**: Independent scanning modules for flexible execution
- **Comprehensive Logging**: Detailed logging with timestamp and severity levels
- **Structured Output**: Organized results in categorized directories
- **XML Export Support**: Nmap results exported in XML format for further analysis
- **Summary Reporting**: Automated generation of executive summary reports
- **Error Handling**: Robust error handling and graceful failure recovery

## Installation

### Prerequisites

BCAR requires the following tools to be installed on your system:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap gobuster nikto whatweb dnsutils whois curl

# CentOS/RHEL/Fedora
sudo yum install nmap gobuster nikto whatweb bind-utils whois curl
# or
sudo dnf install nmap gobuster nikto whatweb bind-utils whois curl

# Arch Linux
sudo pacman -S nmap gobuster nikto whatweb dnsutils whois curl

# macOS (using Homebrew)
brew install nmap gobuster nikto whatweb whois curl
```

### Quick Start

1. Clone the repository:
```bash
git clone https://github.com/cxb3rf1lth/BCAR.git
cd BCAR
```

2. Make the script executable:
```bash
chmod +x bcar.sh
```

3. Run a basic scan:
```bash
./bcar.sh -t example.com
```

## Usage

### Basic Usage
```bash
./bcar.sh [OPTIONS] TARGET
```

### Command Line Options

| Option | Long Form | Description | Default |
|--------|-----------|-------------|---------|
| `-t` | `--target` | Target IP address or domain name | Required |
| `-o` | `--output` | Custom output directory name | `bcar_results_timestamp` |
| `-T` | `--threads` | Number of threads for concurrent operations | `50` |
| `-w` | `--wordlist` | Custom wordlist for directory brute force | `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` |
| `-s` | `--scripts` | Nmap scripts to execute | `default,vuln` |
| `-h` | `--help` | Display help information and exit | N/A |

### Usage Examples

#### Basic Target Scan
```bash
./bcar.sh -t 192.168.1.100
```

#### Comprehensive Domain Assessment
```bash
./bcar.sh -t example.com -o example_assessment -T 100
```

#### Custom Wordlist Scan
```bash
./bcar.sh --target 10.0.0.1 --wordlist /path/to/custom-wordlist.txt
```

#### High-Speed Scanning
```bash
./bcar.sh -t target.com -T 200 --scripts "default,vuln,exploit"
```

## Output Structure

BCAR organizes results in a structured directory hierarchy for easy analysis:

```
bcar_results_YYYYMMDD_HHMMSS/
├── bcar.log                    # Comprehensive execution log
├── BCAR_Report.txt            # Executive summary report
├── dns/                       # DNS enumeration results
│   ├── a_records.txt
│   ├── mx_records.txt
│   ├── ns_records.txt
│   ├── txt_records.txt
│   └── zone_transfer_*.txt
├── whois/                     # Domain registration information
│   └── whois_info.txt
├── nmap/                      # Port scanning results
│   ├── quick_scan.txt
│   ├── quick_scan.xml
│   ├── full_tcp.txt
│   ├── full_tcp.xml
│   ├── service_scan.txt
│   ├── service_scan.xml
│   ├── udp_scan.txt
│   └── udp_scan.xml
├── web/                       # Web application analysis
│   ├── whatweb_*.txt
│   ├── gobuster_*.txt
│   └── nikto_*.txt
└── ssl/                       # SSL/TLS analysis
    └── ssl_analysis_*.txt
```

## Scanning Methodology

### Phase 1: Information Gathering
1. **DNS Enumeration**: Queries for all standard DNS record types
2. **WHOIS Lookup**: Extracts domain registration and contact information
3. **Zone Transfer Testing**: Tests for DNS misconfigurations

### Phase 2: Network Discovery
1. **Quick Port Scan**: Rapid scan of top 1000 TCP ports
2. **Comprehensive TCP Scan**: Full range TCP port scanning
3. **UDP Discovery**: Targeted UDP port scanning for common services
4. **Service Detection**: Version fingerprinting of discovered services

### Phase 3: Service Analysis
1. **Web Service Discovery**: Identification of HTTP/HTTPS services
2. **Technology Fingerprinting**: Detection of web technologies and frameworks
3. **Directory Enumeration**: Brute force discovery of hidden directories and files
4. **Vulnerability Assessment**: Automated vulnerability scanning with Nmap scripts

### Phase 4: Security Analysis
1. **SSL/TLS Assessment**: Analysis of encryption implementations
2. **Certificate Analysis**: Examination of SSL certificates
3. **Security Header Analysis**: Review of HTTP security headers

## Advanced Configuration

### Custom Wordlists

BCAR supports custom wordlists for directory brute forcing. Popular wordlist locations:

- **SecLists**: `/usr/share/seclists/Discovery/Web-Content/`
- **Dirbuster**: `/usr/share/wordlists/dirbuster/`
- **Custom Lists**: Any text file with one entry per line

### Nmap Script Categories

Configure Nmap scripts using the `-s` option with categories:

- `default`: Standard safe scripts
- `vuln`: Vulnerability detection scripts  
- `exploit`: Exploitation scripts (use with caution)
- `auth`: Authentication testing scripts
- `brute`: Brute force scripts
- `discovery`: Additional discovery scripts

### Performance Tuning

Optimize BCAR performance based on your environment:

- **Local Network**: Use higher thread counts (`-T 200`)
- **Remote Targets**: Use conservative thread counts (`-T 50`)
- **Stealth Mode**: Reduce thread count and use custom timing (`-T 10`)

## Security Considerations

### Legal and Ethical Use
- Only use BCAR against systems you own or have explicit permission to test
- Understand and comply with local laws and regulations
- Respect system resources and avoid causing service disruptions
- Document all testing activities for compliance purposes

### Operational Security
- Use VPN or other anonymization techniques when appropriate
- Be aware of logs and monitoring systems that may detect scanning activities
- Consider the impact of scanning on production systems
- Maintain confidentiality of discovered information

## Troubleshooting

### Common Issues and Solutions

#### Missing Dependencies
```bash
# Check for missing tools
which nmap gobuster nikto whatweb dig whois curl

# Install missing packages (Ubuntu/Debian example)
sudo apt install missing-package-name
```

#### Permission Issues
```bash
# Ensure script is executable
chmod +x bcar.sh

# Check file permissions
ls -la bcar.sh
```

#### Network Connectivity
```bash
# Test basic connectivity
ping target.com

# Check DNS resolution
nslookup target.com
```

#### Large Wordlist Performance
For better performance with large wordlists:
- Use SSD storage for output directory
- Increase thread count appropriately
- Consider splitting large wordlists

### Error Logging
All errors are logged to `bcar.log` with timestamps and severity levels:
- **INFO**: General execution information
- **SUCCESS**: Successful operation completion
- **WARNING**: Non-critical issues that do not stop execution
- **ERROR**: Critical errors that may affect results

## Contributing

Contributions to BCAR are welcome and encouraged. Please follow these guidelines:

1. Fork the repository and create a feature branch
2. Follow existing code style and conventions
3. Add appropriate error handling and logging
4. Test changes thoroughly before submitting
5. Update documentation for any new features
6. Submit a pull request with a clear description of changes

## License

This project is developed for educational and authorized testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

## Changelog

### Version 1.0.0
- Initial release with core reconnaissance capabilities
- DNS enumeration and zone transfer testing
- Comprehensive port scanning with Nmap
- Web application discovery and directory brute forcing
- SSL/TLS security analysis
- Automated report generation
- Multi-threaded execution support
- Comprehensive error handling and logging

## Support

For issues, questions, or contributions:
- Open an issue on the GitHub repository
- Follow the project for updates and announcements
- Review the troubleshooting section for common problems

## Acknowledgments

BCAR leverages several excellent open-source tools:
- **Nmap**: Network discovery and security auditing
- **Gobuster**: Directory and file brute forcing
- **Nikto**: Web vulnerability scanner  
- **WhatWeb**: Web application fingerprinting
- **DNS Utils**: DNS enumeration and analysis
- **WHOIS**: Domain registration information lookup
