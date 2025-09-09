#!/usr/bin/env python3
"""
BlackCell Auto Recon (BCAR) - Advanced Python Version
Author: BlackCell Security
Description: Comprehensive automated reconnaissance tool with professional TUI interface
Version: 2.0.0
"""

import asyncio
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

# Rich TUI imports
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.tree import Tree
from rich import box

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bcar.log'),
        logging.StreamHandler()
    ]
)

class BCARConfig:
    """Configuration management for BCAR"""
    
    def __init__(self):
        self.target: Optional[str] = None
        self.output_dir: str = f"bcar_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.threads: int = 50
        self.timing: str = "normal"  # slow, normal, fast
        self.stealth_mode: bool = False
        self.output_format: str = "json"  # txt, json, both
        self.dom_scan_enabled: bool = True
        self.dom_headless: bool = True
        self.nmap_scripts: str = "default,vuln"
        self.wordlist: Optional[str] = None
        self.verbose: bool = False
        
        # Advanced Python features
        self.max_retries: int = 3
        self.timeout: int = 30
        self.user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) BCAR/2.0"
        self.dns_servers: List[str] = ["8.8.8.8", "1.1.1.1"]
        self.skip_phases: List[str] = []
        
    def load_from_file(self, config_path: str = "bcar_config.json") -> None:
        """Load configuration from JSON file"""
        try:
            if Path(config_path).exists():
                with open(config_path, 'r') as f:
                    config_data = json.load(f)
                    for key, value in config_data.items():
                        if hasattr(self, key):
                            setattr(self, key, value)
        except Exception as e:
            logging.warning(f"Could not load config file: {e}")
    
    def save_to_file(self, config_path: str = "bcar_config.json") -> None:
        """Save current configuration to JSON file"""
        try:
            config_data = {
                attr: getattr(self, attr) for attr in dir(self)
                if not attr.startswith('_') and not callable(getattr(self, attr))
            }
            with open(config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
        except Exception as e:
            logging.error(f"Could not save config file: {e}")
    
    def reset_to_defaults(self) -> None:
        """Reset configuration to default values"""
        self.__init__()

class Scanner:
    """Base class for all scanning modules"""
    
    def __init__(self, config: BCARConfig, console: Console):
        self.config = config
        self.console = console
        self.results: Dict[str, Any] = {}
        
    async def run(self) -> Dict[str, Any]:
        """Run the scanner - to be implemented by subclasses"""
        raise NotImplementedError
        
    def validate_target(self, target: str) -> bool:
        """Validate target format (IP or domain)"""
        import re
        import ipaddress
        
        # First try to validate as IP address using ipaddress module for accuracy
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        
        # Enhanced domain validation - must not start or end with hyphen or dot
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        
        # Simple domain without dots (like localhost) - no hyphens at start/end
        simple_domain = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        
        # Additional validation - no consecutive dots, no leading/trailing dots, no empty
        if not target or '..' in target or target.startswith('.') or target.endswith('.') or target.startswith('-') or target.endswith('-'):
            return False
        
        # Check domain patterns
        return bool(re.match(domain_pattern, target) or re.match(simple_domain, target))

class DNSScanner(Scanner):
    """DNS enumeration and zone transfer testing"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform DNS reconnaissance"""
        self.console.print("[cyan]🔍 Starting DNS enumeration...[/cyan]")
        
        dns_results = {
            "records": {},
            "zone_transfer": False,
            "subdomains": []
        }
        
        try:
            # DNS record enumeration
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                task = progress.add_task("Enumerating DNS records...", total=len(record_types))
                
                for record_type in record_types:
                    try:
                        cmd = ["dig", "+short", record_type, self.config.target]
                        result = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        stdout, stderr = await result.communicate()
                        
                        if result.returncode == 0 and stdout:
                            dns_results["records"][record_type] = stdout.decode().strip().split('\n')
                        
                    except Exception as e:
                        logging.warning(f"DNS {record_type} query failed: {e}")
                    
                    progress.update(task, advance=1)
            
            # Zone transfer test
            if 'NS' in dns_results["records"]:
                self.console.print("[yellow]🔄 Testing zone transfers...[/yellow]")
                for ns_server in dns_results["records"]["NS"]:
                    try:
                        cmd = ["dig", "axfr", self.config.target, f"@{ns_server.strip()}"]
                        result = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        stdout, stderr = await result.communicate()
                        
                        if result.returncode == 0 and "failed" not in stdout.decode().lower():
                            dns_results["zone_transfer"] = True
                            self.console.print(f"[red]⚠️  Zone transfer successful on {ns_server}![/red]")
                            break
                            
                    except Exception as e:
                        logging.warning(f"Zone transfer test failed for {ns_server}: {e}")
            
        except Exception as e:
            logging.error(f"DNS scanning failed: {e}")
        
        self.results = dns_results
        return dns_results

class WhoisScanner(Scanner):
    """WHOIS information gathering"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform WHOIS lookup"""
        self.console.print("[cyan]🔍 Starting WHOIS analysis...[/cyan]")
        
        whois_results = {
            "domain_info": {},
            "registrar": {},
            "dates": {},
            "contacts": {},
            "nameservers": [],
            "raw_output": ""
        }
        
        try:
            # Create output directory
            os.makedirs(f"{self.config.output_dir}/whois", exist_ok=True)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                task = progress.add_task("Performing WHOIS lookup...", total=100)
                
                # Run whois command
                cmd = ["whois", self.config.target]
                result = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await result.communicate()
                progress.update(task, advance=50)
                
                if result.returncode == 0 and stdout:
                    whois_output = stdout.decode()
                    whois_results["raw_output"] = whois_output
                    
                    # Save raw output to file
                    with open(f"{self.config.output_dir}/whois/whois_info.txt", 'w') as f:
                        f.write(whois_output)
                    
                    # Parse WHOIS information (basic parsing)
                    lines = whois_output.lower().split('\n')
                    
                    for line in lines:
                        line = line.strip()
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip()
                            value = value.strip()
                            
                            # Extract key information
                            if 'registrar' in key and value:
                                whois_results["registrar"]["name"] = value
                            elif 'creation' in key or 'created' in key:
                                whois_results["dates"]["created"] = value
                            elif 'expir' in key:
                                whois_results["dates"]["expires"] = value
                            elif 'updated' in key or 'modified' in key:
                                whois_results["dates"]["updated"] = value
                            elif 'name server' in key or 'nserver' in key:
                                if value not in whois_results["nameservers"]:
                                    whois_results["nameservers"].append(value)
                    
                    progress.update(task, advance=50)
                    self.console.print(f"[green]✓ WHOIS data retrieved for {self.config.target}[/green]")
                else:
                    self.console.print("[yellow]⚠️  WHOIS lookup failed or no data available[/yellow]")
        
        except Exception as e:
            logging.error(f"WHOIS lookup failed: {e}")
            whois_results["error"] = str(e)
        
        self.results = whois_results
        return whois_results

class PortScanner(Scanner):
    """WHOIS information gathering"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform WHOIS lookup"""
        self.console.print("[cyan]🔍 Starting WHOIS analysis...[/cyan]")
        
        whois_results = {
            "domain_info": {},
            "registrar": {},
            "dates": {},
            "contacts": {},
            "nameservers": [],
            "raw_output": ""
        }
        
        try:
            # Create output directory
            os.makedirs(f"{self.config.output_dir}/whois", exist_ok=True)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                task = progress.add_task("Performing WHOIS lookup...", total=100)
                
                # Run whois command
                cmd = ["whois", self.config.target]
                result = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await result.communicate()
                progress.update(task, advance=50)
                
                if result.returncode == 0 and stdout:
                    whois_output = stdout.decode()
                    whois_results["raw_output"] = whois_output
                    
                    # Save raw output to file
                    with open(f"{self.config.output_dir}/whois/whois_info.txt", 'w') as f:
                        f.write(whois_output)
                    
                    # Parse WHOIS information (basic parsing)
                    lines = whois_output.lower().split('\n')
                    
                    for line in lines:
                        line = line.strip()
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip()
                            value = value.strip()
                            
                            # Extract key information
                            if 'registrar' in key and value:
                                whois_results["registrar"]["name"] = value
                            elif 'creation' in key or 'created' in key:
                                whois_results["dates"]["created"] = value
                            elif 'expir' in key:
                                whois_results["dates"]["expires"] = value
                            elif 'updated' in key or 'modified' in key:
                                whois_results["dates"]["updated"] = value
                            elif 'name server' in key or 'nserver' in key:
                                if value not in whois_results["nameservers"]:
                                    whois_results["nameservers"].append(value)
                    
                    progress.update(task, advance=50)
                    self.console.print(f"[green]✓ WHOIS data retrieved for {self.config.target}[/green]")
                else:
                    self.console.print("[yellow]⚠️  WHOIS lookup failed or no data available[/yellow]")
        
        except Exception as e:
            logging.error(f"WHOIS lookup failed: {e}")
            whois_results["error"] = str(e)
        
        self.results = whois_results
        return whois_results


    """Network port scanning with Nmap"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform port scanning"""
        self.console.print("[cyan]🔍 Starting port scanning...[/cyan]")
        
        port_results = {
            "open_ports": [],
            "services": {},
            "tcp_scan": None,
            "udp_scan": None
        }
        
        try:
            # Create output directory
            os.makedirs(f"{self.config.output_dir}/nmap", exist_ok=True)
            
            # Determine Nmap timing
            timing_map = {
                "slow": "-T1",
                "normal": "-T3", 
                "fast": "-T4"
            }
            timing = timing_map.get(self.config.timing, "-T3")
            if self.config.stealth_mode:
                timing = "-T1"
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                # Quick TCP scan
                task1 = progress.add_task("Quick TCP port scan (top 1000)...", total=100)
                
                cmd = [
                    "nmap", timing, "--top-ports", "1000", "--open",
                    "-oN", f"{self.config.output_dir}/nmap/quick_scan.txt",
                    "-oX", f"{self.config.output_dir}/nmap/quick_scan.xml",
                    self.config.target
                ]
                
                result = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await result.communicate()
                progress.update(task1, completed=100)
                
                if result.returncode == 0:
                    port_results["tcp_scan"] = "completed"
                    # Parse open ports from nmap output
                    await self._parse_nmap_output(f"{self.config.output_dir}/nmap/quick_scan.txt", port_results)
                
                # Service detection on open ports
                if port_results["open_ports"]:
                    task2 = progress.add_task("Service version detection...", total=100)
                    
                    ports_str = ",".join([str(p) for p in port_results["open_ports"]])
                    cmd = [
                        "nmap", "-sV", "-sC", f"--script={self.config.nmap_scripts}",
                        timing, f"-p{ports_str}",
                        "-oN", f"{self.config.output_dir}/nmap/service_scan.txt",
                        "-oX", f"{self.config.output_dir}/nmap/service_scan.xml",
                        self.config.target
                    ]
                    
                    result = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    await result.communicate()
                    progress.update(task2, completed=100)
                
                # UDP scan (if not in stealth mode)
                if not self.config.stealth_mode:
                    task3 = progress.add_task("UDP port scan (top 100)...", total=100)
                    
                    cmd = [
                        "nmap", "-sU", timing, "--top-ports", "100", "--open",
                        "-oN", f"{self.config.output_dir}/nmap/udp_scan.txt",
                        "-oX", f"{self.config.output_dir}/nmap/udp_scan.xml",
                        self.config.target
                    ]
                    
                    result = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    await result.communicate()
                    progress.update(task3, completed=100)
                    
                    if result.returncode == 0:
                        port_results["udp_scan"] = "completed"
        
        except Exception as e:
            logging.error(f"Port scanning failed: {e}")
        
        self.results = port_results
        return port_results
    
    async def _parse_nmap_output(self, file_path: str, results: Dict[str, Any]) -> None:
        """Parse Nmap output to extract open ports"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                import re
                # Extract open ports from nmap output
                port_pattern = r'(\d+)/tcp\s+open'
                matches = re.findall(port_pattern, content)
                results["open_ports"] = [int(port) for port in matches]
        except Exception as e:
            logging.warning(f"Could not parse nmap output: {e}")

class WebScanner(Scanner):
    """Web application scanning and directory enumeration"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform web application scanning"""
        self.console.print("[cyan]🔍 Starting web application scanning...[/cyan]")
        
        web_results = {
            "http_services": [],
            "technologies": {},
            "directories": {},
            "vulnerabilities": []
        }
        
        try:
            # Create output directory
            os.makedirs(f"{self.config.output_dir}/web", exist_ok=True)
            
            # Identify HTTP services from port scan results
            http_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                for port in http_ports:
                    task = progress.add_task(f"Scanning web service on port {port}...", total=100)
                    
                    # Check if port is open (you'd get this from port scanner results)
                    url = f"http{'s' if port in [443, 8443] else ''}://{self.config.target}:{port}"
                    
                    # WhatWeb technology detection
                    try:
                        cmd = ["whatweb", "--color=never", url]
                        result = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        stdout, stderr = await result.communicate()
                        
                        if result.returncode == 0:
                            web_results["technologies"][port] = stdout.decode().strip()
                            web_results["http_services"].append(port)
                    
                    except Exception as e:
                        logging.warning(f"WhatWeb scan failed for port {port}: {e}")
                    
                    # Directory enumeration with Gobuster
                    if self.config.wordlist and os.path.exists(self.config.wordlist):
                        try:
                            cmd = [
                                "gobuster", "dir", "-u", url, "-w", self.config.wordlist,
                                "-t", str(self.config.threads), "-q",
                                "-o", f"{self.config.output_dir}/web/gobuster_{port}.txt"
                            ]
                            
                            result = await asyncio.create_subprocess_exec(
                                *cmd,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE
                            )
                            
                            await result.communicate()
                            
                            if result.returncode == 0:
                                web_results["directories"][port] = f"gobuster_{port}.txt"
                        
                        except Exception as e:
                            logging.warning(f"Gobuster scan failed for port {port}: {e}")
                    
                    progress.update(task, completed=100)
        
        except Exception as e:
            logging.error(f"Web scanning failed: {e}")
        
        self.results = web_results
        return web_results

class DOMScanner(Scanner):
    """DOM-based XSS and security scanning"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform DOM security scanning"""
        if not self.config.dom_scan_enabled:
            return {}
            
        self.console.print("[cyan]🔍 Starting DOM security scanning...[/cyan]")
        
        dom_results = {
            "xss_vulnerabilities": [],
            "open_redirects": [],
            "scanned_urls": []
        }
        
        try:
            # Create output directory
            os.makedirs(f"{self.config.output_dir}/dom_security", exist_ok=True)
            
            # Check if DOMscan is available
            result = await asyncio.create_subprocess_exec(
                "which", "domscan",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            if result.returncode != 0:
                self.console.print("[yellow]⚠️  DOMscan not found, skipping DOM analysis[/yellow]")
                return dom_results
            
            # Get HTTP services from web scanner or port scanner
            http_ports = [80, 443, 8080, 8443]  # This would come from previous scans
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                for port in http_ports:
                    task = progress.add_task(f"DOM scanning on port {port}...", total=100)
                    
                    url = f"http{'s' if port in [443, 8443] else ''}://{self.config.target}:{port}"
                    
                    try:
                        cmd = ["domscan", url]
                        if self.config.dom_headless:
                            cmd.extend(["--headless", "true"])
                        
                        if self.config.stealth_mode:
                            cmd.append("--throttle")
                        else:
                            cmd.extend(["-g", "-G"])
                        
                        result = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        
                        stdout, stderr = await result.communicate()
                        
                        if result.returncode == 0:
                            # Save results
                            with open(f"{self.config.output_dir}/dom_security/domscan_{port}.txt", 'w') as f:
                                f.write(stdout.decode())
                            
                            dom_results["scanned_urls"].append(url)
                            
                            # Parse for vulnerabilities (basic implementation)
                            if "XSS" in stdout.decode():
                                dom_results["xss_vulnerabilities"].append(url)
                            if "redirect" in stdout.decode().lower():
                                dom_results["open_redirects"].append(url)
                    
                    except Exception as e:
                        logging.warning(f"DOM scan failed for {url}: {e}")
                    
                    progress.update(task, completed=100)
        
        except Exception as e:
            logging.error(f"DOM scanning failed: {e}")
        
        self.results = dom_results
        return dom_results

class VulnerabilityScanner(Scanner):
    """Enhanced vulnerability scanning and analysis"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform vulnerability scanning"""
        self.console.print("[cyan]🔍 Starting vulnerability analysis...[/cyan]")
        
        vuln_results = {
            "nmap_vulns": [],
            "ssl_issues": [],
            "web_vulns": [],
            "open_services": [],
            "security_recommendations": []
        }
        
        try:
            # Create output directory
            os.makedirs(f"{self.config.output_dir}/vulnerabilities", exist_ok=True)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                task = progress.add_task("Running vulnerability scans...", total=100)
                
                # Nmap vulnerability scripts
                cmd = [
                    "nmap", "--script", "vuln,safe",
                    "-sV", self.config.target,
                    "-oN", f"{self.config.output_dir}/vulnerabilities/nmap_vulns.txt"
                ]
                
                result = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await result.communicate()
                progress.update(task, advance=60)
                
                if result.returncode == 0:
                    # Parse vulnerability output
                    vuln_output = stdout.decode()
                    
                    # Basic vulnerability parsing
                    if "VULNERABLE" in vuln_output:
                        vuln_lines = [line.strip() for line in vuln_output.split('\n') if 'VULNERABLE' in line]
                        vuln_results["nmap_vulns"] = vuln_lines[:10]  # Limit to first 10
                        self.console.print(f"[red]⚠️  Found {len(vuln_lines)} potential vulnerabilities[/red]")
                    else:
                        self.console.print("[green]✓ No obvious vulnerabilities detected[/green]")
                
                progress.update(task, advance=40)
        
        except Exception as e:
            logging.error(f"Vulnerability scanning failed: {e}")
            vuln_results["error"] = str(e)
        
        # Add security recommendations
        vuln_results["security_recommendations"] = [
            "Review open services and close unnecessary ones",
            "Ensure all services are updated to latest versions",
            "Implement proper firewall rules",
            "Use strong SSL/TLS configurations",
            "Regular security updates and patches"
        ]
        
        self.results = vuln_results
        return vuln_results

class SSLScanner(Scanner):

    """SSL/TLS security analysis"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform SSL/TLS analysis"""
        self.console.print("[cyan]🔍 Starting SSL/TLS analysis...[/cyan]")
        
        ssl_results = {
            "certificates": {},
            "vulnerabilities": [],
            "cipher_suites": {},
            "protocols": {}
        }
        
        try:
            # SSL ports to check
            ssl_ports = [443, 8443, 993, 995, 465]
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                for port in ssl_ports:
                    task = progress.add_task(f"SSL analysis on port {port}...", total=100)
                    
                    try:
                        # Check if port is open with a simple connection test
                        cmd = [
                            "nmap", "--script", "ssl-cert,ssl-enum-ciphers",
                            "-p", str(port), self.config.target
                        ]
                        
                        result = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        
                        stdout, stderr = await result.communicate()
                        
                        if result.returncode == 0 and "open" in stdout.decode():
                            ssl_results["certificates"][port] = stdout.decode()
                        
                    except Exception as e:
                        logging.warning(f"SSL scan failed for port {port}: {e}")
                    
                    progress.update(task, completed=100)
        
        except Exception as e:
            logging.error(f"SSL scanning failed: {e}")
        
        self.results = ssl_results
        return ssl_results

class BCAR:
    """Main BCAR application with Rich TUI interface"""
    
    def __init__(self):
        self.console = Console()
        self.config = BCARConfig()
        self.scanners = {
            "DNS": DNSScanner,
            "WHOIS": WhoisScanner,
            "Ports": PortScanner,
            "Web": WebScanner,
            "DOM": DOMScanner,
            "Vulnerabilities": VulnerabilityScanner,
            "SSL": SSLScanner
        }
        self.scan_results: Dict[str, Any] = {}
        
        # Load configuration
        self.config.load_from_file()
        
        # Set up wordlist
        self._setup_wordlist()
        
    def _setup_wordlist(self):
        """Setup default wordlist paths"""
        wordlist_paths = [
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirb/common.txt"
        ]
        
        for path in wordlist_paths:
            if os.path.exists(path):
                self.config.wordlist = path
                break
        
        if not self.config.wordlist:
            self.console.print("[yellow]⚠️  No wordlist found, web directory enumeration will be limited[/yellow]")
    
    def print_banner(self):
        """Display the BCAR banner"""
        banner = r"""        __________.__      _____          __   _________ ________ .__  .__   
\______   \  |    /  |  |   ____ |  | _\_   ___ \_____  \|  | |  |  
 |    |  _/  |   /   |  |__/ ___\|  |/ /    \  \/  _(__  <|  | |  |  
 |    |   \  |__/    ^   /\  \___|    <\     \____/       \  |_|  |__
 |______  /____/\____   |  \___  >__|_ \\______  /______  /____/____/
        \/           |__|      \/     \/       \/       \/           
   _____          __        __________                               
  /  _  \  __ ___/  |_  ____\______   \ ____   ____  ____   ____     
 /  /_\  \|  |  \   __\/  _ \|       _// __ \_/ ___\/  _ \ /    \    
/    |    \  |  /|  | (  <_> )    |   \  ___/\  \__(  <_> )   |  \   
\____|__  /____/ |__|  \____/|____|_  /\___  >\___  >____/|___|  /   
        \/                          \/     \/     \/           \/"""
        
        self.console.print(Panel(
            f"[red]{banner}[/red]\n[white bold]BlackCell Auto Recon v2.0.0[/white bold]\n[cyan]Advanced Python Reconnaissance Framework[/cyan]",
            box=box.DOUBLE,
            title="[yellow]BCAR[/yellow]",
            title_align="center"
        ))
    
    def show_main_menu(self):
        """Display the main menu"""
        self.console.clear()
        self.print_banner()
        
        # Current configuration table
        config_table = Table(title="Current Configuration", box=box.ROUNDED)
        config_table.add_column("Setting", style="cyan")
        config_table.add_column("Value", style="yellow")
        
        config_table.add_row("Target", self.config.target or "Not set")
        config_table.add_row("Output Directory", self.config.output_dir)
        config_table.add_row("Threads", str(self.config.threads))
        config_table.add_row("Timing", self.config.timing)
        config_table.add_row("Stealth Mode", "Enabled" if self.config.stealth_mode else "Disabled")
        config_table.add_row("DOM Scanning", "Enabled" if self.config.dom_scan_enabled else "Disabled")
        config_table.add_row("Output Format", self.config.output_format)
        
        self.console.print(config_table)
        self.console.print()
        
        # Menu options
        menu_table = Table(box=box.SIMPLE)
        menu_table.add_column("Option", style="green bold", width=8)
        menu_table.add_column("Description", style="white")
        
        menu_table.add_row("1", "Set Target (IP/Domain)")
        menu_table.add_row("2", "Configure Scan Options")
        menu_table.add_row("3", "Start Reconnaissance Scan")
        menu_table.add_row("4", "View Previous Results")
        menu_table.add_row("5", "Reset Configuration")
        menu_table.add_row("6", "Help & Documentation")
        menu_table.add_row("0", "[red]Exit[/red]")
        
        self.console.print(Panel(menu_table, title="[white bold]Main Menu[/white bold]", box=box.ROUNDED))
    
    def set_target(self):
        """Interactive target configuration"""
        self.console.print("\n[cyan]═══ Target Configuration ═══[/cyan]")
        self.console.print("[yellow]Enter target IP address or domain name:[/yellow]")
        self.console.print("[dim]Examples: 192.168.1.100, example.com, subdomain.target.org[/dim]\n")
        
        target = Prompt.ask("[white]Target[/white]")
        
        if target:
            scanner = Scanner(self.config, self.console)
            if scanner.validate_target(target):
                self.config.target = target
                self.console.print(f"[green]✓ Target set to: {target}[/green]")
            else:
                self.console.print("[red]✗ Invalid target format[/red]")
        else:
            self.console.print("[yellow]No target entered[/yellow]")
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    def configure_options(self):
        """Interactive options configuration"""
        while True:
            self.console.clear()
            self.console.print("[cyan]═══ Scan Options Configuration ═══[/cyan]\n")
            
            options_table = Table(box=box.ROUNDED)
            options_table.add_column("Option", style="green bold", width=8)
            options_table.add_column("Setting", style="white", width=25)
            options_table.add_column("Current Value", style="yellow")
            
            options_table.add_row("1", "Threads", str(self.config.threads))
            options_table.add_row("2", "Timing Mode", self.config.timing)
            options_table.add_row("3", "Stealth Mode", "Enabled" if self.config.stealth_mode else "Disabled")
            options_table.add_row("4", "Output Format", self.config.output_format)
            options_table.add_row("5", "DOM Scanning", "Enabled" if self.config.dom_scan_enabled else "Disabled")
            options_table.add_row("6", "DOM Mode", "Headless" if self.config.dom_headless else "GUI")
            options_table.add_row("7", "Output Directory", self.config.output_dir)
            options_table.add_row("8", "Nmap Scripts", self.config.nmap_scripts)
            options_table.add_row("9", "Wordlist", self.config.wordlist or "Default")
            options_table.add_row("0", "[red]Back to Main Menu[/red]", "")
            
            self.console.print(options_table)
            
            choice = Prompt.ask("\n[white]Select option to configure[/white]", choices=["0","1","2","3","4","5","6","7","8","9"])
            
            if choice == "0":
                break
            elif choice == "1":
                threads = IntPrompt.ask("Number of threads", default=self.config.threads, show_default=True)
                if 1 <= threads <= 1000:
                    self.config.threads = threads
                    self.console.print(f"[green]✓ Threads set to: {threads}[/green]")
                else:
                    self.console.print("[red]✗ Invalid thread count (1-1000)[/red]")
            elif choice == "2":
                timing = Prompt.ask("Timing mode", choices=["slow", "normal", "fast"], default=self.config.timing)
                self.config.timing = timing
                self.console.print(f"[green]✓ Timing set to: {timing}[/green]")
            elif choice == "3":
                self.config.stealth_mode = Confirm.ask("Enable stealth mode?", default=self.config.stealth_mode)
                self.console.print(f"[green]✓ Stealth mode: {'Enabled' if self.config.stealth_mode else 'Disabled'}[/green]")
            elif choice == "4":
                format_choice = Prompt.ask("Output format", choices=["txt", "json", "both"], default=self.config.output_format)
                self.config.output_format = format_choice
                self.console.print(f"[green]✓ Output format set to: {format_choice}[/green]")
            elif choice == "5":
                self.config.dom_scan_enabled = Confirm.ask("Enable DOM scanning?", default=self.config.dom_scan_enabled)
                self.console.print(f"[green]✓ DOM scanning: {'Enabled' if self.config.dom_scan_enabled else 'Disabled'}[/green]")
            elif choice == "6":
                self.config.dom_headless = Confirm.ask("Use headless mode for DOM scanning?", default=self.config.dom_headless)
                self.console.print(f"[green]✓ DOM mode: {'Headless' if self.config.dom_headless else 'GUI'}[/green]")
            elif choice == "7":
                output_dir = Prompt.ask("Output directory", default=self.config.output_dir)
                self.config.output_dir = output_dir
                self.console.print(f"[green]✓ Output directory set to: {output_dir}[/green]")
            elif choice == "8":
                scripts = Prompt.ask("Nmap scripts", default=self.config.nmap_scripts)
                self.config.nmap_scripts = scripts
                self.console.print(f"[green]✓ Nmap scripts set to: {scripts}[/green]")
            elif choice == "9":
                wordlist = Prompt.ask("Wordlist path", default=self.config.wordlist or "")
                if wordlist and os.path.exists(wordlist):
                    self.config.wordlist = wordlist
                    self.console.print(f"[green]✓ Wordlist set to: {wordlist}[/green]")
                elif wordlist:
                    self.console.print("[red]✗ Wordlist file not found[/red]")
            
            if choice != "0":
                Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    async def start_scan(self):
        """Start the reconnaissance scan"""
        if not self.config.target:
            self.console.print("[red]✗ No target configured! Please set a target first.[/red]")
            Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
            return
        
        self.console.clear()
        self.console.print("[cyan]═══ Scan Summary ═══[/cyan]\n")
        
        summary_table = Table(box=box.ROUNDED)
        summary_table.add_column("Setting", style="white")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Target", self.config.target)
        summary_table.add_row("Output Directory", self.config.output_dir)
        summary_table.add_row("Threads", str(self.config.threads))
        summary_table.add_row("Timing", self.config.timing)
        summary_table.add_row("Stealth Mode", "Yes" if self.config.stealth_mode else "No")
        
        self.console.print(summary_table)
        
        if not Confirm.ask("\n[yellow]Start reconnaissance scan?[/yellow]"):
            return
        
        # Create output directory
        os.makedirs(self.config.output_dir, exist_ok=True)
        
        # Initialize results
        self.scan_results = {
            "target": self.config.target,
            "start_time": datetime.now().isoformat(),
            "config": self.config.__dict__.copy(),
            "results": {}
        }
        
        # Run scanners
        selected_scanners = ["DNS", "WHOIS", "Ports", "Web"]
        if self.config.dom_scan_enabled:
            selected_scanners.append("DOM")
        selected_scanners.extend(["Vulnerabilities", "SSL"])
        
        self.console.print(f"\n[green]🚀 Starting scan against {self.config.target}...[/green]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            
            main_task = progress.add_task("Overall Progress", total=len(selected_scanners))
            
            for scanner_name in selected_scanners:
                scanner_class = self.scanners[scanner_name]
                scanner = scanner_class(self.config, self.console)
                
                try:
                    results = await scanner.run()
                    self.scan_results["results"][scanner_name.lower()] = results
                    progress.update(main_task, advance=1, description=f"Completed {scanner_name} scan")
                    
                except Exception as e:
                    logging.error(f"{scanner_name} scan failed: {e}")
                    self.scan_results["results"][scanner_name.lower()] = {"error": str(e)}
                    progress.update(main_task, advance=1, description=f"{scanner_name} scan failed")
        
        # Complete scan
        self.scan_results["end_time"] = datetime.now().isoformat()
        
        # Save results
        await self._save_results()
        
        # Display summary
        self._display_scan_summary()
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    async def _save_results(self):
        """Save scan results to files"""
        try:
            # Save JSON results
            json_file = f"{self.config.output_dir}/bcar_results.json"
            with open(json_file, 'w') as f:
                json.dump(self.scan_results, f, indent=2, default=str)
            
            # Save configuration
            config_file = f"{self.config.output_dir}/bcar_config.json"
            self.config.save_to_file(config_file)
            
            # Generate text summary
            summary_file = f"{self.config.output_dir}/bcar_summary.txt"
            with open(summary_file, 'w') as f:
                f.write(f"BCAR Scan Results\n")
                f.write(f"================\n\n")
                f.write(f"Target: {self.config.target}\n")
                f.write(f"Start Time: {self.scan_results['start_time']}\n")
                f.write(f"End Time: {self.scan_results['end_time']}\n")
                f.write(f"Output Directory: {self.config.output_dir}\n\n")
                
                for scanner_name, results in self.scan_results["results"].items():
                    f.write(f"{scanner_name.upper()} Results:\n")
                    f.write(f"{'='*20}\n")
                    if "error" in results:
                        f.write(f"Error: {results['error']}\n")
                    else:
                        f.write(f"{json.dumps(results, indent=2)}\n")
                    f.write("\n")
            
            self.console.print(f"[green]✓ Results saved to: {self.config.output_dir}[/green]")
            
        except Exception as e:
            logging.error(f"Failed to save results: {e}")
            self.console.print(f"[red]✗ Failed to save results: {e}[/red]")
    
    def _analyze_scan_results(self) -> Dict[str, Any]:
        """Analyze scan results and provide security insights"""
        analysis = {
            "risk_level": "low",
            "open_ports_count": 0,
            "web_services_count": 0,
            "vulnerabilities_found": 0,
            "security_recommendations": [],
            "critical_findings": []
        }
        
        try:
            # Analyze port scan results
            if "ports" in self.scan_results["results"]:
                ports_data = self.scan_results["results"]["ports"]
                open_ports = ports_data.get("open_ports", [])
                analysis["open_ports_count"] = len(open_ports)
                
                # Check for high-risk ports
                high_risk_ports = [21, 22, 23, 25, 53, 135, 139, 445, 1433, 3389]
                risky_open = [port for port in open_ports if port in high_risk_ports]
                
                if risky_open:
                    analysis["critical_findings"].append(f"High-risk ports open: {risky_open}")
                    analysis["security_recommendations"].append("Review and secure high-risk open ports")
                    analysis["risk_level"] = "high" if len(risky_open) > 3 else "medium"
            
            # Analyze web services
            if "web" in self.scan_results["results"]:
                web_data = self.scan_results["results"]["web"]
                web_services = web_data.get("http_services", [])
                analysis["web_services_count"] = len(web_services)
                
                if web_services:
                    analysis["security_recommendations"].append("Implement web application security measures")
            
            # Analyze DNS for zone transfer vulnerabilities
            if "dns" in self.scan_results["results"]:
                dns_data = self.scan_results["results"]["dns"]
                if dns_data.get("zone_transfer", False):
                    analysis["critical_findings"].append("DNS Zone Transfer possible - High Risk!")
                    analysis["security_recommendations"].append("Disable DNS zone transfers for unauthorized hosts")
                    analysis["risk_level"] = "high"
            
            # Analyze DOM security findings
            if "dom" in self.scan_results["results"]:
                dom_data = self.scan_results["results"]["dom"]
                xss_count = len(dom_data.get("xss_vulnerabilities", []))
                redirect_count = len(dom_data.get("open_redirects", []))
                
                if xss_count > 0:
                    analysis["critical_findings"].append(f"XSS vulnerabilities found: {xss_count}")
                    analysis["security_recommendations"].append("Implement XSS protection and input validation")
                    analysis["risk_level"] = "high"
                
                if redirect_count > 0:
                    analysis["critical_findings"].append(f"Open redirects found: {redirect_count}")
                    analysis["security_recommendations"].append("Validate redirect URLs to prevent abuse")
            
            # Analyze vulnerability scan results
            if "vulnerabilities" in self.scan_results["results"]:
                vuln_data = self.scan_results["results"]["vulnerabilities"]
                nmap_vulns = vuln_data.get("nmap_vulns", [])
                analysis["vulnerabilities_found"] = len(nmap_vulns)
                
                if nmap_vulns:
                    analysis["critical_findings"].extend(nmap_vulns[:5])  # Top 5
                    analysis["security_recommendations"].append("Address identified vulnerabilities immediately")
                    analysis["risk_level"] = "high"
            
            # Add general recommendations
            if analysis["risk_level"] == "low":
                analysis["security_recommendations"].extend([
                    "Maintain regular security updates",
                    "Implement monitoring and logging",
                    "Regular security assessments"
                ])
        
        except Exception as e:
            logging.error(f"Result analysis failed: {e}")
        
        return analysis
    
    def _display_scan_summary(self):
        """Display scan results summary"""
        self.console.clear()
        self.console.print("[green]═══ Scan Completed Successfully ═══[/green]\n")
        
        # Results summary table
        results_table = Table(title="Scan Results Summary", box=box.ROUNDED)
        results_table.add_column("Scanner", style="cyan")
        results_table.add_column("Status", style="white")
        results_table.add_column("Key Findings", style="yellow")
        
        for scanner_name, results in self.scan_results["results"].items():
            if "error" in results:
                status = "[red]Failed[/red]"
                findings = f"Error: {results['error']}"
            else:
                status = "[green]Completed[/green]"
                # Generate summary based on scanner type
                if scanner_name == "dns":
                    findings = f"Records: {len(results.get('records', {}))}"
                    if results.get('zone_transfer', False):
                        findings += " ⚠️ Zone transfer possible!"
                elif scanner_name == "whois":
                    findings = "Domain info retrieved" if results.get('raw_output') else "No data"
                elif scanner_name == "ports":
                    findings = f"Open ports: {len(results.get('open_ports', []))}"
                elif scanner_name == "web":
                    findings = f"HTTP services: {len(results.get('http_services', []))}"
                elif scanner_name == "dom":
                    xss_count = len(results.get('xss_vulnerabilities', []))
                    redirect_count = len(results.get('open_redirects', []))
                    findings = f"XSS: {xss_count}, Redirects: {redirect_count}"
                elif scanner_name == "vulnerabilities":
                    vuln_count = len(results.get('nmap_vulns', []))
                    findings = f"Vulnerabilities: {vuln_count}"
                elif scanner_name == "ssl":
                    findings = f"SSL services: {len(results.get('certificates', {}))}"
                else:
                    findings = "Completed"
            
            results_table.add_row(scanner_name.upper(), status, findings)
        
        self.console.print(results_table)
        
        # Security Analysis
        analysis = self._analyze_scan_results()
        
        # Risk Assessment Panel
        risk_color = {
            "low": "green",
            "medium": "yellow", 
            "high": "red"
        }
        
        risk_panel = Panel(
            f"[{risk_color[analysis['risk_level']]}]Risk Level: {analysis['risk_level'].upper()}[/{risk_color[analysis['risk_level']]}]\n"
            f"Open Ports: {analysis['open_ports_count']}\n"
            f"Web Services: {analysis['web_services_count']}\n"
            f"Vulnerabilities: {analysis['vulnerabilities_found']}",
            title="[bold red]Security Assessment[/bold red]",
            box=box.HEAVY
        )
        
        self.console.print("\n")
        self.console.print(risk_panel)
        
        # Critical Findings
        if analysis["critical_findings"]:
            self.console.print("\n[red bold]🚨 Critical Findings:[/red bold]")
            for finding in analysis["critical_findings"][:5]:  # Show top 5
                self.console.print(f"  [red]•[/red] {finding}")
        
        # Security Recommendations
        if analysis["security_recommendations"]:
            self.console.print("\n[yellow bold]💡 Security Recommendations:[/yellow bold]")
            for i, rec in enumerate(analysis["security_recommendations"][:5], 1):  # Show top 5
                self.console.print(f"  [yellow]{i}.[/yellow] {rec}")
        
        # Scan Performance Metrics
        if "scan_phases" in self.scan_results:
            self.console.print("\n[cyan bold]⏱️ Scan Performance:[/cyan bold]")
            perf_table = Table(box=box.SIMPLE)
            perf_table.add_column("Phase", style="cyan")
            perf_table.add_column("Duration", style="white")
            perf_table.add_column("Status", style="white")
            
            for phase, data in self.scan_results["scan_phases"].items():
                duration = f"{data.get('duration_seconds', 0):.1f}s"
                status = "[green]✓[/green]" if data.get('status') == 'completed' else "[red]✗[/red]"
                perf_table.add_row(phase, duration, status)
            
            self.console.print(perf_table)
        
        # Output location
        self.console.print(f"\n[cyan]📁 Results saved to:[/cyan] [yellow]{self.config.output_dir}[/yellow]")
        
        # Key files generated
        files_table = Table(title="Generated Files", box=box.SIMPLE)
        files_table.add_column("File", style="white")
        files_table.add_column("Description", style="dim")
        
        files_table.add_row("bcar_results.json", "Complete scan results in JSON format")
        files_table.add_row("bcar_summary.txt", "Human-readable summary report")
        files_table.add_row("bcar_config.json", "Scan configuration used")
        files_table.add_row("nmap/", "Nmap scan results and XML files")
        files_table.add_row("web/", "Web application scan results")
        if self.config.dom_scan_enabled:
            files_table.add_row("dom_security/", "DOM security scan results")
        
        self.console.print(files_table)
    
    def view_results(self):
        """View previous scan results"""
        self.console.print("[cyan]═══ Previous Scan Results ═══[/cyan]\n")
        
        # Find result directories
        result_dirs = [d for d in os.listdir('.') if d.startswith('bcar_results_')]
        
        if not result_dirs:
            self.console.print("[yellow]No previous scan results found[/yellow]")
            Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
            return
        
        # Display available results
        results_table = Table(box=box.ROUNDED)
        results_table.add_column("Index", style="green")
        results_table.add_column("Directory", style="yellow")
        results_table.add_column("Date", style="white")
        
        for i, result_dir in enumerate(sorted(result_dirs, reverse=True), 1):
            # Extract date from directory name
            try:
                date_part = result_dir.replace('bcar_results_', '')
                formatted_date = datetime.strptime(date_part, '%Y%m%d_%H%M%S').strftime('%Y-%m-%d %H:%M:%S')
            except:
                formatted_date = "Unknown"
            
            results_table.add_row(str(i), result_dir, formatted_date)
        
        self.console.print(results_table)
        
        try:
            choice = IntPrompt.ask(f"\nSelect result to view (1-{len(result_dirs)})", default=1)
            if 1 <= choice <= len(result_dirs):
                selected_dir = sorted(result_dirs, reverse=True)[choice - 1]
                self._display_result_details(selected_dir)
        except (ValueError, KeyboardInterrupt):
            pass
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    def _display_result_details(self, result_dir: str):
        """Display details of a specific scan result"""
        json_file = os.path.join(result_dir, "bcar_results.json")
        
        if not os.path.exists(json_file):
            self.console.print(f"[red]Results file not found: {json_file}[/red]")
            return
        
        try:
            with open(json_file, 'r') as f:
                results = json.load(f)
            
            self.console.clear()
            self.console.print(f"[cyan]═══ Scan Results: {result_dir} ═══[/cyan]\n")
            
            # Basic info
            info_table = Table(box=box.ROUNDED)
            info_table.add_column("Property", style="white")
            info_table.add_column("Value", style="yellow")
            
            info_table.add_row("Target", results.get("target", "Unknown"))
            info_table.add_row("Start Time", results.get("start_time", "Unknown"))
            info_table.add_row("End Time", results.get("end_time", "Unknown"))
            
            self.console.print(info_table)
            
            # Results tree view
            tree = Tree(f"[bold cyan]Scan Results[/bold cyan]")
            
            for scanner_name, scanner_results in results.get("results", {}).items():
                scanner_branch = tree.add(f"[green]{scanner_name.upper()}[/green]")
                
                if "error" in scanner_results:
                    scanner_branch.add(f"[red]Error: {scanner_results['error']}[/red]")
                else:
                    for key, value in scanner_results.items():
                        if isinstance(value, list):
                            scanner_branch.add(f"{key}: {len(value)} items")
                        elif isinstance(value, dict):
                            scanner_branch.add(f"{key}: {len(value)} entries")
                        else:
                            scanner_branch.add(f"{key}: {value}")
            
            self.console.print(tree)
            
        except Exception as e:
            self.console.print(f"[red]Error reading results: {e}[/red]")
    
    def reset_config(self):
        """Reset configuration to defaults"""
        if Confirm.ask("[yellow]Reset all configuration to defaults?[/yellow]"):
            self.config.reset_to_defaults()
            self.console.print("[green]✓ Configuration reset to defaults[/green]")
        else:
            self.console.print("[yellow]Reset cancelled[/yellow]")
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    def show_help(self):
        """Display help and documentation"""
        self.console.clear()
        self.console.print("[cyan]═══ BCAR Help & Documentation ═══[/cyan]\n")
        
        help_sections = [
            {
                "title": "About BCAR",
                "content": """BCAR (BlackCell Auto Recon) is a comprehensive automated reconnaissance tool 
designed for security assessments and penetration testing. It performs multiple 
types of scans including DNS enumeration, port scanning, web application testing, 
DOM security analysis, and SSL/TLS assessment."""
            },
            {
                "title": "Scan Types",
                "content": """• DNS Enumeration - Discovers DNS records and tests zone transfers
• Port Scanning - Identifies open ports and running services  
• Web Application - Tests web services and enumerates directories
• DOM Security - Scans for XSS and open redirect vulnerabilities
• SSL/TLS Analysis - Assesses encryption implementations"""
            },
            {
                "title": "Configuration Options",
                "content": """• Threads: Control concurrent operations (1-1000)
• Timing: Adjust scan speed (slow/normal/fast)
• Stealth Mode: Reduce scan noise and detection
• Output Format: Choose result formats (txt/json/both)
• DOM Scanning: Enable/disable DOM security tests
• Custom Wordlists: Specify wordlist for directory enumeration"""
            },
            {
                "title": "Output Files",
                "content": """Results are saved in timestamped directories:
• bcar_results.json - Complete scan data
• bcar_summary.txt - Human-readable report  
• nmap/ - Network scan results
• web/ - Web application scan data
• dom_security/ - DOM vulnerability findings"""
            }
        ]
        
        for section in help_sections:
            panel = Panel(
                section["content"],
                title=f"[white bold]{section['title']}[/white bold]",
                box=box.ROUNDED,
                padding=(1, 2)
            )
            self.console.print(panel)
            self.console.print()
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    async def run(self):
        """Main application loop"""
        try:
            while True:
                self.show_main_menu()
                
                choice = Prompt.ask(
                    "\n[white]Enter your choice[/white]",
                    choices=["0", "1", "2", "3", "4", "5", "6"],
                    default="0"
                )
                
                if choice == "0":
                    self.console.print("\n[cyan]Thank you for using BCAR![/cyan]")
                    # Save configuration before exit
                    self.config.save_to_file()
                    break
                elif choice == "1":
                    self.set_target()
                elif choice == "2":
                    self.configure_options()
                elif choice == "3":
                    await self.start_scan()
                elif choice == "4":
                    self.view_results()
                elif choice == "5":
                    self.reset_config()
                elif choice == "6":
                    self.show_help()
        
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Interrupted by user[/yellow]")
        except Exception as e:
            self.console.print(f"\n[red]Unexpected error: {e}[/red]")
            logging.error(f"Unexpected error in main loop: {e}")

async def install_missing_dependencies(missing_tools: List[str]) -> bool:
    """Attempt to install missing dependencies automatically"""
    console = Console()
    
    if not missing_tools:
        return True
        
    console.print(f"[yellow]🔧 Attempting to install missing tools: {', '.join(missing_tools)}[/yellow]")
    
    # Detect package manager and create appropriate install commands
    package_managers = [
        ("/usr/bin/apt", "apt", ["sudo", "apt", "update", "&&", "sudo", "apt", "install", "-y"]),
        ("/usr/bin/yum", "yum", ["sudo", "yum", "install", "-y"]),
        ("/usr/bin/dnf", "dnf", ["sudo", "dnf", "install", "-y"]),
        ("/usr/bin/pacman", "pacman", ["sudo", "pacman", "-S", "--noconfirm"]),
        ("/opt/homebrew/bin/brew", "brew", ["brew", "install"]),
        ("/usr/local/bin/brew", "brew", ["brew", "install"])
    ]
    
    package_mapping = {
        "dig": {"apt": "dnsutils", "yum": "bind-utils", "dnf": "bind-utils", "pacman": "dnsutils", "brew": "bind"},
        "nmap": {"all": "nmap"},
        "whois": {"all": "whois"},
        "gobuster": {"all": "gobuster"},
        "nikto": {"all": "nikto"},
        "whatweb": {"all": "whatweb"},
        "curl": {"all": "curl"}
    }
    
    for pm_path, pm_name, base_cmd in package_managers:
        if os.path.exists(pm_path):
            console.print(f"[cyan]📦 Found {pm_name} package manager[/cyan]")
            
            success_count = 0
            for tool in missing_tools:
                try:
                    # Get package name for this tool and package manager
                    pkg_name = package_mapping.get(tool, {}).get(pm_name) or package_mapping.get(tool, {}).get("all") or tool
                    
                    if pm_name == "apt" and tool == "dig":
                        # Special case: update first for apt
                        await asyncio.create_subprocess_exec("sudo", "apt", "update", "-qq")
                    
                    # Build install command
                    cmd = base_cmd + [pkg_name]
                    
                    console.print(f"[dim]Installing {pkg_name}...[/dim]")
                    result = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    await result.communicate()
                    
                    if result.returncode == 0:
                        console.print(f"[green]✓ Installed {pkg_name}[/green]")
                        success_count += 1
                    else:
                        console.print(f"[yellow]⚠️  Failed to install {pkg_name}[/yellow]")
                        
                except Exception as e:
                    console.print(f"[red]✗ Error installing {tool}: {e}[/red]")
            
            return success_count > 0
    
    console.print("[red]❌ No supported package manager found[/red]")
    console.print("[yellow]Please install missing tools manually:[/yellow]")
    for tool in missing_tools:
        console.print(f"   - {tool}")
    
    return False

async def check_dependencies():
    """Check for required dependencies with auto-installation option"""
    console = Console()
    
    required_tools = ["nmap", "dig", "whois"]
    optional_tools = ["gobuster", "nikto", "whatweb", "domscan"]
    
    missing_required = []
    missing_optional = []
    
    # Check required tools
    for tool in required_tools:
        result = await asyncio.create_subprocess_exec(
            "which", tool,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await result.communicate()
        
        if result.returncode != 0:
            missing_required.append(tool)
    
    # Check optional tools
    for tool in optional_tools:
        result = await asyncio.create_subprocess_exec(
            "which", tool,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await result.communicate()
        
        if result.returncode != 0:
            missing_optional.append(tool)
    
    if missing_required:
        console.print(f"[red]✗ Missing required tools: {', '.join(missing_required)}[/red]")
        
        # Attempt automatic installation
        if await install_missing_dependencies(missing_required):
            # Re-check after installation
            still_missing = []
            for tool in missing_required:
                result = await asyncio.create_subprocess_exec(
                    "which", tool,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await result.communicate()
                if result.returncode != 0:
                    still_missing.append(tool)
            
            if still_missing:
                console.print(f"[red]❌ Still missing after installation: {', '.join(still_missing)}[/red]")
                return False
            else:
                console.print("[green]✓ All required dependencies installed successfully[/green]")
        else:
            console.print("[yellow]⚠️  Automatic installation failed. Please install manually.[/yellow]")
            return False
    
    if missing_optional:
        console.print(f"[yellow]⚠️  Missing optional tools: {', '.join(missing_optional)}[/yellow]")
        console.print("[dim]Some features may be limited[/dim]")
        
        # Try to install optional tools but don't fail if it doesn't work
        await install_missing_dependencies(missing_optional)
    
    console.print("[green]✓ Dependencies check completed[/green]")
    return True

async def main():
    """Main entry point"""
    try:
        # Check dependencies
        if not await check_dependencies():
            return 1
        
        # Initialize and run BCAR
        bcar = BCAR()
        await bcar.run()
        
        return 0
        
    except Exception as e:
        console = Console()
        console.print(f"[red]Fatal error: {e}[/red]")
        logging.error(f"Fatal error: {e}")
        return 1

if __name__ == "__main__":
    # Ensure we're using the right event loop
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    exit_code = asyncio.run(main())
    sys.exit(exit_code)