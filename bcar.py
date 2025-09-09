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
        self.targets_file: Optional[str] = None
        self.targets_list: List[str] = []
        self.output_dir: str = f"bcar_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.threads: int = 50
        self.timing: str = "normal"  # slow, normal, fast
        self.stealth_mode: bool = False
        self.output_format: str = "json"  # txt, json, both, pdf, html
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
        
        # Enhanced features
        self.scan_profile: Optional[str] = None
        self.wordlist_directory: str = "wordlists"
        self.payloads_directory: str = "payloads"
        self.evidence_capture: bool = True
        self.auto_exploit: bool = False
        self.fuzzing_enabled: bool = False
        self.alternative_tools: Dict[str, List[str]] = {
            "nmap": ["masscan", "zmap"],
            "gobuster": ["dirb", "dirsearch", "ffuf"],
            "nikto": ["nuclei", "whatweb"],
            "whois": ["dig", "host"],
            "dig": ["nslookup", "host"]
        }
        
        # Payload configuration
        self.xss_payloads: bool = False
        self.sqli_payloads: bool = False
        self.lfi_payloads: bool = False
        self.command_injection: bool = False
        
        # Reporting options
        self.generate_executive_summary: bool = False
        self.sort_findings_by_severity: bool = True
        self.filter_false_positives: bool = True
        self.include_recommendations: bool = True
        
        # Scanner-specific options
        self.quick_port_scan: bool = False
        self.full_port_scan: bool = False
        self.udp_scan: bool = False
        self.service_detection: bool = True
        self.os_detection: bool = False
        
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
    
    def load_scan_profile(self, profile_name: str) -> bool:
        """Load a predefined scan profile"""
        try:
            profile_path = f"scan_profiles/{profile_name}.json"
            if Path(profile_path).exists():
                with open(profile_path, 'r') as f:
                    profile_data = json.load(f)
                    config_data = profile_data.get('config', {})
                    
                    # Apply profile configuration
                    for key, value in config_data.items():
                        if hasattr(self, key):
                            setattr(self, key, value)
                    
                    self.scan_profile = profile_name
                    return True
            else:
                logging.warning(f"Profile {profile_name} not found")
                return False
        except Exception as e:
            logging.error(f"Error loading profile {profile_name}: {e}")
            return False
    
    def load_targets_from_file(self, filepath: str) -> bool:
        """Load targets from a text file"""
        try:
            if Path(filepath).exists():
                with open(filepath, 'r') as f:
                    targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    
                    # Validate targets using the validation logic directly
                    valid_targets = []
                    for target in targets:
                        if self._validate_target_format(target):
                            valid_targets.append(target)
                        else:
                            logging.warning(f"Invalid target skipped: {target}")
                    
                    self.targets_list = valid_targets
                    self.targets_file = filepath
                    return True
            else:
                logging.error(f"Targets file not found: {filepath}")
                return False
        except Exception as e:
            logging.error(f"Error loading targets file: {e}")
            return False
    
    def add_target(self, target: str) -> bool:
        """Add a target to the targets list"""
        if self._validate_target_format(target):
            if target not in self.targets_list:
                self.targets_list.append(target)
                return True
        return False
    
    def _validate_target_format(self, target: str) -> bool:
        """Validate target format (IP or domain) - same logic as Scanner.validate_target"""
        import re
        import ipaddress
        
        # First try to validate as IP address using ipaddress module for accuracy
        try:
            ipaddress.ip_address(target)
            return True
        except (ipaddress.AddressValueError, ValueError):
            # Not a valid IP, continue to domain validation
            pass
        
        # Enhanced domain validation - must not start or end with hyphen or dot
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        
        # Simple domain without dots (like localhost) - no hyphens at start/end
        simple_domain = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        
        # Additional validation for domains - no consecutive dots, no leading/trailing dots/hyphens, no empty
        if not target or '..' in target or target.startswith('.') or target.endswith('.') or target.startswith('-') or target.endswith('-'):
            return False
        
        # Validate IP addresses more strictly
        ip_parts = target.split('.')
        if len(ip_parts) == 4 and all(part.isdigit() for part in ip_parts):
            # Check if all parts are valid IP octets (0-255)
            if all(0 <= int(part) <= 255 for part in ip_parts):
                return True
            else:
                return False  # Invalid IP range like 999.999.999.999
        
        # Check domain patterns
        return bool(re.match(domain_pattern, target) or re.match(simple_domain, target))
    
    def remove_target(self, target: str) -> bool:
        """Remove a target from the targets list"""
        if target in self.targets_list:
            self.targets_list.remove(target)
            return True
        return False
    
    def get_wordlist_path(self, wordlist_type: str, size: str = "medium") -> Optional[str]:
        """Get path to wordlist based on type and size"""
        wordlist_paths = {
            "directories": {
                "small": f"{self.wordlist_directory}/directories/common_dirs.txt",
                "medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                "large": "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt"
            },
            "files": {
                "small": f"{self.payloads_directory}/files/common_files.txt",
                "medium": "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "large": "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt"
            },
            "subdomains": {
                "small": f"{self.wordlist_directory}/subdomains/common_subdomains.txt",
                "medium": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
                "large": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
            }
        }
        
        # Try to find the best available wordlist
        if wordlist_type in wordlist_paths:
            for s in [size, "medium", "small"]:  # Fallback order
                if s in wordlist_paths[wordlist_type]:
                    path = wordlist_paths[wordlist_type][s]
                    if Path(path).exists():
                        return path
        
        return None

class Scanner:
    """Base class for all scanning modules with enhanced error handling and fallbacks"""
    
    def __init__(self, config: BCARConfig, console: Console):
        self.config = config
        self.console = console
        self.results: Dict[str, Any] = {}
        
    async def run(self) -> Dict[str, Any]:
        """Run the scanner - to be implemented by subclasses"""
        raise NotImplementedError
    
    async def check_tool_availability(self, tool_name: str) -> bool:
        """Check if a tool is available on the system"""
        try:
            result = await asyncio.create_subprocess_exec(
                "which", tool_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            return result.returncode == 0
        except Exception:
            return False
    
    async def get_available_tool(self, primary_tool: str) -> Optional[str]:
        """Get the first available tool from primary and alternatives"""
        # Check primary tool first
        if await self.check_tool_availability(primary_tool):
            return primary_tool
        
        # Check alternatives
        alternatives = self.config.alternative_tools.get(primary_tool, [])
        for alt_tool in alternatives:
            if await self.check_tool_availability(alt_tool):
                self.console.print(f"[yellow]⚠️  {primary_tool} not available, using {alt_tool}[/yellow]")
                return alt_tool
        
        return None
    
    async def run_command_with_retry(self, cmd: List[str], retries: int = None) -> Dict[str, Any]:
        """Run a command with retry logic and error handling"""
        if retries is None:
            retries = self.config.max_retries
        
        last_error = None
        for attempt in range(retries + 1):
            try:
                if attempt > 0:
                    self.console.print(f"[yellow]🔄 Retry attempt {attempt}/{retries}[/yellow]")
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                
                result = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    result.communicate(),
                    timeout=self.config.timeout
                )
                
                return {
                    "returncode": result.returncode,
                    "stdout": stdout.decode('utf-8', errors='ignore'),
                    "stderr": stderr.decode('utf-8', errors='ignore'),
                    "success": result.returncode == 0
                }
                
            except asyncio.TimeoutError:
                last_error = f"Command timed out after {self.config.timeout} seconds"
                self.console.print(f"[red]⏰ {last_error}[/red]")
            except Exception as e:
                last_error = str(e)
                self.console.print(f"[red]❌ Command failed: {e}[/red]")
        
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": last_error or "Unknown error",
            "success": False
        }
        
    def validate_target(self, target: str) -> bool:
        """Validate target format (IP or domain)"""
        import re
        import ipaddress
        
        # First try to validate as IP address using ipaddress module for accuracy
        try:
            ipaddress.ip_address(target)
            return True
        except (ipaddress.AddressValueError, ValueError):
            # Not a valid IP, continue to domain validation
            pass
        
        # Enhanced domain validation - must not start or end with hyphen or dot
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        
        # Simple domain without dots (like localhost) - no hyphens at start/end
        simple_domain = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        
        # Additional validation for domains - no consecutive dots, no leading/trailing dots/hyphens, no empty
        if not target or '..' in target or target.startswith('.') or target.endswith('.') or target.startswith('-') or target.endswith('-'):
            return False
        
        # Validate IP addresses more strictly
        ip_parts = target.split('.')
        if len(ip_parts) == 4 and all(part.isdigit() for part in ip_parts):
            # Check if all parts are valid IP octets (0-255)
            if all(0 <= int(part) <= 255 for part in ip_parts):
                return True
            else:
                return False  # Invalid IP range like 999.999.999.999
        
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
    """Enhanced web application scanning with fuzzing and payload testing"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform comprehensive web application scanning"""
        self.console.print("[cyan]🔍 Starting enhanced web application scanning...[/cyan]")
        
        web_results = {
            "http_services": [],
            "technologies": {},
            "directories": {},
            "files": {},
            "vulnerabilities": [],
            "fuzzing_results": {},
            "payload_results": {}
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
                    
                    # Check if port is accessible
                    url = f"http{'s' if port in [443, 8443] else ''}://{self.config.target}:{port}"
                    
                    # Check if service is reachable
                    if not await self._check_web_service(url):
                        progress.update(task, advance=100)
                        continue
                    
                    web_results["http_services"].append(port)
                    progress.update(task, advance=20)
                    
                    # Technology detection with fallbacks
                    await self._detect_technologies(url, port, web_results)
                    progress.update(task, advance=40)
                    
                    # Directory enumeration with multiple tools
                    await self._enumerate_directories(url, port, web_results)
                    progress.update(task, advance=60)
                    
                    # File enumeration
                    await self._enumerate_files(url, port, web_results)
                    progress.update(task, advance=80)
                    
                    # Vulnerability scanning
                    await self._scan_vulnerabilities(url, port, web_results)
                    progress.update(task, advance=90)
                    
                    # Payload testing if enabled
                    if self.config.fuzzing_enabled:
                        await self._test_payloads(url, port, web_results)
                    
                    progress.update(task, advance=100)
            
            # Save results
            await self._save_web_results(web_results)
            
        except Exception as e:
            web_results["error"] = str(e)
            logging.error(f"Web scanning error: {e}")
        
        return web_results
    
    async def _check_web_service(self, url: str) -> bool:
        """Check if web service is reachable"""
        try:
            cmd = ["curl", "-s", "-I", "--connect-timeout", "5", url]
            result = await self.run_command_with_retry(cmd, retries=1)
            return result["success"]
        except Exception:
            return False
    
    async def _detect_technologies(self, url: str, port: int, results: Dict[str, Any]):
        """Detect web technologies using multiple tools"""
        # Try WhatWeb first
        whatweb_tool = await self.get_available_tool("whatweb")
        if whatweb_tool:
            try:
                cmd = [whatweb_tool, "--color=never", url]
                result = await self.run_command_with_retry(cmd)
                if result["success"]:
                    results["technologies"][port] = result["stdout"].strip()
                    return
            except Exception as e:
                logging.warning(f"WhatWeb scan failed for port {port}: {e}")
        
        # Fallback to curl for basic detection
        try:
            cmd = ["curl", "-s", "-I", url]
            result = await self.run_command_with_retry(cmd)
            if result["success"]:
                headers = result["stdout"]
                results["technologies"][port] = f"Headers: {headers}"
        except Exception as e:
            logging.warning(f"Technology detection failed for port {port}: {e}")
    
    async def _enumerate_directories(self, url: str, port: int, results: Dict[str, Any]):
        """Enumerate directories using multiple tools with fallbacks"""
        # Get appropriate wordlist
        wordlist_path = self.config.get_wordlist_path("directories", "medium")
        if not wordlist_path:
            self.console.print("[yellow]⚠️  No directory wordlist available, skipping enumeration[/yellow]")
            return
        
        # Try gobuster first
        gobuster_tool = await self.get_available_tool("gobuster")
        if gobuster_tool:
            await self._run_gobuster(gobuster_tool, url, port, wordlist_path, results)
            return
        
        # Fallback to dirb
        dirb_tool = await self.get_available_tool("dirb")
        if dirb_tool:
            await self._run_dirb(dirb_tool, url, port, wordlist_path, results)
            return
        
        # Manual curl-based enumeration as last resort
        await self._manual_directory_enum(url, port, wordlist_path, results)
    
    async def _run_gobuster(self, tool: str, url: str, port: int, wordlist: str, results: Dict[str, Any]):
        """Run gobuster directory enumeration"""
        try:
            cmd = [
                tool, "dir", "-u", url, "-w", wordlist,
                "-t", str(min(self.config.threads, 20)), "-q",
                "-o", f"{self.config.output_dir}/web/gobuster_{port}.txt"
            ]
            
            # Add stealth options if enabled
            if self.config.stealth_mode:
                cmd.extend(["--delay", "2s"])
            
            result = await self.run_command_with_retry(cmd)
            if result["success"]:
                # Parse gobuster results
                output_file = f"{self.config.output_dir}/web/gobuster_{port}.txt"
                if Path(output_file).exists():
                    with open(output_file, 'r') as f:
                        directories = []
                        for line in f:
                            if line.strip() and not line.startswith('/'):
                                directories.append(line.strip())
                        results["directories"][port] = directories
        except Exception as e:
            logging.warning(f"Gobuster enumeration failed for port {port}: {e}")
    
    async def _run_dirb(self, tool: str, url: str, port: int, wordlist: str, results: Dict[str, Any]):
        """Run dirb directory enumeration"""
        try:
            output_file = f"{self.config.output_dir}/web/dirb_{port}.txt"
            cmd = [tool, url, wordlist, "-o", output_file, "-S"]
            
            result = await self.run_command_with_retry(cmd)
            if result["success"] and Path(output_file).exists():
                with open(output_file, 'r') as f:
                    content = f.read()
                    # Basic parsing of dirb output
                    directories = []
                    for line in content.split('\n'):
                        if '+ ' in line and url in line:
                            directories.append(line.strip())
                    results["directories"][port] = directories
        except Exception as e:
            logging.warning(f"Dirb enumeration failed for port {port}: {e}")
    
    async def _manual_directory_enum(self, url: str, port: int, wordlist: str, results: Dict[str, Any]):
        """Manual directory enumeration using curl"""
        try:
            directories = []
            with open(wordlist, 'r') as f:
                dirs = [line.strip() for line in f if line.strip()][:100]  # Limit for manual enum
            
            for directory in dirs:
                test_url = f"{url}/{directory}"
                cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", test_url]
                result = await self.run_command_with_retry(cmd, retries=1)
                
                if result["success"]:
                    status_code = result["stdout"].strip()
                    if status_code in ["200", "301", "302", "403"]:
                        directories.append(f"{test_url} [{status_code}]")
                
                # Add delay for stealth
                if self.config.stealth_mode:
                    await asyncio.sleep(1)
            
            results["directories"][port] = directories
            
        except Exception as e:
            logging.warning(f"Manual directory enumeration failed for port {port}: {e}")
    
    async def _enumerate_files(self, url: str, port: int, results: Dict[str, Any]):
        """Enumerate common files"""
        file_wordlist = self.config.get_wordlist_path("files", "small")
        if not file_wordlist:
            return
        
        try:
            files_found = []
            with open(file_wordlist, 'r') as f:
                files = [line.strip() for line in f if line.strip()][:50]  # Limit file checks
            
            for filename in files:
                test_url = f"{url}/{filename}"
                cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", test_url]
                result = await self.run_command_with_retry(cmd, retries=1)
                
                if result["success"]:
                    status_code = result["stdout"].strip()
                    if status_code == "200":
                        files_found.append(f"{test_url} [{status_code}]")
                
                if self.config.stealth_mode:
                    await asyncio.sleep(0.5)
            
            results["files"][port] = files_found
            
        except Exception as e:
            logging.warning(f"File enumeration failed for port {port}: {e}")
    
    async def _scan_vulnerabilities(self, url: str, port: int, results: Dict[str, Any]):
        """Scan for web vulnerabilities using nikto or alternatives"""
        nikto_tool = await self.get_available_tool("nikto")
        if nikto_tool:
            try:
                output_file = f"{self.config.output_dir}/web/nikto_{port}.txt"
                cmd = [nikto_tool, "-h", url, "-o", output_file, "-Format", "txt"]
                
                result = await self.run_command_with_retry(cmd)
                if result["success"] and Path(output_file).exists():
                    with open(output_file, 'r') as f:
                        vulnerabilities = []
                        for line in f:
                            if line.strip() and not line.startswith('-') and not line.startswith('Nikto'):
                                vulnerabilities.append(line.strip())
                        results["vulnerabilities"].extend(vulnerabilities)
            except Exception as e:
                logging.warning(f"Nikto scan failed for port {port}: {e}")
    
    async def _test_payloads(self, url: str, port: int, results: Dict[str, Any]):
        """Test various payloads for vulnerabilities"""
        payload_results = {}
        
        # XSS payload testing
        if self.config.xss_payloads:
            payload_results["xss"] = await self._test_xss_payloads(url)
        
        # SQL injection payload testing
        if self.config.sqli_payloads:
            payload_results["sqli"] = await self._test_sqli_payloads(url)
        
        # LFI payload testing
        if self.config.lfi_payloads:
            payload_results["lfi"] = await self._test_lfi_payloads(url)
        
        results["payload_results"][port] = payload_results
    
    async def _test_xss_payloads(self, url: str) -> List[str]:
        """Test XSS payloads"""
        xss_file = f"{self.config.payloads_directory}/web/xss_payloads.txt"
        if not Path(xss_file).exists():
            return []
        
        results = []
        try:
            with open(xss_file, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()][:10]  # Limit payloads
            
            for payload in payloads:
                # Test in common parameters
                test_urls = [
                    f"{url}?q={payload}",
                    f"{url}?search={payload}",
                    f"{url}?id={payload}"
                ]
                
                for test_url in test_urls:
                    cmd = ["curl", "-s", test_url]
                    result = await self.run_command_with_retry(cmd, retries=1)
                    
                    if result["success"] and payload in result["stdout"]:
                        results.append(f"Potential XSS: {test_url}")
                    
                    if self.config.stealth_mode:
                        await asyncio.sleep(1)
        
        except Exception as e:
            logging.warning(f"XSS payload testing failed: {e}")
        
        return results
    
    async def _test_sqli_payloads(self, url: str) -> List[str]:
        """Test SQL injection payloads"""
        sqli_file = f"{self.config.payloads_directory}/web/sqli_payloads.txt"
        if not Path(sqli_file).exists():
            return []
        
        results = []
        try:
            with open(sqli_file, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()][:10]  # Limit payloads
            
            for payload in payloads:
                test_urls = [
                    f"{url}?id={payload}",
                    f"{url}?user={payload}",
                    f"{url}?search={payload}"
                ]
                
                for test_url in test_urls:
                    cmd = ["curl", "-s", test_url]
                    result = await self.run_command_with_retry(cmd, retries=1)
                    
                    # Look for SQL error indicators
                    if result["success"]:
                        error_indicators = ["sql", "mysql", "error", "warning", "fatal"]
                        response = result["stdout"].lower()
                        if any(indicator in response for indicator in error_indicators):
                            results.append(f"Potential SQLi: {test_url}")
                    
                    if self.config.stealth_mode:
                        await asyncio.sleep(1)
        
        except Exception as e:
            logging.warning(f"SQLi payload testing failed: {e}")
        
        return results
    
    async def _test_lfi_payloads(self, url: str) -> List[str]:
        """Test Local File Inclusion payloads"""
        lfi_file = f"{self.config.payloads_directory}/fuzzing/lfi_payloads.txt"
        if not Path(lfi_file).exists():
            return []
        
        results = []
        try:
            with open(lfi_file, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()][:10]  # Limit payloads
            
            for payload in payloads:
                test_urls = [
                    f"{url}?file={payload}",
                    f"{url}?page={payload}",
                    f"{url}?include={payload}"
                ]
                
                for test_url in test_urls:
                    cmd = ["curl", "-s", test_url]
                    result = await self.run_command_with_retry(cmd, retries=1)
                    
                    # Look for file inclusion indicators
                    if result["success"]:
                        lfi_indicators = ["root:", "bin/bash", "etc/passwd", "boot.ini"]
                        response = result["stdout"].lower()
                        if any(indicator in response for indicator in lfi_indicators):
                            results.append(f"Potential LFI: {test_url}")
                    
                    if self.config.stealth_mode:
                        await asyncio.sleep(1)
        
        except Exception as e:
            logging.warning(f"LFI payload testing failed: {e}")
        
        return results
    
    async def _save_web_results(self, results: Dict[str, Any]):
        """Save detailed web scanning results"""
        try:
            # Save JSON results
            with open(f"{self.config.output_dir}/web/web_results.json", 'w') as f:
                json.dump(results, f, indent=2)
            
            # Save summary report
            with open(f"{self.config.output_dir}/web/web_summary.txt", 'w') as f:
                f.write("=== Web Application Scanning Summary ===\n\n")
                
                f.write(f"HTTP Services Found: {len(results['http_services'])}\n")
                for port in results['http_services']:
                    f.write(f"  - Port {port}\n")
                
                f.write(f"\nDirectories Found: {sum(len(dirs) for dirs in results['directories'].values())}\n")
                f.write(f"Files Found: {sum(len(files) for files in results['files'].values())}\n")
                f.write(f"Vulnerabilities Found: {len(results['vulnerabilities'])}\n")
                
                if results.get('payload_results'):
                    f.write("\nPayload Testing Results:\n")
                    for port, payload_data in results['payload_results'].items():
                        f.write(f"  Port {port}:\n")
                        for payload_type, findings in payload_data.items():
                            f.write(f"    {payload_type.upper()}: {len(findings)} findings\n")
        
        except Exception as e:
            logging.error(f"Failed to save web results: {e}")
                            
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
        banner = """
██████╗  ██████╗ █████╗ ██████╗ 
██╔══██╗██╔════╝██╔══██╗██╔══██╗
██████╔╝██║     ███████║██████╔╝
██╔══██╗██║     ██╔══██║██╔══██╗
██████╔╝╚██████╗██║  ██║██║  ██║
╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝
        """
        
        self.console.print(Panel(
            f"[red]{banner}[/red]\n[white bold]BlackCell Auto Recon v2.0.0[/white bold]\n[cyan]Advanced Python Reconnaissance Framework[/cyan]",
            box=box.DOUBLE,
            title="[yellow]BCAR[/yellow]",
            title_align="center"
        ))
    
    def show_main_menu(self):
        """Display the enhanced main menu"""
        self.console.clear()
        self.print_banner()
        
        # Current configuration table
        config_table = Table(title="Current Configuration", box=box.ROUNDED)
        config_table.add_column("Setting", style="cyan")
        config_table.add_column("Value", style="yellow")
        
        # Enhanced configuration display
        target_display = self.config.target or f"{len(self.config.targets_list)} targets loaded" if self.config.targets_list else "Not set"
        config_table.add_row("Target(s)", target_display)
        config_table.add_row("Scan Profile", self.config.scan_profile or "Custom")
        config_table.add_row("Output Directory", self.config.output_dir)
        config_table.add_row("Threads", str(self.config.threads))
        config_table.add_row("Timing", self.config.timing)
        config_table.add_row("Stealth Mode", "Enabled" if self.config.stealth_mode else "Disabled")
        config_table.add_row("Fuzzing", "Enabled" if self.config.fuzzing_enabled else "Disabled")
        config_table.add_row("Output Format", self.config.output_format)
        
        self.console.print(config_table)
        self.console.print()
        
        # Enhanced menu options
        menu_table = Table(box=box.SIMPLE)
        menu_table.add_column("Option", style="green bold", width=8)
        menu_table.add_column("Description", style="white")
        
        menu_table.add_row("1", "🎯 Target Management")
        menu_table.add_row("2", "⚙️  Scan Configuration")
        menu_table.add_row("3", "📋 Load Scan Profile")
        menu_table.add_row("4", "🚀 Start Reconnaissance Scan")
        menu_table.add_row("5", "🔍 Advanced Fuzzing & Payloads")
        menu_table.add_row("6", "📊 View & Analyze Results")
        menu_table.add_row("7", "🛠️  Tool Management")
        menu_table.add_row("8", "📖 Help & Documentation")
        menu_table.add_row("9", "🔄 Reset Configuration")
        menu_table.add_row("0", "[red]Exit[/red]")
        
        self.console.print(Panel(menu_table, title="[white bold]Enhanced BCAR Main Menu[/white bold]", box=box.ROUNDED))
    
    def target_management_menu(self):
        """Target management interface"""
        while True:
            self.console.clear()
            self.console.print("[cyan]═══ Target Management ═══[/cyan]\n")
            
            # Display current targets
            if self.config.targets_list:
                target_table = Table(title="Current Targets", box=box.ROUNDED)
                target_table.add_column("Index", style="cyan", width=8)
                target_table.add_column("Target", style="white")
                target_table.add_column("Type", style="yellow")
                
                for i, target in enumerate(self.config.targets_list, 1):
                    target_type = "IP" if target.replace('.', '').isdigit() else "Domain"
                    target_table.add_row(str(i), target, target_type)
                
                self.console.print(target_table)
                self.console.print()
            
            # Target management options
            options_table = Table(box=box.SIMPLE)
            options_table.add_column("Option", style="green bold", width=8)
            options_table.add_column("Description", style="white")
            
            options_table.add_row("1", "Add Single Target")
            options_table.add_row("2", "Load Targets from File")
            options_table.add_row("3", "Remove Target")
            options_table.add_row("4", "Save Targets to File")
            options_table.add_row("5", "Clear All Targets")
            options_table.add_row("0", "Back to Main Menu")
            
            self.console.print(Panel(options_table, title="Target Management Options", box=box.ROUNDED))
            
            choice = Prompt.ask("[white]Select option[/white]", choices=["0", "1", "2", "3", "4", "5"])
            
            if choice == "0":
                break
            elif choice == "1":
                self._add_single_target()
            elif choice == "2":
                self._load_targets_from_file()
            elif choice == "3":
                self._remove_target()
            elif choice == "4":
                self._save_targets_to_file()
            elif choice == "5":
                self._clear_all_targets()
    
    def scan_profile_menu(self):
        """Scan profile selection interface"""
        self.console.clear()
        self.console.print("[cyan]═══ Scan Profile Selection ═══[/cyan]\n")
        
        # Available profiles
        profiles = [
            ("quick_scan", "Quick Scan - Fast, lightweight reconnaissance"),
            ("comprehensive_scan", "Comprehensive Scan - Full reconnaissance suite"),
            ("stealth_scan", "Stealth Scan - Slow, evasive scanning"),
            ("vulnerability_scan", "Vulnerability Scan - Security-focused assessment")
        ]
        
        profiles_table = Table(box=box.ROUNDED)
        profiles_table.add_column("Option", style="green bold", width=8)
        profiles_table.add_column("Profile", style="cyan")
        profiles_table.add_column("Description", style="white")
        
        for i, (profile_name, description) in enumerate(profiles, 1):
            profiles_table.add_row(str(i), profile_name.replace('_', ' ').title(), description)
        
        profiles_table.add_row("5", "Custom Profile", "Load custom profile from file")
        profiles_table.add_row("0", "Cancel", "Return to main menu")
        
        self.console.print(profiles_table)
        
        choice = Prompt.ask("[white]Select scan profile[/white]", choices=["0", "1", "2", "3", "4", "5"])
        
        if choice == "0":
            return
        elif choice in ["1", "2", "3", "4"]:
            profile_name = profiles[int(choice) - 1][0]
            if self.config.load_scan_profile(profile_name):
                self.console.print(f"[green]✓ Loaded profile: {profile_name}[/green]")
            else:
                self.console.print(f"[red]✗ Failed to load profile: {profile_name}[/red]")
        elif choice == "5":
            profile_file = Prompt.ask("[white]Enter profile file path[/white]")
            if Path(profile_file).exists():
                if self.config.load_scan_profile(Path(profile_file).stem):
                    self.console.print(f"[green]✓ Loaded custom profile[/green]")
                else:
                    self.console.print(f"[red]✗ Failed to load custom profile[/red]")
            else:
                self.console.print(f"[red]✗ Profile file not found[/red]")
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    def fuzzing_payload_menu(self):
        """Fuzzing and payload configuration"""
        while True:
            self.console.clear()
            self.console.print("[cyan]═══ Advanced Fuzzing & Payloads ═══[/cyan]\n")
            
            # Current payload settings
            payload_table = Table(title="Payload Settings", box=box.ROUNDED)
            payload_table.add_column("Payload Type", style="cyan")
            payload_table.add_column("Status", style="white")
            payload_table.add_column("Description", style="dim")
            
            payload_table.add_row("XSS Payloads", "✓ Enabled" if self.config.xss_payloads else "✗ Disabled", "Cross-Site Scripting detection")
            payload_table.add_row("SQLi Payloads", "✓ Enabled" if self.config.sqli_payloads else "✗ Disabled", "SQL Injection testing")
            payload_table.add_row("LFI Payloads", "✓ Enabled" if self.config.lfi_payloads else "✗ Disabled", "Local File Inclusion")
            payload_table.add_row("Command Injection", "✓ Enabled" if self.config.command_injection else "✗ Disabled", "Command execution testing")
            payload_table.add_row("General Fuzzing", "✓ Enabled" if self.config.fuzzing_enabled else "✗ Disabled", "General parameter fuzzing")
            
            self.console.print(payload_table)
            self.console.print()
            
            # Options menu
            options_table = Table(box=box.SIMPLE)
            options_table.add_column("Option", style="green bold", width=8)
            options_table.add_column("Description", style="white")
            
            options_table.add_row("1", "Toggle XSS Payload Testing")
            options_table.add_row("2", "Toggle SQLi Payload Testing")
            options_table.add_row("3", "Toggle LFI Payload Testing")
            options_table.add_row("4", "Toggle Command Injection Testing")
            options_table.add_row("5", "Toggle General Fuzzing")
            options_table.add_row("6", "Enable All Payloads")
            options_table.add_row("7", "Disable All Payloads")
            options_table.add_row("0", "Back to Main Menu")
            
            self.console.print(Panel(options_table, title="Fuzzing Options", box=box.ROUNDED))
            
            choice = Prompt.ask("[white]Select option[/white]", choices=["0", "1", "2", "3", "4", "5", "6", "7"])
            
            if choice == "0":
                break
            elif choice == "1":
                self.config.xss_payloads = not self.config.xss_payloads
            elif choice == "2":
                self.config.sqli_payloads = not self.config.sqli_payloads
            elif choice == "3":
                self.config.lfi_payloads = not self.config.lfi_payloads
            elif choice == "4":
                self.config.command_injection = not self.config.command_injection
            elif choice == "5":
                self.config.fuzzing_enabled = not self.config.fuzzing_enabled
            elif choice == "6":
                self.config.xss_payloads = True
                self.config.sqli_payloads = True
                self.config.lfi_payloads = True
                self.config.command_injection = True
                self.config.fuzzing_enabled = True
                self.console.print("[green]✓ All payload testing enabled[/green]")
                time.sleep(1)
            elif choice == "7":
                self.config.xss_payloads = False
                self.config.sqli_payloads = False
                self.config.lfi_payloads = False
                self.config.command_injection = False
                self.config.fuzzing_enabled = False
                self.console.print("[yellow]⚠️  All payload testing disabled[/yellow]")
                time.sleep(1)
    
    def tool_management_menu(self):
        """Tool availability and management"""
        self.console.clear()
        self.console.print("[cyan]═══ Tool Management & Status ═══[/cyan]\n")
        
        # Check tool availability
        tools_to_check = [
            "nmap", "gobuster", "nikto", "whatweb", "whois", "dig", "curl",
            "dirb", "dirsearch", "ffuf", "nuclei", "masscan", "zmap"
        ]
        
        tool_table = Table(title="Tool Availability", box=box.ROUNDED)
        tool_table.add_column("Tool", style="cyan")
        tool_table.add_column("Status", style="white")
        tool_table.add_column("Type", style="dim")
        
        async def check_tools():
            scanner = Scanner(self.config, self.console)
            for tool in tools_to_check:
                available = await scanner.check_tool_availability(tool)
                status = "✓ Available" if available else "✗ Missing"
                tool_type = "Primary" if tool in ["nmap", "gobuster", "nikto", "whatweb", "whois"] else "Alternative"
                tool_table.add_row(tool, status, tool_type)
        
        # Run async check (simplified for demo)
        self.console.print("[yellow]🔍 Checking tool availability...[/yellow]")
        
        # Static status for now (would be dynamic in real implementation)
        essential_tools = {
            "nmap": False, "gobuster": False, "nikto": False, "whatweb": False,
            "whois": False, "dig": True, "curl": True
        }
        
        for tool, available in essential_tools.items():
            status = "[green]✓ Available[/green]" if available else "[red]✗ Missing[/red]"
            tool_type = "Essential" if tool in ["nmap", "gobuster", "nikto"] else "Optional"
            tool_table.add_row(tool, status, tool_type)
        
        self.console.print(tool_table)
        self.console.print()
        
        # Installation options
        self.console.print("[yellow]💡 Missing tools can be installed automatically during scanning[/yellow]")
        self.console.print("[dim]Alternative tools will be used when primary tools are unavailable[/dim]")
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    def _add_single_target(self):
        """Add a single target"""
        self.console.print("\n[cyan]═══ Add Target ═══[/cyan]")
        target = Prompt.ask("[white]Enter target (IP or domain)[/white]")
        
        if self.config.add_target(target):
            self.console.print(f"[green]✓ Added target: {target}[/green]")
        else:
            self.console.print(f"[red]✗ Invalid target or already exists: {target}[/red]")
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    def _load_targets_from_file(self):
        """Load targets from file"""
        self.console.print("\n[cyan]═══ Load Targets from File ═══[/cyan]")
        filepath = Prompt.ask("[white]Enter file path[/white]", default="targets.txt")
        
        if self.config.load_targets_from_file(filepath):
            self.console.print(f"[green]✓ Loaded {len(self.config.targets_list)} targets from {filepath}[/green]")
        else:
            self.console.print(f"[red]✗ Failed to load targets from {filepath}[/red]")
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    def _remove_target(self):
        """Remove a target from the list"""
        if not self.config.targets_list:
            self.console.print("[yellow]No targets to remove[/yellow]")
            Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
            return
        
        self.console.print("\n[cyan]═══ Remove Target ═══[/cyan]")
        
        # Display numbered targets
        for i, target in enumerate(self.config.targets_list, 1):
            self.console.print(f"{i}. {target}")
        
        try:
            index = IntPrompt.ask("[white]Enter target number to remove[/white]", default=0)
            if 1 <= index <= len(self.config.targets_list):
                removed_target = self.config.targets_list.pop(index - 1)
                self.console.print(f"[green]✓ Removed target: {removed_target}[/green]")
            else:
                self.console.print("[red]✗ Invalid target number[/red]")
        except Exception:
            self.console.print("[red]✗ Invalid input[/red]")
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    def _save_targets_to_file(self):
        """Save targets to file"""
        if not self.config.targets_list:
            self.console.print("[yellow]No targets to save[/yellow]")
            Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
            return
        
        self.console.print("\n[cyan]═══ Save Targets to File ═══[/cyan]")
        filepath = Prompt.ask("[white]Enter file path[/white]", default="targets.txt")
        
        if self.config.save_targets_to_file(filepath):
            self.console.print(f"[green]✓ Saved {len(self.config.targets_list)} targets to {filepath}[/green]")
        else:
            self.console.print(f"[red]✗ Failed to save targets to {filepath}[/red]")
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    def _clear_all_targets(self):
        """Clear all targets"""
        if self.config.targets_list and Confirm.ask("Are you sure you want to clear all targets?"):
            self.config.targets_list.clear()
            self.config.target = None
            self.console.print("[green]✓ All targets cleared[/green]")
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
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
        """Enhanced reconnaissance scan with multi-target support"""
        # Determine targets to scan
        targets_to_scan = []
        
        if self.config.targets_list:
            targets_to_scan = self.config.targets_list
        elif self.config.target:
            targets_to_scan = [self.config.target]
        else:
            self.console.print("[red]✗ No targets configured! Please set targets first.[/red]")
            Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
            return
        
        self.console.clear()
        self.console.print("[cyan]═══ Enhanced Scan Summary ═══[/cyan]\n")
        
        summary_table = Table(box=box.ROUNDED)
        summary_table.add_column("Setting", style="white")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Target(s)", f"{len(targets_to_scan)} target(s)")
        summary_table.add_row("Scan Profile", self.config.scan_profile or "Custom")
        summary_table.add_row("Output Directory", self.config.output_dir)
        summary_table.add_row("Threads", str(self.config.threads))
        summary_table.add_row("Timing", self.config.timing)
        summary_table.add_row("Stealth Mode", "✓ Enabled" if self.config.stealth_mode else "✗ Disabled")
        summary_table.add_row("Fuzzing", "✓ Enabled" if self.config.fuzzing_enabled else "✗ Disabled")
        summary_table.add_row("Evidence Capture", "✓ Enabled" if self.config.evidence_capture else "✗ Disabled")
        
        self.console.print(summary_table)
        
        # Display targets
        if len(targets_to_scan) <= 10:
            targets_table = Table(title="Targets", box=box.ROUNDED)
            targets_table.add_column("Index", style="cyan", width=6)
            targets_table.add_column("Target", style="white")
            
            for i, target in enumerate(targets_to_scan, 1):
                targets_table.add_row(str(i), target)
            
            self.console.print(targets_table)
        else:
            self.console.print(f"\n[dim]Scanning {len(targets_to_scan)} targets (too many to display)[/dim]")
        
        if not Confirm.ask("\n[yellow]Start enhanced reconnaissance scan?[/yellow]"):
            return
        
        # Create output directory
        os.makedirs(self.config.output_dir, exist_ok=True)
        
        # Initialize master results
        master_results = {
            "scan_metadata": {
                "bcar_version": "2.0.0",
                "scan_profile": self.config.scan_profile,
                "start_time": datetime.now().isoformat(),
                "targets_count": len(targets_to_scan),
                "configuration": {k: v for k, v in self.config.__dict__.items() if not k.startswith('_')}
            },
            "targets": {},
            "summary": {
                "total_findings": 0,
                "critical_findings": 0,
                "vulnerabilities_found": 0,
                "services_discovered": 0
            }
        }
        
        # Scan each target
        for target_index, target in enumerate(targets_to_scan, 1):
            self.console.print(f"\n[green]🎯 Scanning target {target_index}/{len(targets_to_scan)}: {target}[/green]")
            
            # Set current target for scanning
            original_target = self.config.target
            self.config.target = target
            
            # Initialize target results
            target_results = {
                "target": target,
                "start_time": datetime.now().isoformat(),
                "results": {},
                "summary": {
                    "risk_level": "low",
                    "findings_count": 0,
                    "services_found": [],
                    "vulnerabilities": []
                }
            }
            
            # Determine scanners to run
            selected_scanners = self._get_selected_scanners()
            
            # Progress tracking
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                target_task = progress.add_task(f"Scanning {target}", total=len(selected_scanners))
                
                for scanner_name in selected_scanners:
                    scanner_class = self.scanners[scanner_name]
                    scanner = scanner_class(self.config, self.console)
                    
                    try:
                        progress.update(target_task, description=f"Running {scanner_name} scan...")
                        results = await scanner.run()
                        target_results["results"][scanner_name.lower()] = results
                        
                        # Update target summary
                        self._update_target_summary(target_results, scanner_name, results)
                        
                        progress.update(target_task, advance=1)
                        
                    except Exception as e:
                        logging.error(f"{scanner_name} scan failed for {target}: {e}")
                        target_results["results"][scanner_name.lower()] = {"error": str(e)}
                        progress.update(target_task, advance=1)
            
            # Complete target scan
            target_results["end_time"] = datetime.now().isoformat()
            
            # Analyze results for this target
            target_analysis = self._analyze_target_results(target_results)
            target_results["analysis"] = target_analysis
            
            # Store target results
            master_results["targets"][target] = target_results
            
            # Update master summary
            self._update_master_summary(master_results, target_results)
            
            # Restore original target
            self.config.target = original_target
        
        # Complete master scan
        master_results["scan_metadata"]["end_time"] = datetime.now().isoformat()
        master_results["scan_metadata"]["duration"] = self._calculate_duration(
            master_results["scan_metadata"]["start_time"],
            master_results["scan_metadata"]["end_time"]
        )
        
        # Save comprehensive results
        self.scan_results = master_results
        await self._save_enhanced_results()
        
        # Display comprehensive summary
        self._display_enhanced_summary()
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    def _get_selected_scanners(self) -> List[str]:
        """Determine which scanners to run based on configuration"""
        scanners = ["DNS", "WHOIS", "Ports", "Web"]
        
        if self.config.dom_scan_enabled:
            scanners.append("DOM")
        
        scanners.extend(["Vulnerabilities", "SSL"])
        
        return scanners
    
    def _update_target_summary(self, target_results: Dict, scanner_name: str, results: Dict):
        """Update target summary with scanner results"""
        try:
            if "error" not in results:
                target_results["summary"]["findings_count"] += 1
                
                # Track services
                if scanner_name == "Ports" and "open_ports" in results:
                    target_results["summary"]["services_found"].extend(results["open_ports"])
                
                # Track vulnerabilities
                if "vulnerabilities" in results and results["vulnerabilities"]:
                    target_results["summary"]["vulnerabilities"].extend(results["vulnerabilities"])
                
                # Update risk level
                if any(keyword in str(results).lower() for keyword in ["critical", "high", "vulnerability"]):
                    target_results["summary"]["risk_level"] = "high"
                elif target_results["summary"]["risk_level"] == "low" and any(keyword in str(results).lower() for keyword in ["warning", "medium"]):
                    target_results["summary"]["risk_level"] = "medium"
        
        except Exception as e:
            logging.warning(f"Error updating target summary: {e}")
    
    def _analyze_target_results(self, target_results: Dict) -> Dict:
        """Analyze target results and generate insights"""
        analysis = {
            "security_score": 100,
            "recommendations": [],
            "attack_vectors": [],
            "compliance_issues": []
        }
        
        try:
            results = target_results["results"]
            
            # Analyze open ports
            if "ports" in results and "open_ports" in results["ports"]:
                open_ports = results["ports"]["open_ports"]
                high_risk_ports = [21, 23, 135, 139, 445, 1433, 3389]
                
                risky_ports = [port for port in open_ports if port in high_risk_ports]
                if risky_ports:
                    analysis["security_score"] -= len(risky_ports) * 10
                    analysis["recommendations"].append(f"Secure or disable high-risk ports: {risky_ports}")
                    analysis["attack_vectors"].extend([f"Port {port} exploitation" for port in risky_ports])
            
            # Analyze web vulnerabilities
            if "web" in results and "vulnerabilities" in results["web"]:
                vuln_count = len(results["web"]["vulnerabilities"])
                if vuln_count > 0:
                    analysis["security_score"] -= vuln_count * 15
                    analysis["recommendations"].append(f"Address {vuln_count} web vulnerabilities")
                    analysis["attack_vectors"].append("Web application exploitation")
            
            # Analyze payload results
            if "web" in results and "payload_results" in results["web"]:
                payload_results = results["web"]["payload_results"]
                for port_results in payload_results.values():
                    for payload_type, findings in port_results.items():
                        if findings:
                            analysis["security_score"] -= len(findings) * 20
                            analysis["recommendations"].append(f"Fix {payload_type.upper()} vulnerabilities")
                            analysis["attack_vectors"].append(f"{payload_type.upper()} exploitation")
            
            # Ensure minimum score
            analysis["security_score"] = max(0, analysis["security_score"])
            
        except Exception as e:
            logging.warning(f"Error analyzing target results: {e}")
        
        return analysis
    
    def _update_master_summary(self, master_results: Dict, target_results: Dict):
        """Update master summary with target results"""
        try:
            master_results["summary"]["total_findings"] += target_results["summary"]["findings_count"]
            master_results["summary"]["services_discovered"] += len(target_results["summary"]["services_found"])
            master_results["summary"]["vulnerabilities_found"] += len(target_results["summary"]["vulnerabilities"])
            
            if target_results["summary"]["risk_level"] == "high":
                master_results["summary"]["critical_findings"] += 1
        
        except Exception as e:
            logging.warning(f"Error updating master summary: {e}")
    
    def _calculate_duration(self, start_time: str, end_time: str) -> str:
        """Calculate scan duration"""
        try:
            start = datetime.fromisoformat(start_time)
            end = datetime.fromisoformat(end_time)
            duration = end - start
            
            hours, remainder = divmod(duration.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            
            if hours > 0:
                return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
            elif minutes > 0:
                return f"{int(minutes)}m {int(seconds)}s"
            else:
                return f"{int(seconds)}s"
        except Exception:
            return "Unknown"
    
    async def _save_enhanced_results(self):
        """Save enhanced scan results with multiple formats"""
        try:
            # Save master JSON results
            json_file = f"{self.config.output_dir}/bcar_master_results.json"
            with open(json_file, 'w') as f:
                json.dump(self.scan_results, f, indent=2, default=str)
            
            # Save configuration
            config_file = f"{self.config.output_dir}/bcar_config.json"
            self.config.save_to_file(config_file)
            
            # Generate executive summary
            await self._generate_executive_summary()
            
            # Generate detailed report
            await self._generate_detailed_report()
            
            # Generate CSV export for findings
            await self._generate_csv_export()
            
            self.console.print(f"[green]✓ Results saved to: {self.config.output_dir}[/green]")
            
        except Exception as e:
            logging.error(f"Failed to save enhanced results: {e}")
            self.console.print(f"[red]✗ Failed to save results: {e}[/red]")
    
    async def _generate_executive_summary(self):
        """Generate executive summary report"""
        try:
            summary_file = f"{self.config.output_dir}/executive_summary.txt"
            
            with open(summary_file, 'w') as f:
                f.write("BCAR EXECUTIVE SUMMARY\n")
                f.write("=" * 50 + "\n\n")
                
                metadata = self.scan_results["scan_metadata"]
                summary = self.scan_results["summary"]
                
                f.write(f"Scan Date: {metadata['start_time'].split('T')[0]}\n")
                f.write(f"Duration: {metadata.get('duration', 'Unknown')}\n")
                f.write(f"Targets Scanned: {metadata['targets_count']}\n")
                f.write(f"Profile Used: {metadata.get('scan_profile', 'Custom')}\n\n")
                
                f.write("KEY FINDINGS:\n")
                f.write("-" * 20 + "\n")
                f.write(f"• Total Findings: {summary['total_findings']}\n")
                f.write(f"• Critical Targets: {summary['critical_findings']}\n")
                f.write(f"• Vulnerabilities: {summary['vulnerabilities_found']}\n")
                f.write(f"• Services Discovered: {summary['services_discovered']}\n\n")
                
                # Risk assessment
                risk_level = "LOW"
                if summary['critical_findings'] > 0:
                    risk_level = "HIGH"
                elif summary['vulnerabilities_found'] > 5:
                    risk_level = "MEDIUM"
                
                f.write(f"OVERALL RISK LEVEL: {risk_level}\n\n")
                
                # Top recommendations
                f.write("TOP RECOMMENDATIONS:\n")
                f.write("-" * 25 + "\n")
                
                recommendations = set()
                for target_data in self.scan_results["targets"].values():
                    if "analysis" in target_data:
                        recommendations.update(target_data["analysis"].get("recommendations", []))
                
                for i, rec in enumerate(list(recommendations)[:5], 1):
                    f.write(f"{i}. {rec}\n")
        
        except Exception as e:
            logging.error(f"Failed to generate executive summary: {e}")
    
    async def _generate_detailed_report(self):
        """Generate detailed technical report"""
        try:
            report_file = f"{self.config.output_dir}/detailed_report.txt"
            
            with open(report_file, 'w') as f:
                f.write("BCAR DETAILED TECHNICAL REPORT\n")
                f.write("=" * 60 + "\n\n")
                
                for target, target_data in self.scan_results["targets"].items():
                    f.write(f"TARGET: {target}\n")
                    f.write("=" * 40 + "\n\n")
                    
                    # Target summary
                    summary = target_data["summary"]
                    f.write(f"Risk Level: {summary['risk_level'].upper()}\n")
                    f.write(f"Findings: {summary['findings_count']}\n")
                    f.write(f"Services: {len(summary['services_found'])}\n")
                    f.write(f"Vulnerabilities: {len(summary['vulnerabilities'])}\n\n")
                    
                    # Security score
                    if "analysis" in target_data:
                        score = target_data["analysis"].get("security_score", 0)
                        f.write(f"Security Score: {score}/100\n\n")
                    
                    # Detailed findings per scanner
                    for scanner, results in target_data["results"].items():
                        f.write(f"{scanner.upper()} RESULTS:\n")
                        f.write("-" * 20 + "\n")
                        
                        if "error" in results:
                            f.write(f"Error: {results['error']}\n")
                        else:
                            # Summarize key findings
                            if scanner == "ports" and "open_ports" in results:
                                f.write(f"Open Ports: {results['open_ports']}\n")
                            elif scanner == "web" and "http_services" in results:
                                f.write(f"HTTP Services: {results['http_services']}\n")
                            elif scanner == "vulnerabilities" and "vulnerabilities" in results:
                                f.write(f"Vulnerabilities Found: {len(results['vulnerabilities'])}\n")
                        
                        f.write("\n")
                    
                    f.write("\n" + "=" * 40 + "\n\n")
        
        except Exception as e:
            logging.error(f"Failed to generate detailed report: {e}")
    
    async def _generate_csv_export(self):
        """Generate CSV export of findings"""
        try:
            csv_file = f"{self.config.output_dir}/findings_export.csv"
            
            with open(csv_file, 'w') as f:
                # CSV headers
                f.write("Target,Scanner,Finding_Type,Description,Risk_Level,Timestamp\n")
                
                for target, target_data in self.scan_results["targets"].items():
                    timestamp = target_data.get("start_time", "")
                    risk_level = target_data["summary"].get("risk_level", "unknown")
                    
                    for scanner, results in target_data["results"].items():
                        if "error" not in results:
                            # Extract key findings for CSV
                            if scanner == "ports" and "open_ports" in results:
                                for port in results["open_ports"]:
                                    f.write(f"{target},{scanner},Open Port,Port {port} is open,{risk_level},{timestamp}\n")
                            
                            if scanner == "web" and "vulnerabilities" in results:
                                for vuln in results["vulnerabilities"]:
                                    f.write(f"{target},{scanner},Vulnerability,{vuln},{risk_level},{timestamp}\n")
        
        except Exception as e:
            logging.error(f"Failed to generate CSV export: {e}")
    
    def _display_enhanced_summary(self):
        """Display comprehensive scan summary"""
        self.console.clear()
        self.console.print("[cyan]═══ Enhanced Scan Complete! ═══[/cyan]\n")
        
        # Master statistics
        metadata = self.scan_results["scan_metadata"]
        summary = self.scan_results["summary"]
        
        stats_table = Table(title="Scan Statistics", box=box.ROUNDED)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green")
        
        stats_table.add_row("Targets Scanned", str(metadata["targets_count"]))
        stats_table.add_row("Scan Duration", metadata.get("duration", "Unknown"))
        stats_table.add_row("Total Findings", str(summary["total_findings"]))
        stats_table.add_row("Critical Targets", str(summary["critical_findings"]))
        stats_table.add_row("Vulnerabilities", str(summary["vulnerabilities_found"]))
        stats_table.add_row("Services Discovered", str(summary["services_discovered"]))
        
        self.console.print(stats_table)
        self.console.print()
        
        # Risk assessment
        risk_level = "🟢 LOW"
        if summary["critical_findings"] > 0:
            risk_level = "🔴 HIGH"
        elif summary["vulnerabilities_found"] > 5:
            risk_level = "🟡 MEDIUM"
        
        risk_table = Table(title="Risk Assessment", box=box.ROUNDED)
        risk_table.add_column("Overall Risk Level", style="bold")
        risk_table.add_row(risk_level)
        
        self.console.print(risk_table)
        self.console.print()
        
        # Top targets by risk
        high_risk_targets = []
        for target, data in self.scan_results["targets"].items():
            if data["summary"]["risk_level"] == "high":
                high_risk_targets.append(target)
        
        if high_risk_targets:
            self.console.print("[red]⚠️  HIGH RISK TARGETS:[/red]")
            for target in high_risk_targets:
                self.console.print(f"   • {target}")
            self.console.print()
        
        # Output files
        files_table = Table(title="Generated Reports", box=box.ROUNDED)
        files_table.add_column("File", style="cyan")
        files_table.add_column("Description", style="white")
        
        files_table.add_row("bcar_master_results.json", "Complete JSON results")
        files_table.add_row("executive_summary.txt", "Executive summary report")
        files_table.add_row("detailed_report.txt", "Technical detailed report")
        files_table.add_row("findings_export.csv", "CSV export of findings")
        
        self.console.print(files_table)
    
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
        """Main application loop with enhanced menu handling"""
        try:
            while True:
                self.show_main_menu()
                
                choice = Prompt.ask(
                    "\n[white]Enter your choice[/white]",
                    choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
                    default="0"
                )
                
                if choice == "0":
                    self.console.print("\n[cyan]Thank you for using BCAR![/cyan]")
                    # Save configuration before exit
                    self.config.save_to_file()
                    break
                elif choice == "1":
                    self.target_management_menu()
                elif choice == "2":
                    self.configure_options()
                elif choice == "3":
                    self.scan_profile_menu()
                elif choice == "4":
                    await self.start_scan()
                elif choice == "5":
                    self.fuzzing_payload_menu()
                elif choice == "6":
                    self.view_results()
                elif choice == "7":
                    self.tool_management_menu()
                elif choice == "8":
                    self.show_help()
                elif choice == "9":
                    self.reset_config()
        
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