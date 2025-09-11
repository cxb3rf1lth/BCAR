#!/usr/bin/env python3
"""
BlackCell Auto Recon (BCAR) - Advanced Python Version
Author: BlackCell Security
Description: Comprehensive automated reconnaissance tool with professional TUI interface
Version: 2.1.0 - Enhanced Edition
"""

import asyncio
import json
import os
import subprocess
import sys
import time
import socket
import ssl
import uuid
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import logging
import re
import ipaddress
from dataclasses import dataclass, asdict
from enum import Enum

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

# Try to import additional libraries for enhanced features
try:
    import aiofiles
    import aiohttp
    import dns.resolver
    HAS_ENHANCED_LIBS = True
except ImportError:
    HAS_ENHANCED_LIBS = False

# Configure logging with enhanced format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('bcar.log'),
        logging.StreamHandler()
    ]
)

# Enhanced data structures
class ScanResult:
    """Enhanced scan result structure"""
    def __init__(self, scanner_name: str):
        self.scanner_name = scanner_name
        self.start_time = datetime.now()
        self.end_time: Optional[datetime] = None
        self.status = "running"  # running, completed, failed, skipped
        self.data: Dict[str, Any] = {}
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.metadata: Dict[str, Any] = {}
        
    def complete(self, data: Dict[str, Any], status: str = "completed"):
        self.end_time = datetime.now()
        self.data = data
        self.status = status
        
    def add_error(self, error: str):
        self.errors.append(error)
        logging.error(f"{self.scanner_name}: {error}")
        
    def add_warning(self, warning: str):
        self.warnings.append(warning)
        logging.warning(f"{self.scanner_name}: {warning}")
        
    def duration(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return (datetime.now() - self.start_time).total_seconds()

class ScanPhase(Enum):
    """Scan phases for better organization"""
    VALIDATION = "validation"
    DNS_RECON = "dns_recon"
    WHOIS_LOOKUP = "whois_lookup"
    PORT_SCANNING = "port_scanning"
    SERVICE_DETECTION = "service_detection"
    WEB_SCANNING = "web_scanning"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    SSL_ANALYSIS = "ssl_analysis"
    DOM_ANALYSIS = "dom_analysis"
    INTELLIGENCE_GATHERING = "intelligence_gathering"
    REPORTING = "reporting"

@dataclass
class RetryConfig:
    """Configuration for retry mechanisms"""
    max_attempts: int = 3
    backoff_factor: float = 2.0
    initial_delay: float = 1.0
    max_delay: float = 60.0
    exceptions: tuple = (Exception,)

class EnhancedError(Exception):
    """Enhanced error class with context"""
    def __init__(self, message: str, error_code: str = None, context: Dict[str, Any] = None):
        super().__init__(message)
        self.error_code = error_code or "GENERAL_ERROR"
        self.context = context or {}
        self.timestamp = datetime.now()

async def retry_async(func, config: RetryConfig, *args, **kwargs):
    """Enhanced async retry mechanism"""
    last_exception = None
    delay = config.initial_delay
    
    for attempt in range(config.max_attempts):
        try:
            return await func(*args, **kwargs)
        except config.exceptions as e:
            last_exception = e
            if attempt == config.max_attempts - 1:
                break
                
            logging.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay}s...")
            await asyncio.sleep(delay)
            delay = min(delay * config.backoff_factor, config.max_delay)
    
    raise last_exception

class BCARConfig:
    """Enhanced configuration management for BCAR"""
    
    def __init__(self):
        self.target: Optional[str] = None
        self.output_dir: str = f"bcar_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.threads: int = 50
        self.timing: str = "normal"  # slow, normal, fast, aggressive
        self.stealth_mode: bool = False
        self.output_format: str = "json"  # txt, json, both, xml
        self.dom_scan_enabled: bool = True
        self.dom_headless: bool = True
        self.nmap_scripts: str = "default,vuln"
        self.wordlist: Optional[str] = None
        self.verbose: bool = False
        
        # Enhanced Python features
        self.max_retries: int = 3
        self.timeout: int = 60  # Increased default timeout
        self.user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 BCAR/2.1"
        self.dns_servers: List[str] = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
        self.skip_phases: List[str] = []
        
        # New advanced features
        self.intelligence_enabled: bool = True
        self.subdomain_enum_enabled: bool = True
        self.cve_lookup_enabled: bool = True
        self.threat_intel_enabled: bool = False
        self.api_discovery_enabled: bool = True
        self.screenshot_enabled: bool = False
        self.backup_results: bool = True
        self.result_comparison: bool = True
        
        # Performance optimizations
        self.async_dns_enabled: bool = HAS_ENHANCED_LIBS
        self.connection_pooling: bool = True
        self.rate_limiting: bool = True
        self.memory_efficient: bool = True
        
        # Security enhancements
        self.input_sanitization: bool = True
        self.safe_file_operations: bool = True
        self.secure_networking: bool = True
        
        # Scan profiles
        self.scan_profile: str = "comprehensive"  # quick, comprehensive, stealth, aggressive
        
        # Risk assessment
        self.risk_assessment_enabled: bool = True
        self.auto_recommendations: bool = True
        
        # Reporting enhancements
        self.executive_summary: bool = True
        self.technical_details: bool = True
        self.compliance_checks: bool = False
        
        # Initialize scan profile
        self._apply_scan_profile()
        
    def _apply_scan_profile(self):
        """Apply predefined scan profile configurations"""
        profiles = {
            "quick": {
                "timing": "fast",
                "threads": 100,
                "stealth_mode": False,
                "dom_scan_enabled": False,
                "subdomain_enum_enabled": False,
                "api_discovery_enabled": False,
                "nmap_scripts": "default"
            },
            "comprehensive": {
                "timing": "normal",
                "threads": 50,
                "stealth_mode": False,
                "dom_scan_enabled": True,
                "subdomain_enum_enabled": True,
                "api_discovery_enabled": True,
                "nmap_scripts": "default,vuln,safe"
            },
            "stealth": {
                "timing": "slow",
                "threads": 10,
                "stealth_mode": True,
                "dom_scan_enabled": False,
                "rate_limiting": True,
                "nmap_scripts": "safe"
            },
            "aggressive": {
                "timing": "fast",
                "threads": 200,
                "stealth_mode": False,
                "dom_scan_enabled": True,
                "api_discovery_enabled": True,
                "nmap_scripts": "default,vuln,exploit"
            }
        }
        
        if self.scan_profile in profiles:
            profile_config = profiles[self.scan_profile]
            for key, value in profile_config.items():
                if hasattr(self, key):
                    setattr(self, key, value)
    
    def set_scan_profile(self, profile: str):
        """Set and apply a scan profile"""
        self.scan_profile = profile
        self._apply_scan_profile()
        
    def validate_config(self) -> List[str]:
        """Validate configuration and return any issues"""
        issues = []
        
        if not self.target:
            issues.append("Target is required")
            
        if self.threads < 1 or self.threads > 1000:
            issues.append("Threads must be between 1 and 1000")
            
        if self.timing not in ["slow", "normal", "fast", "aggressive"]:
            issues.append("Invalid timing value")
            
        if self.timeout < 1 or self.timeout > 3600:
            issues.append("Timeout must be between 1 and 3600 seconds")
            
        if self.wordlist and not os.path.exists(self.wordlist):
            issues.append(f"Wordlist file not found: {self.wordlist}")
            
        return issues
        
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
    """Enhanced base class for all scanning modules"""
    
    def __init__(self, config: BCARConfig, console: Console):
        self.config = config
        self.console = console
        self.results: Dict[str, Any] = {}
        self.scan_result = ScanResult(self.__class__.__name__)
        self.retry_config = RetryConfig()
        
    async def run(self) -> Dict[str, Any]:
        """Run the scanner - to be implemented by subclasses"""
        raise NotImplementedError
        
    async def run_with_error_handling(self) -> ScanResult:
        """Run scanner with comprehensive error handling"""
        try:
            self.console.print(f"[cyan]Starting {self.scan_result.scanner_name}...[/cyan]")
            data = await retry_async(self.run, self.retry_config)
            self.scan_result.complete(data, "completed")
            self.console.print(f"[green]✓ {self.scan_result.scanner_name} completed successfully[/green]")
        except Exception as e:
            error_msg = f"Scanner failed: {str(e)}"
            self.scan_result.add_error(error_msg)
            self.scan_result.complete({}, "failed")
            self.console.print(f"[red]✗ {self.scan_result.scanner_name} failed: {e}[/red]")
        
        return self.scan_result
        
    async def safe_command_execution(self, cmd: List[str], timeout: Optional[int] = None) -> tuple:
        """Execute commands safely with proper error handling and timeout"""
        if timeout is None:
            timeout = self.config.timeout
            
        try:
            # Sanitize command arguments if enabled
            if self.config.input_sanitization:
                cmd = [arg for arg in cmd if self._is_safe_argument(arg)]
            
            result = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                ),
                timeout=timeout
            )
            
            stdout, stderr = await result.communicate()
            return result.returncode, stdout.decode('utf-8', errors='ignore'), stderr.decode('utf-8', errors='ignore')
            
        except asyncio.TimeoutError:
            raise EnhancedError(f"Command timed out after {timeout}s", "TIMEOUT_ERROR", {"cmd": cmd})
        except Exception as e:
            raise EnhancedError(f"Command execution failed: {e}", "EXECUTION_ERROR", {"cmd": cmd})
    
    def _is_safe_argument(self, arg: str) -> bool:
        """Check if command argument is safe"""
        dangerous_patterns = [
            r'[;&|`$\(\)<>\n\r]',  # Shell metacharacters
            r'\.\./',  # Path traversal
            r'^\-',  # Starts with dash (potential flag confusion)
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, arg):
                return False
        return True
        
    async def safe_file_operation(self, operation: str, file_path: str, content: str = "") -> Union[bool, str]:
        """Perform file operations safely"""
        if not self.config.safe_file_operations:
            return False
            
        try:
            # Validate file path
            safe_path = Path(file_path).resolve()
            output_base = Path(self.config.output_dir).resolve()
            
            # Ensure file is within output directory (prevent path traversal)
            if not str(safe_path).startswith(str(output_base)):
                raise EnhancedError("Path traversal attempt detected", "SECURITY_ERROR", {"path": file_path})
            
            # Ensure directory exists
            safe_path.parent.mkdir(parents=True, exist_ok=True)
            
            if operation == "write":
                if HAS_ENHANCED_LIBS:
                    async with aiofiles.open(safe_path, 'w') as f:
                        await f.write(content)
                else:
                    with open(safe_path, 'w') as f:
                        f.write(content)
                return True
            elif operation == "read":
                if HAS_ENHANCED_LIBS:
                    async with aiofiles.open(safe_path, 'r') as f:
                        return await f.read()
                else:
                    with open(safe_path, 'r') as f:
                        return f.read()
            
            return True
            
        except Exception as e:
            self.scan_result.add_error(f"File operation failed: {e}")
            return False
            
    def validate_target(self, target: str) -> bool:
        """Enhanced target validation with security checks"""
        if not target or not isinstance(target, str):
            return False
        
        target = target.strip()
        
        # Security: Prevent command injection
        if self.config.input_sanitization:
            dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']
            if any(char in target for char in dangerous_chars):
                return False
        
        # First try to validate as IP address using ipaddress module for accuracy
        try:
            ip = ipaddress.ip_address(target)
            # Security check: reject certain IP ranges if configured
            if self.config.secure_networking:
                # Reject multicast, reserved, etc. for external scanning
                if ip.is_multicast or ip.is_reserved:
                    return False
            return True
        except ValueError:
            pass
        
        # Enhanced domain validation - must not start or end with hyphen or dot
        # Domain names can be up to 253 characters, with each label up to 63 characters
        if len(target) > 253:
            return False
            
        # Additional validation - no consecutive dots, no leading/trailing dots, no empty
        if '..' in target or target.startswith('.') or target.endswith('.') or target.startswith('-') or target.endswith('-'):
            return False
        
        # Split into labels and validate each
        labels = target.split('.')
        for label in labels:
            if not label:  # Empty label
                return False
            if len(label) > 63:  # Label too long
                return False
            if label.startswith('-') or label.endswith('-'):  # Invalid hyphen placement
                return False
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$', label):
                return False
        
        # For single labels (like localhost), apply additional checks
        if len(labels) == 1:
            return re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$', target) is not None
        
        # For domains, the TLD should be at least 2 characters and all letters
        tld = labels[-1]
        if len(tld) < 2 or not tld.isalpha():
            return False
        
        return True

class DNSScanner(Scanner):
    """Enhanced DNS enumeration with subdomain discovery and zone transfer testing"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform comprehensive DNS reconnaissance"""
        self.console.print("[cyan]🔍 Starting enhanced DNS enumeration...[/cyan]")
        
        dns_results = {
            "records": {},
            "zone_transfer": False,
            "subdomains": [],
            "nameservers": [],
            "mx_servers": [],
            "dns_security": {},
            "wildcards": [],
            "reverse_dns": {}
        }
        
        try:
            # Create output directory
            os.makedirs(f"{self.config.output_dir}/dns", exist_ok=True)
            
            # Enhanced DNS record enumeration
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV', 'CAA']
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                total_tasks = len(record_types) + (2 if self.config.subdomain_enum_enabled else 0)
                task = progress.add_task("Enumerating DNS records...", total=total_tasks)
                
                # Standard DNS record enumeration
                for record_type in record_types:
                    try:
                        cmd = ["dig", "+short", record_type, self.config.target]
                        if self.config.dns_servers:
                            cmd.extend([f"@{self.config.dns_servers[0]}"])
                        
                        returncode, stdout, stderr = await self.safe_command_execution(cmd)
                        
                        if returncode == 0 and stdout.strip():
                            records = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
                            dns_results["records"][record_type] = records
                            
                            # Extract specific information
                            if record_type == "NS":
                                dns_results["nameservers"] = records
                            elif record_type == "MX":
                                dns_results["mx_servers"] = records
                        
                    except Exception as e:
                        self.scan_result.add_warning(f"DNS {record_type} query failed: {e}")
                    
                    progress.update(task, advance=1)
                
                # Zone transfer testing
                if dns_results["nameservers"]:
                    progress.update(task, description="Testing zone transfers...")
                    for ns_server in dns_results["nameservers"]:
                        try:
                            ns_clean = ns_server.split()[0] if ' ' in ns_server else ns_server
                            if ns_clean.endswith('.'):
                                ns_clean = ns_clean[:-1]
                            
                            cmd = ["dig", "axfr", self.config.target, f"@{ns_clean}"]
                            returncode, stdout, stderr = await self.safe_command_execution(cmd, timeout=30)
                            
                            if returncode == 0 and stdout and "failed" not in stdout.lower() and "connection timed out" not in stdout.lower():
                                # Check if we actually got zone data
                                lines = stdout.strip().split('\n')
                                if len(lines) > 2:  # More than just SOA records
                                    dns_results["zone_transfer"] = True
                                    await self.safe_file_operation("write", 
                                        f"{self.config.output_dir}/dns/zone_transfer_{ns_clean}.txt", stdout)
                                    self.console.print(f"[red]⚠️  Zone transfer successful on {ns_clean}![/red]")
                                    break
                                    
                        except Exception as e:
                            self.scan_result.add_warning(f"Zone transfer test failed for {ns_server}: {e}")
                
                # Subdomain enumeration (if enabled)
                if self.config.subdomain_enum_enabled:
                    progress.update(task, description="Enumerating subdomains...")
                    subdomains = await self._enumerate_subdomains()
                    dns_results["subdomains"] = subdomains
                    progress.update(task, advance=1)
                    
                    # Wildcard detection
                    progress.update(task, description="Testing for DNS wildcards...")
                    wildcards = await self._detect_wildcards()
                    dns_results["wildcards"] = wildcards
                    progress.update(task, advance=1)
                
                # DNS security checks
                dns_results["dns_security"] = await self._check_dns_security()
        
        except Exception as e:
            self.scan_result.add_error(f"DNS scanning failed: {e}")
        
        self.results = dns_results
        return dns_results
    
    async def _enumerate_subdomains(self) -> List[str]:
        """Enumerate subdomains using various techniques"""
        subdomains = []
        
        # Common subdomain list
        common_subs = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", 
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
            "ns3", "mail2", "new", "mysql", "old", "www1", "email", "img", "www3",
            "help", "shop", "owa", "en", "start", "sms", "api", "exchange", "www4"
        ]
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                
                task = progress.add_task(f"Testing {len(common_subs)} common subdomains...", total=len(common_subs))
                
                # Use async DNS resolution if available
                if HAS_ENHANCED_LIBS and self.config.async_dns_enabled:
                    subdomains = await self._async_subdomain_enum(common_subs, progress, task)
                else:
                    subdomains = await self._sync_subdomain_enum(common_subs, progress, task)
            
            # Save subdomain results
            if subdomains:
                subdomain_content = '\n'.join(subdomains)
                await self.safe_file_operation("write", 
                    f"{self.config.output_dir}/dns/subdomains.txt", subdomain_content)
                
        except Exception as e:
            self.scan_result.add_warning(f"Subdomain enumeration failed: {e}")
        
        return subdomains
    
    async def _async_subdomain_enum(self, subdomains: List[str], progress, task) -> List[str]:
        """Async subdomain enumeration using dnspython"""
        found_subdomains = []
        
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.config.dns_servers
            resolver.timeout = 2
            resolver.lifetime = 5
            
            semaphore = asyncio.Semaphore(self.config.threads)
            
            async def check_subdomain(subdomain):
                async with semaphore:
                    try:
                        full_domain = f"{subdomain}.{self.config.target}"
                        
                        # Try A record
                        try:
                            answers = resolver.resolve(full_domain, 'A')
                            if answers:
                                return full_domain
                        except:
                            pass
                            
                        # Try CNAME record
                        try:
                            answers = resolver.resolve(full_domain, 'CNAME')
                            if answers:
                                return full_domain
                        except:
                            pass
                    except:
                        pass
                    return None
            
            # Create tasks for all subdomains
            tasks = [check_subdomain(sub) for sub in subdomains]
            
            # Process tasks in batches to avoid overwhelming the DNS server
            batch_size = min(20, self.config.threads)
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i + batch_size]
                results = await asyncio.gather(*batch, return_exceptions=True)
                
                for result in results:
                    if result and isinstance(result, str):
                        found_subdomains.append(result)
                
                progress.update(task, advance=len(batch))
                
                # Rate limiting
                if self.config.rate_limiting:
                    await asyncio.sleep(0.1)
        
        except ImportError:
            # Fall back to sync method if dnspython is not available
            found_subdomains = await self._sync_subdomain_enum(subdomains, progress, task)
        except Exception as e:
            self.scan_result.add_warning(f"Async subdomain enumeration failed: {e}")
        
        return found_subdomains
    
    async def _sync_subdomain_enum(self, subdomains: List[str], progress, task) -> List[str]:
        """Synchronous subdomain enumeration using dig"""
        found_subdomains = []
        
        for subdomain in subdomains:
            try:
                full_domain = f"{subdomain}.{self.config.target}"
                cmd = ["dig", "+short", "A", full_domain]
                
                returncode, stdout, stderr = await self.safe_command_execution(cmd, timeout=5)
                
                if returncode == 0 and stdout.strip():
                    found_subdomains.append(full_domain)
                
                progress.update(task, advance=1)
                
                # Rate limiting for stealth mode
                if self.config.stealth_mode:
                    await asyncio.sleep(0.5)
                    
            except Exception as e:
                self.scan_result.add_warning(f"Subdomain check failed for {subdomain}: {e}")
        
        return found_subdomains
    
    async def _detect_wildcards(self) -> List[str]:
        """Detect DNS wildcard records"""
        wildcards = []
        
        try:
            # Test random subdomains to detect wildcards
            random_subs = [f"random-{uuid.uuid4().hex[:8]}" for _ in range(3)]
            
            for random_sub in random_subs:
                try:
                    full_domain = f"{random_sub}.{self.config.target}"
                    cmd = ["dig", "+short", "A", full_domain]
                    
                    returncode, stdout, stderr = await self.safe_command_execution(cmd, timeout=5)
                    
                    if returncode == 0 and stdout.strip():
                        wildcards.append(stdout.strip())
                        
                except Exception as e:
                    self.scan_result.add_warning(f"Wildcard detection failed for {random_sub}: {e}")
        
        except Exception as e:
            self.scan_result.add_warning(f"Wildcard detection failed: {e}")
        
        return wildcards
    
    async def _check_dns_security(self) -> Dict[str, Any]:
        """Check DNS security configurations"""
        security_info = {
            "dnssec_enabled": False,
            "spf_record": None,
            "dmarc_record": None,
            "dkim_records": [],
            "caa_records": []
        }
        
        try:
            # Check DNSSEC
            cmd = ["dig", "+dnssec", "SOA", self.config.target]
            returncode, stdout, stderr = await self.safe_command_execution(cmd)
            if returncode == 0 and "ad" in stdout.lower():
                security_info["dnssec_enabled"] = True
            
            # Check SPF record
            if "TXT" in self.results.get("records", {}):
                for txt_record in self.results["records"]["TXT"]:
                    if "v=spf1" in txt_record.lower():
                        security_info["spf_record"] = txt_record
                        break
            
            # Check DMARC record
            cmd = ["dig", "+short", "TXT", f"_dmarc.{self.config.target}"]
            returncode, stdout, stderr = await self.safe_command_execution(cmd)
            if returncode == 0 and stdout.strip():
                security_info["dmarc_record"] = stdout.strip()
            
            # Check CAA records
            if "CAA" in self.results.get("records", {}):
                security_info["caa_records"] = self.results["records"]["CAA"]
        
        except Exception as e:
            self.scan_result.add_warning(f"DNS security check failed: {e}")
        
        return security_info

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
    """Enhanced network port scanning with advanced Nmap integration"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform comprehensive port scanning"""
        self.console.print("[cyan]🔍 Starting enhanced port scanning...[/cyan]")
        
        port_results = {
            "open_ports": [],
            "services": {},
            "tcp_scan": None,
            "udp_scan": None,
            "service_fingerprints": {},
            "os_detection": {},
            "vulnerabilities": [],
            "firewalls_detected": [],
            "scan_statistics": {}
        }
        
        try:
            # Create output directory
            os.makedirs(f"{self.config.output_dir}/nmap", exist_ok=True)
            
            # Enhanced Nmap timing configuration
            timing_map = {
                "slow": "-T1",
                "normal": "-T3", 
                "fast": "-T4",
                "aggressive": "-T5"
            }
            timing = timing_map.get(self.config.timing, "-T3")
            if self.config.stealth_mode:
                timing = "-T1"
            
            # Additional stealth options
            stealth_options = []
            if self.config.stealth_mode:
                stealth_options.extend(["-f", "-D RND:10", "--randomize-hosts"])
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                # Phase 1: Host discovery
                discovery_task = progress.add_task("Host discovery...", total=100)
                host_up = await self._host_discovery(stealth_options, timing)
                progress.update(discovery_task, completed=100)
                
                if not host_up:
                    self.console.print("[yellow]⚠️  Host appears to be down or filtered[/yellow]")
                    port_results["scan_statistics"]["host_status"] = "down"
                    return port_results
                
                port_results["scan_statistics"]["host_status"] = "up"
                
                # Phase 2: Quick TCP scan
                tcp_task = progress.add_task("TCP port scan (top ports)...", total=100)
                
                # Determine port range based on scan profile
                port_range = "1000" if self.config.scan_profile in ["quick", "stealth"] else "5000"
                if self.config.scan_profile == "aggressive":
                    port_range = "65535"
                
                tcp_cmd = [
                    "nmap", timing, f"--top-ports", port_range, "--open",
                    "-oN", f"{self.config.output_dir}/nmap/tcp_scan.txt",
                    "-oX", f"{self.config.output_dir}/nmap/tcp_scan.xml",
                    "-oG", f"{self.config.output_dir}/nmap/tcp_scan.gnmap"
                ] + stealth_options + [self.config.target]
                
                returncode, stdout, stderr = await self.safe_command_execution(tcp_cmd)
                progress.update(tcp_task, completed=100)
                
                if returncode == 0:
                    port_results["tcp_scan"] = "completed"
                    await self._parse_nmap_output(f"{self.config.output_dir}/nmap/tcp_scan.txt", port_results)
                    await self._parse_nmap_xml(f"{self.config.output_dir}/nmap/tcp_scan.xml", port_results)
                else:
                    self.scan_result.add_error(f"TCP scan failed: {stderr}")
                
                # Phase 3: Service version detection
                if port_results["open_ports"]:
                    service_task = progress.add_task("Service version detection...", total=100)
                    
                    ports_str = ",".join([str(p) for p in port_results["open_ports"]])
                    service_cmd = [
                        "nmap", "-sV", "-sC", f"--script={self.config.nmap_scripts}",
                        timing, f"-p{ports_str}",
                        "-oN", f"{self.config.output_dir}/nmap/service_scan.txt",
                        "-oX", f"{self.config.output_dir}/nmap/service_scan.xml"
                    ] + stealth_options + [self.config.target]
                    
                    returncode, stdout, stderr = await self.safe_command_execution(service_cmd)
                    
                    if returncode == 0:
                        await self._parse_service_info(f"{self.config.output_dir}/nmap/service_scan.xml", port_results)
                    
                    progress.update(service_task, completed=100)
                
                # Phase 4: OS Detection (if not in stealth mode)
                if not self.config.stealth_mode and port_results["open_ports"]:
                    os_task = progress.add_task("OS detection...", total=100)
                    
                    os_cmd = [
                        "nmap", "-O", "--osscan-guess",
                        timing, "-p", ",".join([str(p) for p in port_results["open_ports"][:10]]),
                        "-oN", f"{self.config.output_dir}/nmap/os_scan.txt",
                        "-oX", f"{self.config.output_dir}/nmap/os_scan.xml",
                        self.config.target
                    ]
                    
                    returncode, stdout, stderr = await self.safe_command_execution(os_cmd)
                    
                    if returncode == 0:
                        port_results["os_detection"] = await self._parse_os_detection(
                            f"{self.config.output_dir}/nmap/os_scan.xml")
                    
                    progress.update(os_task, completed=100)
                
                # Phase 5: UDP scan (limited in stealth mode)
                if self.config.scan_profile != "quick":
                    udp_task = progress.add_task("UDP port scan...", total=100)
                    
                    udp_ports = "100" if self.config.stealth_mode else "1000"
                    udp_cmd = [
                        "nmap", "-sU", timing, f"--top-ports", udp_ports, "--open",
                        "-oN", f"{self.config.output_dir}/nmap/udp_scan.txt",
                        "-oX", f"{self.config.output_dir}/nmap/udp_scan.xml"
                    ] + stealth_options + [self.config.target]
                    
                    returncode, stdout, stderr = await self.safe_command_execution(udp_cmd, timeout=300)
                    
                    if returncode == 0:
                        port_results["udp_scan"] = "completed"
                        await self._parse_udp_results(f"{self.config.output_dir}/nmap/udp_scan.xml", port_results)
                    
                    progress.update(udp_task, completed=100)
                
                # Phase 6: Firewall/IDS detection
                if self.config.scan_profile == "comprehensive":
                    fw_task = progress.add_task("Firewall detection...", total=100)
                    port_results["firewalls_detected"] = await self._detect_firewalls()
                    progress.update(fw_task, completed=100)
        
        except Exception as e:
            self.scan_result.add_error(f"Port scanning failed: {e}")
        
        # Generate scan statistics
        port_results["scan_statistics"]["total_open_ports"] = len(port_results["open_ports"])
        port_results["scan_statistics"]["scan_duration"] = self.scan_result.duration()
        
        self.results = port_results
        return port_results
    
    async def _host_discovery(self, stealth_options: List[str], timing: str) -> bool:
        """Perform host discovery to check if target is up"""
        try:
            cmd = ["nmap", "-sn", timing] + stealth_options + [self.config.target]
            returncode, stdout, stderr = await self.safe_command_execution(cmd, timeout=30)
            
            if returncode == 0:
                return "Host is up" in stdout or "1 host up" in stdout
            return False
            
        except Exception as e:
            self.scan_result.add_warning(f"Host discovery failed: {e}")
            return True  # Assume host is up and continue
    
    async def _parse_nmap_output(self, file_path: str, results: Dict[str, Any]) -> None:
        """Parse Nmap text output to extract open ports"""
        try:
            content = await self.safe_file_operation("read", file_path)
            if content:
                # Extract open ports from nmap output
                port_pattern = r'(\d+)/(tcp|udp)\s+open'
                matches = re.findall(port_pattern, content)
                results["open_ports"] = [int(port) for port, protocol in matches if protocol == "tcp"]
                
        except Exception as e:
            self.scan_result.add_warning(f"Could not parse nmap text output: {e}")
    
    async def _parse_nmap_xml(self, file_path: str, results: Dict[str, Any]) -> None:
        """Parse Nmap XML output for detailed information"""
        try:
            content = await self.safe_file_operation("read", file_path)
            if content:
                # Basic XML parsing for port information
                port_pattern = r'<port protocol="tcp" portid="(\d+)"><state state="open"'
                matches = re.findall(port_pattern, content)
                xml_ports = [int(port) for port in matches]
                
                # Merge with existing results
                all_ports = list(set(results.get("open_ports", []) + xml_ports))
                results["open_ports"] = sorted(all_ports)
                
        except Exception as e:
            self.scan_result.add_warning(f"Could not parse nmap XML output: {e}")
    
    async def _parse_service_info(self, file_path: str, results: Dict[str, Any]) -> None:
        """Parse service version information from XML"""
        try:
            content = await self.safe_file_operation("read", file_path)
            if content:
                # Extract service information using regex
                service_pattern = r'<port protocol="tcp" portid="(\d+)">.*?<service name="([^"]*)".*?version="([^"]*)".*?</port>'
                matches = re.findall(service_pattern, content, re.DOTALL)
                
                for port, service, version in matches:
                    results["services"][port] = {
                        "service": service,
                        "version": version.strip() if version else "unknown"
                    }
                
        except Exception as e:
            self.scan_result.add_warning(f"Could not parse service information: {e}")
    
    async def _parse_os_detection(self, file_path: str) -> Dict[str, Any]:
        """Parse OS detection results"""
        os_info = {"detected": False, "os_matches": [], "accuracy": 0}
        
        try:
            content = await self.safe_file_operation("read", file_path)
            if content:
                # Basic OS detection parsing
                os_pattern = r'<osmatch name="([^"]*)" accuracy="(\d+)"'
                matches = re.findall(os_pattern, content)
                
                if matches:
                    os_info["detected"] = True
                    os_info["os_matches"] = [{"name": name, "accuracy": int(acc)} for name, acc in matches[:3]]
                    os_info["accuracy"] = max([int(acc) for _, acc in matches])
                
        except Exception as e:
            self.scan_result.add_warning(f"Could not parse OS detection: {e}")
        
        return os_info
    
    async def _parse_udp_results(self, file_path: str, results: Dict[str, Any]) -> None:
        """Parse UDP scan results"""
        try:
            content = await self.safe_file_operation("read", file_path)
            if content:
                # Extract UDP ports
                udp_pattern = r'<port protocol="udp" portid="(\d+)"><state state="open"'
                matches = re.findall(udp_pattern, content)
                results["udp_ports"] = [int(port) for port in matches]
                
        except Exception as e:
            self.scan_result.add_warning(f"Could not parse UDP results: {e}")
    
    async def _detect_firewalls(self) -> List[str]:
        """Detect potential firewalls or IDS systems"""
        firewalls = []
        
        try:
            # Use nmap firewall detection scripts
            cmd = [
                "nmap", "--script", "firewalk,firewall-bypass",
                "-p", "21,22,23,25,53,80,110,443,993,995",
                self.config.target
            ]
            
            returncode, stdout, stderr = await self.safe_command_execution(cmd, timeout=60)
            
            if returncode == 0:
                if "firewall" in stdout.lower():
                    firewalls.append("Firewall detected")
                if "filtered" in stdout.lower():
                    firewalls.append("Port filtering detected")
            
        except Exception as e:
            self.scan_result.add_warning(f"Firewall detection failed: {e}")
        
        return firewalls

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
    """Enhanced SSL/TLS security analysis"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform comprehensive SSL/TLS analysis"""
        self.console.print("[cyan]🔍 Starting enhanced SSL/TLS analysis...[/cyan]")
        
        ssl_results = {
            "certificates": {},
            "vulnerabilities": [],
            "cipher_suites": {},
            "protocols": {},
            "certificate_details": {},
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Create output directory
            os.makedirs(f"{self.config.output_dir}/ssl", exist_ok=True)
            
            # Common SSL ports to check
            ssl_ports = [443, 8443, 993, 995, 465, 587, 636, 989, 990]
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                task = progress.add_task("Analyzing SSL/TLS configurations...", total=len(ssl_ports))
                
                for port in ssl_ports:
                    try:
                        # Enhanced SSL analysis using nmap scripts
                        cmd = [
                            "nmap", "--script", 
                            "ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-ccs-injection",
                            "-p", str(port), self.config.target,
                            "-oN", f"{self.config.output_dir}/ssl/ssl_scan_{port}.txt"
                        ]
                        
                        returncode, stdout, stderr = await self.safe_command_execution(cmd)
                        
                        if returncode == 0 and "open" in stdout:
                            ssl_results["certificates"][port] = await self._parse_ssl_output(stdout)
                            
                            # Additional certificate validation
                            cert_details = await self._get_certificate_details(port)
                            if cert_details:
                                ssl_results["certificate_details"][port] = cert_details
                        
                    except Exception as e:
                        self.scan_result.add_warning(f"SSL scan failed for port {port}: {e}")
                    
                    progress.update(task, advance=1)
                
                # Generate security recommendations
                ssl_results["recommendations"] = self._generate_ssl_recommendations(ssl_results)
        
        except Exception as e:
            self.scan_result.add_error(f"SSL scanning failed: {e}")
        
        self.results = ssl_results
        return ssl_results
    
    async def _parse_ssl_output(self, output: str) -> Dict[str, Any]:
        """Parse SSL nmap script output"""
        ssl_info = {"protocols": [], "ciphers": [], "vulnerabilities": []}
        
        try:
            lines = output.split('\n')
            for line in lines:
                line = line.strip()
                if "TLSv" in line or "SSLv" in line:
                    ssl_info["protocols"].append(line)
                elif "cipher" in line.lower():
                    ssl_info["ciphers"].append(line)
                elif any(vuln in line.lower() for vuln in ["vulnerable", "heartbleed", "poodle"]):
                    ssl_info["vulnerabilities"].append(line)
        
        except Exception as e:
            self.scan_result.add_warning(f"SSL output parsing failed: {e}")
        
        return ssl_info
    
    async def _get_certificate_details(self, port: int) -> Dict[str, Any]:
        """Get detailed certificate information"""
        cert_details = {}
        
        try:
            # Use openssl to get certificate details
            cmd = ["openssl", "s_client", "-connect", f"{self.config.target}:{port}", "-servername", self.config.target]
            
            returncode, stdout, stderr = await self.safe_command_execution(cmd, timeout=10)
            
            if returncode == 0 or stdout:  # openssl s_client often returns non-zero even on success
                # Parse certificate information
                if "BEGIN CERTIFICATE" in stdout:
                    cert_details["has_certificate"] = True
                    
                    # Extract basic certificate info
                    if "subject=" in stdout:
                        subject_match = re.search(r'subject=(.+)', stdout)
                        if subject_match:
                            cert_details["subject"] = subject_match.group(1).strip()
                    
                    if "issuer=" in stdout:
                        issuer_match = re.search(r'issuer=(.+)', stdout)
                        if issuer_match:
                            cert_details["issuer"] = issuer_match.group(1).strip()
        
        except Exception as e:
            self.scan_result.add_warning(f"Certificate details extraction failed for port {port}: {e}")
        
        return cert_details
    
    def _generate_ssl_recommendations(self, ssl_results: Dict[str, Any]) -> List[str]:
        """Generate SSL security recommendations"""
        recommendations = []
        
        # Check for common SSL issues
        for port, cert_info in ssl_results.get("certificates", {}).items():
            if cert_info.get("vulnerabilities"):
                recommendations.append(f"Port {port}: Address SSL vulnerabilities detected")
            
            if any("SSLv" in protocol for protocol in cert_info.get("protocols", [])):
                recommendations.append(f"Port {port}: Disable legacy SSL protocols")
                
            if any("TLS_RSA" in cipher for cipher in cert_info.get("ciphers", [])):
                recommendations.append(f"Port {port}: Consider disabling RSA key exchange ciphers")
        
        # General recommendations
        if ssl_results.get("certificates"):
            recommendations.extend([
                "Regularly update SSL/TLS certificates",
                "Implement HTTP Strict Transport Security (HSTS)",
                "Use certificate pinning where appropriate",
                "Monitor certificate expiration dates"
            ])
        
        return recommendations

class IntelligenceGatherer(Scanner):
    """Advanced intelligence gathering and OSINT capabilities"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform comprehensive intelligence gathering"""
        if not self.config.intelligence_enabled:
            return {}
            
        self.console.print("[cyan]🔍 Starting intelligence gathering...[/cyan]")
        
        intel_results = {
            "domain_intelligence": {},
            "threat_intelligence": {},
            "social_media": {},
            "breach_data": {},
            "related_domains": [],
            "technologies": {},
            "emails": [],
            "ip_intelligence": {},
            "geolocation": {}
        }
        
        try:
            # Create output directory
            os.makedirs(f"{self.config.output_dir}/intelligence", exist_ok=True)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                total_tasks = 5
                task = progress.add_task("Gathering intelligence...", total=total_tasks)
                
                # Domain intelligence
                progress.update(task, description="Gathering domain intelligence...")
                intel_results["domain_intelligence"] = await self._gather_domain_intel()
                progress.update(task, advance=1)
                
                # Technology fingerprinting
                progress.update(task, description="Analyzing technologies...")
                intel_results["technologies"] = await self._analyze_technologies()
                progress.update(task, advance=1)
                
                # Related domains and infrastructure
                progress.update(task, description="Finding related infrastructure...")
                intel_results["related_domains"] = await self._find_related_domains()
                progress.update(task, advance=1)
                
                # Email harvesting
                progress.update(task, description="Harvesting email addresses...")
                intel_results["emails"] = await self._harvest_emails()
                progress.update(task, advance=1)
                
                # IP intelligence and geolocation
                progress.update(task, description="Analyzing IP intelligence...")
                intel_results["ip_intelligence"] = await self._gather_ip_intel()
                intel_results["geolocation"] = await self._get_geolocation()
                progress.update(task, advance=1)
                
                # Save intelligence report
                await self._save_intelligence_report(intel_results)
        
        except Exception as e:
            self.scan_result.add_error(f"Intelligence gathering failed: {e}")
        
        self.results = intel_results
        return intel_results
    
    async def _gather_domain_intel(self) -> Dict[str, Any]:
        """Gather domain intelligence"""
        domain_intel = {"creation_date": None, "registrar": None, "nameservers": [], "status": []}
        
        try:
            # Enhanced WHOIS analysis
            cmd = ["whois", self.config.target]
            returncode, stdout, stderr = await self.safe_command_execution(cmd)
            
            if returncode == 0 and stdout:
                whois_data = stdout.lower()
                
                # Extract creation date
                creation_patterns = [r'creation date:\s*(.+)', r'created:\s*(.+)', r'domain created:\s*(.+)']
                for pattern in creation_patterns:
                    match = re.search(pattern, whois_data)
                    if match:
                        domain_intel["creation_date"] = match.group(1).strip()
                        break
                
                # Extract registrar
                registrar_match = re.search(r'registrar:\s*(.+)', whois_data)
                if registrar_match:
                    domain_intel["registrar"] = registrar_match.group(1).strip()
                
                # Extract nameservers
                ns_matches = re.findall(r'name server:\s*(.+)', whois_data)
                domain_intel["nameservers"] = [ns.strip() for ns in ns_matches]
        
        except Exception as e:
            self.scan_result.add_warning(f"Domain intelligence gathering failed: {e}")
        
        return domain_intel
    
    async def _analyze_technologies(self) -> Dict[str, Any]:
        """Analyze web technologies in use"""
        tech_info = {"web_servers": [], "frameworks": [], "cms": [], "analytics": []}
        
        try:
            # Use whatweb for technology detection
            cmd = ["whatweb", "--color=never", "--log-brief", "-", f"http://{self.config.target}"]
            returncode, stdout, stderr = await self.safe_command_execution(cmd)
            
            if returncode == 0 and stdout:
                # Parse whatweb output
                if "apache" in stdout.lower():
                    tech_info["web_servers"].append("Apache")
                if "nginx" in stdout.lower():
                    tech_info["web_servers"].append("Nginx")
                if "iis" in stdout.lower():
                    tech_info["web_servers"].append("IIS")
                    
                # Look for common frameworks
                frameworks = ["wordpress", "drupal", "joomla", "django", "flask", "rails"]
                for framework in frameworks:
                    if framework in stdout.lower():
                        tech_info["frameworks"].append(framework.capitalize())
        
        except Exception as e:
            self.scan_result.add_warning(f"Technology analysis failed: {e}")
        
        return tech_info
    
    async def _find_related_domains(self) -> List[str]:
        """Find related domains and infrastructure"""
        related_domains = []
        
        try:
            # Look for domains on same IP
            cmd = ["dig", "+short", "A", self.config.target]
            returncode, stdout, stderr = await self.safe_command_execution(cmd)
            
            if returncode == 0 and stdout.strip():
                ip_address = stdout.strip().split('\n')[0]
                
                # Reverse DNS lookup
                cmd = ["dig", "+short", "-x", ip_address]
                returncode, stdout, stderr = await self.safe_command_execution(cmd)
                
                if returncode == 0 and stdout.strip():
                    reverse_domains = stdout.strip().split('\n')
                    related_domains.extend([d.rstrip('.') for d in reverse_domains if d != self.config.target])
        
        except Exception as e:
            self.scan_result.add_warning(f"Related domain discovery failed: {e}")
        
        return related_domains
    
    async def _harvest_emails(self) -> List[str]:
        """Harvest email addresses from public sources"""
        emails = []
        
        try:
            # Simple email pattern matching from web content
            if HAS_ENHANCED_LIBS:
                async with aiohttp.ClientSession() as session:
                    try:
                        async with session.get(f"http://{self.config.target}", timeout=10) as response:
                            if response.status == 200:
                                content = await response.text()
                                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                                found_emails = re.findall(email_pattern, content)
                                emails.extend(list(set(found_emails)))  # Remove duplicates
                    except:
                        pass  # Fail silently for web scraping
        
        except Exception as e:
            self.scan_result.add_warning(f"Email harvesting failed: {e}")
        
        return emails
    
    async def _gather_ip_intel(self) -> Dict[str, Any]:
        """Gather IP address intelligence"""
        ip_intel = {"ip_address": None, "asn": None, "organization": None, "country": None}
        
        try:
            # Get IP address
            cmd = ["dig", "+short", "A", self.config.target]
            returncode, stdout, stderr = await self.safe_command_execution(cmd)
            
            if returncode == 0 and stdout.strip():
                ip_address = stdout.strip().split('\n')[0]
                ip_intel["ip_address"] = ip_address
                
                # Get ASN information using whois
                cmd = ["whois", ip_address]
                returncode, stdout, stderr = await self.safe_command_execution(cmd)
                
                if returncode == 0 and stdout:
                    whois_data = stdout.lower()
                    
                    # Extract ASN
                    asn_match = re.search(r'as(\d+)', whois_data)
                    if asn_match:
                        ip_intel["asn"] = f"AS{asn_match.group(1)}"
                    
                    # Extract organization
                    org_patterns = [r'orgname:\s*(.+)', r'organization:\s*(.+)', r'org:\s*(.+)']
                    for pattern in org_patterns:
                        match = re.search(pattern, whois_data)
                        if match:
                            ip_intel["organization"] = match.group(1).strip()
                            break
                    
                    # Extract country
                    country_match = re.search(r'country:\s*(.+)', whois_data)
                    if country_match:
                        ip_intel["country"] = country_match.group(1).strip()
        
        except Exception as e:
            self.scan_result.add_warning(f"IP intelligence gathering failed: {e}")
        
        return ip_intel
    
    async def _get_geolocation(self) -> Dict[str, Any]:
        """Get geolocation information"""
        geo_info = {"country": None, "region": None, "city": None, "timezone": None}
        
        try:
            # This would typically use a geolocation API
            # For now, we'll extract what we can from WHOIS data
            if self.results.get("ip_intelligence", {}).get("country"):
                geo_info["country"] = self.results["ip_intelligence"]["country"]
        
        except Exception as e:
            self.scan_result.add_warning(f"Geolocation lookup failed: {e}")
        
        return geo_info
    
    async def _save_intelligence_report(self, intel_results: Dict[str, Any]) -> None:
        """Save intelligence gathering report"""
        try:
            report_content = json.dumps(intel_results, indent=2)
            await self.safe_file_operation("write", 
                f"{self.config.output_dir}/intelligence/intelligence_report.json", report_content)
            
            # Create human-readable summary
            summary = self._create_intelligence_summary(intel_results)
            await self.safe_file_operation("write", 
                f"{self.config.output_dir}/intelligence/intelligence_summary.txt", summary)
        
        except Exception as e:
            self.scan_result.add_error(f"Failed to save intelligence report: {e}")
    
    def _create_intelligence_summary(self, intel_results: Dict[str, Any]) -> str:
        """Create human-readable intelligence summary"""
        summary = f"Intelligence Gathering Summary for {self.config.target}\n"
        summary += "=" * 60 + "\n\n"
        
        # Domain intelligence
        domain_intel = intel_results.get("domain_intelligence", {})
        if domain_intel:
            summary += "Domain Intelligence:\n"
            if domain_intel.get("creation_date"):
                summary += f"  Creation Date: {domain_intel['creation_date']}\n"
            if domain_intel.get("registrar"):
                summary += f"  Registrar: {domain_intel['registrar']}\n"
            summary += "\n"
        
        # IP intelligence
        ip_intel = intel_results.get("ip_intelligence", {})
        if ip_intel:
            summary += "IP Intelligence:\n"
            if ip_intel.get("ip_address"):
                summary += f"  IP Address: {ip_intel['ip_address']}\n"
            if ip_intel.get("organization"):
                summary += f"  Organization: {ip_intel['organization']}\n"
            if ip_intel.get("country"):
                summary += f"  Country: {ip_intel['country']}\n"
            summary += "\n"
        
        # Technologies
        technologies = intel_results.get("technologies", {})
        if any(technologies.values()):
            summary += "Technologies Detected:\n"
            for tech_type, tech_list in technologies.items():
                if tech_list:
                    summary += f"  {tech_type.title()}: {', '.join(tech_list)}\n"
            summary += "\n"
        
        # Related domains
        related_domains = intel_results.get("related_domains", [])
        if related_domains:
            summary += f"Related Domains ({len(related_domains)}):\n"
            for domain in related_domains[:10]:  # Limit to first 10
                summary += f"  - {domain}\n"
            summary += "\n"
        
        # Email addresses
        emails = intel_results.get("emails", [])
        if emails:
            summary += f"Email Addresses Found ({len(emails)}):\n"
            for email in emails[:10]:  # Limit to first 10
                summary += f"  - {email}\n"
            summary += "\n"
        
        return summary

class APIDiscoveryScanner(Scanner):
    """API endpoint discovery and analysis"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform API discovery scanning"""
        if not self.config.api_discovery_enabled:
            return {}
            
        self.console.print("[cyan]🔍 Starting API discovery...[/cyan]")
        
        api_results = {
            "endpoints": [],
            "api_types": [],
            "swagger_docs": [],
            "graphql_endpoints": [],
            "rest_endpoints": [],
            "authentication_methods": [],
            "rate_limiting": {},
            "security_headers": {}
        }
        
        try:
            # Create output directory
            os.makedirs(f"{self.config.output_dir}/api_discovery", exist_ok=True)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                task = progress.add_task("Discovering API endpoints...", total=100)
                
                # Common API paths
                api_paths = [
                    "/api", "/api/v1", "/api/v2", "/rest", "/restapi",
                    "/graphql", "/v1", "/v2", "/swagger", "/docs",
                    "/api-docs", "/openapi.json", "/swagger.json",
                    "/api/swagger", "/api/docs", "/documentation"
                ]
                
                progress.update(task, advance=20, description="Testing common API paths...")
                api_results["endpoints"] = await self._test_api_paths(api_paths)
                
                progress.update(task, advance=30, description="Looking for API documentation...")
                api_results["swagger_docs"] = await self._find_api_docs()
                
                progress.update(task, advance=25, description="Testing for GraphQL...")
                api_results["graphql_endpoints"] = await self._test_graphql()
                
                progress.update(task, advance=25, description="Analyzing API security...")
                api_results["security_headers"] = await self._analyze_api_security()
                
                # Save API discovery results
                await self._save_api_report(api_results)
        
        except Exception as e:
            self.scan_result.add_error(f"API discovery failed: {e}")
        
        self.results = api_results
        return api_results
    
    async def _test_api_paths(self, paths: List[str]) -> List[Dict[str, Any]]:
        """Test common API paths"""
        found_endpoints = []
        
        if not HAS_ENHANCED_LIBS:
            return found_endpoints
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                for path in paths:
                    try:
                        url = f"http://{self.config.target}{path}"
                        async with session.get(url) as response:
                            if response.status in [200, 401, 403]:  # Potentially valid endpoints
                                endpoint_info = {
                                    "url": url,
                                    "status": response.status,
                                    "content_type": response.headers.get("content-type", ""),
                                    "methods": []
                                }
                                
                                # Test different HTTP methods
                                for method in ["GET", "POST", "PUT", "DELETE", "OPTIONS"]:
                                    try:
                                        async with session.request(method, url) as method_response:
                                            if method_response.status != 404:
                                                endpoint_info["methods"].append(method)
                                    except:
                                        pass
                                
                                found_endpoints.append(endpoint_info)
                                
                        # Rate limiting
                        if self.config.rate_limiting:
                            await asyncio.sleep(0.1)
                            
                    except Exception as e:
                        self.scan_result.add_warning(f"Failed to test API path {path}: {e}")
        
        except Exception as e:
            self.scan_result.add_warning(f"API path testing failed: {e}")
        
        return found_endpoints
    
    async def _find_api_docs(self) -> List[str]:
        """Find API documentation"""
        docs_found = []
        
        doc_paths = [
            "/swagger-ui", "/swagger-ui/", "/docs", "/documentation",
            "/api/docs", "/redoc", "/rapidoc", "/openapi.json",
            "/swagger.json", "/api.json", "/schema.json"
        ]
        
        if not HAS_ENHANCED_LIBS:
            return docs_found
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                for doc_path in doc_paths:
                    try:
                        url = f"http://{self.config.target}{doc_path}"
                        async with session.get(url) as response:
                            if response.status == 200:
                                content_type = response.headers.get("content-type", "")
                                if "json" in content_type or "html" in content_type:
                                    docs_found.append(url)
                    except:
                        pass
        
        except Exception as e:
            self.scan_result.add_warning(f"API documentation discovery failed: {e}")
        
        return docs_found
    
    async def _test_graphql(self) -> List[str]:
        """Test for GraphQL endpoints"""
        graphql_endpoints = []
        
        graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
        
        if not HAS_ENHANCED_LIBS:
            return graphql_endpoints
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                for path in graphql_paths:
                    try:
                        url = f"http://{self.config.target}{path}"
                        
                        # Test with a simple GraphQL introspection query
                        graphql_query = {"query": "{ __schema { types { name } } }"}
                        
                        async with session.post(url, json=graphql_query) as response:
                            if response.status == 200:
                                response_text = await response.text()
                                if "__schema" in response_text or "types" in response_text:
                                    graphql_endpoints.append(url)
                    except:
                        pass
        
        except Exception as e:
            self.scan_result.add_warning(f"GraphQL testing failed: {e}")
        
        return graphql_endpoints
    
    async def _analyze_api_security(self) -> Dict[str, Any]:
        """Analyze API security headers and configurations"""
        security_info = {
            "cors_enabled": False,
            "auth_headers": [],
            "security_headers": [],
            "rate_limiting_detected": False
        }
        
        if not HAS_ENHANCED_LIBS:
            return security_info
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                url = f"http://{self.config.target}/api"
                
                try:
                    async with session.options(url) as response:
                        headers = response.headers
                        
                        # Check CORS
                        if "access-control-allow-origin" in headers:
                            security_info["cors_enabled"] = True
                        
                        # Check security headers
                        security_headers = [
                            "x-content-type-options", "x-frame-options",
                            "strict-transport-security", "content-security-policy"
                        ]
                        
                        for header in security_headers:
                            if header in headers:
                                security_info["security_headers"].append(header)
                        
                        # Check authentication headers
                        auth_headers = ["www-authenticate", "authorization"]
                        for header in auth_headers:
                            if header in headers:
                                security_info["auth_headers"].append(header)
                
                except:
                    pass
        
        except Exception as e:
            self.scan_result.add_warning(f"API security analysis failed: {e}")
        
        return security_info
    
    async def _save_api_report(self, api_results: Dict[str, Any]) -> None:
        """Save API discovery report"""
        try:
            report_content = json.dumps(api_results, indent=2)
            await self.safe_file_operation("write", 
                f"{self.config.output_dir}/api_discovery/api_report.json", report_content)
            
            # Create summary
            summary = self._create_api_summary(api_results)
            await self.safe_file_operation("write", 
                f"{self.config.output_dir}/api_discovery/api_summary.txt", summary)
        
        except Exception as e:
            self.scan_result.add_error(f"Failed to save API report: {e}")
    
    def _create_api_summary(self, api_results: Dict[str, Any]) -> str:
        """Create API discovery summary"""
        summary = f"API Discovery Summary for {self.config.target}\n"
        summary += "=" * 50 + "\n\n"
        
        endpoints = api_results.get("endpoints", [])
        if endpoints:
            summary += f"API Endpoints Found ({len(endpoints)}):\n"
            for endpoint in endpoints:
                summary += f"  - {endpoint['url']} (Status: {endpoint['status']})\n"
                if endpoint.get("methods"):
                    summary += f"    Methods: {', '.join(endpoint['methods'])}\n"
            summary += "\n"
        
        swagger_docs = api_results.get("swagger_docs", [])
        if swagger_docs:
            summary += "API Documentation:\n"
            for doc in swagger_docs:
                summary += f"  - {doc}\n"
            summary += "\n"
        
        graphql = api_results.get("graphql_endpoints", [])
        if graphql:
            summary += "GraphQL Endpoints:\n"
            for endpoint in graphql:
                summary += f"  - {endpoint}\n"
            summary += "\n"
        
        return summary

class RiskAnalyzer:
    """Advanced risk analysis and assessment engine"""
    
    def __init__(self, console: Console):
        self.console = console
        
    def analyze_scan_results(self, scan_results: Dict[str, ScanResult]) -> Dict[str, Any]:
        """Comprehensive risk analysis of all scan results"""
        self.console.print("[cyan]🔍 Performing risk analysis...[/cyan]")
        
        risk_analysis = {
            "overall_risk_score": 0.0,
            "risk_level": "unknown",
            "critical_findings": [],
            "high_risk_findings": [],
            "medium_risk_findings": [],
            "low_risk_findings": [],
            "recommendations": [],
            "attack_vectors": [],
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        }
        
        try:
            # Analyze each scanner's results
            for scanner_name, scan_result in scan_results.items():
                if scan_result.status == "completed" and scan_result.data:
                    scanner_risks = self._analyze_scanner_risks(scanner_name, scan_result.data)
                    self._merge_risk_findings(risk_analysis, scanner_risks)
            
            # Calculate overall risk score
            risk_analysis["overall_risk_score"] = self._calculate_risk_score(risk_analysis)
            risk_analysis["risk_level"] = self._determine_risk_level(risk_analysis["overall_risk_score"])
            
            # Generate recommendations
            risk_analysis["recommendations"] = self._generate_recommendations(risk_analysis)
            
            # Identify attack vectors
            risk_analysis["attack_vectors"] = self._identify_attack_vectors(scan_results)
            
        except Exception as e:
            logging.error(f"Risk analysis failed: {e}")
        
        return risk_analysis
    
    def _analyze_scanner_risks(self, scanner_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze risks from specific scanner results"""
        risks = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        
        if scanner_name == "Ports":
            open_ports = data.get("open_ports", [])
            high_risk_ports = [21, 23, 25, 53, 135, 139, 445, 1433, 3389, 5900]
            for port in open_ports:
                if port in high_risk_ports:
                    risks["high"].append(f"High-risk port {port} is open")
        elif scanner_name == "DNS":
            if data.get("zone_transfer"):
                risks["high"].append("DNS zone transfer is enabled")
        elif scanner_name == "Vulnerabilities":
            nmap_vulns = data.get("nmap_vulns", [])
            for vuln in nmap_vulns:
                risks["medium"].append(f"Vulnerability detected: {vuln}")
        
        return risks
    
    def _merge_risk_findings(self, risk_analysis: Dict[str, Any], scanner_risks: Dict[str, Any]) -> None:
        """Merge scanner risks into overall risk analysis"""
        for severity in ["critical", "high", "medium", "low", "info"]:
            risk_analysis[f"{severity}_risk_findings"].extend(scanner_risks.get(severity, []))
            risk_analysis["severity_breakdown"][severity] += len(scanner_risks.get(severity, []))
    
    def _calculate_risk_score(self, risk_analysis: Dict[str, Any]) -> float:
        """Calculate overall risk score (0-10 scale)"""
        breakdown = risk_analysis["severity_breakdown"]
        
        if sum(breakdown.values()) == 0:
            return 0.0
        
        score = (
            breakdown["critical"] * 10.0 +
            breakdown["high"] * 7.5 +
            breakdown["medium"] * 5.0 +
            breakdown["low"] * 2.5 +
            breakdown["info"] * 1.0
        ) / sum(breakdown.values())
        
        return min(10.0, score)
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score"""
        if risk_score >= 8.0:
            return "critical"
        elif risk_score >= 6.0:
            return "high"
        elif risk_score >= 4.0:
            return "medium"
        elif risk_score >= 2.0:
            return "low"
        else:
            return "minimal"
    
    def _generate_recommendations(self, risk_analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if risk_analysis["severity_breakdown"]["critical"] > 0:
            recommendations.append("URGENT: Address critical vulnerabilities immediately")
        if risk_analysis["severity_breakdown"]["high"] > 0:
            recommendations.append("High priority: Patch high-severity vulnerabilities")
        
        recommendations.extend([
            "Implement regular security assessments",
            "Keep all software and systems updated",
            "Monitor security logs and implement alerting"
        ])
        
        return recommendations
    
    def _identify_attack_vectors(self, scan_results: Dict[str, ScanResult]) -> List[str]:
        """Identify potential attack vectors"""
        attack_vectors = []
        
        if "Ports" in scan_results and scan_results["Ports"].data:
            open_ports = scan_results["Ports"].data.get("open_ports", [])
            if 22 in open_ports:
                attack_vectors.append("SSH brute force attacks")
            if 80 in open_ports or 443 in open_ports:
                attack_vectors.append("Web application attacks")
        
        return attack_vectors

class ReportGenerator:
    """Advanced report generation with multiple formats"""
    
    def __init__(self, config: BCARConfig, console: Console):
        self.config = config
        self.console = console
        
    async def generate_comprehensive_report(self, scan_results: Dict[str, ScanResult], risk_analysis: Dict[str, Any]) -> None:
        """Generate comprehensive security assessment report"""
        self.console.print("[cyan]📊 Generating comprehensive report...[/cyan]")
        
        try:
            # Create reports directory
            os.makedirs(f"{self.config.output_dir}/reports", exist_ok=True)
            
            # Generate different report formats
            if self.config.output_format in ["json", "both"]:
                await self._generate_json_report(scan_results, risk_analysis)
            
            if self.config.output_format in ["txt", "both"]:
                await self._generate_text_report(scan_results, risk_analysis)
            
            if self.config.executive_summary:
                await self._generate_executive_summary(risk_analysis)
            
            self.console.print("[green]✓ Reports generated successfully[/green]")
            
        except Exception as e:
            logging.error(f"Report generation failed: {e}")
    
    async def _generate_json_report(self, scan_results: Dict[str, ScanResult], risk_analysis: Dict[str, Any]) -> None:
        """Generate JSON report"""
        report_data = {
            "scan_metadata": {
                "target": self.config.target,
                "scan_date": datetime.now().isoformat(),
                "scan_profile": self.config.scan_profile
            },
            "risk_analysis": risk_analysis,
            "scan_results": {
                name: {
                    "status": result.status,
                    "duration": result.duration(),
                    "data": result.data
                } for name, result in scan_results.items()
            }
        }
        
        content = json.dumps(report_data, indent=2, default=str)
        with open(f"{self.config.output_dir}/reports/comprehensive_report.json", 'w') as f:
            f.write(content)
    
    async def _generate_text_report(self, scan_results: Dict[str, ScanResult], risk_analysis: Dict[str, Any]) -> None:
        """Generate text report"""
        report_lines = [
            "=" * 80,
            "BCAR SECURITY ASSESSMENT REPORT",
            "=" * 80,
            "",
            f"Target: {self.config.target}",
            f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Risk Level: {risk_analysis.get('risk_level', 'Unknown').upper()}",
            f"Overall Risk Score: {risk_analysis.get('overall_risk_score', 0):.1f}/10",
            ""
        ]
        
        content = "\n".join(report_lines)
        with open(f"{self.config.output_dir}/reports/security_assessment_report.txt", 'w') as f:
            f.write(content)
    
    async def _generate_executive_summary(self, risk_analysis: Dict[str, Any]) -> None:
        """Generate executive summary"""
        summary_lines = [
            "EXECUTIVE SUMMARY",
            "=" * 50,
            "",
            f"Target System: {self.config.target}",
            f"Risk Level: {risk_analysis.get('risk_level', 'Unknown').upper()}",
            f"Risk Score: {risk_analysis.get('overall_risk_score', 0):.1f}/10"
        ]
        
        content = "\n".join(summary_lines)
        with open(f"{self.config.output_dir}/reports/executive_summary.txt", 'w') as f:
            f.write(content)

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
            "SSL": SSLScanner,
            "Intelligence": IntelligenceGatherer,
            "API_Discovery": APIDiscoveryScanner
        }
        self.scan_results: Dict[str, ScanResult] = {}
        self.overall_scan_start: Optional[datetime] = None
        
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
        """Start the enhanced reconnaissance scan with risk analysis"""
        if not self.config.target:
            self.console.print("[red]✗ No target configured! Please set a target first.[/red]")
            Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
            return
        
        self.console.clear()
        self.console.print("[cyan]═══ Enhanced Scan Summary ═══[/cyan]\n")
        
        summary_table = Table(box=box.ROUNDED)
        summary_table.add_column("Setting", style="white")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Target", self.config.target)
        summary_table.add_row("Scan Profile", self.config.scan_profile)
        summary_table.add_row("Output Directory", self.config.output_dir)
        summary_table.add_row("Threads", str(self.config.threads))
        summary_table.add_row("Timing", self.config.timing)
        summary_table.add_row("Stealth Mode", "Yes" if self.config.stealth_mode else "No")
        summary_table.add_row("Intelligence Gathering", "Yes" if self.config.intelligence_enabled else "No")
        summary_table.add_row("API Discovery", "Yes" if self.config.api_discovery_enabled else "No")
        
        self.console.print(summary_table)
        
        if not Confirm.ask("\n[yellow]Start enhanced reconnaissance scan?[/yellow]"):
            return
        
        # Validate configuration
        config_issues = self.config.validate_config()
        if config_issues:
            self.console.print("[red]Configuration issues found:[/red]")
            for issue in config_issues:
                self.console.print(f"  - {issue}")
            if not Confirm.ask("Continue with current configuration?"):
                return
        
        # Create output directory
        os.makedirs(self.config.output_dir, exist_ok=True)
        
        # Initialize enhanced results tracking
        self.scan_results = {}
        self.overall_scan_start = datetime.now()
        
        # Determine which scanners to run based on configuration
        selected_scanners = ["DNS", "WHOIS", "Ports"]
        
        # Add optional scanners based on configuration
        if self.config.intelligence_enabled:
            selected_scanners.append("Intelligence")
        
        selected_scanners.extend(["Web"])
        
        if self.config.dom_scan_enabled:
            selected_scanners.append("DOM")
        
        if self.config.api_discovery_enabled:
            selected_scanners.append("API_Discovery")
            
        selected_scanners.extend(["Vulnerabilities", "SSL"])
        
        self.console.print(f"\n[green]🚀 Starting enhanced scan against {self.config.target}...[/green]")
        self.console.print(f"[cyan]Scanners: {', '.join(selected_scanners)}[/cyan]\n")
        
        # Execute scanners with enhanced error handling
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            
            main_task = progress.add_task("Overall Progress", total=len(selected_scanners) + 2)  # +2 for analysis and reporting
            
            for scanner_name in selected_scanners:
                scanner_class = self.scanners[scanner_name]
                scanner = scanner_class(self.config, self.console)
                
                # Run scanner with enhanced error handling
                scan_result = await scanner.run_with_error_handling()
                self.scan_results[scanner_name] = scan_result
                
                progress.update(main_task, advance=1, description=f"Completed {scanner_name}")
            
            # Perform risk analysis
            progress.update(main_task, description="Performing risk analysis...")
            risk_analyzer = RiskAnalyzer(self.console)
            risk_analysis = risk_analyzer.analyze_scan_results(self.scan_results)
            progress.update(main_task, advance=1)
            
            # Generate comprehensive reports
            progress.update(main_task, description="Generating reports...")
            report_generator = ReportGenerator(self.config, self.console)
            await report_generator.generate_comprehensive_report(self.scan_results, risk_analysis)
            progress.update(main_task, advance=1)
        
        # Display enhanced summary with risk analysis
        await self._display_enhanced_summary(risk_analysis)
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    async def _display_enhanced_summary(self, risk_analysis: Dict[str, Any]):
        """Display enhanced scan summary with risk analysis"""
        self.console.clear()
        self.console.print("[cyan]═══ Enhanced Scan Results ═══[/cyan]\n")
        
        # Overall scan metrics
        total_duration = (datetime.now() - self.overall_scan_start).total_seconds()
        completed_scanners = sum(1 for result in self.scan_results.values() if result.status == "completed")
        failed_scanners = sum(1 for result in self.scan_results.values() if result.status == "failed")
        
        # Scan summary table
        summary_table = Table(title="Scan Summary", box=box.ROUNDED)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="white")
        
        summary_table.add_row("Target", self.config.target)
        summary_table.add_row("Total Duration", f"{total_duration:.1f}s")
        summary_table.add_row("Scanners Completed", f"{completed_scanners}/{len(self.scan_results)}")
        summary_table.add_row("Scanners Failed", str(failed_scanners))
        summary_table.add_row("Output Directory", self.config.output_dir)
        
        self.console.print(summary_table)
        self.console.print()
        
        # Risk analysis summary
        risk_level = risk_analysis.get("risk_level", "unknown")
        risk_score = risk_analysis.get("overall_risk_score", 0)
        
        # Color-code risk level
        risk_colors = {
            "critical": "red",
            "high": "orange",
            "medium": "yellow", 
            "low": "green",
            "minimal": "bright_green"
        }
        risk_color = risk_colors.get(risk_level, "white")
        
        risk_table = Table(title="Risk Assessment", box=box.ROUNDED)
        risk_table.add_column("Risk Metric", style="cyan")
        risk_table.add_column("Value", style="white")
        
        risk_table.add_row("Overall Risk Level", f"[{risk_color}]{risk_level.upper()}[/{risk_color}]")
        risk_table.add_row("Risk Score", f"{risk_score:.1f}/10")
        
        # Severity breakdown
        breakdown = risk_analysis["severity_breakdown"]
        risk_table.add_row("Critical Findings", f"[red]{breakdown['critical']}[/red]")
        risk_table.add_row("High Risk Findings", f"[orange]{breakdown['high']}[/orange]")
        risk_table.add_row("Medium Risk Findings", f"[yellow]{breakdown['medium']}[/yellow]")
        risk_table.add_row("Low Risk Findings", f"[green]{breakdown['low']}[/green]")
        
        self.console.print(risk_table)
        self.console.print()
        
        # Top recommendations
        recommendations = risk_analysis.get("recommendations", [])
        if recommendations:
            rec_table = Table(title="Top Security Recommendations", box=box.ROUNDED)
            rec_table.add_column("#", style="cyan", width=3)
            rec_table.add_column("Recommendation", style="white")
            
            for i, rec in enumerate(recommendations[:5], 1):
                rec_table.add_row(str(i), rec)
            
            self.console.print(rec_table)
            self.console.print()
        
        # Scanner status
        scanner_table = Table(title="Scanner Results", box=box.ROUNDED)
        scanner_table.add_column("Scanner", style="cyan")
        scanner_table.add_column("Status", style="white")
        scanner_table.add_column("Duration", style="white")
        scanner_table.add_column("Findings", style="white")
        
        for scanner_name, result in self.scan_results.items():
            status_style = "green" if result.status == "completed" else "red"
            status_text = f"[{status_style}]{result.status}[/{status_style}]"
            
            # Count findings
            findings_count = 0
            if result.data:
                # Simple heuristic to count findings
                findings_count = sum(len(v) if isinstance(v, list) else 1 for v in result.data.values() if v)
            
            scanner_table.add_row(
                scanner_name,
                status_text,
                f"{result.duration():.1f}s",
                str(findings_count)
            )
        
        self.console.print(scanner_table)
        
        # Critical findings alert
        critical_findings = risk_analysis.get("critical_findings", [])
        if critical_findings:
            self.console.print()
            self.console.print(Panel(
                "\n".join([f"• {finding}" for finding in critical_findings[:5]]),
                title="[red bold]⚠️  CRITICAL SECURITY ISSUES ⚠️[/red bold]",
                border_style="red"
            ))
        
        # Success message
        self.console.print(f"\n[green]✅ Enhanced scan completed successfully![/green]")
        self.console.print(f"[green]📁 All results saved to: {self.config.output_dir}[/green]")
        
        if risk_level in ["critical", "high"]:
            self.console.print(f"[red]⚠️  URGENT: This system requires immediate security attention![/red]")
        elif risk_level == "medium":
            self.console.print(f"[yellow]⚠️  NOTICE: Security improvements recommended[/yellow]")
    
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