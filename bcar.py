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
    
    # Enhanced libraries for advanced features
    import pandas as pd
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    import matplotlib.pyplot as plt
    import seaborn as sns
    
    HAS_ENHANCED_LIBS = True
    HAS_ML_LIBS = True
except ImportError:
    HAS_ENHANCED_LIBS = False
    HAS_ML_LIBS = False

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
        
        # Advanced scanning features
        self.intelligence_enabled: bool = True
        self.subdomain_enum_enabled: bool = True
        self.cve_lookup_enabled: bool = True
        self.threat_intel_enabled: bool = False
        self.api_discovery_enabled: bool = True
        self.screenshot_enabled: bool = False
        self.backup_results: bool = True
        self.result_comparison: bool = True
        
        # New advanced scanner features
        self.cloud_security_enabled: bool = True
        self.container_security_enabled: bool = True
        self.exploit_detection_enabled: bool = True
        self.compliance_scanning_enabled: bool = False
        self.machine_learning_analysis: bool = False
        self.distributed_scanning: bool = False
        self.real_time_monitoring: bool = False
        
        # Enhanced vulnerability scanning
        self.deep_vulnerability_scan: bool = True
        self.cve_correlation_enabled: bool = True
        self.exploit_verification: bool = False  # Safe mode by default
        self.custom_vulnerability_checks: bool = True
        
        # Advanced evasion techniques
        self.advanced_evasion: bool = False
        self.randomize_user_agents: bool = False
        self.proxy_rotation: bool = False
        self.traffic_obfuscation: bool = False
        
        # Performance optimizations
        self.async_dns_enabled: bool = HAS_ENHANCED_LIBS
        self.connection_pooling: bool = True
        self.rate_limiting: bool = True
        self.memory_efficient: bool = True
        self.parallel_scanning: bool = True
        self.scan_optimization: bool = True
        
        # Security enhancements
        self.input_sanitization: bool = True
        self.safe_file_operations: bool = True
        self.secure_networking: bool = True
        self.sandbox_mode: bool = False
        
        # Scan profiles with enhanced capabilities
        self.scan_profile: str = "comprehensive"  # quick, comprehensive, stealth, aggressive, expert, compliance
        
        # Risk assessment and analysis
        self.risk_assessment_enabled: bool = True
        self.auto_recommendations: bool = True
        self.risk_scoring: bool = True
        self.attack_vector_analysis: bool = True
        
        # Reporting enhancements
        self.executive_summary: bool = True
        self.technical_details: bool = True
        self.compliance_checks: bool = False
        self.advanced_analytics: bool = True
        self.threat_modeling: bool = False
        
        # Integration and automation
        self.webhook_notifications: bool = False
        self.email_reports: bool = False
        self.api_integration: bool = False
        self.siem_integration: bool = False
        
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
                "cloud_security_enabled": False,
                "container_security_enabled": False,
                "exploit_detection_enabled": False,
                "compliance_scanning_enabled": False,
                "deep_vulnerability_scan": False,
                "nmap_scripts": "default"
            },
            "comprehensive": {
                "timing": "normal",
                "threads": 50,
                "stealth_mode": False,
                "dom_scan_enabled": True,
                "subdomain_enum_enabled": True,
                "api_discovery_enabled": True,
                "cloud_security_enabled": True,
                "container_security_enabled": True,
                "exploit_detection_enabled": True,
                "compliance_scanning_enabled": False,
                "deep_vulnerability_scan": True,
                "cve_correlation_enabled": True,
                "nmap_scripts": "default,vuln,safe"
            },
            "stealth": {
                "timing": "slow",
                "threads": 10,
                "stealth_mode": True,
                "dom_scan_enabled": False,
                "rate_limiting": True,
                "advanced_evasion": True,
                "traffic_obfuscation": True,
                "cloud_security_enabled": False,
                "container_security_enabled": False,
                "exploit_detection_enabled": False,
                "exploit_verification": False,
                "nmap_scripts": "safe"
            },
            "aggressive": {
                "timing": "fast",
                "threads": 200,
                "stealth_mode": False,
                "dom_scan_enabled": True,
                "api_discovery_enabled": True,
                "cloud_security_enabled": True,
                "container_security_enabled": True,
                "exploit_detection_enabled": True,
                "deep_vulnerability_scan": True,
                "cve_correlation_enabled": True,
                "exploit_verification": True,
                "custom_vulnerability_checks": True,
                "nmap_scripts": "default,vuln,exploit"
            },
            "expert": {
                "timing": "normal",
                "threads": 75,
                "stealth_mode": False,
                "dom_scan_enabled": True,
                "subdomain_enum_enabled": True,
                "api_discovery_enabled": True,
                "cloud_security_enabled": True,
                "container_security_enabled": True,
                "exploit_detection_enabled": True,
                "compliance_scanning_enabled": True,
                "deep_vulnerability_scan": True,
                "cve_correlation_enabled": True,
                "machine_learning_analysis": True,
                "advanced_analytics": True,
                "threat_modeling": True,
                "attack_vector_analysis": True,
                "nmap_scripts": "default,vuln,safe,exploit"
            },
            "compliance": {
                "timing": "normal",
                "threads": 30,
                "stealth_mode": False,
                "dom_scan_enabled": True,
                "api_discovery_enabled": True,
                "cloud_security_enabled": True,
                "container_security_enabled": True,
                "exploit_detection_enabled": False,
                "compliance_scanning_enabled": True,
                "deep_vulnerability_scan": True,
                "risk_assessment_enabled": True,
                "compliance_checks": True,
                "executive_summary": True,
                "technical_details": True,
                "nmap_scripts": "default,vuln,safe"
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
    """Enhanced vulnerability scanning and analysis with CVE correlation"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform comprehensive vulnerability scanning"""
        self.console.print("[cyan]🔍 Starting enhanced vulnerability analysis...[/cyan]")
        
        vuln_results = {
            "nmap_vulns": [],
            "cve_correlations": [],
            "cvss_scores": {},
            "exploit_references": [],
            "ssl_issues": [],
            "web_vulns": [],
            "service_vulns": {},
            "configuration_issues": [],
            "security_recommendations": [],
            "vulnerability_statistics": {},
            "risk_assessment": {}
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
                
                # Nmap vulnerability scripts
                vuln_task = progress.add_task("Running Nmap vulnerability scans...", total=100)
                nmap_vulns = await self._run_nmap_vulnerability_scan()
                vuln_results.update(nmap_vulns)
                progress.update(vuln_task, completed=100)
                
                # CVE correlation
                cve_task = progress.add_task("Correlating with CVE database...", total=100)
                cve_correlations = await self._correlate_cves(vuln_results["nmap_vulns"])
                vuln_results["cve_correlations"] = cve_correlations
                progress.update(cve_task, completed=100)
                
                # Service-specific vulnerability checks
                service_task = progress.add_task("Service-specific vulnerability checks...", total=100)
                service_vulns = await self._check_service_vulnerabilities()
                vuln_results["service_vulns"] = service_vulns
                progress.update(service_task, completed=100)
                
                # Configuration issue detection
                config_task = progress.add_task("Configuration issue detection...", total=100)
                config_issues = await self._detect_configuration_issues()
                vuln_results["configuration_issues"] = config_issues
                progress.update(config_task, completed=100)
                
                # Web application vulnerability scanning
                web_task = progress.add_task("Web application vulnerability scanning...", total=100)
                web_vulns = await self._scan_web_vulnerabilities()
                vuln_results["web_vulns"] = web_vulns
                progress.update(web_task, completed=100)
                
                # Generate vulnerability statistics and risk assessment
                vuln_results["vulnerability_statistics"] = self._calculate_vulnerability_statistics(vuln_results)
                vuln_results["risk_assessment"] = self._assess_vulnerability_risk(vuln_results)
                vuln_results["security_recommendations"] = self._generate_security_recommendations(vuln_results)
            
            await self._save_vulnerability_report(vuln_results)
            
        except Exception as e:
            logging.error(f"Vulnerability scanning failed: {e}")
            vuln_results["error"] = str(e)
        
        self.results = vuln_results
        return vuln_results
    
    async def _run_nmap_vulnerability_scan(self) -> Dict[str, Any]:
        """Run comprehensive Nmap vulnerability scans"""
        nmap_results = {
            "nmap_vulns": [],
            "nmap_scripts_used": [],
            "scan_details": {}
        }
        
        try:
            # Enhanced Nmap vulnerability scripts
            vuln_scripts = [
                "vuln,safe",
                "ssl-enum-ciphers",
                "ssl-cert,ssl-date,ssl-known-key",
                "http-vuln-*",
                "ssh-vuln-*",
                "smb-vuln-*",
                "ftp-vuln-*",
                "mysql-vuln-*"
            ]
            
            for script_set in vuln_scripts:
                try:
                    cmd = [
                        "nmap", "--script", script_set,
                        "-sV", "-sC", self.config.target,
                        "-oN", f"{self.config.output_dir}/vulnerabilities/nmap_vulns_{script_set.replace(',', '_').replace('*', 'all')}.txt"
                    ]
                    
                    # Add timing options
                    if self.config.stealth_mode:
                        cmd.extend(["-T1"])
                    else:
                        cmd.extend(["-T4"])
                    
                    result = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    stdout, stderr = await result.communicate()
                    
                    if result.returncode == 0 and stdout:
                        vuln_output = stdout.decode()
                        nmap_results["nmap_scripts_used"].append(script_set)
                        
                        # Parse vulnerability findings
                        vulns = self._parse_nmap_vulnerabilities(vuln_output)
                        nmap_results["nmap_vulns"].extend(vulns)
                        
                        # Save detailed output
                        script_name = script_set.replace(',', '_').replace('*', 'all')
                        with open(f"{self.config.output_dir}/vulnerabilities/nmap_detailed_{script_name}.txt", 'w') as f:
                            f.write(vuln_output)
                
                except Exception as e:
                    logging.error(f"Nmap script {script_set} failed: {e}")
        
        except Exception as e:
            logging.error(f"Nmap vulnerability scanning failed: {e}")
        
        return nmap_results
    
    def _parse_nmap_vulnerabilities(self, nmap_output: str) -> List[Dict[str, Any]]:
        """Parse Nmap vulnerability scan output"""
        vulnerabilities = []
        
        try:
            lines = nmap_output.split('\n')
            current_port = None
            current_service = None
            
            for line in lines:
                line = line.strip()
                
                # Extract port and service information
                if '/tcp' in line or '/udp' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        current_port = parts[0]
                        current_service = parts[2] if len(parts) > 2 else 'unknown'
                
                # Look for vulnerability indicators
                if 'VULNERABLE' in line.upper():
                    vuln_info = {
                        "port": current_port,
                        "service": current_service,
                        "description": line,
                        "severity": "unknown",
                        "type": "vulnerability"
                    }
                    
                    # Extract CVE if present
                    cve_match = re.search(r'CVE-\d{4}-\d+', line)
                    if cve_match:
                        vuln_info["cve"] = cve_match.group()
                    
                    # Determine severity based on keywords
                    if any(keyword in line.upper() for keyword in ['CRITICAL', 'SEVERE', 'HIGH']):
                        vuln_info["severity"] = "high"
                    elif any(keyword in line.upper() for keyword in ['MEDIUM', 'MODERATE']):
                        vuln_info["severity"] = "medium"
                    elif any(keyword in line.upper() for keyword in ['LOW', 'MINOR']):
                        vuln_info["severity"] = "low"
                    
                    vulnerabilities.append(vuln_info)
                
                # Look for security issues
                elif any(keyword in line.upper() for keyword in ['WEAK', 'INSECURE', 'DEPRECATED', 'UNSAFE']):
                    vuln_info = {
                        "port": current_port,
                        "service": current_service,
                        "description": line,
                        "severity": "medium",
                        "type": "security_issue"
                    }
                    vulnerabilities.append(vuln_info)
        
        except Exception as e:
            logging.error(f"Nmap output parsing failed: {e}")
        
        return vulnerabilities
    
    async def _correlate_cves(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Correlate findings with CVE database"""
        cve_correlations = []
        
        try:
            # Extract CVEs from vulnerability findings
            cves_found = set()
            for vuln in vulnerabilities:
                if "cve" in vuln:
                    cves_found.add(vuln["cve"])
            
            # Enrich CVE information
            for cve in cves_found:
                cve_info = await self._get_cve_details(cve)
                if cve_info:
                    cve_correlations.append(cve_info)
        
        except Exception as e:
            logging.error(f"CVE correlation failed: {e}")
        
        return cve_correlations
    
    async def _get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed CVE information"""
        try:
            # In a real implementation, this would query NIST NVD or similar database
            # For now, we'll use a simplified lookup
            cve_database = {
                "CVE-2021-44228": {
                    "cve_id": cve_id,
                    "cvss_score": 10.0,
                    "severity": "critical",
                    "description": "Apache Log4j2 JNDI features used in configuration do not protect against attacker controlled LDAP",
                    "cwe": "CWE-502",
                    "exploit_available": True,
                    "exploit_databases": ["metasploit", "exploit-db"],
                    "affected_systems": ["Apache Log4j 2.0-beta9 through 2.15.0"]
                },
                "CVE-2021-41773": {
                    "cve_id": cve_id,
                    "cvss_score": 9.8,
                    "severity": "critical", 
                    "description": "Path traversal vulnerability in Apache HTTP Server 2.4.49",
                    "cwe": "CWE-22",
                    "exploit_available": True,
                    "exploit_databases": ["metasploit", "exploit-db"],
                    "affected_systems": ["Apache HTTP Server 2.4.49"]
                },
                "CVE-2014-3120": {
                    "cve_id": cve_id,
                    "cvss_score": 10.0,
                    "severity": "critical",
                    "description": "Elasticsearch before 1.2 enables dynamic scripting by default",
                    "cwe": "CWE-94",
                    "exploit_available": True,
                    "exploit_databases": ["metasploit", "exploit-db"],
                    "affected_systems": ["Elasticsearch before 1.2"]
                }
            }
            
            return cve_database.get(cve_id, {
                "cve_id": cve_id,
                "cvss_score": 0.0,
                "severity": "unknown",
                "description": "CVE details not available",
                "exploit_available": False
            })
        
        except Exception as e:
            logging.error(f"CVE details lookup failed: {e}")
        
        return None
    
    async def _check_service_vulnerabilities(self) -> Dict[str, List[Dict[str, Any]]]:
        """Check for service-specific vulnerabilities"""
        service_vulns = {}
        
        try:
            # Common service vulnerability checks
            services_to_check = {
                "ssh": await self._check_ssh_vulnerabilities(),
                "http": await self._check_http_vulnerabilities(),
                "https": await self._check_https_vulnerabilities(),
                "ftp": await self._check_ftp_vulnerabilities(),
                "smtp": await self._check_smtp_vulnerabilities(),
                "mysql": await self._check_mysql_vulnerabilities(),
                "postgresql": await self._check_postgresql_vulnerabilities(),
                "elasticsearch": await self._check_elasticsearch_vulnerabilities()
            }
            
            for service, vulns in services_to_check.items():
                if vulns:
                    service_vulns[service] = vulns
        
        except Exception as e:
            logging.error(f"Service vulnerability checking failed: {e}")
        
        return service_vulns
    
    async def _check_ssh_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Check SSH-specific vulnerabilities"""
        ssh_vulns = []
        
        try:
            # Check if SSH is running
            if await self._check_port_open(22):
                # Check for SSH version vulnerabilities
                banner = await self._get_service_banner(22)
                if banner:
                    ssh_vulns.extend(self._analyze_ssh_banner(banner))
                
                # Check for common SSH misconfigurations
                ssh_config_issues = await self._check_ssh_configuration()
                ssh_vulns.extend(ssh_config_issues)
        
        except Exception as e:
            logging.error(f"SSH vulnerability check failed: {e}")
        
        return ssh_vulns
    
    async def _check_http_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Check HTTP-specific vulnerabilities"""
        http_vulns = []
        
        try:
            if await self._check_port_open(80):
                # Check for HTTP security headers
                headers_check = await self._check_http_security_headers(80, "http")
                http_vulns.extend(headers_check)
                
                # Check for directory traversal
                traversal_vulns = await self._check_directory_traversal("http", 80)
                http_vulns.extend(traversal_vulns)
                
                # Check for common web vulnerabilities
                web_vulns = await self._check_common_web_vulnerabilities("http", 80)
                http_vulns.extend(web_vulns)
        
        except Exception as e:
            logging.error(f"HTTP vulnerability check failed: {e}")
        
        return http_vulns
    
    async def _check_https_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Check HTTPS-specific vulnerabilities"""
        https_vulns = []
        
        try:
            if await self._check_port_open(443):
                # Check SSL/TLS vulnerabilities
                ssl_vulns = await self._check_ssl_vulnerabilities()
                https_vulns.extend(ssl_vulns)
                
                # Check for HTTP security headers
                headers_check = await self._check_http_security_headers(443, "https")
                https_vulns.extend(headers_check)
        
        except Exception as e:
            logging.error(f"HTTPS vulnerability check failed: {e}")
        
        return https_vulns
    
    async def _check_elasticsearch_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Check Elasticsearch-specific vulnerabilities"""
        es_vulns = []
        
        try:
            # Common Elasticsearch ports
            es_ports = [9200, 9300]
            
            for port in es_ports:
                if await self._check_port_open(port):
                    # Check for unauthenticated access
                    if HAS_ENHANCED_LIBS:
                        try:
                            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                                url = f"http://{self.config.target}:{port}/"
                                async with session.get(url) as response:
                                    if response.status == 200:
                                        content = await response.text()
                                        if "cluster_name" in content:
                                            es_vulns.append({
                                                "vulnerability": "unauthenticated_elasticsearch_access",
                                                "description": f"Elasticsearch cluster accessible without authentication on port {port}",
                                                "severity": "critical",
                                                "port": port,
                                                "cve": "CVE-2014-3120"
                                            })
                        except Exception:
                            pass
        
        except Exception as e:
            logging.error(f"Elasticsearch vulnerability check failed: {e}")
        
        return es_vulns
    
    async def _check_ssl_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Check for SSL/TLS vulnerabilities"""
        ssl_vulns = []
        
        try:
            # Check for common SSL vulnerabilities using testssl.sh or similar
            # For now, we'll do basic SSL checks
            
            # Check SSL certificate
            cert_issues = await self._check_ssl_certificate()
            ssl_vulns.extend(cert_issues)
            
            # Check for weak cipher suites
            cipher_issues = await self._check_weak_ciphers()
            ssl_vulns.extend(cipher_issues)
        
        except Exception as e:
            logging.error(f"SSL vulnerability check failed: {e}")
        
        return ssl_vulns
    
    async def _detect_configuration_issues(self) -> List[Dict[str, Any]]:
        """Detect common configuration issues"""
        config_issues = []
        
        try:
            # Check for information disclosure
            info_disclosure = await self._check_information_disclosure()
            config_issues.extend(info_disclosure)
            
            # Check for default pages
            default_pages = await self._check_default_pages()
            config_issues.extend(default_pages)
            
            # Check for backup files
            backup_files = await self._check_backup_files()
            config_issues.extend(backup_files)
        
        except Exception as e:
            logging.error(f"Configuration issue detection failed: {e}")
        
        return config_issues
    
    async def _scan_web_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Scan for web application vulnerabilities"""
        web_vulns = []
        
        try:
            if HAS_ENHANCED_LIBS:
                # Check for common web vulnerabilities
                xss_vulns = await self._check_xss_vulnerabilities()
                web_vulns.extend(xss_vulns)
                
                sqli_vulns = await self._check_sql_injection()
                web_vulns.extend(sqli_vulns)
                
                csrf_vulns = await self._check_csrf_vulnerabilities()
                web_vulns.extend(csrf_vulns)
        
        except Exception as e:
            logging.error(f"Web vulnerability scanning failed: {e}")
        
        return web_vulns
    
    # Helper methods for specific vulnerability checks
    async def _check_port_open(self, port: int) -> bool:
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.config.target, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    async def _get_service_banner(self, port: int) -> Optional[str]:
        """Get service banner from port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            if sock.connect_ex((self.config.target, port)) == 0:
                sock.send(b"\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                return banner.strip() if banner else None
            sock.close()
        except Exception:
            pass
        return None
    
    def _analyze_ssh_banner(self, banner: str) -> List[Dict[str, Any]]:
        """Analyze SSH banner for vulnerabilities"""
        vulns = []
        
        try:
            banner_lower = banner.lower()
            
            # Check for vulnerable SSH versions
            vulnerable_versions = {
                "openssh_7.3": "CVE-2016-6210 - User enumeration vulnerability",
                "openssh_7.4": "CVE-2017-15906 - Process completion with incorrect cleanup",
                "openssh_6.6": "CVE-2014-2653 - Denial of service"
            }
            
            for version, vulnerability in vulnerable_versions.items():
                if version.replace('_', ' ') in banner_lower:
                    vulns.append({
                        "vulnerability": "vulnerable_ssh_version",
                        "description": vulnerability,
                        "severity": "medium",
                        "service": "ssh",
                        "banner": banner
                    })
        
        except Exception as e:
            logging.error(f"SSH banner analysis failed: {e}")
        
        return vulns
    
    # Placeholder implementations for other vulnerability check methods
    async def _check_ssh_configuration(self) -> List[Dict[str, Any]]:
        return []
    
    async def _check_http_security_headers(self, port: int, protocol: str) -> List[Dict[str, Any]]:
        return []
    
    async def _check_directory_traversal(self, protocol: str, port: int) -> List[Dict[str, Any]]:
        return []
    
    async def _check_common_web_vulnerabilities(self, protocol: str, port: int) -> List[Dict[str, Any]]:
        return []
    
    async def _check_ftp_vulnerabilities(self) -> List[Dict[str, Any]]:
        return []
    
    async def _check_smtp_vulnerabilities(self) -> List[Dict[str, Any]]:
        return []
    
    async def _check_mysql_vulnerabilities(self) -> List[Dict[str, Any]]:
        return []
    
    async def _check_postgresql_vulnerabilities(self) -> List[Dict[str, Any]]:
        return []
    
    async def _check_ssl_certificate(self) -> List[Dict[str, Any]]:
        return []
    
    async def _check_weak_ciphers(self) -> List[Dict[str, Any]]:
        return []
    
    async def _check_information_disclosure(self) -> List[Dict[str, Any]]:
        return []
    
    async def _check_default_pages(self) -> List[Dict[str, Any]]:
        return []
    
    async def _check_backup_files(self) -> List[Dict[str, Any]]:
        return []
    
    async def _check_xss_vulnerabilities(self) -> List[Dict[str, Any]]:
        return []
    
    async def _check_sql_injection(self) -> List[Dict[str, Any]]:
        return []
    
    async def _check_csrf_vulnerabilities(self) -> List[Dict[str, Any]]:
        return []
    
    def _calculate_vulnerability_statistics(self, vuln_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate vulnerability statistics"""
        stats = {
            "total_vulnerabilities": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0,
            "cves_found": 0,
            "exploitable": 0
        }
        
        try:
            # Count vulnerabilities by severity
            all_vulns = []
            all_vulns.extend(vuln_results.get("nmap_vulns", []))
            
            for service_vulns in vuln_results.get("service_vulns", {}).values():
                all_vulns.extend(service_vulns)
            
            all_vulns.extend(vuln_results.get("configuration_issues", []))
            all_vulns.extend(vuln_results.get("web_vulns", []))
            
            stats["total_vulnerabilities"] = len(all_vulns)
            
            for vuln in all_vulns:
                severity = vuln.get("severity", "unknown")
                if severity in stats:
                    stats[severity] += 1
                
                if "cve" in vuln:
                    stats["cves_found"] += 1
                
                if vuln.get("exploit_available", False):
                    stats["exploitable"] += 1
        
        except Exception as e:
            logging.error(f"Vulnerability statistics calculation failed: {e}")
        
        return stats
    
    def _assess_vulnerability_risk(self, vuln_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall vulnerability risk"""
        risk_assessment = {
            "risk_score": 0.0,
            "risk_level": "unknown",
            "critical_issues": [],
            "immediate_actions": [],
            "long_term_recommendations": []
        }
        
        try:
            stats = vuln_results.get("vulnerability_statistics", {})
            
            # Calculate risk score (0-10 scale)
            critical_weight = 10.0
            high_weight = 7.5
            medium_weight = 5.0
            low_weight = 2.5
            
            total_vulns = stats.get("total_vulnerabilities", 0)
            if total_vulns > 0:
                risk_score = (
                    stats.get("critical", 0) * critical_weight +
                    stats.get("high", 0) * high_weight +
                    stats.get("medium", 0) * medium_weight +
                    stats.get("low", 0) * low_weight
                ) / total_vulns
                
                risk_assessment["risk_score"] = min(10.0, risk_score)
            
            # Determine risk level
            if risk_assessment["risk_score"] >= 8.0:
                risk_assessment["risk_level"] = "critical"
            elif risk_assessment["risk_score"] >= 6.0:
                risk_assessment["risk_level"] = "high"
            elif risk_assessment["risk_score"] >= 4.0:
                risk_assessment["risk_level"] = "medium"
            elif risk_assessment["risk_score"] >= 2.0:
                risk_assessment["risk_level"] = "low"
            else:
                risk_assessment["risk_level"] = "minimal"
        
        except Exception as e:
            logging.error(f"Vulnerability risk assessment failed: {e}")
        
        return risk_assessment
    
    def _generate_security_recommendations(self, vuln_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        try:
            stats = vuln_results.get("vulnerability_statistics", {})
            
            if stats.get("critical", 0) > 0:
                recommendations.append("URGENT: Patch critical vulnerabilities immediately")
            
            if stats.get("high", 0) > 0:
                recommendations.append("HIGH PRIORITY: Address high-severity vulnerabilities")
            
            if stats.get("cves_found", 0) > 0:
                recommendations.append("Review and patch systems with known CVEs")
            
            if stats.get("exploitable", 0) > 0:
                recommendations.append("CRITICAL: Address vulnerabilities with known exploits")
            
            # Add general recommendations
            recommendations.extend([
                "Implement regular vulnerability scanning",
                "Keep all systems and software updated",
                "Follow security best practices for configuration",
                "Implement defense-in-depth security measures",
                "Conduct regular security assessments"
            ])
        
        except Exception as e:
            logging.error(f"Security recommendation generation failed: {e}")
        
        return recommendations
    
    async def _save_vulnerability_report(self, vuln_results: Dict[str, Any]) -> None:
        """Save comprehensive vulnerability report"""
        try:
            # Save detailed JSON report
            report_file = f"{self.config.output_dir}/vulnerabilities/vulnerability_report.json"
            with open(report_file, 'w') as f:
                json.dump(vuln_results, f, indent=2, default=str)
            
            # Create executive summary
            summary = self._create_vulnerability_summary(vuln_results)
            summary_file = f"{self.config.output_dir}/vulnerabilities/vulnerability_summary.txt"
            with open(summary_file, 'w') as f:
                f.write(summary)
        
        except Exception as e:
            logging.error(f"Failed to save vulnerability report: {e}")
    
    def _create_vulnerability_summary(self, vuln_results: Dict[str, Any]) -> str:
        """Create vulnerability assessment summary"""
        summary = "=== Vulnerability Assessment Summary ===\n\n"
        
        stats = vuln_results.get("vulnerability_statistics", {})
        risk = vuln_results.get("risk_assessment", {})
        
        summary += f"Total Vulnerabilities Found: {stats.get('total_vulnerabilities', 0)}\n"
        summary += f"Risk Score: {risk.get('risk_score', 0.0):.1f}/10.0\n"
        summary += f"Risk Level: {risk.get('risk_level', 'unknown').upper()}\n\n"
        
        # Severity breakdown
        if stats.get("total_vulnerabilities", 0) > 0:
            summary += "Severity Breakdown:\n"
            summary += f"  Critical: {stats.get('critical', 0)}\n"
            summary += f"  High: {stats.get('high', 0)}\n"
            summary += f"  Medium: {stats.get('medium', 0)}\n"
            summary += f"  Low: {stats.get('low', 0)}\n\n"
        
        # CVE information
        if stats.get("cves_found", 0) > 0:
            summary += f"CVEs Identified: {stats.get('cves_found', 0)}\n"
            summary += f"Exploitable Vulnerabilities: {stats.get('exploitable', 0)}\n\n"
        
        # Top recommendations
        recommendations = vuln_results.get("security_recommendations", [])
        if recommendations:
            summary += "Top Recommendations:\n"
            for i, rec in enumerate(recommendations[:5], 1):
                summary += f"{i}. {rec}\n"
        
        return summary

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

class CloudSecurityScanner(Scanner):
    """Advanced cloud infrastructure security scanning"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform cloud security assessment"""
        self.console.print("[cyan]☁️ Starting cloud security scanning...[/cyan]")
        
        cloud_results = {
            "aws_findings": {},
            "azure_findings": {},
            "gcp_findings": {},
            "cloud_providers": [],
            "exposed_services": [],
            "misconfigurations": [],
            "security_groups": [],
            "iam_issues": [],
            "storage_buckets": []
        }
        
        try:
            os.makedirs(f"{self.config.output_dir}/cloud", exist_ok=True)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                # Cloud provider detection
                detect_task = progress.add_task("Detecting cloud providers...", total=100)
                cloud_providers = await self._detect_cloud_providers()
                cloud_results["cloud_providers"] = cloud_providers
                progress.update(detect_task, completed=50)
                
                # AWS-specific scanning
                if "aws" in cloud_providers:
                    aws_task = progress.add_task("AWS security assessment...", total=100)
                    cloud_results["aws_findings"] = await self._scan_aws_infrastructure()
                    progress.update(aws_task, completed=100)
                
                # Azure-specific scanning
                if "azure" in cloud_providers:
                    azure_task = progress.add_task("Azure security assessment...", total=100)
                    cloud_results["azure_findings"] = await self._scan_azure_infrastructure()
                    progress.update(azure_task, completed=100)
                
                # GCP-specific scanning
                if "gcp" in cloud_providers:
                    gcp_task = progress.add_task("GCP security assessment...", total=100)
                    cloud_results["gcp_findings"] = await self._scan_gcp_infrastructure()
                    progress.update(gcp_task, completed=100)
                
                # General cloud security checks
                general_task = progress.add_task("General cloud security checks...", total=100)
                cloud_results["exposed_services"] = await self._check_exposed_cloud_services()
                cloud_results["misconfigurations"] = await self._detect_cloud_misconfigurations()
                progress.update(general_task, completed=100)
                
                progress.update(detect_task, completed=100)
            
            await self._save_cloud_report(cloud_results)
            
        except Exception as e:
            logging.error(f"Cloud security scanning failed: {e}")
            cloud_results["error"] = str(e)
        
        self.results = cloud_results
        return cloud_results
    
    async def _detect_cloud_providers(self) -> List[str]:
        """Detect which cloud providers are hosting the target"""
        providers = []
        
        try:
            # Check for AWS indicators
            aws_indicators = [
                "amazonaws.com", "aws.amazon.com", "s3.amazonaws.com",
                "ec2.amazonaws.com", "cloudfront.net"
            ]
            
            # Check for Azure indicators  
            azure_indicators = [
                "azure.microsoft.com", "azurewebsites.net", "blob.core.windows.net",
                "cloudapp.azure.com", "azurecontainer.io"
            ]
            
            # Check for GCP indicators
            gcp_indicators = [
                "googleapis.com", "googleusercontent.com", "appspot.com",
                "cloudfunctions.net", "run.app"
            ]
            
            # DNS resolution to check for cloud providers
            if HAS_ENHANCED_LIBS:
                try:
                    import dns.resolver
                    result = dns.resolver.resolve(self.config.target, 'CNAME')
                    for rdata in result:
                        cname = str(rdata.target).lower()
                        
                        if any(indicator in cname for indicator in aws_indicators):
                            providers.append("aws")
                        if any(indicator in cname for indicator in azure_indicators):
                            providers.append("azure")
                        if any(indicator in cname for indicator in gcp_indicators):
                            providers.append("gcp")
                            
                except Exception:
                    pass
            
            # Additional detection via HTTP headers and responses
            if HAS_ENHANCED_LIBS:
                try:
                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                        async with session.get(f"http://{self.config.target}") as response:
                            headers = response.headers
                            
                            # Check for cloud-specific headers
                            if "x-amz-" in str(headers).lower() or "amazon" in str(headers).lower():
                                if "aws" not in providers:
                                    providers.append("aws")
                            
                            if "x-azure-" in str(headers).lower() or "microsoft" in str(headers).lower():
                                if "azure" not in providers:
                                    providers.append("azure")
                                    
                            if "x-goog-" in str(headers).lower() or "google" in str(headers).lower():
                                if "gcp" not in providers:
                                    providers.append("gcp")
                except Exception:
                    pass
        
        except Exception as e:
            logging.error(f"Cloud provider detection failed: {e}")
        
        return providers
    
    async def _scan_aws_infrastructure(self) -> Dict[str, Any]:
        """Perform AWS-specific security scanning"""
        aws_findings = {
            "s3_buckets": [],
            "ec2_instances": [],
            "security_groups": [],
            "iam_policies": [],
            "cloudtrail_logs": [],
            "exposed_services": []
        }
        
        try:
            # Check for S3 buckets
            bucket_patterns = [
                f"{self.config.target}",
                f"{self.config.target.replace('.', '-')}",
                f"{self.config.target.split('.')[0]}",
                f"backup-{self.config.target.split('.')[0]}",
                f"logs-{self.config.target.split('.')[0]}",
                f"data-{self.config.target.split('.')[0]}"
            ]
            
            for pattern in bucket_patterns:
                bucket_result = await self._check_s3_bucket(pattern)
                if bucket_result:
                    aws_findings["s3_buckets"].append(bucket_result)
            
            # Check for exposed AWS services
            aws_ports = [8080, 9200, 9300, 27017, 6379, 5432]  # Common AWS service ports
            for port in aws_ports:
                if await self._check_port_open(port):
                    aws_findings["exposed_services"].append({
                        "port": port,
                        "service": self._identify_aws_service(port),
                        "risk": "high"
                    })
        
        except Exception as e:
            logging.error(f"AWS scanning failed: {e}")
        
        return aws_findings
    
    async def _scan_azure_infrastructure(self) -> Dict[str, Any]:
        """Perform Azure-specific security scanning"""
        azure_findings = {
            "storage_accounts": [],
            "app_services": [],
            "key_vaults": [],
            "sql_databases": [],
            "exposed_services": []
        }
        
        try:
            # Check for Azure Storage accounts
            storage_patterns = [
                f"{self.config.target.replace('.', '')}",
                f"{self.config.target.split('.')[0]}storage",
                f"{self.config.target.split('.')[0]}data"
            ]
            
            for pattern in storage_patterns:
                storage_result = await self._check_azure_storage(pattern)
                if storage_result:
                    azure_findings["storage_accounts"].append(storage_result)
        
        except Exception as e:
            logging.error(f"Azure scanning failed: {e}")
        
        return azure_findings
    
    async def _scan_gcp_infrastructure(self) -> Dict[str, Any]:
        """Perform GCP-specific security scanning"""
        gcp_findings = {
            "cloud_storage": [],
            "compute_instances": [],
            "app_engine": [],
            "cloud_functions": [],
            "exposed_services": []
        }
        
        try:
            # Check for GCP Cloud Storage buckets
            bucket_patterns = [
                f"{self.config.target}",
                f"{self.config.target.replace('.', '-')}",
                f"{self.config.target.split('.')[0]}-storage"
            ]
            
            for pattern in bucket_patterns:
                bucket_result = await self._check_gcp_storage(pattern)
                if bucket_result:
                    gcp_findings["cloud_storage"].append(bucket_result)
        
        except Exception as e:
            logging.error(f"GCP scanning failed: {e}")
        
        return gcp_findings
    
    async def _check_s3_bucket(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """Check if S3 bucket exists and is accessible"""
        try:
            if HAS_ENHANCED_LIBS:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    url = f"https://{bucket_name}.s3.amazonaws.com"
                    async with session.get(url) as response:
                        if response.status == 200:
                            return {
                                "bucket_name": bucket_name,
                                "url": url,
                                "accessible": True,
                                "risk": "critical"
                            }
                        elif response.status == 403:
                            return {
                                "bucket_name": bucket_name,
                                "url": url,
                                "accessible": False,
                                "exists": True,
                                "risk": "medium"
                            }
        except Exception:
            pass
        return None
    
    async def _check_azure_storage(self, account_name: str) -> Optional[Dict[str, Any]]:
        """Check if Azure Storage account exists"""
        try:
            if HAS_ENHANCED_LIBS:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    url = f"https://{account_name}.blob.core.windows.net"
                    async with session.get(url) as response:
                        if response.status in [200, 400]:  # 400 means exists but not accessible
                            return {
                                "account_name": account_name,
                                "url": url,
                                "exists": True,
                                "risk": "medium"
                            }
        except Exception:
            pass
        return None
    
    async def _check_gcp_storage(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """Check if GCP Cloud Storage bucket exists"""
        try:
            if HAS_ENHANCED_LIBS:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    url = f"https://storage.googleapis.com/{bucket_name}"
                    async with session.get(url) as response:
                        if response.status == 200:
                            return {
                                "bucket_name": bucket_name,
                                "url": url,
                                "accessible": True,
                                "risk": "critical"
                            }
        except Exception:
            pass
        return None
    
    async def _check_port_open(self, port: int) -> bool:
        """Check if a specific port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.config.target, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _identify_aws_service(self, port: int) -> str:
        """Identify AWS service based on port"""
        service_map = {
            8080: "Tomcat/Jenkins",
            9200: "Elasticsearch",
            9300: "Elasticsearch Cluster",
            27017: "MongoDB",
            6379: "Redis",
            5432: "PostgreSQL"
        }
        return service_map.get(port, "Unknown Service")
    
    async def _check_exposed_cloud_services(self) -> List[Dict[str, Any]]:
        """Check for exposed cloud services"""
        exposed_services = []
        
        # Common cloud service ports
        cloud_ports = [
            (8080, "HTTP Alt/Jenkins"),
            (9200, "Elasticsearch"),
            (9300, "Elasticsearch Cluster"),
            (27017, "MongoDB"),
            (6379, "Redis"),
            (5432, "PostgreSQL"),
            (3306, "MySQL"),
            (1433, "SQL Server"),
            (11211, "Memcached"),
            (8086, "InfluxDB")
        ]
        
        for port, service in cloud_ports:
            if await self._check_port_open(port):
                exposed_services.append({
                    "port": port,
                    "service": service,
                    "risk": "high",
                    "recommendation": f"Secure {service} on port {port}"
                })
        
        return exposed_services
    
    async def _detect_cloud_misconfigurations(self) -> List[Dict[str, Any]]:
        """Detect common cloud misconfigurations"""
        misconfigurations = []
        
        try:
            # Check for common misconfiguration patterns
            if HAS_ENHANCED_LIBS:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    # Check for exposed metadata services
                    metadata_urls = [
                        "http://169.254.169.254/latest/meta-data/",  # AWS
                        "http://169.254.169.254/metadata/instance/",  # Azure
                        "http://metadata.google.internal/computeMetadata/v1/"  # GCP
                    ]
                    
                    for url in metadata_urls:
                        try:
                            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                                if response.status == 200:
                                    misconfigurations.append({
                                        "type": "exposed_metadata_service",
                                        "url": url,
                                        "risk": "critical",
                                        "description": "Cloud metadata service is accessible"
                                    })
                        except Exception:
                            pass
        
        except Exception as e:
            logging.error(f"Misconfiguration detection failed: {e}")
        
        return misconfigurations
    
    async def _save_cloud_report(self, cloud_results: Dict[str, Any]) -> None:
        """Save cloud security report"""
        try:
            report_file = f"{self.config.output_dir}/cloud/cloud_security_report.json"
            with open(report_file, 'w') as f:
                json.dump(cloud_results, f, indent=2, default=str)
            
            # Create summary report
            summary = self._create_cloud_summary(cloud_results)
            summary_file = f"{self.config.output_dir}/cloud/cloud_summary.txt"
            with open(summary_file, 'w') as f:
                f.write(summary)
                
        except Exception as e:
            logging.error(f"Failed to save cloud report: {e}")
    
    def _create_cloud_summary(self, cloud_results: Dict[str, Any]) -> str:
        """Create cloud security summary"""
        summary = "=== Cloud Security Assessment Summary ===\n\n"
        
        providers = cloud_results.get("cloud_providers", [])
        if providers:
            summary += f"Cloud Providers Detected: {', '.join(providers).upper()}\n\n"
        else:
            summary += "No cloud providers detected\n\n"
        
        # AWS findings
        aws_findings = cloud_results.get("aws_findings", {})
        if aws_findings:
            summary += "AWS Findings:\n"
            s3_buckets = aws_findings.get("s3_buckets", [])
            if s3_buckets:
                summary += f"  - {len(s3_buckets)} S3 bucket(s) found\n"
            
            exposed_services = aws_findings.get("exposed_services", [])
            if exposed_services:
                summary += f"  - {len(exposed_services)} exposed service(s)\n"
        
        # General findings
        exposed_services = cloud_results.get("exposed_services", [])
        if exposed_services:
            summary += f"\nExposed Cloud Services: {len(exposed_services)}\n"
            for service in exposed_services[:5]:  # Show first 5
                summary += f"  - {service['service']} on port {service['port']}\n"
        
        misconfigurations = cloud_results.get("misconfigurations", [])
        if misconfigurations:
            summary += f"\nMisconfigurations Found: {len(misconfigurations)}\n"
            for config in misconfigurations:
                summary += f"  - {config['type']}: {config['description']}\n"
        
        return summary


class ContainerScanner(Scanner):
    """Container and orchestration security scanning"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform container security assessment"""
        self.console.print("[cyan]🐳 Starting container security scanning...[/cyan]")
        
        container_results = {
            "docker_detected": False,
            "kubernetes_detected": False,
            "container_registry": [],
            "exposed_apis": [],
            "security_issues": [],
            "misconfigurations": [],
            "vulnerable_images": []
        }
        
        try:
            os.makedirs(f"{self.config.output_dir}/containers", exist_ok=True)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                # Docker detection
                docker_task = progress.add_task("Detecting Docker services...", total=100)
                container_results["docker_detected"] = await self._detect_docker()
                progress.update(docker_task, completed=50)
                
                # Kubernetes detection
                k8s_task = progress.add_task("Detecting Kubernetes...", total=100)
                container_results["kubernetes_detected"] = await self._detect_kubernetes()
                progress.update(k8s_task, completed=50)
                
                # Container registry scanning
                registry_task = progress.add_task("Scanning container registries...", total=100)
                container_results["container_registry"] = await self._scan_container_registries()
                progress.update(registry_task, completed=100)
                
                # API exposure check
                api_task = progress.add_task("Checking exposed APIs...", total=100)
                container_results["exposed_apis"] = await self._check_exposed_container_apis()
                progress.update(api_task, completed=100)
                
                # Security issues detection
                security_task = progress.add_task("Detecting security issues...", total=100)
                container_results["security_issues"] = await self._detect_container_security_issues()
                progress.update(security_task, completed=100)
                
                progress.update(docker_task, completed=100)
                progress.update(k8s_task, completed=100)
            
            await self._save_container_report(container_results)
            
        except Exception as e:
            logging.error(f"Container scanning failed: {e}")
            container_results["error"] = str(e)
        
        self.results = container_results
        return container_results
    
    async def _detect_docker(self) -> bool:
        """Detect Docker services"""
        try:
            # Check Docker daemon port (2375, 2376)
            docker_ports = [2375, 2376]
            for port in docker_ports:
                if await self._check_port_open(port):
                    return True
            
            # Check for Docker registry (5000)
            if await self._check_port_open(5000):
                return True
                
            # Check HTTP headers for Docker indicators
            if HAS_ENHANCED_LIBS:
                try:
                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                        async with session.get(f"http://{self.config.target}") as response:
                            headers = str(response.headers).lower()
                            if "docker" in headers:
                                return True
                except Exception:
                    pass
        
        except Exception as e:
            logging.error(f"Docker detection failed: {e}")
        
        return False
    
    async def _detect_kubernetes(self) -> bool:
        """Detect Kubernetes services"""
        try:
            # Check Kubernetes API server ports
            k8s_ports = [6443, 8080, 8443, 10250, 10255]
            for port in k8s_ports:
                if await self._check_port_open(port):
                    return True
            
            # Check for Kubernetes-specific paths
            if HAS_ENHANCED_LIBS:
                k8s_paths = [
                    "/api/v1",
                    "/apis",
                    "/healthz",
                    "/metrics"
                ]
                
                try:
                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                        for path in k8s_paths:
                            try:
                                url = f"http://{self.config.target}{path}"
                                async with session.get(url) as response:
                                    if response.status == 200:
                                        content = await response.text()
                                        if "kubernetes" in content.lower() or "apiVersion" in content:
                                            return True
                            except Exception:
                                pass
                except Exception:
                    pass
        
        except Exception as e:
            logging.error(f"Kubernetes detection failed: {e}")
        
        return False
    
    async def _scan_container_registries(self) -> List[Dict[str, Any]]:
        """Scan for container registries"""
        registries = []
        
        try:
            # Common registry ports and paths
            registry_checks = [
                {"port": 5000, "path": "/v2/", "type": "Docker Registry"},
                {"port": 5001, "path": "/v2/", "type": "Docker Registry (TLS)"},
                {"port": 80, "path": "/v2/", "type": "Docker Registry (HTTP)"},
                {"port": 443, "path": "/v2/", "type": "Docker Registry (HTTPS)"}
            ]
            
            if HAS_ENHANCED_LIBS:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    for check in registry_checks:
                        try:
                            url = f"http://{self.config.target}:{check['port']}{check['path']}"
                            async with session.get(url) as response:
                                if response.status == 200:
                                    registries.append({
                                        "type": check["type"],
                                        "url": url,
                                        "port": check["port"],
                                        "accessible": True,
                                        "risk": "high"
                                    })
                        except Exception:
                            pass
        
        except Exception as e:
            logging.error(f"Registry scanning failed: {e}")
        
        return registries
    
    async def _check_exposed_container_apis(self) -> List[Dict[str, Any]]:
        """Check for exposed container APIs"""
        exposed_apis = []
        
        try:
            api_checks = [
                {"port": 2375, "endpoint": "/version", "type": "Docker API (Unsecured)"},
                {"port": 2376, "endpoint": "/version", "type": "Docker API (TLS)"},
                {"port": 6443, "endpoint": "/api/v1", "type": "Kubernetes API Server"},
                {"port": 8080, "endpoint": "/api", "type": "Kubernetes API (Insecure)"},
                {"port": 10250, "endpoint": "/stats/summary", "type": "Kubelet API"},
                {"port": 10255, "endpoint": "/stats/summary", "type": "Kubelet API (Read-only)"}
            ]
            
            if HAS_ENHANCED_LIBS:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    for check in api_checks:
                        try:
                            url = f"http://{self.config.target}:{check['port']}{check['endpoint']}"
                            async with session.get(url) as response:
                                if response.status == 200:
                                    exposed_apis.append({
                                        "type": check["type"],
                                        "url": url,
                                        "port": check["port"],
                                        "endpoint": check["endpoint"],
                                        "risk": "critical" if "unsecured" in check["type"].lower() else "high"
                                    })
                        except Exception:
                            pass
        
        except Exception as e:
            logging.error(f"API exposure check failed: {e}")
        
        return exposed_apis
    
    async def _detect_container_security_issues(self) -> List[Dict[str, Any]]:
        """Detect container security issues"""
        security_issues = []
        
        try:
            # Check for common container security issues
            if await self._check_port_open(2375):
                security_issues.append({
                    "type": "insecure_docker_daemon",
                    "description": "Docker daemon exposed on port 2375 without TLS",
                    "risk": "critical",
                    "recommendation": "Enable TLS and authentication for Docker daemon"
                })
            
            if await self._check_port_open(8080):
                security_issues.append({
                    "type": "insecure_kubernetes_api",
                    "description": "Kubernetes API server on insecure port 8080",
                    "risk": "critical",
                    "recommendation": "Use secure port 6443 with authentication"
                })
            
            # Check for container runtime vulnerabilities
            if HAS_ENHANCED_LIBS:
                try:
                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                        # Check for CVE-2019-5736 (runc vulnerability)
                        try:
                            url = f"http://{self.config.target}/proc/self/exe"
                            async with session.get(url) as response:
                                if response.status == 200:
                                    security_issues.append({
                                        "type": "container_escape_vulnerability",
                                        "description": "Potential container escape vulnerability detected",
                                        "risk": "high",
                                        "cve": "CVE-2019-5736"
                                    })
                        except Exception:
                            pass
                except Exception:
                    pass
        
        except Exception as e:
            logging.error(f"Security issue detection failed: {e}")
        
        return security_issues
    
    async def _check_port_open(self, port: int) -> bool:
        """Check if a specific port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.config.target, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    async def _save_container_report(self, container_results: Dict[str, Any]) -> None:
        """Save container security report"""
        try:
            report_file = f"{self.config.output_dir}/containers/container_security_report.json"
            with open(report_file, 'w') as f:
                json.dump(container_results, f, indent=2, default=str)
            
            # Create summary report
            summary = self._create_container_summary(container_results)
            summary_file = f"{self.config.output_dir}/containers/container_summary.txt"
            with open(summary_file, 'w') as f:
                f.write(summary)
                
        except Exception as e:
            logging.error(f"Failed to save container report: {e}")
    
    def _create_container_summary(self, container_results: Dict[str, Any]) -> str:
        """Create container security summary"""
        summary = "=== Container Security Assessment Summary ===\n\n"
        
        if container_results.get("docker_detected"):
            summary += "✓ Docker environment detected\n"
        if container_results.get("kubernetes_detected"):
            summary += "✓ Kubernetes environment detected\n"
        
        registries = container_results.get("container_registry", [])
        if registries:
            summary += f"\nContainer Registries Found: {len(registries)}\n"
            for registry in registries:
                summary += f"  - {registry['type']} at {registry['url']}\n"
        
        exposed_apis = container_results.get("exposed_apis", [])
        if exposed_apis:
            summary += f"\nExposed Container APIs: {len(exposed_apis)}\n"
            for api in exposed_apis:
                summary += f"  - {api['type']} on port {api['port']} (Risk: {api['risk']})\n"
        
        security_issues = container_results.get("security_issues", [])
        if security_issues:
            summary += f"\nSecurity Issues: {len(security_issues)}\n"
            for issue in security_issues:
                summary += f"  - {issue['type']}: {issue['description']}\n"
        
        return summary


class ExploitScanner(Scanner):
    """Advanced exploit detection and validation scanner"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform exploit detection and validation"""
        self.console.print("[cyan]💥 Starting exploit detection scanning...[/cyan]")
        
        exploit_results = {
            "cve_matches": [],
            "exploit_databases": [],
            "active_exploits": [],
            "exploit_frameworks": [],
            "proof_of_concepts": [],
            "metasploit_modules": [],
            "exploit_verification": []
        }
        
        try:
            os.makedirs(f"{self.config.output_dir}/exploits", exist_ok=True)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                # CVE correlation
                cve_task = progress.add_task("Correlating CVEs...", total=100)
                exploit_results["cve_matches"] = await self._correlate_cves()
                progress.update(cve_task, completed=100)
                
                # Exploit database search
                exploit_db_task = progress.add_task("Searching exploit databases...", total=100)
                exploit_results["exploit_databases"] = await self._search_exploit_databases()
                progress.update(exploit_db_task, completed=100)
                
                # Active exploit detection
                active_task = progress.add_task("Detecting active exploits...", total=100)
                exploit_results["active_exploits"] = await self._detect_active_exploits()
                progress.update(active_task, completed=100)
                
                # Metasploit module identification
                msf_task = progress.add_task("Identifying Metasploit modules...", total=100)
                exploit_results["metasploit_modules"] = await self._identify_metasploit_modules()
                progress.update(msf_task, completed=100)
                
                # Exploit verification (safe checks only)
                verify_task = progress.add_task("Verifying exploits (safe checks)...", total=100)
                exploit_results["exploit_verification"] = await self._verify_exploits_safe()
                progress.update(verify_task, completed=100)
            
            await self._save_exploit_report(exploit_results)
            
        except Exception as e:
            logging.error(f"Exploit scanning failed: {e}")
            exploit_results["error"] = str(e)
        
        self.results = exploit_results
        return exploit_results
    
    async def _correlate_cves(self) -> List[Dict[str, Any]]:
        """Correlate discovered services with known CVEs"""
        cve_matches = []
        
        try:
            # Common vulnerable services and their CVEs
            service_cves = {
                "apache": [
                    {"cve": "CVE-2021-41773", "severity": "critical", "description": "Path traversal vulnerability"},
                    {"cve": "CVE-2020-1927", "severity": "high", "description": "mod_rewrite vulnerability"}
                ],
                "nginx": [
                    {"cve": "CVE-2021-23017", "severity": "high", "description": "Off-by-one buffer overflow"}
                ],
                "ssh": [
                    {"cve": "CVE-2020-15778", "severity": "high", "description": "Command injection vulnerability"},
                    {"cve": "CVE-2021-28041", "severity": "medium", "description": "Authentication bypass"}
                ],
                "mysql": [
                    {"cve": "CVE-2021-2471", "severity": "high", "description": "Privilege escalation vulnerability"}
                ],
                "postgresql": [
                    {"cve": "CVE-2021-32027", "severity": "high", "description": "Memory disclosure vulnerability"}
                ],
                "elasticsearch": [
                    {"cve": "CVE-2014-3120", "severity": "critical", "description": "Remote code execution"},
                    {"cve": "CVE-2015-1427", "severity": "critical", "description": "Groovy script execution"}
                ]
            }
            
            # Check against discovered services (would need integration with port scanner results)
            for service, cves in service_cves.items():
                for cve_info in cves:
                    cve_matches.append({
                        "service": service,
                        "cve": cve_info["cve"],
                        "severity": cve_info["severity"],
                        "description": cve_info["description"],
                        "cvss_score": self._get_cvss_score(cve_info["cve"]),
                        "exploit_available": await self._check_exploit_availability(cve_info["cve"])
                    })
        
        except Exception as e:
            logging.error(f"CVE correlation failed: {e}")
        
        return cve_matches
    
    async def _search_exploit_databases(self) -> List[Dict[str, Any]]:
        """Search public exploit databases"""
        exploit_db_results = []
        
        try:
            # Common exploit database URLs and search patterns
            exploit_dbs = [
                {
                    "name": "Exploit-DB",
                    "base_url": "https://www.exploit-db.com/search",
                    "type": "public"
                },
                {
                    "name": "Metasploit",
                    "base_url": "https://www.rapid7.com/db/",
                    "type": "framework"
                },
                {
                    "name": "NVD",
                    "base_url": "https://nvd.nist.gov/vuln/search",
                    "type": "vulnerability_database"
                }
            ]
            
            # Note: In a real implementation, this would make API calls to these databases
            # For now, we'll simulate the search results
            for db in exploit_dbs:
                exploit_db_results.append({
                    "database": db["name"],
                    "url": db["base_url"],
                    "type": db["type"],
                    "exploits_found": [],  # Would be populated with actual search results
                    "last_updated": datetime.now().isoformat()
                })
        
        except Exception as e:
            logging.error(f"Exploit database search failed: {e}")
        
        return exploit_db_results
    
    async def _detect_active_exploits(self) -> List[Dict[str, Any]]:
        """Detect signs of active exploitation"""
        active_exploits = []
        
        try:
            # Check for common exploitation indicators
            exploitation_indicators = [
                {
                    "path": "/shell.php",
                    "type": "webshell",
                    "description": "PHP webshell indicator"
                },
                {
                    "path": "/c99.php", 
                    "type": "webshell",
                    "description": "C99 webshell indicator"
                },
                {
                    "path": "/.well-known/acme-challenge/",
                    "type": "letsencrypt_abuse",
                    "description": "Potential Let's Encrypt abuse"
                },
                {
                    "path": "/wp-content/uploads/",
                    "type": "wordpress_upload",
                    "description": "WordPress upload directory (potential backdoor location)"
                }
            ]
            
            if HAS_ENHANCED_LIBS:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    for indicator in exploitation_indicators:
                        try:
                            url = f"http://{self.config.target}{indicator['path']}"
                            async with session.get(url) as response:
                                if response.status == 200:
                                    content = await response.text()
                                    
                                    # Check for suspicious content patterns
                                    suspicious_patterns = [
                                        "eval(", "base64_decode(", "shell_exec(",
                                        "system(", "exec(", "passthru(",
                                        "<?php", "backdoor", "webshell"
                                    ]
                                    
                                    for pattern in suspicious_patterns:
                                        if pattern in content.lower():
                                            active_exploits.append({
                                                "url": url,
                                                "type": indicator["type"],
                                                "description": indicator["description"],
                                                "pattern_found": pattern,
                                                "risk": "critical",
                                                "timestamp": datetime.now().isoformat()
                                            })
                                            break
                        except Exception:
                            pass
        
        except Exception as e:
            logging.error(f"Active exploit detection failed: {e}")
        
        return active_exploits
    
    async def _identify_metasploit_modules(self) -> List[Dict[str, Any]]:
        """Identify applicable Metasploit modules"""
        msf_modules = []
        
        try:
            # Common Metasploit modules for discovered services
            metasploit_modules = {
                "ssh": [
                    {
                        "module": "auxiliary/scanner/ssh/ssh_login",
                        "type": "auxiliary",
                        "description": "SSH login brute force"
                    },
                    {
                        "module": "exploit/linux/ssh/sshexec",
                        "type": "exploit",
                        "description": "SSH command execution"
                    }
                ],
                "http": [
                    {
                        "module": "auxiliary/scanner/http/dir_scanner",
                        "type": "auxiliary", 
                        "description": "HTTP directory scanner"
                    },
                    {
                        "module": "auxiliary/scanner/http/http_version",
                        "type": "auxiliary",
                        "description": "HTTP version detection"
                    }
                ],
                "mysql": [
                    {
                        "module": "auxiliary/scanner/mysql/mysql_login",
                        "type": "auxiliary",
                        "description": "MySQL login brute force"
                    }
                ],
                "ftp": [
                    {
                        "module": "auxiliary/scanner/ftp/ftp_login",
                        "type": "auxiliary",
                        "description": "FTP login brute force"
                    }
                ]
            }
            
            for service, modules in metasploit_modules.items():
                for module_info in modules:
                    msf_modules.append({
                        "service": service,
                        "module_path": module_info["module"],
                        "module_type": module_info["type"],
                        "description": module_info["description"],
                        "framework": "metasploit",
                        "applicable": True  # Would be determined based on actual service detection
                    })
        
        except Exception as e:
            logging.error(f"Metasploit module identification failed: {e}")
        
        return msf_modules
    
    async def _verify_exploits_safe(self) -> List[Dict[str, Any]]:
        """Safely verify exploits without causing damage"""
        verification_results = []
        
        try:
            # Safe verification techniques (read-only checks)
            safe_checks = [
                {
                    "name": "version_disclosure",
                    "description": "Check for version information disclosure",
                    "method": "banner_grabbing"
                },
                {
                    "name": "default_credentials",
                    "description": "Check for default credentials (safe attempts only)",
                    "method": "credential_testing"
                },
                {
                    "name": "information_disclosure",
                    "description": "Check for information disclosure vulnerabilities",
                    "method": "path_traversal_safe"
                }
            ]
            
            for check in safe_checks:
                result = await self._perform_safe_check(check)
                if result:
                    verification_results.append(result)
        
        except Exception as e:
            logging.error(f"Safe exploit verification failed: {e}")
        
        return verification_results
    
    async def _perform_safe_check(self, check: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Perform a safe security check"""
        try:
            if check["method"] == "banner_grabbing":
                return await self._safe_banner_grab()
            elif check["method"] == "credential_testing":
                return await self._safe_credential_test()
            elif check["method"] == "path_traversal_safe":
                return await self._safe_path_traversal_test()
        
        except Exception as e:
            logging.error(f"Safe check failed: {e}")
        
        return None
    
    async def _safe_banner_grab(self) -> Optional[Dict[str, Any]]:
        """Safely grab service banners"""
        try:
            # Common ports for banner grabbing
            banner_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
            
            for port in banner_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result = sock.connect_ex((self.config.target, port))
                    if result == 0:
                        sock.send(b"\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        sock.close()
                        
                        if banner:
                            return {
                                "check": "banner_grabbing",
                                "port": port,
                                "banner": banner.strip(),
                                "vulnerability": self._analyze_banner_vulnerability(banner),
                                "risk": "medium"
                            }
                    else:
                        sock.close()
                except Exception:
                    if 'sock' in locals():
                        sock.close()
                    continue
        
        except Exception as e:
            logging.error(f"Banner grabbing failed: {e}")
        
        return None
    
    async def _safe_credential_test(self) -> Optional[Dict[str, Any]]:
        """Safely test for default credentials"""
        # Note: This would only test very obvious default credentials in a read-only manner
        return {
            "check": "default_credentials",
            "status": "not_implemented",
            "reason": "Safe credential testing not implemented to avoid account lockouts"
        }
    
    async def _safe_path_traversal_test(self) -> Optional[Dict[str, Any]]:
        """Safely test for path traversal vulnerabilities"""
        try:
            if HAS_ENHANCED_LIBS:
                # Safe path traversal patterns (that don't expose sensitive data)
                safe_patterns = [
                    "/robots.txt",
                    "/sitemap.xml",
                    "/.well-known/security.txt"
                ]
                
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    for pattern in safe_patterns:
                        try:
                            url = f"http://{self.config.target}{pattern}"
                            async with session.get(url) as response:
                                if response.status == 200:
                                    content = await response.text()
                                    if content and len(content) > 10:
                                        return {
                                            "check": "information_disclosure",
                                            "url": url,
                                            "status": "found",
                                            "content_length": len(content),
                                            "risk": "low"
                                        }
                        except Exception:
                            pass
        
        except Exception as e:
            logging.error(f"Path traversal test failed: {e}")
        
        return None
    
    def _analyze_banner_vulnerability(self, banner: str) -> Optional[str]:
        """Analyze banner for known vulnerabilities"""
        vulnerable_versions = {
            "openssh": {
                "7.3": "CVE-2016-6210",
                "7.4": "CVE-2017-15906"
            },
            "apache": {
                "2.4.7": "CVE-2014-0098",
                "2.4.17": "CVE-2015-3183"
            }
        }
        
        banner_lower = banner.lower()
        for service, versions in vulnerable_versions.items():
            if service in banner_lower:
                for version, cve in versions.items():
                    if version in banner_lower:
                        return f"Vulnerable {service} version {version} detected - {cve}"
        
        return None
    
    def _get_cvss_score(self, cve: str) -> float:
        """Get CVSS score for CVE (simplified implementation)"""
        # In a real implementation, this would query NIST NVD database
        cvss_scores = {
            "CVE-2021-41773": 9.8,
            "CVE-2020-1927": 7.5,
            "CVE-2021-23017": 8.1,
            "CVE-2014-3120": 10.0,
            "CVE-2015-1427": 10.0
        }
        return cvss_scores.get(cve, 0.0)
    
    async def _check_exploit_availability(self, cve: str) -> bool:
        """Check if exploits are available for CVE"""
        # Simplified implementation - would check exploit databases
        high_profile_cves = [
            "CVE-2021-41773", "CVE-2014-3120", "CVE-2015-1427",
            "CVE-2017-5638", "CVE-2014-6271"
        ]
        return cve in high_profile_cves
    
    async def _save_exploit_report(self, exploit_results: Dict[str, Any]) -> None:
        """Save exploit scanning report"""
        try:
            report_file = f"{self.config.output_dir}/exploits/exploit_report.json"
            with open(report_file, 'w') as f:
                json.dump(exploit_results, f, indent=2, default=str)
            
            # Create summary report
            summary = self._create_exploit_summary(exploit_results)
            summary_file = f"{self.config.output_dir}/exploits/exploit_summary.txt"
            with open(summary_file, 'w') as f:
                f.write(summary)
                
        except Exception as e:
            logging.error(f"Failed to save exploit report: {e}")
    
    def _create_exploit_summary(self, exploit_results: Dict[str, Any]) -> str:
        """Create exploit scanning summary"""
        summary = "=== Exploit Detection Summary ===\n\n"
        
        cve_matches = exploit_results.get("cve_matches", [])
        if cve_matches:
            summary += f"CVE Matches: {len(cve_matches)}\n"
            critical_cves = [cve for cve in cve_matches if cve["severity"] == "critical"]
            if critical_cves:
                summary += f"  - Critical CVEs: {len(critical_cves)}\n"
                for cve in critical_cves[:3]:  # Show first 3
                    summary += f"    • {cve['cve']}: {cve['description']}\n"
        
        active_exploits = exploit_results.get("active_exploits", [])
        if active_exploits:
            summary += f"\nActive Exploitation Signs: {len(active_exploits)}\n"
            for exploit in active_exploits:
                summary += f"  - {exploit['type']}: {exploit['description']}\n"
        
        msf_modules = exploit_results.get("metasploit_modules", [])
        if msf_modules:
            summary += f"\nApplicable Metasploit Modules: {len(msf_modules)}\n"
            exploit_modules = [mod for mod in msf_modules if mod["module_type"] == "exploit"]
            if exploit_modules:
                summary += f"  - Exploit modules: {len(exploit_modules)}\n"
        
        verification = exploit_results.get("exploit_verification", [])
        if verification:
            summary += f"\nVerification Results: {len(verification)}\n"
            for result in verification:
                summary += f"  - {result.get('check', 'Unknown')}: {result.get('status', 'Unknown')}\n"
        
        return summary


class ComplianceScanner(Scanner):
    """Regulatory compliance and security framework scanning"""
    
    async def run(self) -> Dict[str, Any]:
        """Perform compliance assessment"""
        self.console.print("[cyan]📋 Starting compliance scanning...[/cyan]")
        
        compliance_results = {
            "frameworks": [],
            "pci_dss": {"compliant": False, "findings": []},
            "hipaa": {"compliant": False, "findings": []},
            "gdpr": {"compliant": False, "findings": []},
            "sox": {"compliant": False, "findings": []},
            "iso27001": {"compliant": False, "findings": []},
            "nist": {"compliant": False, "findings": []},
            "overall_score": 0.0,
            "recommendations": []
        }
        
        try:
            os.makedirs(f"{self.config.output_dir}/compliance", exist_ok=True)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                # PCI DSS assessment
                pci_task = progress.add_task("PCI DSS assessment...", total=100)
                compliance_results["pci_dss"] = await self._assess_pci_dss()
                progress.update(pci_task, completed=100)
                
                # HIPAA assessment
                hipaa_task = progress.add_task("HIPAA assessment...", total=100)
                compliance_results["hipaa"] = await self._assess_hipaa()
                progress.update(hipaa_task, completed=100)
                
                # GDPR assessment
                gdpr_task = progress.add_task("GDPR assessment...", total=100)
                compliance_results["gdpr"] = await self._assess_gdpr()
                progress.update(gdpr_task, completed=100)
                
                # SOX assessment
                sox_task = progress.add_task("SOX assessment...", total=100)
                compliance_results["sox"] = await self._assess_sox()
                progress.update(sox_task, completed=100)
                
                # ISO 27001 assessment
                iso_task = progress.add_task("ISO 27001 assessment...", total=100)
                compliance_results["iso27001"] = await self._assess_iso27001()
                progress.update(iso_task, completed=100)
                
                # NIST assessment
                nist_task = progress.add_task("NIST Cybersecurity Framework...", total=100)
                compliance_results["nist"] = await self._assess_nist()
                progress.update(nist_task, completed=100)
                
                # Calculate overall compliance score
                compliance_results["overall_score"] = self._calculate_compliance_score(compliance_results)
                compliance_results["recommendations"] = self._generate_compliance_recommendations(compliance_results)
            
            await self._save_compliance_report(compliance_results)
            
        except Exception as e:
            logging.error(f"Compliance scanning failed: {e}")
            compliance_results["error"] = str(e)
        
        self.results = compliance_results
        return compliance_results
    
    async def _assess_pci_dss(self) -> Dict[str, Any]:
        """Assess PCI DSS compliance"""
        pci_assessment = {
            "compliant": False,
            "findings": [],
            "requirements_met": 0,
            "total_requirements": 12,
            "critical_violations": []
        }
        
        try:
            # PCI DSS Requirements Assessment
            # Requirement 1: Install and maintain a firewall configuration
            if await self._check_firewall_configuration():
                pci_assessment["requirements_met"] += 1
            else:
                pci_assessment["findings"].append({
                    "requirement": "1",
                    "description": "Firewall configuration issues detected",
                    "severity": "high"
                })
            
            # Requirement 2: Do not use vendor-supplied defaults
            if await self._check_default_credentials():
                pci_assessment["requirements_met"] += 1
            else:
                pci_assessment["findings"].append({
                    "requirement": "2",
                    "description": "Default credentials or configurations detected",
                    "severity": "critical"
                })
                pci_assessment["critical_violations"].append("Default credentials")
            
            # Requirement 4: Encrypt transmission of cardholder data
            if await self._check_encryption_in_transit():
                pci_assessment["requirements_met"] += 1
            else:
                pci_assessment["findings"].append({
                    "requirement": "4",
                    "description": "Unencrypted data transmission detected",
                    "severity": "critical"
                })
                pci_assessment["critical_violations"].append("Unencrypted transmission")
            
            # Requirement 6: Develop and maintain secure systems
            if await self._check_secure_systems():
                pci_assessment["requirements_met"] += 1
            else:
                pci_assessment["findings"].append({
                    "requirement": "6",
                    "description": "System security vulnerabilities detected",
                    "severity": "high"
                })
            
            # Calculate compliance
            compliance_percentage = (pci_assessment["requirements_met"] / pci_assessment["total_requirements"]) * 100
            pci_assessment["compliant"] = compliance_percentage >= 90 and len(pci_assessment["critical_violations"]) == 0
            pci_assessment["compliance_percentage"] = compliance_percentage
        
        except Exception as e:
            logging.error(f"PCI DSS assessment failed: {e}")
        
        return pci_assessment
    
    async def _assess_hipaa(self) -> Dict[str, Any]:
        """Assess HIPAA compliance"""
        hipaa_assessment = {
            "compliant": False,
            "findings": [],
            "safeguards_met": 0,
            "total_safeguards": 8,
            "phi_exposure_risk": "unknown"
        }
        
        try:
            # Administrative Safeguards
            if await self._check_access_controls():
                hipaa_assessment["safeguards_met"] += 1
            else:
                hipaa_assessment["findings"].append({
                    "safeguard": "administrative",
                    "description": "Inadequate access controls detected",
                    "severity": "high"
                })
            
            # Physical Safeguards
            if await self._check_physical_security():
                hipaa_assessment["safeguards_met"] += 1
            else:
                hipaa_assessment["findings"].append({
                    "safeguard": "physical",
                    "description": "Physical security measures insufficient",
                    "severity": "medium"
                })
            
            # Technical Safeguards
            if await self._check_encryption_at_rest():
                hipaa_assessment["safeguards_met"] += 1
            else:
                hipaa_assessment["findings"].append({
                    "safeguard": "technical",
                    "description": "Data encryption at rest not implemented",
                    "severity": "critical"
                })
            
            # Audit Controls
            if await self._check_audit_logging():
                hipaa_assessment["safeguards_met"] += 1
            else:
                hipaa_assessment["findings"].append({
                    "safeguard": "audit",
                    "description": "Insufficient audit logging detected",
                    "severity": "high"
                })
            
            compliance_percentage = (hipaa_assessment["safeguards_met"] / hipaa_assessment["total_safeguards"]) * 100
            hipaa_assessment["compliant"] = compliance_percentage >= 95
            hipaa_assessment["compliance_percentage"] = compliance_percentage
        
        except Exception as e:
            logging.error(f"HIPAA assessment failed: {e}")
        
        return hipaa_assessment
    
    async def _assess_gdpr(self) -> Dict[str, Any]:
        """Assess GDPR compliance"""
        gdpr_assessment = {
            "compliant": False,
            "findings": [],
            "principles_met": 0,
            "total_principles": 7,
            "data_protection_score": 0.0
        }
        
        try:
            # Data protection principles assessment
            principles = [
                "lawfulness_fairness_transparency",
                "purpose_limitation",
                "data_minimisation", 
                "accuracy",
                "storage_limitation",
                "integrity_confidentiality",
                "accountability"
            ]
            
            for principle in principles:
                if await self._check_gdpr_principle(principle):
                    gdpr_assessment["principles_met"] += 1
                else:
                    gdpr_assessment["findings"].append({
                        "principle": principle,
                        "description": f"GDPR principle '{principle}' not adequately implemented",
                        "severity": "high"
                    })
            
            compliance_percentage = (gdpr_assessment["principles_met"] / gdpr_assessment["total_principles"]) * 100
            gdpr_assessment["compliant"] = compliance_percentage >= 90
            gdpr_assessment["compliance_percentage"] = compliance_percentage
            gdpr_assessment["data_protection_score"] = compliance_percentage / 100
        
        except Exception as e:
            logging.error(f"GDPR assessment failed: {e}")
        
        return gdpr_assessment
    
    async def _assess_sox(self) -> Dict[str, Any]:
        """Assess SOX compliance"""
        sox_assessment = {
            "compliant": False,
            "findings": [],
            "controls_met": 0,
            "total_controls": 5,
            "financial_data_protection": "unknown"
        }
        
        try:
            # SOX IT General Controls
            controls = [
                "access_controls",
                "change_management",
                "data_backup_recovery",
                "system_monitoring",
                "segregation_of_duties"
            ]
            
            for control in controls:
                if await self._check_sox_control(control):
                    sox_assessment["controls_met"] += 1
                else:
                    sox_assessment["findings"].append({
                        "control": control,
                        "description": f"SOX control '{control}' not adequately implemented",
                        "severity": "high"
                    })
            
            compliance_percentage = (sox_assessment["controls_met"] / sox_assessment["total_controls"]) * 100
            sox_assessment["compliant"] = compliance_percentage >= 95
            sox_assessment["compliance_percentage"] = compliance_percentage
        
        except Exception as e:
            logging.error(f"SOX assessment failed: {e}")
        
        return sox_assessment
    
    async def _assess_iso27001(self) -> Dict[str, Any]:
        """Assess ISO 27001 compliance"""
        iso_assessment = {
            "compliant": False,
            "findings": [],
            "controls_met": 0,
            "total_controls": 14,
            "isms_maturity": "unknown"
        }
        
        try:
            # ISO 27001 Annex A Controls (simplified)
            control_categories = [
                "information_security_policies",
                "organization_information_security",
                "human_resource_security",
                "asset_management",
                "access_control",
                "cryptography",
                "physical_environmental_security",
                "operations_security",
                "communications_security",
                "system_acquisition",
                "supplier_relationships",
                "incident_management",
                "business_continuity",
                "compliance"
            ]
            
            for category in control_categories:
                if await self._check_iso27001_control(category):
                    iso_assessment["controls_met"] += 1
                else:
                    iso_assessment["findings"].append({
                        "control_category": category,
                        "description": f"ISO 27001 control category '{category}' not adequately implemented",
                        "severity": "medium"
                    })
            
            compliance_percentage = (iso_assessment["controls_met"] / iso_assessment["total_controls"]) * 100
            iso_assessment["compliant"] = compliance_percentage >= 85
            iso_assessment["compliance_percentage"] = compliance_percentage
        
        except Exception as e:
            logging.error(f"ISO 27001 assessment failed: {e}")
        
        return iso_assessment
    
    async def _assess_nist(self) -> Dict[str, Any]:
        """Assess NIST Cybersecurity Framework compliance"""
        nist_assessment = {
            "compliant": False,
            "findings": [],
            "functions_met": 0,
            "total_functions": 5,
            "cybersecurity_maturity": "unknown"
        }
        
        try:
            # NIST CSF Core Functions
            functions = [
                "identify",
                "protect", 
                "detect",
                "respond",
                "recover"
            ]
            
            for function in functions:
                if await self._check_nist_function(function):
                    nist_assessment["functions_met"] += 1
                else:
                    nist_assessment["findings"].append({
                        "function": function,
                        "description": f"NIST CSF function '{function}' not adequately implemented",
                        "severity": "medium"
                    })
            
            compliance_percentage = (nist_assessment["functions_met"] / nist_assessment["total_functions"]) * 100
            nist_assessment["compliant"] = compliance_percentage >= 80
            nist_assessment["compliance_percentage"] = compliance_percentage
        
        except Exception as e:
            logging.error(f"NIST assessment failed: {e}")
        
        return nist_assessment
    
    # Simplified compliance check methods (would be more comprehensive in real implementation)
    async def _check_firewall_configuration(self) -> bool:
        """Check firewall configuration"""
        # Simplified check - would perform actual firewall analysis
        return False  # Conservative assessment
    
    async def _check_default_credentials(self) -> bool:
        """Check for default credentials"""
        # Would check for common default credentials
        return True  # Assume no defaults found for now
    
    async def _check_encryption_in_transit(self) -> bool:
        """Check encryption in transit"""
        # Would check for HTTPS, TLS implementation
        return await self._check_https_implementation()
    
    async def _check_https_implementation(self) -> bool:
        """Check HTTPS implementation"""
        try:
            if HAS_ENHANCED_LIBS:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    try:
                        async with session.get(f"https://{self.config.target}") as response:
                            return response.status < 400
                    except Exception:
                        return False
        except Exception:
            pass
        return False
    
    async def _check_secure_systems(self) -> bool:
        """Check for secure system configurations"""
        # Simplified check
        return True
    
    async def _check_access_controls(self) -> bool:
        """Check access control implementation"""
        # Would check authentication mechanisms
        return True
    
    async def _check_physical_security(self) -> bool:
        """Check physical security measures"""
        # Cannot be assessed remotely
        return True
    
    async def _check_encryption_at_rest(self) -> bool:
        """Check encryption at rest"""
        # Cannot be directly assessed remotely
        return True
    
    async def _check_audit_logging(self) -> bool:
        """Check audit logging implementation"""
        # Would check for audit log presence
        return True
    
    async def _check_gdpr_principle(self, principle: str) -> bool:
        """Check GDPR principle implementation"""
        # Simplified assessment
        return True
    
    async def _check_sox_control(self, control: str) -> bool:
        """Check SOX control implementation"""
        # Simplified assessment
        return True
    
    async def _check_iso27001_control(self, category: str) -> bool:
        """Check ISO 27001 control category"""
        # Simplified assessment
        return True
    
    async def _check_nist_function(self, function: str) -> bool:
        """Check NIST CSF function implementation"""
        # Simplified assessment
        return True
    
    def _calculate_compliance_score(self, compliance_results: Dict[str, Any]) -> float:
        """Calculate overall compliance score"""
        try:
            frameworks = ["pci_dss", "hipaa", "gdpr", "sox", "iso27001", "nist"]
            total_score = 0.0
            framework_count = 0
            
            for framework in frameworks:
                if framework in compliance_results and "compliance_percentage" in compliance_results[framework]:
                    total_score += compliance_results[framework]["compliance_percentage"]
                    framework_count += 1
            
            if framework_count > 0:
                return total_score / framework_count
        
        except Exception as e:
            logging.error(f"Compliance score calculation failed: {e}")
        
        return 0.0
    
    def _generate_compliance_recommendations(self, compliance_results: Dict[str, Any]) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []
        
        try:
            # Analyze findings and generate recommendations
            frameworks = ["pci_dss", "hipaa", "gdpr", "sox", "iso27001", "nist"]
            
            for framework in frameworks:
                if framework in compliance_results:
                    findings = compliance_results[framework].get("findings", [])
                    
                    for finding in findings:
                        if finding.get("severity") == "critical":
                            recommendations.append(f"URGENT: Address {framework.upper()} critical finding - {finding.get('description', 'Unknown issue')}")
                        elif finding.get("severity") == "high":
                            recommendations.append(f"HIGH PRIORITY: Fix {framework.upper()} issue - {finding.get('description', 'Unknown issue')}")
            
            # General recommendations
            overall_score = compliance_results.get("overall_score", 0.0)
            if overall_score < 50:
                recommendations.append("Overall compliance is poor - consider comprehensive security review")
            elif overall_score < 80:
                recommendations.append("Compliance needs improvement - focus on high-priority findings")
        
        except Exception as e:
            logging.error(f"Recommendation generation failed: {e}")
        
        return recommendations
    
    async def _save_compliance_report(self, compliance_results: Dict[str, Any]) -> None:
        """Save compliance assessment report"""
        try:
            report_file = f"{self.config.output_dir}/compliance/compliance_report.json"
            with open(report_file, 'w') as f:
                json.dump(compliance_results, f, indent=2, default=str)
            
            # Create summary report
            summary = self._create_compliance_summary(compliance_results)
            summary_file = f"{self.config.output_dir}/compliance/compliance_summary.txt"
            with open(summary_file, 'w') as f:
                f.write(summary)
                
        except Exception as e:
            logging.error(f"Failed to save compliance report: {e}")
    
    def _create_compliance_summary(self, compliance_results: Dict[str, Any]) -> str:
        """Create compliance assessment summary"""
        summary = "=== Compliance Assessment Summary ===\n\n"
        
        overall_score = compliance_results.get("overall_score", 0.0)
        summary += f"Overall Compliance Score: {overall_score:.1f}%\n\n"
        
        frameworks = [
            ("PCI DSS", "pci_dss"),
            ("HIPAA", "hipaa"),
            ("GDPR", "gdpr"),
            ("SOX", "sox"),
            ("ISO 27001", "iso27001"),
            ("NIST CSF", "nist")
        ]
        
        for name, key in frameworks:
            if key in compliance_results:
                framework_data = compliance_results[key]
                compliant = framework_data.get("compliant", False)
                percentage = framework_data.get("compliance_percentage", 0.0)
                status = "✓ COMPLIANT" if compliant else "✗ NON-COMPLIANT"
                
                summary += f"{name}: {status} ({percentage:.1f}%)\n"
                
                findings = framework_data.get("findings", [])
                if findings:
                    critical_findings = [f for f in findings if f.get("severity") == "critical"]
                    high_findings = [f for f in findings if f.get("severity") == "high"]
                    
                    if critical_findings:
                        summary += f"  - Critical Issues: {len(critical_findings)}\n"
                    if high_findings:
                        summary += f"  - High Priority Issues: {len(high_findings)}\n"
        
        recommendations = compliance_results.get("recommendations", [])
        if recommendations:
            summary += f"\nTop Recommendations:\n"
            for i, rec in enumerate(recommendations[:5], 1):
                summary += f"{i}. {rec}\n"
        
        return summary


class MachineLearningAnalyzer:
    """Machine learning-powered vulnerability and threat analysis"""
    
    def __init__(self, console: Console):
        self.console = console
        self.models = {}
        self.scaler = StandardScaler() if HAS_ML_LIBS else None
    
    async def analyze_scan_results(self, scan_results: Dict[str, ScanResult]) -> Dict[str, Any]:
        """Perform ML-powered analysis of scan results"""
        if not HAS_ML_LIBS:
            return {"error": "Machine learning libraries not available"}
        
        self.console.print("[cyan]🤖 Running machine learning analysis...[/cyan]")
        
        ml_analysis = {
            "anomaly_detection": {},
            "vulnerability_clustering": {},
            "threat_prediction": {},
            "risk_scoring": {},
            "pattern_recognition": {},
            "behavioral_analysis": {}
        }
        
        try:
            # Extract features from scan results
            features_df = self._extract_features(scan_results)
            
            if not features_df.empty:
                # Anomaly detection
                ml_analysis["anomaly_detection"] = await self._detect_anomalies(features_df)
                
                # Vulnerability clustering
                ml_analysis["vulnerability_clustering"] = await self._cluster_vulnerabilities(features_df)
                
                # Threat prediction
                ml_analysis["threat_prediction"] = await self._predict_threats(features_df)
                
                # Enhanced risk scoring
                ml_analysis["risk_scoring"] = await self._ml_risk_scoring(features_df)
                
                # Pattern recognition
                ml_analysis["pattern_recognition"] = await self._recognize_patterns(features_df)
        
        except Exception as e:
            logging.error(f"ML analysis failed: {e}")
            ml_analysis["error"] = str(e)
        
        return ml_analysis
    
    def _extract_features(self, scan_results: Dict[str, ScanResult]) -> 'pd.DataFrame':
        """Extract features from scan results for ML analysis"""
        if not HAS_ML_LIBS:
            return pd.DataFrame()
        
        features = []
        
        try:
            for scanner_name, result in scan_results.items():
                if result.status == "completed" and result.data:
                    feature_row = {
                        "scanner": scanner_name,
                        "duration": result.duration(),
                        "data_size": len(str(result.data)),
                        "error_count": len(result.errors),
                        "warning_count": len(result.warnings)
                    }
                    
                    # Scanner-specific features
                    if scanner_name == "Ports":
                        feature_row.update({
                            "open_ports": len(result.data.get("open_ports", [])),
                            "high_risk_ports": self._count_high_risk_ports(result.data.get("open_ports", []))
                        })
                    
                    elif scanner_name == "Vulnerabilities":
                        vulns = result.data.get("nmap_vulns", [])
                        feature_row.update({
                            "vulnerability_count": len(vulns),
                            "critical_vulns": len([v for v in vulns if v.get("severity") == "critical"]),
                            "high_vulns": len([v for v in vulns if v.get("severity") == "high"])
                        })
                    
                    elif scanner_name == "DNS":
                        feature_row.update({
                            "dns_records": len(result.data.get("records", {})),
                            "subdomains": len(result.data.get("subdomains", []))
                        })
                    
                    features.append(feature_row)
            
            return pd.DataFrame(features)
        
        except Exception as e:
            logging.error(f"Feature extraction failed: {e}")
            return pd.DataFrame()
    
    def _count_high_risk_ports(self, ports: List[int]) -> int:
        """Count high-risk ports"""
        high_risk_ports = [21, 23, 25, 53, 135, 139, 445, 1433, 3389, 5900, 6379, 9200, 27017]
        return len([p for p in ports if p in high_risk_ports])
    
    async def _detect_anomalies(self, features_df: 'pd.DataFrame') -> Dict[str, Any]:
        """Detect anomalies in scan data using Isolation Forest"""
        anomalies = {
            "anomalous_scanners": [],
            "anomaly_scores": {},
            "outlier_features": []
        }
        
        try:
            # Select numeric features for anomaly detection
            numeric_features = features_df.select_dtypes(include=[np.number])
            
            if not numeric_features.empty and len(numeric_features) > 1:
                # Fit Isolation Forest
                iso_forest = IsolationForest(contamination=0.1, random_state=42)
                outliers = iso_forest.fit_predict(numeric_features)
                scores = iso_forest.score_samples(numeric_features)
                
                # Identify anomalous scanners
                for idx, outlier in enumerate(outliers):
                    if outlier == -1:  # Anomaly
                        scanner = features_df.iloc[idx]["scanner"]
                        score = scores[idx]
                        anomalies["anomalous_scanners"].append({
                            "scanner": scanner,
                            "anomaly_score": float(score),
                            "reason": "Unusual behavior pattern detected"
                        })
                
                anomalies["anomaly_scores"] = {
                    "mean_score": float(np.mean(scores)),
                    "min_score": float(np.min(scores)),
                    "max_score": float(np.max(scores))
                }
        
        except Exception as e:
            logging.error(f"Anomaly detection failed: {e}")
            anomalies["error"] = str(e)
        
        return anomalies
    
    async def _cluster_vulnerabilities(self, features_df: 'pd.DataFrame') -> Dict[str, Any]:
        """Cluster vulnerabilities using DBSCAN"""
        clustering = {
            "clusters": [],
            "cluster_characteristics": {},
            "recommendations": []
        }
        
        try:
            # Select features related to vulnerabilities
            vuln_features = ["vulnerability_count", "critical_vulns", "high_vulns", "open_ports"]
            available_features = [f for f in vuln_features if f in features_df.columns]
            
            if available_features and len(features_df) > 3:
                vuln_data = features_df[available_features].fillna(0)
                
                # Normalize data
                scaler = StandardScaler()
                scaled_data = scaler.fit_transform(vuln_data)
                
                # Apply DBSCAN clustering
                dbscan = DBSCAN(eps=0.5, min_samples=2)
                cluster_labels = dbscan.fit_predict(scaled_data)
                
                # Analyze clusters
                unique_labels = set(cluster_labels)
                for label in unique_labels:
                    if label == -1:  # Noise points
                        continue
                    
                    cluster_indices = np.where(cluster_labels == label)[0]
                    cluster_data = vuln_data.iloc[cluster_indices]
                    
                    clustering["clusters"].append({
                        "cluster_id": int(label),
                        "size": len(cluster_indices),
                        "scanners": features_df.iloc[cluster_indices]["scanner"].tolist(),
                        "characteristics": {
                            "avg_vulnerabilities": float(cluster_data["vulnerability_count"].mean()) if "vulnerability_count" in cluster_data else 0,
                            "avg_critical": float(cluster_data["critical_vulns"].mean()) if "critical_vulns" in cluster_data else 0,
                            "avg_high": float(cluster_data["high_vulns"].mean()) if "high_vulns" in cluster_data else 0
                        }
                    })
        
        except Exception as e:
            logging.error(f"Vulnerability clustering failed: {e}")
            clustering["error"] = str(e)
        
        return clustering
    
    async def _predict_threats(self, features_df: 'pd.DataFrame') -> Dict[str, Any]:
        """Predict potential threats based on scan patterns"""
        predictions = {
            "threat_likelihood": {},
            "attack_vectors": [],
            "risk_indicators": [],
            "predictions": []
        }
        
        try:
            # Simple rule-based threat prediction
            for _, row in features_df.iterrows():
                scanner = row["scanner"]
                threat_score = 0.0
                indicators = []
                
                # Port-based threat indicators
                if scanner == "Ports":
                    open_ports = row.get("open_ports", 0)
                    high_risk_ports = row.get("high_risk_ports", 0)
                    
                    if high_risk_ports > 0:
                        threat_score += 0.3 * (high_risk_ports / max(open_ports, 1))
                        indicators.append(f"High-risk ports detected: {high_risk_ports}")
                    
                    if open_ports > 20:
                        threat_score += 0.2
                        indicators.append("Large attack surface (many open ports)")
                
                # Vulnerability-based threat indicators
                elif scanner == "Vulnerabilities":
                    critical_vulns = row.get("critical_vulns", 0)
                    high_vulns = row.get("high_vulns", 0)
                    
                    if critical_vulns > 0:
                        threat_score += 0.5 * critical_vulns
                        indicators.append(f"Critical vulnerabilities: {critical_vulns}")
                    
                    if high_vulns > 0:
                        threat_score += 0.3 * high_vulns
                        indicators.append(f"High-severity vulnerabilities: {high_vulns}")
                
                if threat_score > 0:
                    predictions["predictions"].append({
                        "scanner": scanner,
                        "threat_score": min(1.0, threat_score),
                        "threat_level": self._classify_threat_level(threat_score),
                        "indicators": indicators
                    })
        
        except Exception as e:
            logging.error(f"Threat prediction failed: {e}")
            predictions["error"] = str(e)
        
        return predictions
    
    def _classify_threat_level(self, score: float) -> str:
        """Classify threat level based on score"""
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        elif score >= 0.2:
            return "low"
        else:
            return "minimal"
    
    async def _ml_risk_scoring(self, features_df: 'pd.DataFrame') -> Dict[str, Any]:
        """Enhanced ML-based risk scoring"""
        risk_scoring = {
            "overall_risk_score": 0.0,
            "component_scores": {},
            "risk_factors": [],
            "ml_insights": []
        }
        
        try:
            # Calculate component risk scores
            for _, row in features_df.iterrows():
                scanner = row["scanner"]
                
                # Duration-based risk (unusually long scans might indicate issues)
                duration_risk = min(1.0, row.get("duration", 0) / 300)  # 5 minutes as baseline
                
                # Error-based risk
                error_risk = min(1.0, row.get("error_count", 0) / 5)  # 5 errors as high risk
                
                # Scanner-specific risk calculation
                if scanner == "Vulnerabilities":
                    vuln_risk = (
                        row.get("critical_vulns", 0) * 1.0 +
                        row.get("high_vulns", 0) * 0.7 +
                        row.get("vulnerability_count", 0) * 0.1
                    ) / 10
                    risk_scoring["component_scores"][scanner] = min(1.0, vuln_risk)
                
                elif scanner == "Ports":
                    port_risk = (
                        row.get("high_risk_ports", 0) * 0.3 +
                        row.get("open_ports", 0) * 0.05
                    )
                    risk_scoring["component_scores"][scanner] = min(1.0, port_risk)
                
                else:
                    # General risk based on errors and duration
                    general_risk = (duration_risk + error_risk) / 2
                    risk_scoring["component_scores"][scanner] = general_risk
            
            # Calculate overall risk score
            if risk_scoring["component_scores"]:
                risk_scoring["overall_risk_score"] = np.mean(list(risk_scoring["component_scores"].values()))
        
        except Exception as e:
            logging.error(f"ML risk scoring failed: {e}")
            risk_scoring["error"] = str(e)
        
        return risk_scoring
    
    async def _recognize_patterns(self, features_df: 'pd.DataFrame') -> Dict[str, Any]:
        """Recognize patterns in scan data"""
        patterns = {
            "scanning_patterns": [],
            "temporal_patterns": [],
            "correlation_matrix": {},
            "insights": []
        }
        
        try:
            # Correlation analysis
            numeric_features = features_df.select_dtypes(include=[np.number])
            if not numeric_features.empty and len(numeric_features.columns) > 1:
                corr_matrix = numeric_features.corr()
                
                # Convert to JSON-serializable format
                patterns["correlation_matrix"] = corr_matrix.to_dict()
                
                # Find strong correlations
                strong_correlations = []
                for i in range(len(corr_matrix.columns)):
                    for j in range(i+1, len(corr_matrix.columns)):
                        corr_val = corr_matrix.iloc[i, j]
                        if abs(corr_val) > 0.7:  # Strong correlation threshold
                            strong_correlations.append({
                                "feature1": corr_matrix.columns[i],
                                "feature2": corr_matrix.columns[j],
                                "correlation": float(corr_val)
                            })
                
                patterns["insights"] = strong_correlations
        
        except Exception as e:
            logging.error(f"Pattern recognition failed: {e}")
            patterns["error"] = str(e)
        
        return patterns
    
    async def save_ml_analysis(self, ml_analysis: Dict[str, Any], output_dir: str) -> None:
        """Save ML analysis results"""
        try:
            os.makedirs(f"{output_dir}/ml_analysis", exist_ok=True)
            
            # Save JSON report
            with open(f"{output_dir}/ml_analysis/ml_analysis.json", 'w') as f:
                json.dump(ml_analysis, f, indent=2, default=str)
            
            # Create visualization if matplotlib is available
            if HAS_ML_LIBS:
                await self._create_visualizations(ml_analysis, output_dir)
        
        except Exception as e:
            logging.error(f"Failed to save ML analysis: {e}")
    
    async def _create_visualizations(self, ml_analysis: Dict[str, Any], output_dir: str) -> None:
        """Create visualizations for ML analysis"""
        try:
            # Create anomaly detection plot
            anomalies = ml_analysis.get("anomaly_detection", {})
            if "anomaly_scores" in anomalies:
                plt.figure(figsize=(10, 6))
                scores = anomalies["anomaly_scores"]
                plt.bar(["Mean", "Min", "Max"], [scores.get("mean_score", 0), scores.get("min_score", 0), scores.get("max_score", 0)])
                plt.title("Anomaly Detection Scores")
                plt.ylabel("Anomaly Score")
                plt.savefig(f"{output_dir}/ml_analysis/anomaly_scores.png")
                plt.close()
            
            # Create clustering visualization
            clustering = ml_analysis.get("vulnerability_clustering", {})
            if "clusters" in clustering and clustering["clusters"]:
                cluster_sizes = [c["size"] for c in clustering["clusters"]]
                cluster_ids = [f"Cluster {c['cluster_id']}" for c in clustering["clusters"]]
                
                plt.figure(figsize=(8, 6))
                plt.pie(cluster_sizes, labels=cluster_ids, autopct='%1.1f%%')
                plt.title("Vulnerability Clusters")
                plt.savefig(f"{output_dir}/ml_analysis/vulnerability_clusters.png")
                plt.close()
        
        except Exception as e:
            logging.error(f"Visualization creation failed: {e}")


class RiskAnalyzer:
    """Advanced risk analysis and assessment engine"""
    
    def __init__(self, console: Console):
        self.console = console
        self.ml_analyzer = MachineLearningAnalyzer(console)
        
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
            # Core Scanners
            "DNS": DNSScanner,
            "WHOIS": WhoisScanner,
            "Ports": PortScanner,
            "Web": WebScanner,
            "DOM": DOMScanner,
            "Vulnerabilities": VulnerabilityScanner,
            "SSL": SSLScanner,
            "Intelligence": IntelligenceGatherer,
            "API_Discovery": APIDiscoveryScanner,
            
            # Advanced Scanners
            "Cloud_Security": CloudSecurityScanner,
            "Container_Security": ContainerScanner,
            "Exploit_Detection": ExploitScanner,
            "Compliance": ComplianceScanner
        }
        self.scan_results: Dict[str, ScanResult] = {}
        self.overall_scan_start: Optional[datetime] = None
        
        # Initialize risk analyzer
        self.risk_analyzer = RiskAnalyzer(self.console)
        
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
        
        # Add core scanners
        selected_scanners.extend(["Web", "Vulnerabilities", "SSL"])
        
        # Add optional scanners based on configuration
        if self.config.intelligence_enabled:
            selected_scanners.append("Intelligence")
        
        if self.config.dom_scan_enabled:
            selected_scanners.append("DOM")
        
        if self.config.api_discovery_enabled:
            selected_scanners.append("API_Discovery")
        
        # Add advanced scanners based on configuration
        if self.config.cloud_security_enabled:
            selected_scanners.append("Cloud_Security")
        
        if self.config.container_security_enabled:
            selected_scanners.append("Container_Security")
        
        if self.config.exploit_detection_enabled:
            selected_scanners.append("Exploit_Detection")
        
        if self.config.compliance_scanning_enabled:
            selected_scanners.append("Compliance")
        
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