#!/usr/bin/env python3
"""
BCAR Installation and Setup Script
Automatically installs dependencies and sets up BCAR
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, description=""):
    """Run a command and handle errors"""
    print(f"🔄 {description}")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} - Success")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} - Failed: {e}")
        if e.stdout:
            print(f"   Output: {e.stdout}")
        if e.stderr:
            print(f"   Error: {e.stderr}")
        return False

def install_python_deps():
    """Install Python dependencies"""
    print("\n📦 Installing Python dependencies...")
    
    # Upgrade pip first
    run_command(f"{sys.executable} -m pip install --upgrade pip", "Upgrading pip")
    
    # Install requirements
    if Path("requirements.txt").exists():
        return run_command(f"{sys.executable} -m pip install -r requirements.txt", "Installing Python packages")
    else:
        # Install essential packages manually
        packages = ["rich>=13.7.0", "aiofiles", "aiohttp", "pyyaml", "python-dateutil"]
        for package in packages:
            if not run_command(f"{sys.executable} -m pip install {package}", f"Installing {package}"):
                return False
        return True

def install_system_deps():
    """Install system dependencies"""
    print("\n🔧 Installing system dependencies...")
    
    # Detect package manager and install
    if os.path.exists("/usr/bin/apt"):
        # Debian/Ubuntu
        commands = [
            "sudo apt update",
            "sudo apt install -y nmap dnsutils whois curl",
            "sudo apt install -y gobuster nikto whatweb || echo 'Optional tools not available'"
        ]
    elif os.path.exists("/usr/bin/yum"):
        # RedHat/CentOS
        commands = [
            "sudo yum update -y",
            "sudo yum install -y nmap bind-utils whois curl",
            "sudo yum install -y gobuster nikto whatweb || echo 'Optional tools not available'"
        ]
    elif os.path.exists("/usr/bin/dnf"):
        # Fedora
        commands = [
            "sudo dnf update -y", 
            "sudo dnf install -y nmap bind-utils whois curl",
            "sudo dnf install -y gobuster nikto whatweb || echo 'Optional tools not available'"
        ]
    elif os.path.exists("/usr/bin/pacman"):
        # Arch Linux
        commands = [
            "sudo pacman -Sy",
            "sudo pacman -S --noconfirm nmap bind whois curl",
            "sudo pacman -S --noconfirm gobuster nikto whatweb || echo 'Optional tools not available'"
        ]
    else:
        print("❌ Unsupported package manager. Please install manually:")
        print("   Required: nmap, dig, whois, curl")
        print("   Optional: gobuster, nikto, whatweb, domscan")
        return False
    
    for cmd in commands:
        if not run_command(cmd, f"Running: {cmd}"):
            print(f"⚠️  Command failed (may be non-critical): {cmd}")
    
    return True

def setup_wordlists():
    """Setup wordlists for directory enumeration"""
    print("\n📝 Setting up wordlists...")
    
    wordlist_paths = [
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirb/common.txt"
    ]
    
    # Check if any wordlist exists
    for path in wordlist_paths:
        if Path(path).exists():
            print(f"✅ Found wordlist: {path}")
            return True
    
    # Try to install wordlists
    if os.path.exists("/usr/bin/apt"):
        run_command("sudo apt install -y wordlists seclists || echo 'Wordlists not available in repos'", 
                   "Installing wordlists package")
    
    # Check again
    for path in wordlist_paths:
        if Path(path).exists():
            print(f"✅ Found wordlist: {path}")
            return True
    
    print("⚠️  No wordlists found. Web directory enumeration will be limited.")
    print("   Consider installing SecLists or Dirbuster wordlists manually")
    return True

def create_config():
    """Create default configuration"""
    print("\n⚙️  Creating default configuration...")
    
    config_content = {
        "threads": 50,
        "timing": "normal",
        "stealth_mode": False,
        "output_format": "json",
        "dom_scan_enabled": True,
        "dom_headless": True,
        "nmap_scripts": "default,vuln",
        "verbose": False
    }
    
    try:
        import json
        with open("bcar_config.json", "w") as f:
            json.dump(config_content, f, indent=2)
        print("✅ Created default configuration: bcar_config.json")
        return True
    except Exception as e:
        print(f"❌ Failed to create config: {e}")
        return False

def main():
    """Main installation function"""
    print("🚀 BCAR Installation and Setup")
    print("=" * 40)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ required")
        return 1
    
    print(f"✅ Python {sys.version.split()[0]} detected")
    
    # Install dependencies
    success = True
    
    success &= install_python_deps()
    success &= install_system_deps() 
    success &= setup_wordlists()
    success &= create_config()
    
    print("\n" + "=" * 40)
    
    if success:
        print("🎉 BCAR installation completed successfully!")
        print("\n📖 Usage:")
        print("   python3 bcar.py          # Start BCAR with TUI interface")
        print("   python3 run_bcar.py      # Alternative launcher")
        print("   python3 test_bcar_python.py  # Run tests")
        print("\n📁 Configuration:")
        print("   Edit bcar_config.json to customize defaults")
        print("\n🔍 First Run:")
        print("   1. Start BCAR: python3 bcar.py")
        print("   2. Set your target (option 1)")
        print("   3. Configure scan options (option 2)")
        print("   4. Start reconnaissance scan (option 3)")
    else:
        print("⚠️  Installation completed with some warnings")
        print("   BCAR should still work, but some features may be limited")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())