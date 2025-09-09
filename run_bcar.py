#!/usr/bin/env python3
"""
BCAR Launcher Script
Simple launcher for BCAR with dependency checks and setup
"""

import asyncio
import sys
import os
from pathlib import Path

# Ensure we can import bcar
sys.path.insert(0, str(Path(__file__).parent))

def main():
    """Main launcher function"""
    try:
        from rich.console import Console
        
        console = Console()
        
        # Welcome message
        console.print("[cyan]🔍 BlackCell Auto Recon (BCAR) v2.0.0[/cyan]")
        console.print("[dim]Advanced Python Reconnaissance Framework[/dim]\n")
        
        # Check Python version
        if sys.version_info < (3, 8):
            console.print("[red]❌ Python 3.8+ required[/red]")
            return 1
            
        console.print(f"[green]✓ Python {sys.version.split()[0]}[/green]")
        
        # Import and run BCAR
        from bcar import main as bcar_main
        return asyncio.run(bcar_main())
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Try installing requirements: pip install -r requirements.txt")
        return 1
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        return 0
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())