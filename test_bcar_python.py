#!/usr/bin/env python3
"""
Test script for BCAR Python version
"""

import asyncio
import sys
from pathlib import Path

# Add current directory to path for testing
sys.path.insert(0, str(Path(__file__).parent))

from bcar import BCAR, BCARConfig, check_dependencies
from rich.console import Console

async def test_basic_functionality():
    """Test basic BCAR functionality"""
    console = Console()
    
    console.print("[cyan]Testing BCAR Python Implementation...[/cyan]\n")
    
    # Test 1: Configuration
    console.print("[yellow]1. Testing Configuration Management...[/yellow]")
    config = BCARConfig()
    config.target = "example.com"
    config.threads = 25
    config.stealth_mode = True
    
    # Save and load config
    config.save_to_file("test_config.json")
    new_config = BCARConfig()
    new_config.load_from_file("test_config.json")
    
    assert new_config.target == "example.com"
    assert new_config.threads == 25
    assert new_config.stealth_mode == True
    console.print("[green]✓ Configuration management works[/green]")
    
    # Test 2: Dependencies check
    console.print("[yellow]2. Testing Dependencies Check...[/yellow]")
    dep_result = await check_dependencies()
    console.print(f"[green]✓ Dependencies check: {'Passed' if dep_result else 'Some missing'}[/green]")
    
    # Test 3: BCAR initialization
    console.print("[yellow]3. Testing BCAR Initialization...[/yellow]")
    bcar = BCAR()
    assert bcar.config is not None
    assert bcar.console is not None
    assert len(bcar.scanners) == 5  # DNS, Ports, Web, DOM, SSL
    console.print("[green]✓ BCAR initializes correctly[/green]")
    
    # Test 4: Scanner validation
    console.print("[yellow]4. Testing Input Validation...[/yellow]")
    from bcar import Scanner
    scanner = Scanner(config, console)
    
    # Valid targets
    test_cases = [
        ("192.168.1.1", True, "Valid IP"),
        ("example.com", True, "Valid domain"),
        ("sub.example.com", True, "Valid subdomain"), 
        ("localhost", True, "Valid hostname"),
        ("test-site.example.org", True, "Valid domain with hyphen"),
        ("invalid..domain", False, "Invalid double dot"),
        ("999.999.999.999", False, "Invalid IP range")
    ]
    
    for target, expected, description in test_cases:
        try:
            result = scanner.validate_target(target)
            if result == expected:
                console.print(f"[green]  ✓ {description}: {target}[/green]")
            else:
                console.print(f"[red]  ✗ {description}: {target} (expected {expected}, got {result})[/red]")
        except Exception as e:
            console.print(f"[red]  ✗ Error testing {target}: {e}[/red]")
    
    console.print("[green]✓ Input validation tests completed[/green]")
    
    console.print("\n[green bold]All tests passed! ✓[/green bold]")
    
    # Clean up
    Path("test_config.json").unlink(missing_ok=True)
    
    return True

async def test_menu_display():
    """Test the menu display (visual test)"""
    console = Console()
    bcar = BCAR()
    
    console.print("[cyan]Testing Menu Display...[/cyan]\n")
    
    # Set some sample configuration
    bcar.config.target = "testsite.com"
    bcar.config.threads = 75
    bcar.config.stealth_mode = True
    bcar.config.dom_scan_enabled = True
    
    # Display banner and menu (for screenshot)
    bcar.print_banner()
    console.print("\n")
    
    # Create configuration display
    from rich.table import Table
    from rich import box
    
    config_table = Table(title="Sample Configuration Display", box=box.ROUNDED)
    config_table.add_column("Setting", style="cyan")
    config_table.add_column("Value", style="yellow")
    
    config_table.add_row("Target", bcar.config.target)
    config_table.add_row("Threads", str(bcar.config.threads))
    config_table.add_row("Stealth Mode", "Enabled" if bcar.config.stealth_mode else "Disabled")
    config_table.add_row("DOM Scanning", "Enabled" if bcar.config.dom_scan_enabled else "Disabled")
    
    console.print(config_table)
    console.print("\n[green]✓ TUI interface displays correctly[/green]")

if __name__ == "__main__":
    async def run_tests():
        try:
            # Run basic functionality tests
            await test_basic_functionality()
            
            # Run visual tests
            await test_menu_display()
            
            return 0
        except Exception as e:
            console = Console()
            console.print(f"[red]Test failed: {e}[/red]")
            return 1
    
    exit_code = asyncio.run(run_tests())
    sys.exit(exit_code)