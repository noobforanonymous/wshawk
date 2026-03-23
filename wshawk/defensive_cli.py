#!/usr/bin/env python3
"""
WSHawk Defensive Validation CLI
Entry point for defensive security validation
"""

import asyncio
import sys
from .defensive_validation import run_defensive_validation
from .__main__ import Colors, Logger


async def main():
    """
    Main entry point for defensive validation
    """
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        print(f"{Colors.CYAN}╦ ╦╔═╗╦ ╦╔═╗╦ ╦╦╔═{Colors.END}")
        print(f"{Colors.CYAN}║║║╚═╗╠═╣╠═╣║║║╠╩╗{Colors.END}")
        print(f"{Colors.CYAN}╚╩╝╚═╝╩ ╩╩ ╩╚╩╝╩ ╩{Colors.END}")
        print()
        print(f"{Colors.BOLD}Defensive Validation Suite{Colors.END}")
        print(f"Created by: Regaan (@regaan)")
        print("━" * 70)
        print()
        print(f"{Colors.CYAN}Enter WebSocket URL (e.g., ws://example.com or wss://example.com):{Colors.END}")
        target_url = input(f"{Colors.YELLOW}> {Colors.END}").strip()
    
    if not target_url:
        Logger.error("No URL provided")
        return
    
    # Validate URL
    if not target_url.startswith(('ws://', 'wss://')):
        Logger.error("URL must start with ws:// or wss://")
        return
    
    # Run defensive validation
    await run_defensive_validation(target_url)


def cli():
    """Entry point for pip-installed command"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Validation interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] Fatal error: {e}{Colors.END}")


if __name__ == "__main__":
    cli()
