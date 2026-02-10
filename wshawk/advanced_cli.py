#!/usr/bin/env python3
"""
WSHawk Advanced CLI - Easy command-line interface for all v2.0 features
"""

import asyncio
import argparse
from .__main__ import Logger, Colors


async def main():
    """Advanced CLI with options"""
    parser = argparse.ArgumentParser(
        description='WSHawk v2.0 - Advanced WebSocket Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  wshawk-advanced ws://target.com                    # Quick scan
  wshawk-advanced ws://target.com --playwright       # With browser XSS verification
  wshawk-advanced ws://target.com --no-oast          # Disable OAST
  wshawk-advanced ws://target.com --rate 5           # 5 requests/second
  wshawk-advanced ws://target.com --full             # All features enabled
        '''
    )
    
    parser.add_argument('url', help='WebSocket URL (ws:// or wss://)')
    parser.add_argument('--playwright', action='store_true', 
                       help='Enable Playwright browser for XSS verification (requires: playwright install chromium)')
    parser.add_argument('--no-oast', action='store_true',
                       help='Disable OAST (Out-of-Band) testing')
    parser.add_argument('--rate', type=int, default=10,
                       help='Max requests per second (default: 10)')
    parser.add_argument('--full', action='store_true',
                       help='Enable ALL features (Playwright + OAST + Session tests)')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('ws://', 'wss://')):
        Logger.error("URL must start with ws:// or wss://")
        return
    
    # Import scanner
    from .scanner_v2 import WSHawkV2
    
    Logger.banner()
    Logger.info("WSHawk v2.0 - Advanced Scanner")
    Logger.info(f"Target: {args.url}")
    Logger.info(f"Rate limit: {args.rate} req/s")
    
    # Create scanner
    scanner = WSHawkV2(args.url, max_rps=args.rate)
    
    # Configure features
    if args.full:
        scanner.use_headless_browser = True
        scanner.use_oast = True
        Logger.info("Mode: FULL (All features enabled)")
    else:
        scanner.use_headless_browser = args.playwright
        scanner.use_oast = not args.no_oast
        
        features = []
        if scanner.use_headless_browser:
            features.append("Playwright XSS")
        if scanner.use_oast:
            features.append("OAST")
        
        Logger.info(f"Features: {', '.join(features) if features else 'Standard'}")
    
    print()
    
    # Run scan
    await scanner.run_heuristic_scan()
    
    Logger.success("Scan complete!")


def cli():
    """Entry point"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] Error: {e}{Colors.END}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    cli()
