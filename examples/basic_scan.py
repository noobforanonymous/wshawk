#!/usr/bin/env python3
"""
WSHawk - Basic WebSocket Security Scan Example

This example shows the simplest way to use WSHawk programmatically.
"""

import asyncio
from wshawk.scanner_v2 import WSHawkV2


async def basic_scan():
    # Target WebSocket URL
    target = "ws://localhost:8080/ws"
    
    # Create scanner with rate limiting (10 requests/sec)
    scanner = WSHawkV2(target, max_rps=10)
    
    # Disable optional features for a quick scan
    scanner.use_headless_browser = False
    scanner.use_oast = False
    
    print(f"[*] Starting basic scan against {target}")
    
    # Run the full heuristic scan
    await scanner.run_heuristic_scan()
    
    # Print results
    print(f"\n[*] Scan complete!")
    print(f"[*] Vulnerabilities found: {len(scanner.vulnerabilities)}")
    
    for vuln in scanner.vulnerabilities:
        print(f"  [{vuln.get('confidence', 'N/A')}] {vuln.get('type', 'Unknown')}")
        print(f"    Description: {vuln.get('description', 'N/A')}")
        print(f"    Payload:     {vuln.get('payload', 'N/A')[:80]}")
        print()


if __name__ == "__main__":
    asyncio.run(basic_scan())
