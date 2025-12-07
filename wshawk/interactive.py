#!/usr/bin/env python3
"""
WSHawk Interactive Menu
"""

import asyncio
from .__main__ import WSHawk, Logger, Colors

def show_banner():
    Logger.banner()
    
def show_menu():
    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}Select Tests to Run:{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}\n")
    
    print(f"{Colors.GREEN}1.{Colors.END}  Origin Validation Bypass - CSWSH (60+ payloads)")
    print(f"{Colors.GREEN}2.{Colors.END}  SQL Injection (ALL 722 payloads)")
    print(f"{Colors.GREEN}3.{Colors.END}  XSS - Cross-Site Scripting (ALL 7,106 payloads)")
    print(f"{Colors.GREEN}4.{Colors.END}  Command Injection (ALL 8,562 payloads)")
    print(f"{Colors.GREEN}5.{Colors.END}  NoSQL Injection (ALL payloads)")
    print(f"{Colors.GREEN}6.{Colors.END}  LDAP Injection (ALL payloads)")
    print(f"{Colors.GREEN}7.{Colors.END}  Path Traversal (ALL payloads)")
    print(f"{Colors.GREEN}8.{Colors.END}  SSTI - Server Side Template Injection (ALL payloads)")
    print(f"{Colors.GREEN}9.{Colors.END}  XXE - XML External Entity (ALL payloads)")
    print(f"{Colors.GREEN}10.{Colors.END} Open Redirect (ALL payloads)")
    print(f"{Colors.GREEN}11.{Colors.END} Message Replay Attack")
    print(f"{Colors.GREEN}12.{Colors.END} Rate Limiting Test")
    print(f"{Colors.GREEN}13.{Colors.END} Authentication Bypass")
    print(f"{Colors.GREEN}99.{Colors.END} {Colors.BOLD}FULL SCAN{Colors.END} (ALL tests with ALL payloads!)")
    print(f"{Colors.RED}0.{Colors.END}  Exit\n")

async def run_selected_tests(scanner, choices):
    """Run only selected tests"""
    
    if '1' in choices or '99' in choices:
        await scanner.test_origin_bypass()
    
    if '2' in choices or '99' in choices:
        await scanner.test_sql_injection()
    
    if '3' in choices or '99' in choices:
        await scanner.test_xss()
    
    if '4' in choices or '99' in choices:
        await scanner.test_command_injection()
    
    if '5' in choices or '99' in choices:
        await scanner.test_nosql_injection()
    
    if '6' in choices or '99' in choices:
        await scanner.test_ldap_injection()
    
    if '7' in choices or '99' in choices:
        await scanner.test_path_traversal()
    
    if '8' in choices or '99' in choices:
        await scanner.test_ssti()
    
    if '9' in choices or '99' in choices:
        await scanner.test_xxe()
    
    if '10' in choices or '99' in choices:
        await scanner.test_open_redirect()
    
    if '11' in choices or '99' in choices:
        await scanner.test_message_replay()
    
    if '12' in choices or '99' in choices:
        await scanner.test_rate_limiting()
    
    if '13' in choices or '99' in choices:
        await scanner.test_authentication_bypass()

async def main():
    show_banner()
    
    # Get target URL
    print(f"{Colors.CYAN}Enter WebSocket URL:{Colors.END}")
    url = input(f"{Colors.YELLOW}> {Colors.END}").strip()
    
    if not url:
        Logger.error("No URL provided")
        return
    
    if not url.startswith(('ws://', 'wss://')):
        Logger.error("URL must start with ws:// or wss://")
        return
    
    # Show menu
    show_menu()
    
    # Get user choice
    print(f"{Colors.CYAN}Enter test numbers (comma-separated, e.g., 1,2,3 or 8 for all):{Colors.END}")
    choice = input(f"{Colors.YELLOW}> {Colors.END}").strip()
    
    if choice == '0':
        print(f"{Colors.YELLOW}Exiting...{Colors.END}")
        return
    
    # Parse choices
    choices = [c.strip() for c in choice.split(',')]
    
    # All tests use ALL payloads (max_payloads=None)
    max_payloads = None
    
    if '99' in choices:
        Logger.warning("FULL SCAN mode - running ALL tests with ALL payloads!")
        Logger.warning("This may take several minutes...")
    else:
        Logger.info("Individual test mode - using ALL payloads for selected tests")
    
    # Create scanner with max_payloads parameter
    scanner = WSHawk(url, max_payloads=max_payloads)
    scanner.start_time = __import__('datetime').datetime.now()
    
    Logger.info(f"Target: {url}")
    Logger.info("Starting selected tests...")
    print()
    
    # Test connection first
    if not await scanner.test_connection():
        Logger.error("Cannot proceed without valid connection")
        return
    
    print()
    
    # Run selected tests
    await run_selected_tests(scanner, choices)
    
    scanner.end_time = __import__('datetime').datetime.now()
    duration = (scanner.end_time - scanner.start_time).total_seconds()
    
    print()
    Logger.success(f"Scan complete in {duration:.2f}s")
    Logger.info(f"Messages sent: {scanner.messages_sent}")
    Logger.info(f"Messages received: {scanner.messages_received}")
    Logger.info(f"Vulnerabilities found: {len(scanner.vulnerabilities)}")
    
    # Generate report
    scanner.generate_html_report()
    
    # Show summary
    report = scanner.generate_report()
    print()
    print("="*60)
    print("VULNERABILITY SUMMARY")
    print("="*60)
    print(f"Total: {report['summary']['total']}")
    print(f"Critical: {report['summary']['critical']}")
    print(f"High: {report['summary']['high']}")
    print(f"Medium: {report['summary']['medium']}")
    print("="*60)


def cli():
    """Entry point for pip-installed command"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] Fatal error: {e}{Colors.END}")


if __name__ == "__main__":
    cli()
