#!/usr/bin/env python3
"""
WSHawk v2.0 - Intelligent WebSocket Security Scanner
Integrated with all intelligence modules
"""

import asyncio
import websockets
import json
import time
from typing import List, Dict, Optional
from datetime import datetime

# Import new intelligence modules
from .message_intelligence import MessageIntelligence, MessageFormat
from .vulnerability_verifier import VulnerabilityVerifier, ConfidenceLevel
from .server_fingerprint import ServerFingerprinter
from .state_machine import SessionStateMachine, SessionState
from .rate_limiter import TokenBucketRateLimiter
from .enhanced_reporter import EnhancedHTMLReporter
from .headless_xss_verifier import HeadlessBrowserXSSVerifier
from .oast_provider import OASTProvider, SimpleOASTServer
from .session_hijacking_tester import SessionHijackingTester

# Import existing modules
from .__main__ import WSPayloads, Logger, Colors

class WSHawkV2:
    """
    Enhanced WebSocket Security Scanner with Intelligence
    """
    
    def __init__(self, url: str, headers: Optional[Dict] = None, 
                 auth_sequence: Optional[str] = None,
                 max_rps: int = 10):
        self.url = url
        self.headers = headers or {}
        self.vulnerabilities = []
        
        # Initialize intelligence modules
        self.message_intel = MessageIntelligence()
        self.verifier = VulnerabilityVerifier()
        self.fingerprinter = ServerFingerprinter()
        self.state_machine = SessionStateMachine()
        self.rate_limiter = TokenBucketRateLimiter(
            tokens_per_second=max_rps,
            bucket_size=max_rps * 2,
            enable_adaptive=True
        )
        self.reporter = EnhancedHTMLReporter()
        
        # Advanced verification (optional, can be disabled)
        self.use_headless_browser = True
        self.headless_verifier = None
        
        # OAST for blind vulnerabilities
        self.use_oast = True
        self.oast_provider = None
        
        # Load auth sequence if provided
        if auth_sequence:
            self.state_machine.load_sequence_from_yaml(auth_sequence)
        
        # Statistics
        self.messages_sent = 0
        self.messages_received = 0
        self.start_time = None
        self.end_time = None
        
        # Learning phase
        self.learning_complete = False
        self.sample_messages = []
        
        # Traffic logs for reporting
        self.traffic_logs = []
    
    async def connect(self):
        """Establish WebSocket connection"""
        try:
            ws = await websockets.connect(self.url, additional_headers=self.headers)
            self.state_machine._update_state('connected')
            return ws
        except Exception as e:
            Logger.error(f"Connection failed: {e}")
            return None
    
    async def learning_phase(self, ws, duration: int = 5):
        """
        Learning phase: collect sample messages to understand protocol
        """
        Logger.info(f"Starting learning phase ({duration}s)...")
        Logger.info("Listening to understand message structure...")
        
        start = time.monotonic()
        samples = []
        
        try:
            while time.monotonic() - start < duration:
                try:
                    # Set timeout for receiving
                    message = await asyncio.wait_for(ws.recv(), timeout=1.0)
                    samples.append(message)
                    self.messages_received += 1
                    
                    # Add to fingerprinter
                    self.fingerprinter.add_response(message)
                    
                    if len(samples) <= 3:
                        Logger.info(f"Sample message {len(samples)}: {message[:100]}...")
                
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    break
        
        except Exception as e:
            Logger.error(f"Learning phase error: {e}")
        
        # Learn from collected samples
        if samples:
            self.message_intel.learn_from_messages(samples)
            self.sample_messages = samples
            
            # Get format info
            format_info = self.message_intel.get_format_info()
            Logger.success(f"Detected format: {format_info['format']}")
            
            if format_info['injectable_fields']:
                Logger.info(f"Injectable fields: {', '.join(format_info['injectable_fields'][:5])}")
            
            # Fingerprint server
            fingerprint = self.fingerprinter.fingerprint()
            if fingerprint.language:
                Logger.success(f"Server: {fingerprint.language or 'unknown'} / {fingerprint.framework or 'unknown'}")
            if fingerprint.database:
                Logger.info(f"Database: {fingerprint.database}")
            
            self.learning_complete = True
        else:
            Logger.warning("No messages received during learning phase")
            Logger.info("Will use basic payload injection")
    
    async def test_sql_injection_v2(self, ws) -> List[Dict]:
        """
        Enhanced SQL injection testing with intelligence
        """
        Logger.info("Testing SQL injection with intelligent verification...")
        
        results = []
        payloads = WSPayloads.get_sql_injection()[:100]  # Use subset for speed
        
        # Get server-specific payloads if fingerprinted
        fingerprint = self.fingerprinter.fingerprint()
        if fingerprint.database:
            recommended = self.fingerprinter.get_recommended_payloads(fingerprint)
            if recommended.get('sql'):
                Logger.info(f"Using {fingerprint.database}-specific payloads")
                payloads = recommended['sql'] + payloads[:50]
        
        # Get base message for injection
        base_message = self.sample_messages[0] if self.sample_messages else '{"test": "value"}'
        
        for payload in payloads:
            try:
                # Smart injection into message structure
                if self.learning_complete and self.message_intel.detected_format == MessageFormat.JSON:
                    injected_messages = self.message_intel.inject_payload_into_message(
                        base_message, payload
                    )
                else:
                    injected_messages = [payload]
                
                for msg in injected_messages:
                    await ws.send(msg)
                    self.messages_sent += 1
                    
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                        self.messages_received += 1
                        
                        # Add to fingerprinter
                        self.fingerprinter.add_response(response)
                        
                        # REAL VERIFICATION - not just reflection
                        is_vuln, confidence, description = self.verifier.verify_sql_injection(
                            response, payload
                        )
                        
                        if is_vuln and confidence != ConfidenceLevel.LOW:
                            Logger.vuln(f"SQL Injection [{confidence.value}]: {description}")
                            Logger.vuln(f"Payload: {payload[:80]}")
                            
                            self.vulnerabilities.append({
                                'type': 'SQL Injection',
                                'severity': confidence.value,
                                'confidence': confidence.value,
                                'description': description,
                                'payload': payload,
                                'response_snippet': response[:200],
                                'recommendation': 'Use parameterized queries'
                            })
                            results.append({'payload': payload, 'confidence': confidence.value})
                    
                    except asyncio.TimeoutError:
                        pass
                    
                    await asyncio.sleep(0.05)  # Rate limiting
            
            except Exception as e:
                Logger.error(f"SQL test error: {e}")
                continue
        
        return results
    
    async def test_xss_v2(self, ws) -> List[Dict]:
        """
        Enhanced XSS testing with context analysis
        """
        Logger.info("Testing XSS with context analysis...")
        
        results = []
        payloads = WSPayloads.get_xss()[:100]
        
        base_message = self.sample_messages[0] if self.sample_messages else '{"message": "test"}'
        
        for payload in payloads:
            try:
                if self.learning_complete and self.message_intel.detected_format == MessageFormat.JSON:
                    injected_messages = self.message_intel.inject_payload_into_message(
                        base_message, payload
                    )
                else:
                    injected_messages = [payload]
                
                for msg in injected_messages:
                    await ws.send(msg)
                    self.messages_sent += 1
                    
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                        self.messages_received += 1
                        
                        # REAL VERIFICATION with context analysis
                        is_vuln, confidence, description = self.verifier.verify_xss(
                            response, payload
                        )
                        
                        if is_vuln and confidence != ConfidenceLevel.LOW:
                            # For HIGH confidence, verify with headless browser
                            browser_verified = False
                            if confidence == ConfidenceLevel.HIGH and self.use_headless_browser:
                                try:
                                    if not self.headless_verifier:
                                        self.headless_verifier = HeadlessBrowserXSSVerifier()
                                        await self.headless_verifier.start()
                                    
                                    is_executed, evidence = await self.headless_verifier.verify_xss_execution(
                                        response, payload
                                    )
                                    
                                    if is_executed:
                                        browser_verified = True
                                        confidence = ConfidenceLevel.CRITICAL
                                        description = f"REAL EXECUTION: {evidence}"
                                except Exception as e:
                                    Logger.error(f"Browser verification failed: {e}")
                            
                            Logger.vuln(f"XSS [{confidence.value}]: {description}")
                            Logger.vuln(f"Payload: {payload[:80]}")
                            if browser_verified:
                                Logger.vuln("  [BROWSER VERIFIED] Payload executed in real browser!")
                            
                            self.vulnerabilities.append({
                                'type': 'Cross-Site Scripting (XSS)',
                                'severity': confidence.value,
                                'confidence': confidence.value,
                                'description': description,
                                'payload': payload,
                                'response_snippet': response[:200],
                                'browser_verified': browser_verified,
                                'recommendation': 'Sanitize and encode all user input'
                            })
                            results.append({'payload': payload, 'confidence': confidence.value})
                    
                    except asyncio.TimeoutError:
                        pass
                    
                    await asyncio.sleep(0.05)
            
            except Exception as e:
                continue
        
        return results
    
    async def test_command_injection_v2(self, ws) -> List[Dict]:
        """
        Enhanced command injection with timing attacks
        """
        Logger.info("Testing command injection with execution detection...")
        
        results = []
        payloads = WSPayloads.get_command_injection()[:100]
        
        # Get language-specific payloads
        fingerprint = self.fingerprinter.fingerprint()
        if fingerprint.language:
            recommended = self.fingerprinter.get_recommended_payloads(fingerprint)
            if recommended.get('command'):
                Logger.info(f"Using {fingerprint.language}-specific command payloads")
                payloads = recommended['command'] + payloads[:50]
        
        base_message = self.sample_messages[0] if self.sample_messages else '{"cmd": "test"}'
        
        for payload in payloads:
            try:
                if self.learning_complete and self.message_intel.detected_format == MessageFormat.JSON:
                    injected_messages = self.message_intel.inject_payload_into_message(
                        base_message, payload
                    )
                else:
                    injected_messages = [payload]
                
                for msg in injected_messages:
                    await ws.send(msg)
                    self.messages_sent += 1
                    
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                        self.messages_received += 1
                        
                        # REAL VERIFICATION
                        is_vuln, confidence, description = self.verifier.verify_command_injection(
                            response, payload
                        )
                        
                        if is_vuln and confidence != ConfidenceLevel.LOW:
                            Logger.vuln(f"Command Injection [{confidence.value}]: {description}")
                            Logger.vuln(f"Payload: {payload[:80]}")
                            
                            self.vulnerabilities.append({
                                'type': 'Command Injection',
                                'severity': confidence.value,
                                'confidence': confidence.value,
                                'description': description,
                                'payload': payload,
                                'response_snippet': response[:200],
                                'recommendation': 'Never pass user input to system commands'
                            })
                            results.append({'payload': payload, 'confidence': confidence.value})
                    
                    except asyncio.TimeoutError:
                        pass
                    
                    await asyncio.sleep(0.05)
            
            except Exception as e:
                continue
        
        return results
    
    async def test_path_traversal_v2(self, ws) -> List[Dict]:
        """Enhanced path traversal testing"""
        Logger.info("Testing path traversal...")
        
        results = []
        payloads = WSPayloads.get_path_traversal()[:50]
        
        for payload in payloads:
            try:
                msg = json.dumps({"action": "read_file", "filename": payload})
                await ws.send(msg)
                self.messages_sent += 1
                
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                    self.messages_received += 1
                    
                    is_vuln, confidence, description = self.verifier.verify_path_traversal(response, payload)
                    
                    if is_vuln and confidence != ConfidenceLevel.LOW:
                        Logger.vuln(f"Path Traversal [{confidence.value}]: {description}")
                        self.vulnerabilities.append({
                            'type': 'Path Traversal',
                            'severity': confidence.value,
                            'confidence': confidence.value,
                            'description': description,
                            'payload': payload,
                            'response_snippet': response[:200],
                            'recommendation': 'Validate and sanitize file paths'
                        })
                        results.append({'payload': payload, 'confidence': confidence.value})
                
                except asyncio.TimeoutError:
                    pass
                
                await asyncio.sleep(0.05)
            except Exception as e:
                continue
        
        return results
    
    async def test_xxe_v2(self, ws) -> List[Dict]:
        """Enhanced XXE testing with OAST"""
        Logger.info("Testing XXE with OAST...")
        
        results = []
        payloads = WSPayloads.get_xxe()[:30]
        
        # Start OAST if enabled
        if self.use_oast and not self.oast_provider:
            try:
                self.oast_provider = OASTProvider(use_interactsh=False, custom_server="localhost:8888")
                await self.oast_provider.start()
                Logger.info("OAST provider started for blind XXE detection")
            except Exception as e:
                Logger.error(f"OAST start failed: {e}")
                self.use_oast = False
        
        for payload in payloads:
            try:
                # Generate OAST payload if available
                if self.use_oast and self.oast_provider:
                    oast_payload = self.oast_provider.generate_payload('xxe', f'test{len(results)}')
                    msg = json.dumps({"action": "parse_xml", "xml": oast_payload})
                else:
                    msg = json.dumps({"action": "parse_xml", "xml": payload})
                
                await ws.send(msg)
                self.messages_sent += 1
                
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                    self.messages_received += 1
                    
                    xxe_indicators = ['<!entity', 'system', 'file://', 'root:', 'XML Parse Error']
                    if any(ind.lower() in response.lower() for ind in xxe_indicators):
                        Logger.vuln(f"XXE [HIGH]: Entity processing detected")
                        self.vulnerabilities.append({
                            'type': 'XML External Entity (XXE)',
                            'severity': 'HIGH',
                            'confidence': 'HIGH',
                            'description': 'XXE vulnerability - external entities processed',
                            'payload': payload[:80],
                            'response_snippet': response[:200],
                            'recommendation': 'Disable external entity processing'
                        })
                        results.append({'payload': payload, 'confidence': 'HIGH'})
                
                except asyncio.TimeoutError:
                    pass
                
                await asyncio.sleep(0.05)
            except Exception as e:
                continue
        
        return results
    
    async def test_nosql_injection_v2(self, ws) -> List[Dict]:
        """Enhanced NoSQL injection testing"""
        Logger.info("Testing NoSQL injection...")
        
        results = []
        payloads = WSPayloads.get_nosql_injection()[:50]
        
        for payload in payloads:
            try:
                msg = json.dumps({"action": "find_user", "query": {"username": payload}})
                await ws.send(msg)
                self.messages_sent += 1
                
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                    self.messages_received += 1
                    
                    nosql_indicators = ['mongodb', 'bson', 'query error', '$ne', '$gt', 'Query Error']
                    if any(ind.lower() in response.lower() for ind in nosql_indicators):
                        Logger.vuln(f"NoSQL Injection [HIGH]: Query manipulation detected")
                        self.vulnerabilities.append({
                            'type': 'NoSQL Injection',
                            'severity': 'HIGH',
                            'confidence': 'HIGH',
                            'description': 'NoSQL injection vulnerability detected',
                            'payload': payload,
                            'response_snippet': response[:200],
                            'recommendation': 'Use parameterized queries'
                        })
                        results.append({'payload': payload, 'confidence': 'HIGH'})
                
                except asyncio.TimeoutError:
                    pass
                
                await asyncio.sleep(0.05)
            except Exception as e:
                continue
        
        return results
    
    async def test_ssrf_v2(self, ws) -> List[Dict]:
        """Enhanced SSRF testing"""
        Logger.info("Testing SSRF...")
        
        results = []
        internal_targets = [
            'http://localhost',
            'http://127.0.0.1',
            'http://169.254.169.254/latest/meta-data/',
            'http://metadata.google.internal',
        ]
        
        for target in internal_targets:
            try:
                await self.rate_limiter.acquire()
                
                msg = json.dumps({"action": "fetch_url", "url": target})
                await ws.send(msg)
                self.messages_sent += 1
                
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=3.0)
                    self.messages_received += 1
                    
                    ssrf_indicators = ['connection refused', 'timeout', 'metadata', 'instance-id', 'localhost']
                    if any(ind.lower() in response.lower() for ind in ssrf_indicators):
                        Logger.vuln(f"SSRF [HIGH]: Internal endpoint accessible - {target}")
                        self.vulnerabilities.append({
                            'type': 'Server-Side Request Forgery (SSRF)',
                            'severity': 'HIGH',
                            'confidence': 'HIGH',
                            'description': f'SSRF vulnerability - accessed {target}',
                            'payload': target,
                            'response_snippet': response[:200],
                            'recommendation': 'Validate and whitelist allowed URLs'
                        })
                        results.append({'payload': target, 'confidence': 'HIGH'})
                
                except asyncio.TimeoutError:
                    pass
                
                await asyncio.sleep(0.1)
            except Exception as e:
                continue
        
        return results
    
    async def run_intelligent_scan(self):
        """
        Run full intelligent scan with all modules
        """
        self.start_time = datetime.now()
        Logger.banner()
        Logger.info(f"Target: {self.url}")
        Logger.info("Starting intelligent scan with rate limiting...")
        print()
        
        # Connect
        ws = await self.connect()
        if not ws:
            return None
        
        Logger.success("Connected!")
        print()
        
        # Learning phase
        await self.learning_phase(ws, duration=5)
        print()
        
        # Run ALL tests with intelligence and rate limiting
        await self.test_sql_injection_v2(ws)
        print()
        
        await self.test_xss_v2(ws)
        print()
        
        await self.test_command_injection_v2(ws)
        print()
        
        await self.test_path_traversal_v2(ws)
        print()
        
        await self.test_xxe_v2(ws)
        print()
        
        await self.test_nosql_injection_v2(ws)
        print()
        
        await self.test_ssrf_v2(ws)
        print()
        
        # Close connection
        await ws.close()
        
        # Run session hijacking tests
        Logger.info("\n" + "="*50)
        Logger.info("Running Session Hijacking Tests...")
        Logger.info("="*50)
        try:
            session_tester = SessionHijackingTester(self.url)
            session_results = await session_tester.run_all_tests()
            
            # Add session vulnerabilities to main results
            for result in session_results:
                if result.is_vulnerable:
                    self.vulnerabilities.append({
                        'type': f'Session Security: {result.vuln_type.value}',
                        'severity': result.confidence,
                        'confidence': result.confidence,
                        'description': result.description,
                        'payload': 'N/A',
                        'response_snippet': str(result.evidence)[:200],
                        'recommendation': result.recommendation,
                        'cvss_score': result.cvss_score
                    })
            
            Logger.success(f"Session tests complete: {len(session_results)} tests run")
        except Exception as e:
            Logger.error(f"Session hijacking tests failed: {e}")
        
        # Cleanup advanced verification resources
        if self.headless_verifier:
            try:
                await self.headless_verifier.stop()
                Logger.info("Headless browser stopped")
            except Exception as e:
                Logger.error(f"Browser cleanup error: {e}")
        
        if self.oast_provider:
            try:
                await self.oast_provider.stop()
                Logger.info("OAST provider stopped")
            except Exception as e:
                Logger.error(f"OAST cleanup error: {e}")
        
        # Summary
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        
        Logger.success(f"Scan complete in {duration:.2f}s")
        Logger.info(f"Messages sent: {self.messages_sent}")
        Logger.info(f"Messages received: {self.messages_received}")
        Logger.info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        
        # Show confidence breakdown
        if self.vulnerabilities:
            print()
            Logger.info("Confidence breakdown:")
            for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = sum(1 for v in self.vulnerabilities if v['confidence'] == level)
                if count > 0:
                    print(f"  {level}: {count}")
        
        # Generate enhanced HTML report
        Logger.info("\nGenerating enhanced HTML report...")
        scan_info = {
            'target': self.url,
            'duration': duration,
            'messages_sent': self.messages_sent,
            'messages_received': self.messages_received
        }
        
        fingerprint_info = self.fingerprinter.get_info()
        
        report_html = self.reporter.generate_report(
            self.vulnerabilities,
            scan_info,
            fingerprint_info
        )
        
        # Save report
        report_filename = f"wshawk_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(report_filename, 'w') as f:
            f.write(report_html)
        
        Logger.success(f"Enhanced HTML report saved: {report_filename}")
        
        # Show rate limiter stats
        rate_stats = self.rate_limiter.get_stats()
        Logger.info(f"Rate limiter: {rate_stats['total_requests']} requests, {rate_stats['total_waits']} waits")
        Logger.info(f"  Current rate: {rate_stats['current_rate']}, Adaptive adjustments: {rate_stats['adaptive_adjustments']}")
        
        return self.vulnerabilities
