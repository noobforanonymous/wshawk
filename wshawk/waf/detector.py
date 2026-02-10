"""WAF detection with proper types"""
from typing import Dict, Optional
from dataclasses import dataclass

@dataclass
class WAFInfo:
    """WAF detection information"""
    name: str
    confidence: float
    recommended_strategy: str

class WAFDetector:
    """Detects WAFs from responses"""
    
    def __init__(self):
        self.detected_waf: Optional[str] = None
        self.confidence: float = 0.0
    
    def detect(self, headers: Dict[str, str], body: str) -> Optional[WAFInfo]:
        """
        Detect WAF from response
        
        Args:
            headers: Response headers
            body: Response body
            
        Returns:
            WAFInfo if detected
        """
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower()
        
        # Cloudflare
        if 'cf-ray' in headers_lower or 'cloudflare' in body_lower:
            return WAFInfo(name="Cloudflare", confidence=1.0, recommended_strategy="encoding")
        
        # Akamai
        if 'akamai' in str(headers_lower) or 'akamai' in body_lower:
            return WAFInfo(name="Akamai", confidence=0.9, recommended_strategy="tag_break")
        
        # Imperva
        if 'imperva' in body_lower or 'incapsula' in body_lower:
            return WAFInfo(name="Imperva", confidence=0.95, recommended_strategy="polyglot")
        
        # ModSecurity
        if 'mod_security' in body_lower or 'modsec' in body_lower:
            return WAFInfo(name="ModSecurity", confidence=0.85, recommended_strategy="comment")
        
        # AWS WAF
        if 'x-amzn-requestid' in headers_lower or 'awselb' in str(headers_lower) or 'aws' in body_lower:
            return WAFInfo(name="AWS WAF", confidence=0.85, recommended_strategy="encoding")
        
        # F5 BIG-IP ASM
        if 'x-cnection' in headers_lower or 'bigip' in str(headers_lower) or 'f5' in body_lower or 'bigipserver' in str(headers_lower):
            return WAFInfo(name="F5 BIG-IP", confidence=0.9, recommended_strategy="whitespace")
        
        # Barracuda
        if 'barra_counter_session' in str(headers_lower) or 'barracuda' in body_lower:
            return WAFInfo(name="Barracuda", confidence=0.9, recommended_strategy="concatenation")
        
        # Sucuri
        if 'x-sucuri-id' in headers_lower or 'sucuri' in body_lower or 'sucuri-cloudproxy' in body_lower:
            return WAFInfo(name="Sucuri", confidence=0.95, recommended_strategy="encoding")
        
        # Fortinet FortiWeb
        if 'fortiwafsid' in str(headers_lower) or 'fortiweb' in body_lower or 'fortinet' in body_lower:
            return WAFInfo(name="Fortinet FortiWeb", confidence=0.9, recommended_strategy="tag_break")
        
        # Azure WAF (Application Gateway)
        if 'x-azure-ref' in headers_lower or 'azure' in body_lower or 'microsoft' in body_lower:
            return WAFInfo(name="Azure WAF", confidence=0.8, recommended_strategy="comment")
        
        # Citrix NetScaler AppFirewall
        if 'ns_af' in str(headers_lower) or 'citrix' in body_lower or 'netscaler' in body_lower:
            return WAFInfo(name="Citrix NetScaler", confidence=0.85, recommended_strategy="polyglot")
        
        # DenyAll
        if 'sessioncookie' in str(headers_lower) or 'denyall' in body_lower:
            return WAFInfo(name="DenyAll", confidence=0.8, recommended_strategy="bypass_filter")
        
        return None

__all__ = ['WAFDetector', 'WAFInfo']
