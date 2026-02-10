#!/usr/bin/env python3
"""
WSHawk Message Analyzer Module
Handles message format detection and automated payload injection
"""

import json
import base64
import re
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum

class MessageFormat(Enum):
    JSON = "json"
    XML = "xml"
    BINARY = "binary"
    BASE64 = "base64"
    PLAIN_TEXT = "plaintext"
    PROTOBUF = "protobuf"
    MSGPACK = "msgpack"

class MessageAnalyzer:
    """
    Automated message format detection and payload injection
    """
    
    def __init__(self):
        self.detected_format = None
        self.json_schema = {}
        self.sample_messages = []
        self.field_types = {}
        
    def detect_message_format(self, message: str) -> MessageFormat:
        """
        Detect message format from sample
        """
        # Try JSON first (most common)
        try:
            json.loads(message)
            return MessageFormat.JSON
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Check for XML
        if message.strip().startswith('<') and message.strip().endswith('>'):
            return MessageFormat.XML
        
        # Check for base64
        try:
            if re.match(r'^[A-Za-z0-9+/]+={0,2}$', message.strip()):
                decoded = base64.b64decode(message)
                # Try to detect format of decoded content
                try:
                    json.loads(decoded)
                    return MessageFormat.BASE64
                except (json.JSONDecodeError, ValueError):
                    pass
        except (ValueError, TypeError):
            pass
        
        # Check for binary (non-printable characters)
        if any(ord(c) < 32 or ord(c) > 126 for c in message if c not in '\n\r\t'):
            return MessageFormat.BINARY
        
        # Default to plaintext
        return MessageFormat.PLAIN_TEXT
    
    def learn_from_messages(self, messages: List[str]) -> None:
        """
        Heuristic message structure learning from samples (5-20 messages)
        """
        self.sample_messages = messages[:20]
        
        # Detect format from first message
        if messages:
            self.detected_format = self.detect_message_format(messages[0])
        
        # If JSON, infer schema
        if self.detected_format == MessageFormat.JSON:
            self._infer_json_schema(messages)
    
    def _infer_json_schema(self, messages: List[str]) -> None:
        """
        Infer JSON schema from multiple messages
        """
        field_occurrences = {}
        
        for msg in messages:
            try:
                data = json.loads(msg)
                self._walk_json(data, field_occurrences)
            except (json.JSONDecodeError, ValueError):
                continue
        
        # Store schema
        self.json_schema = field_occurrences
    
    def _walk_json(self, obj: Any, field_map: Dict, path: str = "") -> None:
        """
        Recursively walk JSON structure
        """
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                
                # Track field type
                if current_path not in field_map:
                    field_map[current_path] = {
                        'type': type(value).__name__,
                        'count': 0,
                        'sample_values': []
                    }
                
                field_map[current_path]['count'] += 1
                if len(field_map[current_path]['sample_values']) < 5:
                    field_map[current_path]['sample_values'].append(value)
                
                # Recurse
                self._walk_json(value, field_map, current_path)
        
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._walk_json(item, field_map, f"{path}[{i}]")
    
    def inject_payload_into_message(self, base_message: str, payload: str, 
                                    target_fields: Optional[List[str]] = None) -> List[str]:
        """
        Inject payload into appropriate message fields
        Returns list of mutated messages
        """
        if self.detected_format == MessageFormat.JSON:
            return self._inject_into_json(base_message, payload, target_fields)
        elif self.detected_format == MessageFormat.XML:
            return self._inject_into_xml(base_message, payload)
        else:
            # For plain text, just append/prepend
            return [
                payload,
                f"{payload} {base_message}",
                f"{base_message} {payload}"
            ]
    
    def _inject_into_json(self, message: str, payload: str, 
                         target_fields: Optional[List[str]] = None) -> List[str]:
        """
        Inject payload into JSON message fields
        """
        try:
            data = json.loads(message)
        except (json.JSONDecodeError, ValueError):
            return [payload]
        
        mutated_messages = []
        
        # If no target fields specified, inject into all string fields
        if not target_fields:
            target_fields = [
                field for field, info in self.json_schema.items()
                if info['type'] == 'str'
            ]
        
        # Inject into each target field
        for field_path in target_fields:
            mutated = self._inject_at_path(data.copy(), field_path, payload)
            if mutated:
                mutated_messages.append(json.dumps(mutated))
        
        return mutated_messages if mutated_messages else [payload]
    
    def _inject_at_path(self, obj: Any, path: str, value: str) -> Optional[Dict]:
        """
        Inject value at specific JSON path
        """
        parts = path.split('.')
        current = obj
        
        try:
            # Navigate to parent
            for part in parts[:-1]:
                if '[' in part:
                    # Handle array index
                    key, idx = part.split('[')
                    idx = int(idx.rstrip(']'))
                    current = current[key][idx]
                else:
                    current = current[part]
            
            # Set value
            final_key = parts[-1]
            if '[' in final_key:
                key, idx = final_key.split('[')
                idx = int(idx.rstrip(']'))
                current[key][idx] = value
            else:
                current[final_key] = value
            
            return obj
        except (KeyError, TypeError, IndexError):
            return None
    
    def _inject_into_xml(self, message: str, payload: str) -> List[str]:
        """
        Inject payload into XML message
        """
        # Simple XML injection - find text nodes
        import re
        
        mutated = []
        
        # Inject into tag content
        pattern = r'>([^<]+)<'
        matches = list(re.finditer(pattern, message))
        
        for match in matches:
            new_msg = message[:match.start(1)] + payload + message[match.end(1):]
            mutated.append(new_msg)
        
        return mutated if mutated else [payload]
    
    def get_injectable_fields(self) -> List[str]:
        """
        Get list of fields suitable for injection
        """
        if self.detected_format == MessageFormat.JSON:
            return [
                field for field, info in self.json_schema.items()
                if info['type'] in ['str', 'int', 'float']
            ]
        return []
    
    def get_format_info(self) -> Dict:
        """
        Get detected format information
        """
        return {
            'format': self.detected_format.value if self.detected_format else 'unknown',
            'schema': self.json_schema,
            'injectable_fields': self.get_injectable_fields(),
            'sample_count': len(self.sample_messages)
        }
