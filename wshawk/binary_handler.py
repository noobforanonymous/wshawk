#!/usr/bin/env python3
"""
WSHawk Binary WebSocket Message Handler
Support for binary frames, fragmented messages, and protocol-specific formats

Author: Regaan (@noobforanonymous)
"""

import struct
import json
import base64
import zlib
import hashlib
from typing import List, Dict, Optional, Any, Tuple, Union
from enum import Enum
from datetime import datetime

try:
    from .__main__ import Logger, Colors
except ImportError:
    from __main__ import Logger, Colors


class BinaryFormat(Enum):
    """Detected binary message format."""
    RAW = "raw"
    PROTOBUF = "protobuf"
    MSGPACK = "msgpack"
    CBOR = "cbor"
    BSON = "bson"
    AVRO = "avro"
    FLATBUFFERS = "flatbuffers"
    CUSTOM = "custom"
    COMPRESSED = "compressed"
    ENCRYPTED = "encrypted"


class FragmentState(Enum):
    """WebSocket frame fragment state."""
    COMPLETE = "complete"
    FIRST = "first"
    CONTINUATION = "continuation"
    FINAL = "final"


class BinaryMessageHandler:
    """
    Handle binary WebSocket messages for security testing.

    Features:
    - Binary format auto-detection (protobuf, msgpack, CBOR, BSON, etc.)
    - Fragmented message reassembly
    - Binary payload injection strategies
    - Compression/decompression support
    - Hex dump analysis
    - Field mutation for binary formats
    """

    def __init__(self):
        self.fragment_buffer: Dict[str, bytearray] = {}
        self.detected_format: Optional[BinaryFormat] = None
        self.sample_messages: List[bytes] = []
        self.field_map: Dict[str, Any] = {}
        self._msgpack_available = False
        self._cbor_available = False

        # Try importing optional libraries
        try:
            import msgpack
            self._msgpack_available = True
        except ImportError:
            pass

        try:
            import cbor2
            self._cbor_available = True
        except ImportError:
            pass

    # ─── Binary Format Detection ────────────────────────────────────

    def detect_format(self, data: bytes) -> BinaryFormat:
        """
        Auto-detect binary message format from raw bytes.

        Args:
            data: Raw binary message

        Returns:
            Detected BinaryFormat
        """
        if not data or len(data) < 2:
            return BinaryFormat.RAW

        # Check for compression (zlib/gzip/deflate)
        if data[:2] == b'\x78\x9c' or data[:2] == b'\x78\x01' or data[:2] == b'\x78\xda':
            self.detected_format = BinaryFormat.COMPRESSED
            return BinaryFormat.COMPRESSED

        if data[:2] == b'\x1f\x8b':  # gzip magic
            self.detected_format = BinaryFormat.COMPRESSED
            return BinaryFormat.COMPRESSED

        # Check for Avro (magic bytes — very specific)
        if data[:4] == b'Obj\x01':
            self.detected_format = BinaryFormat.AVRO
            return BinaryFormat.AVRO

        # Check for BSON (specific: 4-byte LE size must match len, ends with \x00)
        if self._is_bson(data):
            self.detected_format = BinaryFormat.BSON
            return BinaryFormat.BSON

        # Check for Protocol Buffers (heuristic — before library-based checks)
        if self._is_protobuf(data):
            self.detected_format = BinaryFormat.PROTOBUF
            return BinaryFormat.PROTOBUF

        # Check for FlatBuffers
        if self._is_flatbuffers(data):
            self.detected_format = BinaryFormat.FLATBUFFERS
            return BinaryFormat.FLATBUFFERS

        # Check for MessagePack (library check last — can be greedy)
        if self._is_msgpack(data):
            self.detected_format = BinaryFormat.MSGPACK
            return BinaryFormat.MSGPACK

        # Check for CBOR (library check last — most greedy)
        if self._is_cbor(data):
            self.detected_format = BinaryFormat.CBOR
            return BinaryFormat.CBOR

        # Check for encryption patterns (high entropy)
        if self._is_likely_encrypted(data):
            self.detected_format = BinaryFormat.ENCRYPTED
            return BinaryFormat.ENCRYPTED

        self.detected_format = BinaryFormat.RAW
        return BinaryFormat.RAW

    def _is_msgpack(self, data: bytes) -> bool:
        """Check if data looks like MessagePack."""
        if not self._msgpack_available:
            # Heuristic: msgpack maps start with 0x80-0x8f (fixmap) or 0xde/0xdf
            first = data[0]
            return first in range(0x80, 0x90) or first in (0xde, 0xdf)
        try:
            import msgpack
            msgpack.unpackb(data, raw=False)
            return True
        except Exception:
            return False

    def _is_cbor(self, data: bytes) -> bool:
        """Check if data looks like CBOR."""
        if not self._cbor_available:
            # CBOR maps start with 0xa0-0xbf (small map) or 0xbf (indefinite)
            first = data[0]
            return first in range(0xa0, 0xc0)
        try:
            import cbor2
            cbor2.loads(data)
            return True
        except Exception:
            return False

    def _is_bson(self, data: bytes) -> bool:
        """Check if data looks like BSON."""
        if len(data) < 5:
            return False
        # BSON starts with 4-byte LE size and ends with \x00
        size = struct.unpack('<I', data[:4])[0]
        return size == len(data) and data[-1] == 0x00

    def _is_protobuf(self, data: bytes) -> bool:
        """Heuristic check for Protocol Buffers."""
        if len(data) < 2:
            return False
        # Protobuf fields start with field_number << 3 | wire_type
        # Wire types: 0 (varint), 1 (64-bit), 2 (length-delimited), 5 (32-bit)
        first = data[0]
        wire_type = first & 0x07
        field_number = first >> 3
        return wire_type in (0, 1, 2, 5) and 1 <= field_number <= 100

    def _is_flatbuffers(self, data: bytes) -> bool:
        """Check for FlatBuffers format."""
        if len(data) < 8:
            return False
        # FlatBuffers starts with a root table offset (4 bytes LE)
        offset = struct.unpack('<I', data[:4])[0]
        return 4 <= offset < len(data)

    def _is_likely_encrypted(self, data: bytes) -> bool:
        """Check if data appears to be encrypted (high entropy)."""
        if len(data) < 16:
            return False
        # Calculate byte frequency distribution
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        # Shannon entropy
        entropy = 0.0
        for f in freq:
            if f > 0:
                p = f / len(data)
                entropy -= p * (p and __import__('math').log2(p))
        # Encrypted data typically has entropy > 7.5
        return entropy > 7.5

    # ─── Binary Message Parsing ─────────────────────────────────────

    def parse(self, data: bytes) -> Dict[str, Any]:
        """
        Parse a binary message into a structured representation.

        Args:
            data: Raw binary data

        Returns:
            Parsed structure with format info and fields
        """
        fmt = self.detect_format(data)
        result = {
            'format': fmt.value,
            'size': len(data),
            'hex_preview': data[:64].hex(),
            'fields': {},
            'raw': data,
        }

        if fmt == BinaryFormat.COMPRESSED:
            try:
                decompressed = zlib.decompress(data)
                result['decompressed_size'] = len(decompressed)
                result['compression_ratio'] = round(len(data) / len(decompressed), 3)
                # Recursively parse decompressed data
                inner = self.parse(decompressed)
                result['inner_format'] = inner['format']
                result['fields'] = inner['fields']
            except Exception:
                result['decompression_error'] = True

        elif fmt == BinaryFormat.MSGPACK and self._msgpack_available:
            try:
                import msgpack
                parsed = msgpack.unpackb(data, raw=False)
                result['fields'] = self._flatten_dict(parsed) if isinstance(parsed, dict) else {'value': parsed}
            except Exception:
                pass

        elif fmt == BinaryFormat.PROTOBUF:
            result['fields'] = self._parse_protobuf_heuristic(data)

        elif fmt == BinaryFormat.BSON:
            result['fields'] = self._parse_bson_heuristic(data)

        return result

    def _parse_protobuf_heuristic(self, data: bytes) -> Dict:
        """Parse protobuf without schema using heuristic field extraction."""
        fields = {}
        offset = 0
        field_count = 0

        try:
            while offset < len(data) and field_count < 50:
                if offset >= len(data):
                    break

                # Read field tag
                tag_byte = data[offset]
                wire_type = tag_byte & 0x07
                field_number = tag_byte >> 3
                offset += 1

                if wire_type == 0:  # Varint
                    value = 0
                    shift = 0
                    while offset < len(data):
                        b = data[offset]
                        offset += 1
                        value |= (b & 0x7F) << shift
                        if not (b & 0x80):
                            break
                        shift += 7
                    fields[f'field_{field_number}_varint'] = value

                elif wire_type == 1:  # 64-bit
                    if offset + 8 <= len(data):
                        value = struct.unpack('<d', data[offset:offset+8])[0]
                        fields[f'field_{field_number}_fixed64'] = value
                        offset += 8

                elif wire_type == 2:  # Length-delimited
                    length = 0
                    shift = 0
                    while offset < len(data):
                        b = data[offset]
                        offset += 1
                        length |= (b & 0x7F) << shift
                        if not (b & 0x80):
                            break
                        shift += 7
                    if offset + length <= len(data):
                        payload = data[offset:offset+length]
                        # Try to decode as string
                        try:
                            fields[f'field_{field_number}_string'] = payload.decode('utf-8')
                        except UnicodeDecodeError:
                            fields[f'field_{field_number}_bytes'] = payload.hex()
                        offset += length

                elif wire_type == 5:  # 32-bit
                    if offset + 4 <= len(data):
                        value = struct.unpack('<f', data[offset:offset+4])[0]
                        fields[f'field_{field_number}_fixed32'] = value
                        offset += 4

                else:
                    break

                field_count += 1

        except Exception:
            pass

        return fields

    def _parse_bson_heuristic(self, data: bytes) -> Dict:
        """Basic BSON field extraction."""
        fields = {}
        try:
            offset = 4  # Skip size
            while offset < len(data) - 1:
                element_type = data[offset]
                offset += 1

                if element_type == 0x00:  # End of document
                    break

                # Read key (null-terminated string)
                key_end = data.index(0x00, offset)
                key = data[offset:key_end].decode('utf-8', errors='replace')
                offset = key_end + 1

                if element_type == 0x02:  # String
                    str_len = struct.unpack('<I', data[offset:offset+4])[0]
                    offset += 4
                    value = data[offset:offset+str_len-1].decode('utf-8', errors='replace')
                    fields[key] = value
                    offset += str_len

                elif element_type == 0x10:  # Int32
                    value = struct.unpack('<i', data[offset:offset+4])[0]
                    fields[key] = value
                    offset += 4

                elif element_type == 0x01:  # Double
                    value = struct.unpack('<d', data[offset:offset+8])[0]
                    fields[key] = value
                    offset += 8

                elif element_type == 0x08:  # Boolean
                    fields[key] = bool(data[offset])
                    offset += 1

                else:
                    break

        except Exception:
            pass

        return fields

    def _flatten_dict(self, d: Any, prefix: str = '') -> Dict:
        """Flatten a nested dict for easier payload injection."""
        items = {}
        if isinstance(d, dict):
            for k, v in d.items():
                new_key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    items.update(self._flatten_dict(v, new_key))
                else:
                    items[new_key] = v
        elif isinstance(d, list):
            for i, v in enumerate(d):
                new_key = f"{prefix}[{i}]"
                if isinstance(v, (dict, list)):
                    items.update(self._flatten_dict(v, new_key))
                else:
                    items[new_key] = v
        return items

    # ─── Fragment Reassembly ────────────────────────────────────────

    def handle_fragment(self,
                        data: bytes,
                        connection_id: str = 'default',
                        is_final: bool = False) -> Optional[bytes]:
        """
        Handle fragmented WebSocket frames.

        Args:
            data: Frame payload
            connection_id: Unique connection identifier
            is_final: Whether this is the final fragment (FIN bit)

        Returns:
            Complete reassembled message if final fragment, else None
        """
        if connection_id not in self.fragment_buffer:
            self.fragment_buffer[connection_id] = bytearray()

        self.fragment_buffer[connection_id].extend(data)

        if is_final:
            complete = bytes(self.fragment_buffer[connection_id])
            del self.fragment_buffer[connection_id]
            Logger.info(f"Reassembled fragmented message: {len(complete)} bytes from {connection_id}")
            return complete

        return None

    def clear_fragments(self, connection_id: str = None):
        """Clear fragment buffer."""
        if connection_id:
            self.fragment_buffer.pop(connection_id, None)
        else:
            self.fragment_buffer.clear()

    # ─── Binary Payload Generation ──────────────────────────────────

    def generate_binary_payloads(self, sample: bytes, vuln_type: str = 'all') -> List[bytes]:
        """
        Generate binary attack payloads based on a sample message.

        Args:
            sample: Sample binary message to base payloads on
            vuln_type: Target vulnerability type ('sqli', 'xss', 'cmdi', 'all')

        Returns:
            List of mutated binary payloads
        """
        fmt = self.detect_format(sample)
        payloads = []

        # Strategy 1: Raw binary injection (works for all formats)
        payloads.extend(self._raw_binary_injections(sample))

        # Strategy 2: Format-specific mutations
        if fmt == BinaryFormat.MSGPACK and self._msgpack_available:
            payloads.extend(self._msgpack_mutations(sample, vuln_type))
        elif fmt == BinaryFormat.PROTOBUF:
            payloads.extend(self._protobuf_mutations(sample, vuln_type))
        elif fmt == BinaryFormat.COMPRESSED:
            payloads.extend(self._compressed_mutations(sample, vuln_type))

        # Strategy 3: Boundary testing
        payloads.extend(self._boundary_payloads(sample))

        Logger.info(f"Generated {len(payloads)} binary payloads for {fmt.value} format")
        return payloads

    def _raw_binary_injections(self, sample: bytes) -> List[bytes]:
        """Generate raw binary injection payloads."""
        text_payloads = [
            b"' OR 1=1--",
            b'<script>alert(1)</script>',
            b'; ls -la',
            b'{{7*7}}',
            b'../../etc/passwd',
            b'\x00' * 100,  # NULL flood
            b'\xff' * 100,  # High-byte flood
        ]

        payloads = []
        for tp in text_payloads:
            # Append to sample
            payloads.append(sample + tp)
            # Prepend to sample
            payloads.append(tp + sample)
            # Replace middle section
            if len(sample) > 10:
                mid = len(sample) // 2
                payloads.append(sample[:mid] + tp + sample[mid:])

        return payloads

    def _msgpack_mutations(self, sample: bytes, vuln_type: str) -> List[bytes]:
        """Generate MessagePack-specific attack payloads."""
        payloads = []
        try:
            import msgpack

            parsed = msgpack.unpackb(sample, raw=False)
            if not isinstance(parsed, dict):
                return payloads

            injection_values = self._get_injection_values(vuln_type)

            for key in parsed:
                if isinstance(parsed[key], str):
                    for injection in injection_values:
                        mutated = dict(parsed)
                        mutated[key] = injection
                        payloads.append(msgpack.packb(mutated, use_bin_type=True))

                elif isinstance(parsed[key], (int, float)):
                    # Integer overflow / underflow
                    for val in [0, -1, 2**31, 2**63, -2**31, float('inf'), float('nan')]:
                        mutated = dict(parsed)
                        mutated[key] = val
                        try:
                            payloads.append(msgpack.packb(mutated, use_bin_type=True))
                        except (OverflowError, ValueError):
                            pass

        except Exception:
            pass

        return payloads

    def _protobuf_mutations(self, sample: bytes, vuln_type: str) -> List[bytes]:
        """Generate protobuf-targeted attack payloads."""
        payloads = []
        parsed = self._parse_protobuf_heuristic(sample)

        injection_values = self._get_injection_values(vuln_type)

        for field_name, value in parsed.items():
            if 'string' in field_name:
                for injection in injection_values:
                    # Rebuild the protobuf field with injection
                    field_num = int(field_name.split('_')[1])
                    tag = (field_num << 3) | 2  # wire_type = 2 (length-delimited)
                    encoded = injection.encode('utf-8')
                    length = len(encoded)

                    # Simple varint encoding for length
                    varint_bytes = self._encode_varint(length)
                    payload = bytes([tag]) + varint_bytes + encoded
                    payloads.append(payload)

        return payloads

    def _compressed_mutations(self, sample: bytes, vuln_type: str) -> List[bytes]:
        """Generate compressed payload mutations."""
        payloads = []
        try:
            decompressed = zlib.decompress(sample)

            injection_values = self._get_injection_values(vuln_type)
            for injection in injection_values:
                # Inject into decompressed data and recompress
                mutated = decompressed + injection.encode('utf-8')
                payloads.append(zlib.compress(mutated))

                # Also try with the injection replacing the end
                if len(decompressed) > 20:
                    mutated = decompressed[:-20] + injection.encode('utf-8')
                    payloads.append(zlib.compress(mutated))

        except Exception:
            pass

        # Also send decompression bomb
        payloads.append(zlib.compress(b'\x00' * 1000000)[:100])  # Compressed null bomb

        return payloads

    def _boundary_payloads(self, sample: bytes) -> List[bytes]:
        """Generate boundary condition payloads."""
        return [
            b'',                           # Empty message
            b'\x00',                       # Single NULL
            sample[:1],                    # Truncated (1 byte)
            sample[:len(sample)//2],       # Truncated (half)
            sample * 100,                  # Oversized message
            bytes(reversed(sample)),       # Reversed bytes
            bytes([b ^ 0xFF for b in sample]),  # Bitflipped
            sample + b'\x00' * 1000,       # Padded with NULLs
        ]

    def _get_injection_values(self, vuln_type: str) -> List[str]:
        """Get text injection values for a vulnerability type."""
        injections = {
            'sqli': [
                "' OR 1=1--",
                "'; DROP TABLE users;--",
                "1 UNION SELECT null,null,null--",
                "admin'--",
            ],
            'xss': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '"><svg onload=alert(1)>',
                "javascript:alert(document.cookie)",
            ],
            'cmdi': [
                '; cat /etc/passwd',
                '| whoami',
                '$(id)',
                '`id`',
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            ],
            'traversal': [
                '../../etc/passwd',
                '..\\..\\windows\\system32\\config\\sam',
                '/etc/shadow',
            ],
        }

        if vuln_type == 'all':
            all_inj = []
            for vals in injections.values():
                all_inj.extend(vals)
            return all_inj

        return injections.get(vuln_type, injections.get('sqli', []))

    def _encode_varint(self, value: int) -> bytes:
        """Encode an integer as a protobuf varint."""
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)

    # ─── Analysis & Reporting ───────────────────────────────────────

    def hex_dump(self, data: bytes, width: int = 16) -> str:
        """Generate a formatted hex dump for reporting."""
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{i:08x}  {hex_part:<{width*3}}  |{ascii_part}|')
        return '\n'.join(lines)

    def analyze_message(self, data: bytes) -> Dict[str, Any]:
        """
        Full analysis of a binary message for reporting.

        Returns:
            Comprehensive analysis dict
        """
        fmt = self.detect_format(data)
        parsed = self.parse(data)

        analysis = {
            'format': fmt.value,
            'size_bytes': len(data),
            'hex_preview': data[:32].hex(),
            'hex_dump': self.hex_dump(data[:256]),
            'md5': hashlib.md5(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
            'entropy': self._calculate_entropy(data),
            'printable_ratio': sum(1 for b in data if 32 <= b < 127) / max(len(data), 1),
            'null_ratio': data.count(0) / max(len(data), 1),
            'fields': parsed.get('fields', {}),
            'injectable_fields': [
                k for k, v in parsed.get('fields', {}).items()
                if isinstance(v, str) and len(v) > 0
            ],
        }

        if fmt == BinaryFormat.COMPRESSED:
            analysis['compressed'] = True
            analysis['decompressed_size'] = parsed.get('decompressed_size', 'unknown')

        return analysis

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        import math
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        entropy = 0.0
        for f in freq:
            if f > 0:
                p = f / len(data)
                entropy -= p * math.log2(p)
        return round(entropy, 4)


if __name__ == "__main__":
    handler = BinaryMessageHandler()

    # Demo: analyze sample binary messages
    samples = {
        'Compressed (zlib)': zlib.compress(b'{"user":"admin","action":"login"}'),
        'Raw text as binary': b'Hello, WebSocket!',
        'NULL-padded': b'\x00\x00\x00\x05Hello\x00\x00',
        'High entropy': bytes(range(256)),
    }

    for name, data in samples.items():
        print(f"\n{'='*60}")
        print(f"Sample: {name}")
        print(f"{'='*60}")

        analysis = handler.analyze_message(data)
        print(f"  Format: {analysis['format']}")
        print(f"  Size: {analysis['size_bytes']} bytes")
        print(f"  Entropy: {analysis['entropy']}")
        print(f"  Printable: {analysis['printable_ratio']:.1%}")
        print(f"  Fields: {analysis['fields']}")

        payloads = handler.generate_binary_payloads(data)
        print(f"  Generated {len(payloads)} attack payloads")

    print("\n[SUCCESS] Binary Message Handler working!")
