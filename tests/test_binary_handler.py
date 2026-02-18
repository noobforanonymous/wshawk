#!/usr/bin/env python3
"""
Tests for WSHawk Binary Message Handler
"""
import os
import sys
import json
import zlib
import struct
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wshawk.binary_handler import BinaryMessageHandler, BinaryFormat


class TestBinaryHandler(unittest.TestCase):

    def setUp(self):
        self.handler = BinaryMessageHandler()

    # ─── Format Detection ───────────────────────────────────────

    def test_detect_compressed_zlib(self):
        data = zlib.compress(b'{"test": "hello"}')
        fmt = self.handler.detect_format(data)
        self.assertEqual(fmt, BinaryFormat.COMPRESSED)

    def test_detect_compressed_gzip(self):
        import gzip
        data = gzip.compress(b'test data')
        fmt = self.handler.detect_format(data)
        self.assertEqual(fmt, BinaryFormat.COMPRESSED)

    def test_detect_raw_small(self):
        fmt = self.handler.detect_format(b'\x01')
        self.assertEqual(fmt, BinaryFormat.RAW)

    def test_detect_empty(self):
        fmt = self.handler.detect_format(b'')
        self.assertEqual(fmt, BinaryFormat.RAW)

    def test_detect_protobuf_heuristic(self):
        # Construct a simple protobuf-like message
        # field 1, wire type 2 (length-delimited), length 5, "hello"
        data = bytes([0x0a, 0x05]) + b'hello'
        fmt = self.handler.detect_format(data)
        self.assertEqual(fmt, BinaryFormat.PROTOBUF)

    def test_detect_bson(self):
        # Simple BSON document: size(4) + type(1) + key + \x00 + value + \x00
        doc = bytearray()
        doc.extend(b'\x00' * 4)  # placeholder for size
        doc.append(0x02)  # string type
        doc.extend(b'name\x00')  # key
        value = b'test'
        doc.extend(struct.pack('<I', len(value) + 1))  # string length with null
        doc.extend(value)
        doc.append(0x00)  # string null terminator
        doc.append(0x00)  # document end
        struct.pack_into('<I', doc, 0, len(doc))  # fill in size
        fmt = self.handler.detect_format(bytes(doc))
        self.assertEqual(fmt, BinaryFormat.BSON)

    # ─── Parsing ────────────────────────────────────────────────

    def test_parse_compressed(self):
        original = b'{"user": "admin", "action": "login"}'
        data = zlib.compress(original)
        result = self.handler.parse(data)
        self.assertEqual(result['format'], 'compressed')
        self.assertIn('decompressed_size', result)
        self.assertEqual(result['decompressed_size'], len(original))

    def test_parse_protobuf_heuristic(self):
        # field 1 (string): "hello"
        data = bytes([0x0a, 0x05]) + b'hello'
        result = self.handler.parse(data)
        self.assertIn('fields', result)
        # Should have extracted the string field
        string_fields = [k for k in result['fields'] if 'string' in k]
        self.assertTrue(len(string_fields) > 0)
        self.assertEqual(result['fields'][string_fields[0]], 'hello')

    # ─── Fragment Reassembly ────────────────────────────────────

    def test_fragment_reassembly(self):
        result1 = self.handler.handle_fragment(b'Hello, ', 'conn1', is_final=False)
        self.assertIsNone(result1)

        result2 = self.handler.handle_fragment(b'World!', 'conn1', is_final=True)
        self.assertIsNotNone(result2)
        self.assertEqual(result2, b'Hello, World!')

    def test_fragment_multiple_connections(self):
        self.handler.handle_fragment(b'A1', 'conn1', is_final=False)
        self.handler.handle_fragment(b'B1', 'conn2', is_final=False)
        self.handler.handle_fragment(b'A2', 'conn1', is_final=True)
        result = self.handler.handle_fragment(b'B2', 'conn2', is_final=True)

        self.assertEqual(result, b'B1B2')

    def test_clear_fragments(self):
        self.handler.handle_fragment(b'data', 'conn1', is_final=False)
        self.handler.clear_fragments('conn1')
        self.assertNotIn('conn1', self.handler.fragment_buffer)

    def test_clear_all_fragments(self):
        self.handler.handle_fragment(b'data', 'conn1', is_final=False)
        self.handler.handle_fragment(b'data', 'conn2', is_final=False)
        self.handler.clear_fragments()
        self.assertEqual(len(self.handler.fragment_buffer), 0)

    # ─── Payload Generation ─────────────────────────────────────

    def test_generate_payloads_raw(self):
        sample = b'AAAA'
        payloads = self.handler.generate_binary_payloads(sample)
        self.assertGreater(len(payloads), 0)

    def test_generate_payloads_compressed(self):
        sample = zlib.compress(b'{"test": "value"}')
        payloads = self.handler.generate_binary_payloads(sample)
        self.assertGreater(len(payloads), 0)

    def test_boundary_payloads(self):
        sample = b'A' * 50
        payloads = self.handler._boundary_payloads(sample)
        # Should include empty, truncated, oversized, reversed, bitflipped, padded
        self.assertGreaterEqual(len(payloads), 6)
        self.assertIn(b'', payloads)  # Empty message

    # ─── Analysis ───────────────────────────────────────────────

    def test_hex_dump(self):
        data = b'Hello, World!'
        dump = self.handler.hex_dump(data)
        self.assertIn('48 65 6c 6c 6f', dump)  # "Hello"
        self.assertIn('|Hello, World!|', dump)

    def test_analyze_message(self):
        data = b'Test binary message'
        analysis = self.handler.analyze_message(data)
        self.assertIn('format', analysis)
        self.assertIn('size_bytes', analysis)
        self.assertIn('entropy', analysis)
        self.assertIn('md5', analysis)
        self.assertIn('sha256', analysis)
        self.assertEqual(analysis['size_bytes'], len(data))

    def test_entropy_calculation(self):
        # Low entropy (all same bytes)
        low = self.handler._calculate_entropy(b'\x00' * 100)
        self.assertEqual(low, 0.0)

        # High entropy (all different bytes)
        high = self.handler._calculate_entropy(bytes(range(256)))
        self.assertEqual(high, 8.0)

    def test_printable_ratio(self):
        data = b'Hello World'  # All printable
        analysis = self.handler.analyze_message(data)
        self.assertGreater(analysis['printable_ratio'], 0.9)

    # ─── Varint Encoding ────────────────────────────────────────

    def test_encode_varint_small(self):
        result = self.handler._encode_varint(5)
        self.assertEqual(result, b'\x05')

    def test_encode_varint_large(self):
        result = self.handler._encode_varint(300)
        self.assertEqual(result, b'\xac\x02')


if __name__ == '__main__':
    unittest.main()
