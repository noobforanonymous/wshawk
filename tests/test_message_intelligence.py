#!/usr/bin/env python3
"""
Tests for WSHawk Message Analyzer Module
"""

import pytest
import json
from wshawk.message_intelligence import MessageAnalyzer, MessageFormat


@pytest.fixture
def analyzer():
    return MessageAnalyzer()


class TestFormatDetection:
    """Message format auto-detection"""

    def test_detects_json(self, analyzer):
        fmt = analyzer.detect_message_format('{"action": "login", "user": "test"}')
        assert fmt == MessageFormat.JSON

    def test_detects_json_array(self, analyzer):
        fmt = analyzer.detect_message_format('[{"id": 1}, {"id": 2}]')
        assert fmt == MessageFormat.JSON

    def test_detects_xml(self, analyzer):
        fmt = analyzer.detect_message_format('<message><type>login</type></message>')
        assert fmt == MessageFormat.XML

    def test_detects_plaintext(self, analyzer):
        fmt = analyzer.detect_message_format('hello world')
        assert fmt == MessageFormat.PLAIN_TEXT

    def test_detects_binary(self, analyzer):
        fmt = analyzer.detect_message_format('hello\x00\x01\x02world')
        assert fmt == MessageFormat.BINARY


class TestLearning:
    """Learning from sample messages"""

    def test_learn_from_json_messages(self, analyzer):
        messages = [
            '{"action": "chat", "message": "hello"}',
            '{"action": "chat", "message": "world"}',
            '{"action": "ping", "timestamp": 123}',
        ]
        analyzer.learn_from_messages(messages)
        assert analyzer.detected_format == MessageFormat.JSON
        assert len(analyzer.json_schema) > 0

    def test_learn_detects_string_fields(self, analyzer):
        messages = [
            '{"name": "Alice", "age": 30}',
            '{"name": "Bob", "age": 25}',
        ]
        analyzer.learn_from_messages(messages)
        assert "name" in analyzer.json_schema
        assert analyzer.json_schema["name"]["type"] == "str"

    def test_learn_from_empty_list(self, analyzer):
        analyzer.learn_from_messages([])
        assert analyzer.detected_format is None

    def test_learn_caps_at_20_samples(self, analyzer):
        messages = [f'{{"id": {i}}}' for i in range(50)]
        analyzer.learn_from_messages(messages)
        assert len(analyzer.sample_messages) == 20


class TestPayloadInjection:
    """Payload injection into messages"""

    def test_inject_into_json_string_field(self, analyzer):
        messages = ['{"action": "search", "query": "test"}']
        analyzer.learn_from_messages(messages)

        results = analyzer.inject_payload_into_message(
            '{"action": "search", "query": "test"}',
            "' OR 1=1--"
        )
        assert len(results) > 0
        # At least one result should contain the payload
        assert any("OR 1=1" in r for r in results)

    def test_inject_into_xml_message(self, analyzer):
        messages = ['<request><query>test</query></request>']
        analyzer.learn_from_messages(messages)

        results = analyzer.inject_payload_into_message(
            '<request><query>test</query></request>',
            "<script>alert(1)</script>"
        )
        assert len(results) > 0

    def test_inject_into_plaintext_message(self, analyzer):
        messages = ['hello world']
        analyzer.learn_from_messages(messages)

        results = analyzer.inject_payload_into_message("hello world", "INJECTED")
        assert len(results) > 0
        assert any("INJECTED" in r for r in results)


class TestInjectableFields:
    """Get injectable fields from schema"""

    def test_returns_string_fields(self, analyzer):
        messages = [
            '{"username": "test", "age": 25, "active": true}',
            '{"username": "admin", "age": 30, "active": false}',
        ]
        analyzer.learn_from_messages(messages)
        fields = analyzer.get_injectable_fields()
        assert "username" in fields

    def test_returns_empty_for_no_learning(self, analyzer):
        fields = analyzer.get_injectable_fields()
        assert fields == []


class TestFormatInfo:
    """Format info reporting"""

    def test_format_info_structure(self, analyzer):
        messages = ['{"key": "value"}']
        analyzer.learn_from_messages(messages)
        info = analyzer.get_format_info()
        assert "format" in info
        assert "schema" in info
        assert "injectable_fields" in info
        assert "sample_count" in info

    def test_format_info_unknown(self, analyzer):
        info = analyzer.get_format_info()
        assert info["format"] == "unknown"
