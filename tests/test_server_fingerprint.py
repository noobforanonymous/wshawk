#!/usr/bin/env python3
"""
Tests for WSHawk Server Fingerprinter
"""

import pytest
from wshawk.server_fingerprint import ServerFingerprinter, ServerFingerprint


@pytest.fixture
def fingerprinter():
    return ServerFingerprinter()


class TestLanguageDetection:
    """Detect backend programming language"""

    def test_detects_python_from_traceback(self, fingerprinter):
        fingerprinter.add_response('Traceback (most recent call last):\n  File "app.py", line 42')
        fp = fingerprinter.fingerprint()
        assert fp.language == "python"

    def test_detects_node_from_error(self, fingerprinter):
        fingerprinter.add_response("Error: Cannot read property\n    at Object.<anonymous> (/app/server.js:15:3)")
        fp = fingerprinter.fingerprint()
        assert fp.language == "nodejs"

    def test_detects_java_from_stacktrace(self, fingerprinter):
        fingerprinter.add_response("java.lang.NullPointerException\n\tat com.app.Main.run(Main.java:15)")
        fp = fingerprinter.fingerprint()
        assert fp.language == "java"

    def test_unknown_with_clean_response(self, fingerprinter):
        fingerprinter.add_response('{"status": "ok"}')
        fp = fingerprinter.fingerprint()
        # With no identifying info, language may be None
        assert isinstance(fp, ServerFingerprint)


class TestFingerprintStructure:
    """ServerFingerprint data structure"""

    def test_has_all_fields(self, fingerprinter):
        fingerprinter.add_response("test")
        fp = fingerprinter.fingerprint()
        assert hasattr(fp, "language")
        assert hasattr(fp, "framework")
        assert hasattr(fp, "database")
        assert hasattr(fp, "libraries")
        assert hasattr(fp, "confidence")

    def test_confidence_in_range(self, fingerprinter):
        fingerprinter.add_response('Traceback (most recent call last):')
        fp = fingerprinter.fingerprint()
        assert 0.0 <= fp.confidence <= 1.0

    def test_libraries_is_list(self, fingerprinter):
        fingerprinter.add_response("test")
        fp = fingerprinter.fingerprint()
        assert isinstance(fp.libraries, list)


class TestPayloadRecommendation:
    """Recommend payloads based on fingerprint"""

    def test_recommends_payloads(self, fingerprinter):
        fingerprinter.add_response('Traceback (most recent call last):\ndjango')
        fp = fingerprinter.fingerprint()
        recommendations = fingerprinter.get_recommended_payloads(fp)
        assert isinstance(recommendations, (list, dict))

    def test_get_info_returns_dict(self, fingerprinter):
        fingerprinter.add_response("test")
        info = fingerprinter.get_info()
        assert isinstance(info, dict)
