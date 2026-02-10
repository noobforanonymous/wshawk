#!/usr/bin/env python3
"""
Tests for WSHawk WAF Detector
"""

import pytest
from wshawk.waf.detector import WAFDetector, WAFInfo


@pytest.fixture
def detector():
    return WAFDetector()


class TestWAFDetection:
    """WAF detection from response headers and body"""

    def test_detects_cloudflare_by_header(self, detector):
        result = detector.detect({"cf-ray": "abc123"}, "")
        assert result is not None
        assert result.name == "Cloudflare"
        assert result.confidence == 1.0

    def test_detects_cloudflare_by_body(self, detector):
        result = detector.detect({}, "Blocked by Cloudflare security")
        assert result is not None
        assert result.name == "Cloudflare"

    def test_detects_akamai(self, detector):
        result = detector.detect({"x-akamai-session": "123"}, "")
        assert result is not None
        assert result.name == "Akamai"

    def test_detects_imperva(self, detector):
        result = detector.detect({}, "Request blocked by Imperva Incapsula")
        assert result is not None
        assert result.name == "Imperva"

    def test_detects_modsecurity(self, detector):
        result = detector.detect({}, "Blocked by mod_security rule 942100")
        assert result is not None
        assert result.name == "ModSecurity"

    def test_returns_none_when_no_waf(self, detector):
        result = detector.detect(
            {"content-type": "application/json"},
            '{"status": "ok"}',
        )
        assert result is None

    def test_case_insensitive_detection(self, detector):
        result = detector.detect({"CF-RAY": "abc123"}, "")
        assert result is not None
        assert result.name == "Cloudflare"


class TestWAFInfo:
    """WAFInfo dataclass structure"""

    def test_waf_info_has_strategy(self, detector):
        result = detector.detect({"cf-ray": "abc123"}, "")
        assert hasattr(result, "recommended_strategy")
        assert isinstance(result.recommended_strategy, str)

    def test_waf_info_has_confidence(self, detector):
        result = detector.detect({"cf-ray": "abc123"}, "")
        assert 0.0 <= result.confidence <= 1.0
