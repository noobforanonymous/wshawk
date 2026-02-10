#!/usr/bin/env python3
"""
Tests for WSHawk CVSS Calculator
"""

import pytest
from wshawk.cvss_calculator import CVSSCalculator, CVSSScore


@pytest.fixture
def calc():
    return CVSSCalculator()


class TestCVSSScoreRange:
    """Scores must be within valid CVSS v3.1 range"""

    def test_score_between_0_and_10(self, calc):
        vuln_types = [
            "SQL Injection", "Cross-Site Scripting (XSS)",
            "Command Injection", "XXE", "SSRF",
            "Path Traversal", "NoSQL Injection",
        ]
        for vt in vuln_types:
            for conf in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                score = calc.calculate_for_vulnerability(vt, conf)
                assert 0.0 <= score.base_score <= 10.0, (
                    f"{vt}/{conf}: score {score.base_score} out of range"
                )


class TestCVSSSeverityLabels:
    """Severity labels must follow CVSS v3.1 spec"""

    VALID_SEVERITIES = {"None", "Low", "Medium", "High", "Critical"}

    def test_severity_is_valid_label(self, calc):
        score = calc.calculate_for_vulnerability("SQL Injection", "HIGH")
        assert score.severity in self.VALID_SEVERITIES

    def test_none_severity_for_zero_score(self, calc):
        # A 0.0 score should map to "None"
        assert calc._get_severity(0.0) == "None"

    def test_low_severity(self, calc):
        assert calc._get_severity(3.9) == "Low"

    def test_medium_severity(self, calc):
        assert calc._get_severity(5.0) == "Medium"

    def test_high_severity(self, calc):
        assert calc._get_severity(7.5) == "High"

    def test_critical_severity(self, calc):
        assert calc._get_severity(9.5) == "Critical"


class TestCVSSVectorString:
    """Vector strings must match CVSS:3.1 format"""

    def test_vector_starts_with_prefix(self, calc):
        score = calc.calculate_for_vulnerability("Command Injection", "HIGH")
        assert score.vector_string.startswith("CVSS:3.1/")

    def test_vector_contains_all_metrics(self, calc):
        score = calc.calculate_for_vulnerability("SQL Injection", "HIGH")
        for metric in ["AV:", "AC:", "PR:", "UI:", "S:", "C:", "I:", "A:"]:
            assert metric in score.vector_string, (
                f"Missing metric {metric} in vector: {score.vector_string}"
            )


class TestCVSSPerVulnType:
    """Specific vulnerability types should produce expected score ranges"""

    def test_sql_injection_is_high_or_critical(self, calc):
        score = calc.calculate_for_vulnerability("SQL Injection", "CRITICAL")
        assert score.base_score >= 7.0, "SQLi should be High or Critical"

    def test_command_injection_is_high_or_critical(self, calc):
        score = calc.calculate_for_vulnerability("Command Injection", "CRITICAL")
        assert score.base_score >= 7.0, "CMDi should be High or Critical"

    def test_path_traversal_lower_than_rce(self, calc):
        pt = calc.calculate_for_vulnerability("Path Traversal", "HIGH")
        ci = calc.calculate_for_vulnerability("Command Injection", "HIGH")
        assert pt.base_score <= ci.base_score, (
            "Path traversal should not score higher than RCE"
        )

    def test_xss_requires_user_interaction(self, calc):
        score = calc.calculate_for_vulnerability("Cross-Site Scripting (XSS)", "MEDIUM")
        assert "UI:R" in score.vector_string, "XSS should require user interaction"

    def test_unknown_type_returns_valid_score(self, calc):
        """Unknown vuln types should still produce a valid score, not crash"""
        score = calc.calculate_for_vulnerability("UnknownVulnType", "MEDIUM")
        assert 0.0 <= score.base_score <= 10.0


class TestCVSSReturnType:
    """Return values must be CVSSScore dataclass"""

    def test_returns_cvss_score(self, calc):
        score = calc.calculate_for_vulnerability("XXE", "HIGH")
        assert isinstance(score, CVSSScore)

    def test_breakdown_is_dict(self, calc):
        score = calc.calculate_for_vulnerability("SSRF", "MEDIUM")
        assert isinstance(score.breakdown, dict)
        assert "AV" in score.breakdown
