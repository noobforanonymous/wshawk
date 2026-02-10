#!/usr/bin/env python3
"""
Tests for WSHawk Payload Mutation Engine
"""

import pytest
from wshawk.payload_mutator import PayloadMutator, MutationStrategy


@pytest.fixture
def mutator():
    return PayloadMutator()


class TestMutationGeneration:
    """Mutations must produce valid, non-empty output"""

    def test_encoding_mutations_produce_output(self, mutator):
        results = mutator.mutate_payload("<script>alert(1)</script>", MutationStrategy.ENCODING, count=5)
        assert len(results) > 0, "Encoding mutations should produce at least 1 variant"

    def test_case_mutations_produce_output(self, mutator):
        results = mutator.mutate_payload("SELECT * FROM users", MutationStrategy.CASE_VARIATION, count=5)
        assert len(results) > 0

    def test_comment_mutations_produce_output(self, mutator):
        results = mutator.mutate_payload("' OR 1=1--", MutationStrategy.COMMENT_INJECTION, count=5)
        assert len(results) > 0

    def test_whitespace_mutations_produce_output(self, mutator):
        results = mutator.mutate_payload("test payload", MutationStrategy.WHITESPACE, count=5)
        assert len(results) > 0

    def test_concatenation_mutations_produce_output(self, mutator):
        results = mutator.mutate_payload("alert(1)", MutationStrategy.CONCATENATION, count=5)
        assert len(results) > 0

    def test_bypass_mutations_produce_output(self, mutator):
        results = mutator.mutate_payload("<script>alert(1)</script>", MutationStrategy.BYPASS_FILTER, count=5)
        assert len(results) > 0

    def test_tag_breaking_mutations_produce_output(self, mutator):
        results = mutator.mutate_payload("<img src=x onerror=alert(1)>", MutationStrategy.TAG_BREAKING, count=5)
        assert len(results) > 0

    def test_polyglot_mutations_produce_output(self, mutator):
        results = mutator.mutate_payload("test", MutationStrategy.POLYGLOT, count=5)
        assert len(results) > 0


class TestMutationDiversity:
    """Mutations should produce diverse variants, not duplicates"""

    def test_mutations_are_unique(self, mutator):
        results = mutator.mutate_payload("<script>alert(1)</script>", MutationStrategy.ENCODING, count=10)
        unique = set(results)
        # Allow some duplicates but at least half should be unique
        assert len(unique) >= len(results) // 2, "Too many duplicate mutations"

    def test_mutations_differ_from_original(self, mutator):
        original = "<script>alert(1)</script>"
        results = mutator.mutate_payload(original, MutationStrategy.ENCODING, count=5)
        # At least some should differ from the original
        different = [r for r in results if r != original]
        assert len(different) > 0, "No mutations differed from original"


class TestAdaptivePayloads:
    """Adaptive payload generation using weighted strategies"""

    def test_adaptive_payloads_returns_list(self, mutator):
        results = mutator.generate_adaptive_payloads("<script>alert(1)</script>", max_count=10)
        assert isinstance(results, list)

    def test_adaptive_payloads_respects_max_count(self, mutator):
        max_count = 5
        results = mutator.generate_adaptive_payloads("' OR 1=1--", max_count=max_count)
        assert len(results) <= max_count

    def test_adaptive_payloads_includes_original(self, mutator):
        original = "test_payload"
        results = mutator.generate_adaptive_payloads(original, max_count=10)
        assert original in results, "Adaptive payloads should include the original"

    def test_adaptive_payloads_with_empty_string(self, mutator):
        results = mutator.generate_adaptive_payloads("", max_count=5)
        assert isinstance(results, list)


class TestLearning:
    """Learning system should adapt strategy weights"""

    def test_learn_from_blocked_response(self, mutator):
        mutator.learn_from_response(
            payload="<script>alert(1)</script>",
            response="403 Forbidden - Request blocked by WAF",
            is_blocked=True,
            response_time=0.1,
        )
        # Blocked payloads should be tracked in failed_mutations
        assert len(mutator.mutation_history) > 0
        assert "<script>alert(1)</script>" in mutator.failed_mutations

    def test_learn_from_successful_response(self, mutator):
        mutator.learn_from_response(
            payload="<ScRiPt>alert(1)</ScRiPt>",
            response="<div><ScRiPt>alert(1)</ScRiPt></div>",
            is_blocked=False,
            response_time=0.05,
        )
        assert len(mutator.mutation_history) > 0

    def test_recommended_strategy_returns_valid(self, mutator):
        strategy = mutator.get_recommended_strategy()
        assert isinstance(strategy, MutationStrategy)


class TestEdgeCases:
    """Edge cases and robustness"""

    def test_very_long_payload(self, mutator):
        long_payload = "A" * 10000
        results = mutator.mutate_payload(long_payload, MutationStrategy.ENCODING, count=3)
        assert isinstance(results, list)

    def test_unicode_payload(self, mutator):
        unicode_payload = "テスト<script>alert('XSS')</script>"
        results = mutator.mutate_payload(unicode_payload, MutationStrategy.ENCODING, count=3)
        assert isinstance(results, list)

    def test_special_characters_payload(self, mutator):
        payload = "'; DROP TABLE users; --\x00\n\r\t"
        results = mutator.mutate_payload(payload, MutationStrategy.BYPASS_FILTER, count=3)
        assert isinstance(results, list)
