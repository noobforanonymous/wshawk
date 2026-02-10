#!/usr/bin/env python3
"""
WSHawk - Payload Mutation Example

Demonstrates the payload mutation engine with WAF-aware strategies.
"""

from wshawk.payload_mutator import PayloadMutator, MutationStrategy


def mutation_demo():
    mutator = PayloadMutator()
    
    # --- Example 1: Generate mutations for an XSS payload ---
    print("=" * 60)
    print("1. XSS Payload Mutations")
    print("=" * 60)
    
    xss_payload = "<script>alert(document.cookie)</script>"
    
    for strategy in MutationStrategy:
        variants = mutator.mutate_payload(xss_payload, strategy, count=3)
        if variants:
            print(f"\n  [{strategy.value}]")
            for v in variants:
                print(f"    {v[:80]}")
    
    # --- Example 2: Adaptive payload generation ---
    print("\n" + "=" * 60)
    print("2. Adaptive Payloads (auto-selected strategies)")
    print("=" * 60)
    
    sqli_payload = "' OR 1=1--"
    adaptive = mutator.generate_adaptive_payloads(sqli_payload, max_count=10)
    
    for i, p in enumerate(adaptive, 1):
        print(f"  {i:2d}. {p}")
    
    # --- Example 3: Learning from responses ---
    print("\n" + "=" * 60)
    print("3. Learning from WAF Responses")
    print("=" * 60)
    
    # Simulate a blocked response
    mutator.learn_from_response(
        payload="<script>alert(1)</script>",
        response="403 Forbidden - Blocked by Cloudflare",
        is_blocked=True,
        response_time=0.02,
    )
    
    # After learning, recommended strategy changes
    recommended = mutator.get_recommended_strategy()
    print(f"  Recommended strategy after block: {recommended.value}")
    
    # Generate new mutations using the recommended strategy
    new_variants = mutator.mutate_payload(
        "<script>alert(1)</script>", recommended, count=5
    )
    print(f"  New variants ({recommended.value}):")
    for v in new_variants:
        print(f"    {v[:80]}")


if __name__ == "__main__":
    mutation_demo()
