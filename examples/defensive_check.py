#!/usr/bin/env python3
"""
WSHawk - Defensive Validation Example

Demonstrates the blue-team defensive module for validating
WebSocket security posture.
"""

import asyncio
from wshawk.defensive_validation import DefensiveValidator


async def defensive_demo():
    target = "ws://localhost:8080/ws"
    
    print("=" * 60)
    print("WSHawk Defensive Validation")
    print("=" * 60)
    print(f"Target: {target}\n")
    
    validator = DefensiveValidator(target)
    
    # Run all defensive checks
    results = await validator.run_all_checks()
    
    print(f"\n{'='*60}")
    print("RESULTS SUMMARY")
    print(f"{'='*60}")
    
    for check in results:
        status = "✓ PASS" if check.get("passed") else "✗ FAIL"
        print(f"  [{status}] {check.get('name', 'Unknown')}")
        if not check.get("passed"):
            print(f"         → {check.get('recommendation', 'N/A')}")
    
    passed = sum(1 for c in results if c.get("passed"))
    total = len(results)
    print(f"\nScore: {passed}/{total} checks passed")


if __name__ == "__main__":
    asyncio.run(defensive_demo())
