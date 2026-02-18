# Changelog

All notable changes to WSHawk will be documented in this file.

## [2.0.7] - 2026-02-18

### Added
- **Production-Grade Resilience Layer** - Integrated `ResilientSession` with Exponential Backoff and Circuit Breakers for all integrations
- **Smart Payload Evolution** - New adaptive learning phase that evolves payloads based on server feedback loops
- **Persistent Web Dashboard** - SQLite-backed GUI with scan history and professional user management
- **Hardened Web Authentication** - Secure login system with SHA-256 hashing and API key support
- **Enterprise Integrations** - Multi-platform support for Jira, DefectDojo, and Webhooks (Slack, Discord, Teams)
- **Hierarchical Configuration** - Professional `wshawk.yaml` with environment variable secret resolution

### Improved
- **Professional Logging** - Centralized logging system with persistent file logs and custom security log levels
- **Endpoint Discovery** - Resilient crawler for finding hidden WebSocket endpoints behind hardened targets
- **Refined Reporting** - Support for SARIF, JSON, and CSV exports for SOC/CI-CD integration

## [2.0.6] - 2026-02-10

### Added
- **Comprehensive Test Suite** - 90+ unit and integration tests covering all core modules
- **Full OAST Integration** - Complete interact.sh API integration (registration, polling, and deregistration)
- **Expanded WAF Detection** - Added support for 8 additional WAFs (total 12 detected)
- **Examples Directory** - New `examples/` directory with practical usage scripts for the scanner, mutator, and defensive module

### Fixed
- **Interactive Mode** - Fixed bug where user test selections were completely ignored
- **Code Quality** - Replaced all 18 bare `except:` blocks with specific exception handling
- **Version Mismatch** - Synced version across `__init__.py`, `pyproject.toml`, and `setup.py`

### Removed
- **Redundant Files** - Removed orphaned drafts (`scanner_v2_additions.py`, `scanner_v2_new.py`, `payload_mutator_v3.py`)
- **Dead Dependencies** - Removed unused `asyncio-mqtt` from `requirements.txt`

## [2.0.5] - 2025-12-08

### Fixed
- CSWSH test compatibility with newer websockets library (use `additional_headers` instead of `extra_headers`)
- Defensive validation now correctly detects Origin header vulnerabilities

## [2.0.4] - 2025-12-08

### Added
- **Defensive Validation Module** - New module for blue teams to validate security controls
  - DNS Exfiltration Prevention Test - Validates egress filtering effectiveness
  - Bot Detection Validation Test - Tests anti-bot measure effectiveness  
  - CSWSH (Cross-Site WebSocket Hijacking) Test - Validates Origin header enforcement
  - **WSS Protocol Security Validation** - Tests TLS/SSL configuration for secure WebSocket connections
    - TLS version validation (detects SSLv2/v3, TLS 1.0/1.1)
    - Weak cipher suite detection (RC4, DES, 3DES, etc.)
    - Certificate validation (expiration, self-signed, chain integrity)
    - Forward secrecy verification
    - TLS renegotiation security
- New CLI command: `wshawk-defensive` for running defensive validation tests
- 216+ malicious origin payloads for comprehensive CSWSH testing
- Comprehensive documentation in `docs/DEFENSIVE_VALIDATION.md`
- CVSS scoring for all defensive validation findings

### Improved
- Payload management - Malicious origins now loaded from `payloads/malicious_origins.txt`
- Better separation between offensive and defensive testing capabilities
- Enhanced documentation for blue team security validation

## [2.0.3] - 2025-12-07

### Fixed
- Version mismatch between `__init__.py` and package files (now all 2.0.2)
- Inconsistent time usage: Changed `time.time()` to `time.monotonic()` in scanner_v2.py for system-time-change safety
- Added missing PyYAML dependency
- Fixed entry point for `wshawk` command

### Added
- Centralized logging system (`wshawk/logger.py`) with colored output and file logging support
- Configurable authentication in SessionHijackingTester - no longer hardcoded to user1/pass1
- CHANGELOG.md for tracking all changes

### Improved
- Session tester now accepts `auth_config` parameter for custom authentication flows
- Better error handling with specific exception types (ongoing)
- All CLI commands work correctly (wshawk, wshawk-interactive, wshawk-advanced)

## [2.0.1] - 2025-12-07

### Changed
- Cleaned up documentation
- Removed attribution text from README

## [2.0.0] - 2025-12-07

### Added
- Complete rewrite with advanced features
- Real vulnerability verification with Playwright
- OAST integration for blind vulnerabilities
- Session hijacking tests (6 security tests)
- Advanced mutation engine with WAF bypass
- CVSS v3.1 scoring
- Professional HTML reporting
- Adaptive rate limiting
- Plugin system
- Three CLI modes (quick, interactive, advanced)

### Changed
- Scanner API completely rewritten
- New command-line interface
- Python 3.8+ required
- New dependencies: playwright, aiohttp, PyYAML

## [1.0.6] - Previous

### Features
- Basic WebSocket scanning
- Reflection-based detection
- 22,000+ payloads
