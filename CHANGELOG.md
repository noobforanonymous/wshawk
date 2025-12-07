# Changelog

All notable changes to WSHawk will be documented in this file.

## [2.0.3] - Upcoming

### Fixed
- Version mismatch between `__init__.py` (1.0.6) and package files (2.0.2)
- Inconsistent time usage: Changed `time.time()` to `time.monotonic()` in scanner_v2.py
- Improved exception handling specificity in core modules
- Session tester now supports configurable authentication flows

### Improved
- Better error messages when imports fail
- Added logging support with configurable verbosity levels
- Plugin system now uses more robust path resolution

## [2.0.2] - 2024-12-07

### Fixed
- Added missing PyYAML dependency
- Fixed entry point for `wshawk` command
- All three CLI commands now work correctly

## [2.0.1] - 2024-12-07

### Changed
- Cleaned up documentation
- Removed attribution text from README

## [2.0.0] - 2024-12-07

### Added
- Complete rewrite with advanced features
- Real vulnerability verification with Playwright
- OAST integration for blind vulnerabilities
- Session hijacking tests (6 security tests)
- Intelligent mutation engine with WAF bypass
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
