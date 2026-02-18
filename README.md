# WSHawk v2.0 - Professional WebSocket Security Scanner

# SECURITY WARNING: FAKE VERSIONS CIRCULATING

> **PLEASE READ CAREFULLY:**  
> Fake versions of WSHawk are being distributed on third-party download sites and linked in social media posts (e.g., LinkedIn). These versions may contain **MALWARE**.  
>  
> **OFFICIAL SOURCES ONLY:**  
> - **Official Website:** [`https://wshawk.rothackers.com`](https://wshawk.rothackers.com)
> - **GitHub:** [`https://github.com/noobforanonymous/wshawk`](https://github.com/noobforanonymous/wshawk)  
> - **PyPI:** `pip install wshawk`  
> - **Docker:** `docker pull rothackers/wshawk` or `ghcr.io/noobforanonymous/wshawk`  
>  
> **DO NOT DOWNLOAD** from any other website. If you see "WSHawk" on a "software download" site, it is likely fake/malicious.


[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/wshawk.svg)](https://badge.fury.io/py/wshawk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Playwright](https://img.shields.io/badge/Playwright-Supported-green.svg)](https://playwright.dev/)
[![Status: Production](https://img.shields.io/badge/status-production-green.svg)](https://github.com/noobforanonymous/wshawk)

**WSHawk v2.0** is a production-grade WebSocket security scanner with advanced features including real vulnerability verification, dynamic mutation, and comprehensive session security testing. It also includes a **Persistent Web GUI** for dashboarding and history.

## Why WSHawk?

WSHawk is the only open-source WebSocket scanner that provides:
- **Smart Payload Evolution** - Adaptive feedback-driven mutation engine
- **Hierarchical Configuration** - `wshawk.yaml` with env var secret resolution
- **Persistent Web GUI** - Dashboard with SQLite history and password auth
- **Enterprise Integrations** - Auto-push to **Jira**, **DefectDojo**, and **Webhooks**
- **Real browser XSS verification** (Playwright) - Not just pattern matching
- **Blind vulnerability detection** via OAST - Finds XXE, SSRF that others miss
- **Session hijacking analysis** - 6 advanced session security tests
- **WAF-aware payload mutation** - Dynamic evasion techniques
- **CVSS-based professional reporting** - Industry-standard risk assessment

## Features

- **22,000+ Attack Payloads** - Comprehensive vulnerability coverage
- **Real Vulnerability Verification** - Confirms exploitability, not just reflection
- **Playwright XSS Verification** - Actual browser-based script execution testing
- **OAST Integration** - Detects blind vulnerabilities (XXE, SSRF)
- **Session Hijacking Tests** - Token reuse, impersonation, privilege escalation
- **Advanced Mutation Engine** - WAF bypass with 8+ evasion strategies
- **CVSS v3.1 Scoring** - Automatic vulnerability risk assessment
- **Professional HTML Reports** - Screenshots, replay sequences, traffic logs
- **Adaptive Rate Limiting** - Server-friendly scanning

### Vulnerability Detection
SQL Injection • XSS • Command Injection • XXE • SSRF • NoSQL Injection • Path Traversal • LDAP Injection • SSTI • Open Redirect • Session Security Issues

## Installation

### Option 1: pip (Recommended)

```bash
pip install wshawk

# Optional: For browser-based XSS verification
playwright install chromium
```

### Option 2: Docker

```bash
# From Docker Hub
docker pull rothackers/wshawk:latest

# Or from GitHub Container Registry
docker pull ghcr.io/noobforanonymous/wshawk:latest

# Run WSHawk
docker run --rm rothackers/wshawk ws://target.com

# Defensive validation
docker run --rm rothackers/wshawk wshawk-defensive ws://target.com
```

See [Docker Guide](docs/DOCKER.md) for detailed usage.

## Quick Start

WSHawk provides **4 easy ways** to scan WebSocket applications:

### Method 1: Quick Scan (Fastest)
```bash
wshawk ws://target.com
```

### Method 2: Interactive Menu (User-Friendly)
```bash
wshawk-interactive
```

### Method 3: Advanced CLI (Full Control)
```bash
# Basic scan
wshawk-advanced ws://target.com

# With Smart Payloads and Playwright verification
wshawk-advanced ws://target.com --smart-payloads --playwright --full
```

### Method 4: Web Management Dashboard (GUI)
```bash
# Launch the persistent web dashboard
wshawk --web
```
Best for teams requiring scan history, visual progress tracking, and professional report management.

## 🖥️ Web Management Dashboard

WSHawk v2.0 introduces a persistent, secure web-based dashboard for managing all your WebSocket security assessments.

### Launching the GUI
```bash
wshawk --web --port 5000 --host 0.0.0.0
```

### Authentication
For production security, the Web GUI is protected by a password. Set it using an environment variable:
```bash
export WSHAWK_WEB_PASSWORD='your-strong-password'
wshawk --web
```
*Note: If no password is set, the dashboard will run in open mode (only recommended for local testing).*

### Features
| Feature | Description |
|---------|-------------|
| **Persistent History** | All scans are saved to a local SQLite database (`scans.db`). |
| **Visual Progress** | Real-time scan status and vulnerability counters. |
| **Interactive Reports** | View, delete, and manage comprehensive HTML reports in-browser. |
| **API Key Support** | Programmatic access via `--api-key` or `WSHAWK_API_KEY`. |

## ⚙️ Hierarchical Configuration (`wshawk.yaml`)

WSHawk now supports a professional configuration system. Generate a template to get started:
```bash
python3 -m wshawk.config --generate
```

Rename `wshawk.yaml.example` to `wshawk.yaml`. You can resolve secrets from environment variables or files:
```yaml
integrations:
  jira:
    api_token: "env:JIRA_TOKEN"  # Fetched from environment
    project: "SEC"
```

## Command Comparison

| Feature | `wshawk` | `wshawk-interactive` | `wshawk-advanced` | `wshawk --web` |
|---------|----------|----------------------|-------------------|----------------|
| Ease of Use | High | High | Medium | **Highest** |
| Persistence | No | No | No | **Yes (SQLite)** |
| Auth Support | No | No | No | **Yes (SHA-256)** |
| Best For | Automation | Learning | Power Users | **Teams / SOC** |


## What You Get

All methods include:
- Real vulnerability verification (not just pattern matching)
- 22,000+ attack payloads
- Advanced mutation engine with WAF bypass
- CVSS v3.1 scoring for all findings
- Session hijacking tests (6 security tests)
- Professional HTML reports
- Adaptive rate limiting
- OAST integration for blind vulnerabilities
- Optional Playwright for browser-based XSS verification

## Output

WSHawk generates comprehensive HTML reports with:
- CVSS v3.1 scores for all vulnerabilities
- Screenshots (for XSS browser verification)
- Message replay sequences
- Raw WebSocket traffic logs
- Server fingerprints
- Actionable remediation recommendations

Reports saved as: `wshawk_report_YYYYMMDD_HHMMSS.html`

## Advanced Options

```bash
wshawk-advanced --help

Options:
  --playwright     Enable browser-based XSS verification
  --rate N         Set max requests per second (default: 10)
  --full           Enable ALL features
  --no-oast        Disable OAST testing
```

## Defensive Validation (NEW in v2.0.4)

WSHawk now includes a **Defensive Validation Module** designed for blue teams to validate their security controls.

```bash
# Run defensive validation tests
wshawk-defensive ws://your-server.com
```

### What It Tests

**1. DNS Exfiltration Prevention**
- Validates if DNS-based data exfiltration is blocked
- Tests egress filtering effectiveness
- Detects potential APT-style attack vectors

**2. Bot Detection Effectiveness**
- Tests if anti-bot measures detect headless browsers
- Validates resistance to evasion techniques
- Identifies gaps in bot protection

**3. CSWSH (Cross-Site WebSocket Hijacking)**
- Tests Origin header validation (216+ malicious origins)
- Validates CSRF token requirements
- Critical for preventing session hijacking

**4. WSS Protocol Security Validation**
- TLS version validation (detects deprecated SSLv2/v3, TLS 1.0/1.1)
- Weak cipher suite detection (RC4, DES, 3DES)
- Certificate validation (expiration, self-signed, chain integrity)
- Forward secrecy verification (ECDHE, DHE)
- Prevents MITM and protocol downgrade attacks

### Use Cases

- Validate security controls before production deployment
- Regular security posture assessment
- Compliance and audit requirements
- Blue team defensive capability testing

See [Defensive Validation Documentation](docs/DEFENSIVE_VALIDATION.md) for detailed usage and remediation guidance.


## Documentation

- [Getting Started Guide](docs/getting_started.md)
- [Advanced Usage](docs/advanced_usage.md)
- [Vulnerability Details](docs/vulnerabilities.md)
- [Session Security Tests](docs/session_tests.md)
- [Mutation Engine](docs/mutation_engine.md)
- [Architecture](docs/architecture.md)

## Python API

For integration into custom scripts:

```python
import asyncio
from wshawk.scanner_v2 import WSHawkV2

scanner = WSHawkV2("ws://target.com")
scanner.use_headless_browser = True
scanner.use_oast = True
asyncio.run(scanner.run_heuristic_scan())
```

See [Advanced Usage](docs/advanced_usage.md) for more examples.

## Responsible Disclosure

WSHawk is designed for:
- Authorized penetration testing
- Bug bounty programs
- Security research
- Educational purposes

**Always obtain proper authorization before testing.**

## License

MIT License - see [LICENSE](LICENSE) file

## Author

**Regaan** (@noobforanonymous)

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

## Legal Disclaimer

**WSHawk is designed for security professionals, researchers, and developers for authorized testing only.**

- **Usage:** You must have explicit permission from the system owner before scanning.
- **Liability:** The author (Regaan) is **NOT** responsible for any damage caused by the misuse of this tool.
- **Malware:** WSHawk is a security scanner, NOT malware. Any repackaged version found on third-party sites containing malicious code is **NOT** associated with this project.

By using WSHawk, you agree to these terms and use it at your own risk.

## Support

- **Issues:** [GitHub Issues](https://github.com/noobforanonymous/wshawk/issues)
- **Documentation:** [docs/](docs/)
- **Examples:** [examples/](examples/)
- **Email:** support@rothackers.com

---

**WSHawk v2.0** - Professional WebSocket Security Scanner

*Built for the security community*
