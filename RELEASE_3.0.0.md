# WSHawk V3.0.1 - Enterprise Release Summary

WSHawk V3.0.1 represents a major architectural leap, transforming from a high-performance scanner into a production-grade, enterprise-ready WebSocket security ecosystem. This release focuses on **Resilience**, **Persistence**, and **Automation**.

---

## Key Feature Pillar: Enterprise Infrastructure

### Production-Grade Resilience Layer
The core communication engine has been rewritten to handle unstable targets and rate-limited environments.
- **ResilientSession**: Custom wrapper for all HTTP, WebSocket, and API calls.
- **Exponential Backoff**: Automatic retry logic with jitter to handle `429 Too Many Requests` elegantly.
- **Circuit Breakers**: Prevents "cascading failures" when integrated with external platforms like Jira or DefectDojo. If a service is down, WSHawk fails gracefully instead of hanging.

### Persistent Web Management Portal
WSHawk now includes a fully functional, SQLite-backed management dashboard.
- **Scan History**: All scans, vulnerabilities, and traffic logs are persisted to `~/.wshawk/scans.db`.
- **Authenticated Login**: Secure dashboard access protected by SHA-256 password hashing.
- **REST API**: A full JSON API for programmatic control of the scanner (`/api/scans`, `/api/stats`, etc.).

---

## Key Feature Pillar: Cognitive Security

### Smart Payload Evolution (New Phase)
The scanning engine is no longer static; it now adapts to the target server's response patterns.
- **Adaptive Feedback Loop**: Real-time classification of server responses to prioritize promising attack vectors.
- **Genetic Mutation Phase**: A new post-scan process that evolves novel payloads by mutating successful bypasses found during the initial heuristic scan.

### SOC & CI/CD Integrations
WSHawk V3.0.1 is built to live inside a modern security operations center.
- **Jira Integration**: Automated ticket creation with full reproduction steps and CVSS severity.
- **DefectDojo Integration**: Direct push of findings to the open-source vulnerability management platform.
- **Rich Webhooks**: Structured notifications for **Slack**, **Discord**, and **Microsoft Teams**.

---

## Technical Improvements & Bug Fixes

### Refactored Distribution (The "Fix")
- **MANIFEST.in System**: Comprehensive asset management ensure that HTML templates, CSS, and payloads are correctly bundled during `pip install`.
- **TemplateNotFound Fix**: Resolved the critical issue where the Web GUI could not find its layouts when installed as a package.

### Modern CLI Interface
- **Argparse Refactor**: Unified command-line interface with full support for flags:
  - `wshawk --web`: Launches the Management Dashboard.
  - `wshawk --version`: Displays the official V3.0.1 build info.
  - `wshawk --port <port>`: Custom port binding for the web server.
- **Async Safety**: Implemented thread-safe event loop management to prevent "RuntimeError: Event loop already running" when calling multiple entry points.

---

## Reporting & Outputs
- **SARIF Support**: Standardized Static Analysis Results Interchange Format for GitHub Security tab integration.
- **JSON/CSV/HTML**: Multi-format exports for both human reading and machine processing.
- **CVSS v3.1 Integration**: Every finding includes a calculated vector and score for risk prioritization.

---

### **Built by Regaan (@noobforanonymous)**
*Empowering secondary-security researchers and blue teams with enterprise-grade WebSocket auditing.*
