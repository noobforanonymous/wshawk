# WSHawk V3.0.1: The Complete Enterprise Evolution Guide
## The Definitive Manual for Professional WebSocket Security Auditing

---

## 🦅 Table of Contents

1.  **[Introduction](#1-introduction)**
    - Vision and Roadmap
    - Why WebSocket Security Matters
2.  **[What is WSHawk V3.0.1?](#2-what-is-wshawk)**
    - The Enterprise Release Philosophy
    - High-Level Capability Matrix
3.  **[Core Architectural Framework](#3-architecture)**
    - The Red Team Execution Plane
    - The Infrastructure Persistence Plane
    - The Resilience Control Plane
    - The Integration Collaboration Plane
4.  **[The Resilience Layer: Mission-Critical Stability](#4-resilience)**
    - ResilientSession Implementation Logic
    - Exponential Backoff with Jitter
    - Circuit Breaker State Machine
    - Handling Network Partitioning
5.  **[Smart Payload Evolution (SPE) Engine](#5-spe-engine)**
    - Heuristic Discovery and Fingerprinting
    - Context-Aware Attack Prioritization
    - Genetic Mutation Algorithms
    - WAF Evasion and Neutralization
6.  **[WebSocket Discovery & Reconnaissance](#6-discovery)**
    - Hidden Endpoint Identification
    - Protocol Version Fingerprinting
    - Sub-protocol Negotiation Auditing
7.  **[Vulnerability Encyclopedia](#7-vulnerability-encyclopedia)**
    - **Injections**: SQLi, NoSQLi, OS CMD, LDAPs
    - **Cross-Request**: CSWSH, CSRF, SSRF
    - **Data Processing**: XXE, SSTI, JSON/XML Bombs
    - **Logic Flaws**: IDOR, Race Conditions
    - **Resource Exhaustion**: Slow-WS, Frame Flooding
8.  **[Session Security Suite](#8-session-security)**
    - Token Entropy Analysis
    - Session Replay and Side-jacking
    - JWT/OAuth Token Validation
    - Token Leakage Identification
9.  **[Defensive Validation Module (DVM)](#9-defensive-validation)**
    - DNS Exfiltration Auditing
    - Bot Detection Effectiveness Testing
    - TLS/SSL Protocol Hardening Validation
    - Origin Policy Enforcement Verification
10. **[Web Management Dashboard](#10-dashboard)**
    - Persistent SQLite Data Layer
    - Security and Authentication Architecture
    - Real-time Progress Tracking
    - Historical Comparison and Diffing
11. **[Dashboard REST API Documentation](#11-api)**
    - Authentication Flow
    - Endpoint Reference
    - Programmatic Orchestration
12. **[Enterprise Collaboration Integrations](#12-integrations)**
    - Jira Software Cloud/On-Prem Setup
    - DefectDojo Vulnerability Management
    - Slack, Teams, and Discord Hooking
13. **[Deployment, Scaling, and CI/CD](#13-deployment)**
    - Docker Production Environment
    - Kubernetes (K8s) Scaling
    - GitHub Actions / GitLab CI Integration
14. **[Advanced CLI Mastery](#14-cli)**
    - Flag Permutations
    - Interactive vs Manual Modes
    - Custom YAML Configuration Files
15. **[Vulnerability Remediation Guide](#15-remediation)**
    - Input Sanitization for Real-time Streams
    - Secure Architecture Patterns
    - WAF Tuning for WebSockets
16. **[Troubleshooting & Technical FAQ](#16-troubleshooting)**
    - Common Error Codes
    - Performance Tuning
17. **[Glossary of Terms](#17-glossary)**
18. **[Community and Support](#18-support)**

---

## 1. Introduction <a name="1-introduction"></a>

### Vision and Roadmap
WSHawk V3.0.1 is not an update; it is a paradigm shift. In the early days of WebSocket research, tools were often fragmented—one script for a handshake, another for a single payload. WSHawk V3.0.1 consolidates a decade of research into a single, unified execution engine. Our vision is to provide a "Cognitive Security" experience where the tool understands the context of the application it is scanning.

### Why WebSocket Security Matters
As the web moves towards real-time interactivity, WebSockets have become the backbone of modern finance, healthcare telemetry, and collaborative SaaS. However, traditional DAST scanners struggle with the asynchronous, bi-directional nature of the protocol. WSHawk V3.0.1 bridges this gap by maintaining stateful connections and analyzing responses that may arrive long after the attack payload was sent.

---

## 2. What is WSHawk V3.0.1? <a name="2-what-is-wshawk"></a>

### The Enterprise Release Philosophy
V3.0.1 is built on three pillars:
1.  **Zero-Loss Persistence**: Security data should never be ephemeral. 
2.  **Autonomous Evolution**: The tool should adapt to the target, not vice versa.
3.  **Actionable Output**: A vulnerability is only as useful as the ticket it creates.

### High-Level Capability Matrix
| Capability | Description | Role |
| :--- | :--- | :--- |
| **SPE Engine** | Mutates payloads based on server feedback (Heuristics). | Offensive |
| **Resilience Module** | Circuit Breakers and retries for unstable networks. | Infrastructure |
| **Defensive Validator** | Validates WAF, Bot Detection, and TLS. | Defensive |
| **Web Dashboard** | Real-time monitoring and historical data storage. | Management |
| **SARIF Export**| Standardized reporting for GitHub/GitLab. | Integration |

---

## 3. Core Architectural Framework <a name="3-architecture"></a>

WSHawk's architecture is built on a modular, async-first principle using Python's `asyncio` for maximum concurrency.

### The Red Team Execution Plane
This is the heart of the scanner. It manages the lifecycle of a WebSocket connection, from the initial HTTP Upgrade request to the final graceful shutdown.
- **Connection Manager**: Handles SSL/TLS handshakes and keep-alives.
- **Payload Injector**: Streams thousands of mutated payloads without blocking.
- **Async Verifier**: Evaluates asynchronous "side-effect" responses.

### The Infrastructure Persistence Plane
We replaced memory-resident data structures with a **Persistent SQLite Implementation**.
- **DB Schema**: Optimized for fast lookups of traffic logs and vulnerability snippets.
- **WAL Mode**: Write-Ahead Logging ensures that even if WSHawk is killed during a high-speed scan, the data remains intact.

### The Resilience Control Plane
This plane sits between the logic and the network. It uses a state-machine based approach to monitor target health and apply "back-pressure" if the target server starts failing.

### The Integration Collaboration Plane
Speaks JSON/Rest to external platforms. It is decoupled from the scanning logic, meaning integrations can fail or be misconfigured without impacting the primary audit.

---

## 4. The Resilience Layer: Mission-Critical Stability <a name="4-resilience"></a>

### ResilientSession Implementation Logic
WSHawk uses a custom wrapper around `aiohttp` and `websockets` called the `ResilientSession`. This component is responsible for the "self-healing" nature of the scanner.

```python
# Conceptual Implementation of v3.0 Resilience
async def execute_resiliently(self, payload):
    attempt = 0
    while attempt < self.max_retries:
        if self.circuit_breaker.is_open():
            Logger.warning("Circuit Breaker OPEN - Cooling down...")
            await asyncio.sleep(60)
            continue
            
        try:
            return await self.raw_send(payload)
        except Exception as e:
            if self.is_transient(e):
                attempt += 1
                delay = self.calculate_backoff(attempt)
                Logger.info(f"Retrying in {delay}s (Attempt {attempt})...")
                await asyncio.sleep(delay)
            else:
                self.circuit_breaker.record_failure()
                raise e
```

### Exponential Backoff with Jitter
Traditional "retry every 5 seconds" logic often crashes a recovering server. WSHawk implements **Exponential Backoff with Jitter**:
`Wait = Min(Cap, Base * 2^Attempt) + Random_Jitter`

### Circuit Breaker State Machine
1.  **CLOSED**: Everything is healthy. Requests flow through.
2.  **OPEN**: Threshold of failures reached. Requests are blocked globally to allow the target to recover.
3.  **HALF-OPEN**: Cooldown period finished. A single "canary" request is sent. If it succeeds, the circuit closes. If it fails, it re-opens.

### Handling Network Partitioning
If WSHawk detects a full network loss (e.g., local Wi-Fi drops), it enters a "Safe-Pause" state. It pauses all timers and resumes exactly where it left off once the interface returns, preserving the scan's continuity.

---

## 5. Smart Payload Evolution (SPE) Engine <a name="SPE"></a>

The SPE Engine is what separates WSHawk from "fuzzers." It doesn't just smash strings; it builds attacks.

### Heuristic Discovery and Fingerprinting
Before the aggressive scan, WSHawk performs a "Fingerprinting Phase":
- **Reflection Check**: Sends unique patterns to see how the server echoes them.
- **Type Sensitivity**: Sends `{"key": 1}` vs `{"key": "1"}` to see if the server validates types.
- **Encoding Preference**: Tests Base64, Hex, and URL encoding support.

### Context-Aware Attack Prioritization
If the fingerprinting reveals that the server is a Node.js/Express backend, WSHawk prioritizes NoSQL and Type-Confusion attacks over traditional SQLi. This saves time and minimizes noise.

### Genetic Mutation Algorithms
When a payload triggers an interesting server state (e.g., a longer response time or a 500 status code), the SPE engine creates "Generations":
- **Generation 0**: Base payload.
- **Generation 1**: URL-encoded version.
- **Generation 2**: Double-URL encoded with null bytes.
- **Generation 3**: Polyglot injected into a JSON structure.

### WAF Evasion and Neutralization
WSHawk recognizes signatures for Cloudflare, AWS, and more. When detected, it activates the **Evasion Modules**:
- **Protocol Obfuscation**: Camouflaging WebSocket frames.
- **Temporal Evasion**: Spacing out malicious characters over multiple frames.
- **Character Switching**: Using Unicode equivalents for blocked characters (e.g., `＜` instead of `<`).

---

## 6. WebSocket Discovery & Reconnaissance <a name="6-discovery"></a>

Finding the entry point is the first challenge of WebSocket security.

### Hidden Endpoint Identification
WSHawk uses wordlists and directory brute-forcing techniques specifically tuned for common WebSocket paths:
- `/socket.io/`
- `/ws/`
- `/graphql/`
- `/chat/`
- `/api/v1/stream/`

### Protocol Version Fingerprinting
It identifies if the server supports Sec-WebSocket-Version 13 (Standard) or older, legacy versions which may have inherent security flaws.

### Sub-protocol Negotiation Auditing
WSHawk probes the `Sec-WebSocket-Protocol` header to see if the server supports dangerous or unauthenticated sub-protocols like `ssh`, `rdp`, or outdated chat binary protocols.

---

## 7. Vulnerability Encyclopedia <a name="7-vulnerability-encyclopedia"></a>

This section outlines the primary attack vectors supported in V3.0.1.

### 7.1 Injections
- **SQL Injection**: Targeting the persistence layer. WSHawk tests for Time-based (using `SLEEP` or `pg_sleep`) and Error-based signatures.
- **NoSQL Injection**: Specifically for MongoDB and CouchDB style queries like `{$ne: null}`.
- **OS Command Injection**: Attempting to break out of the runtime using `; ls`, `| whoami`, and `$(id)`.
- **LDAP Injection**: Exploiting logic in real-time user lookup systems.

### 7.2 Cross-Request Attacks
- **CSWSH (Cross-Site WebSocket Hijacking)**: The most prevalent WebSocket flaw. WSHawk tests if the server fails to validate the `Origin` header, allowing any website to hijack a user's WebSocket session.
- **CSRF**: Even without the Handshake hijacking, individual frames may be susceptible if the server lacks per-message validation.
- **SSRF**: Using the WebSocket as a proxy to probe internal private networks or cloud metadata services (`169.254.169.254`).

### 7.3 Data Processing Flaws
- **XXE (XML External Entity)**: Many WebSockets use XML for structured data. WSHawk sends payloads meant to trigger external DTD resolution, verified via OAST (Out-of-Band) callbacks.
- **SSTI (Server-Side Template Injection)**: Targeting template engines like Jinja2 or Mako when they process real-time messages.

### 7.4 Logic and Integrity Flaws
- **IDOR (Insecure Direct Object Reference)**: Modifying message IDS (e.g., `{"msg_id": 101}`) to view messages belonging to other users.
- **Race Conditions**: Sending multiple rapid-fire messages to exploit timing windows in the server's state management.

### 7.5 Resource Exhaustion (DoS)
- **Slow-WS**: Keeping connections open with minimal traffic to exhaust server memory.
- **Frame Flooding**: Sending tens of thousands of tiny frames to overload the server's CPU.

---

## 8. Session Security Suite <a name="8-session-security"></a>

WebSockets are only as secure as the session that created them.

### Token Entropy Analysis
WSHawk analyzes session tokens passed in the `Cookie` or `Authorization` headers. It checks for predictable patterns, low entropy, and common weaknesses.

### Session Replay and Side-jacking
The scanner attempts to replay a valid session token from different IP addresses and user agents to see if the server enforces session binding.

### JWT/OAuth Token Validation
Full auditing of JWT tokens used for WebSocket auth:
- **None Algorithm Attack**: Testing if the server accepts unsigned tokens.
- **Key Confusion**: Testing if the server accepts HMAC-signed tokens using the public RSA key.
- **Expiry Validation**: Checking if tokens are still valid long after the `exp` claim.

---

## 9. Defensive Validation Module (DVM) <a name="9-defensive-validation"></a>

A major addition in the v3 series for **Blue Teams**.

### DNS Exfiltration Auditing
WSHawk attempts to tunnel data through DNS queries to a controlled OAST server. This validates if your organization's DNS egress filtering is actually working.

### Bot Detection Effectiveness Testing
The DVM executes a series of "Bot Challenges" against the server. It tests if basic anti-bot headers are enough to block automation or if the server is smart enough to detect browser fingerprinting.

### TLS/SSL Protocol Hardening Validation
Comprehensive auditing of the `wss://` handshake:
- **Deprecated Versions**: Detects SSLv2, SSLv3, TLS 1.0, and TLS 1.1.
- **Weak Ciphers**: Flags RC4, DES, and 3DES.
- **HSTS Enforcement**: Validates that the server requires secure connections.

---

## 10. Web Management Dashboard <a name="10-dashboard"></a>

The dashboard is the central hub for the WSHawk ecosystem.

### Persistent SQLite Data Layer
The dashboard uses a structured database to store:
- **Scan Metrics**: Start/End times, average RPS, and message counts.
- **Findings**: Every vulnerability with proof-of-concept payloads.
- **Logs**: Every frame sent and received for deep manual auditing.

### Security and Authentication Architecture
- **Environment Driven**: Set `WSHAWK_WEB_PASSWORD` to lock the GUI.
- **Encryption**: Passwords are hashed with SHA-256 and salted.
- **TLS Support**: Can be proxied behind Nginx/Apache for full secure access.

### Real-time Progress Tracking
The dashboard provides a live view of the scan "Brain." You can see which mutation strategies are being applied right now and what the current success rate is.

---

## 11. Dashboard REST API Documentation <a name="11-api"></a>

The dashboard is fully "Headless Compatible."

### Authentication Flow
1.  **Request**: `POST /login` with `password`.
2.  **Response**: A session cookie or API token.

### Endpoint Reference
- `GET /api/scans`: Returns a list of all historical scans.
- `POST /api/scans`:
    ```json
    {
      "target": "ws://example.com/api",
      "options": {
        "smart_payloads": true,
        "playwright": false
      }
    }
    ```
- `GET /api/scans/{id}/report`: Returns the full JSON report for a specific scan.

---

## 12. Enterprise Collaboration Integrations <a name="12-integrations"></a>

WSHawk integrates directly into your existing workflow.

### Jira Software Setup
1.  Configure `wshawk.yaml` with your Jira URL and API Token.
2.  Set `auto_create_issue: true`.
3.  When a scan finishes, WSHawk creates a Jira ticket for every high/critical finding.

### DefectDojo Vulnerability Management
WSHawk supports the **DefectDojo API v2**. It can automatically create "Engagements" and push findings into your central security dashboard.

### Slack, Teams, and Discord Hooking
Real-time alerts for your SOC team. 
- "Critical SQL injection found on Production WebSocket!" 
- Alerts include the CVSS score and a link to the HTML report.

---

## 13. Deployment, Scaling, and CI/CD <a name="13-deployment"></a>

### Docker Production Environment
The recommended way to run WSHawk in production.
- **Minimal Image**: Based on alpine/slim to reduce attack surface.
- **Volume Mounts**: Mount `/app/reports` and `~/.wshawk` to persist data.

### Kubernetes (K8s) Scaling
You can deploy a fleet of WSHawk instances as **K8s Jobs**. Each Job can be tasked with scanning a different service in your cluster, with all results centralizing into a common DefectDojo instance.

### GitHub Actions Integration
```yaml
name: Security Audit
on: [push]
jobs:
  wshawk_scan:
    runs-on: ubuntu-latest
    steps:
      - name: Run WSHawk
        run: docker run --rm rothackers/wshawk ws://my-app.com --sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: reports/wshawk.sarif
```

---

## 14. Advanced CLI Mastery <a name="14-cli"></a>

The CLI is designed for speed.

### Power Flags
- `-s, --smart`: Activate SPE engine.
- `-p, --playwright`: Visual browser verification (Headless).
- `-r, --rate`: Throttle the scanner (e.g., `-r 5` for stealth).

### Fully Headless Mode
Use `--web-only` to start the dashboard in the background without launching a terminal UI.

---

## 15. Vulnerability Remediation Guide <a name="15-remediation"></a>

Fixing a WebSocket vulnerability is different from fixing a standard web bug.

### 15.1 Input Sanitization
**Never trust client input.** Use a strong schema validator (like JSON Schema) before the message ever reaches your database logic.

### 15.2 Secure Architecture Patterns
- **WSS Only**: Force TLS for all connections.
- **Hardened Handshake**: Validate the `Origin` header against a whitelist.
- **Rate Limiting**: Implement per-connection and per-IP message limits (e.g., 50 messages/sec).

### 15.3 WAF Tuning for WebSockets
Configure your WAF to analyze the **WebSocket Payload**, not just the initial Handshake. Platforms like Cloudflare now support "WebSocket Inspection" rules.

---

## 16. Troubleshooting & Technical FAQ <a name="16-troubleshooting"></a>

**Q: Why am I getting "TemplateNotFound" errors?**
A: This usually happens with older v2 installations. Upgrade to V3.0.1 and ensure you use `pip install .` or `pip install wshawk`.

**Q: How do I scan a server that requires Auth?**
A: Use the `wshawk.yaml` config to set custom headers like `Authorization: Bearer <TOKEN>`.

**Q: WSHawk is too slow. How do I speed it up?**
A: Increase the rate with `--rate 50` and disable Playwright with `--no-playwright`.

---

## 17. Glossary of Terms <a name="17-glossary"></a>

- **OAST**: Out-of-Band Application Security Testing (e.g., interact.sh).
- **SPE**: Smart Payload Evolution.
- **CSWSH**: Cross-Site WebSocket Hijacking.
- **Handshake**: The initial HTTP Upgrade request that establishes a WebSocket.
- **Frame**: An individual message unit in the WebSocket protocol.

---

## 18. Community and Support <a name="18-support"></a>

WSHawk is a community-driven project. We rely on your feedback to improve our mutation engines and detection signatures.

- **Developer**: Regaan (@noobforanonymous)
- **Organization**: Rot Hackers
- **GitHub**: https://github.com/noobforanonymous/wshawk

---
**WSHawk V3.0.1** - *Built by Regaan and for the global security research community.*
