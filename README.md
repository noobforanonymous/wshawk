# WSHawk - WebSocket Security Scanner
## Overview

WSHawk is an automated security testing tool designed to identify vulnerabilities in WebSocket implementations. It includes comprehensive payload databases covering SQL injection, XSS, command injection, and other common attack vectors.

## Features

- Automated vulnerability scanning for WebSocket endpoints
- 22,634 attack payloads across 10 vulnerability categories
- 13 different security test modules
- Interactive command-line interface
- HTML report generation
- Asynchronous testing for improved performance
- Origin validation bypass detection

## Installation

### Linux / macOS

```bash
git clone https://github.com/noobforanonymous/wshawk.git
cd wshawk
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Windows

```bash
git clone https://github.com/noobforanonymous/wshawk.git
cd wshawk
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

### Interactive Mode

```bash
python wshawk_interactive.py
```

Follow the prompts to:
1. Enter the target WebSocket URL
2. Select which tests to run
3. Review results in the generated HTML report

### Direct Mode

```bash
python wshawk.py wss://target.example.com/socket
```

## Test Modules

The scanner includes the following test modules:

1. Origin Validation Bypass - Tests for Cross-Site WebSocket Hijacking
2. SQL Injection - Database injection attacks
3. Cross-Site Scripting - XSS payload testing
4. Command Injection - OS command execution tests
5. NoSQL Injection - NoSQL database attacks
6. LDAP Injection - Directory service vulnerabilities
7. Path Traversal - File system access attempts
8. Server Side Template Injection - Template engine exploits
9. XML External Entity - XXE vulnerability detection
10. Open Redirect - URL redirection issues
11. Message Replay - Replay attack detection
12. Rate Limiting - Abuse prevention verification
13. Authentication Bypass - Authentication validation

## Finding WebSocket Endpoints

Use browser developer tools to identify WebSocket connections:

1. Open Developer Tools (F12)
2. Navigate to the Network tab
3. Filter by WS (WebSocket)
4. Identify connections starting with ws:// or wss://

Common WebSocket endpoint patterns:
- /ws
- /socket
- /chat
- /notifications
- /live
- /updates

## Output

Test results are saved to `wshawk_report.html` with detailed information about:
- Vulnerability type and severity
- Successful payloads
- Affected endpoints
- Remediation recommendations

## Requirements

- Python 3.8 or higher
- websockets library

## Legal Disclaimer

**IMPORTANT - READ BEFORE USE:**

This tool is designed exclusively for authorized security testing and research purposes. By using WSHawk, you agree to the following terms:

- You must have explicit written permission from the system owner before conducting any security tests
- This tool should only be used on systems you own or have been authorized to test
- Unauthorized access to computer systems is illegal and may result in criminal prosecution
- The author and contributors are not responsible for any misuse or damage caused by this tool
- This tool is provided "as-is" for educational and professional security testing purposes only

**Violation of these terms may result in severe legal consequences. Use responsibly.**

## Author

Created by Regaan (@noobforanonymous)

## License

For educational and authorized security testing purposes only.
