# Getting Started with WSHawk

## Installation

### Basic Installation
```bash
pip install wshawk
```

### With Playwright Support
For browser-based XSS verification:
```bash
pip install wshawk
playwright install chromium
```

### From Source
```bash
git clone https://github.com/regaan/wshawk
cd wshawk
pip install -e .
```

## Your First Scan

### Quick Scan
```bash
wshawk ws://echo.websocket.org
```

### Interactive Mode
```bash
wshawk-interactive
```
Then enter the WebSocket URL and select tests from the menu.

### Advanced Mode
```bash
wshawk-advanced ws://echo.websocket.org --full
```

## Understanding the Output

### Console Output
WSHawk displays real-time progress:
- `[*]` - Information
- `[+]` - Success
- `[!]` - Warning
- `[-]` - Error
- `[VULN]` - Vulnerability found

### HTML Report
After scanning, WSHawk generates `wshawk_report_YYYYMMDD_HHMMSS.html` containing:
- Executive summary
- CVSS scores
- Detailed findings
- Remediation recommendations
- Screenshots (if Playwright enabled)
- Message replay sequences

## Common Use Cases

### Bug Bounty Hunting
```bash
wshawk-advanced wss://target.com --playwright --rate 3
```

### CI/CD Integration
```bash
wshawk ws://staging-app.com || exit 1
```

### Penetration Testing
```bash
wshawk-interactive  # Select specific tests
```

## Next Steps

- [Advanced Usage](advanced_usage.md) - Python API and custom scripts
- [Vulnerability Details](vulnerabilities.md) - What WSHawk detects
- [Session Tests](session_tests.md) - Session security testing
