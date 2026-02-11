# WSHawk Plugins Directory

This directory is for custom plugins that extend WSHawk's functionality.

## Plugin Types

1. **Payload Plugins** - Custom payload collections
2. **Detector Plugins** - Custom vulnerability detectors
3. **Protocol Plugins** - Custom protocol handlers

## Creating a Plugin

Create a Python file in this directory with the following structure:

```python
from wshawk.plugin_system import PayloadPlugin

class MyCustomPlugin(PayloadPlugin):
    def __init__(self):
        super().__init__(
            name="my_plugin",
            version="1.0.0",
            author="Regaan"
        )
    
    def get_payloads(self, vuln_type: str):
        return ["payload1", "payload2"]
```

## Plugin Discovery

WSHawk automatically discovers and loads plugins from this directory.

## Example Plugins

See the documentation for example plugin implementations.
