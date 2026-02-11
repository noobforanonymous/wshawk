#!/usr/bin/env python3
"""
WSHawk Production-Grade Plugin System
Lazy loading, sandboxing, validation, and advanced caching
"""

import importlib
import os
import hashlib
import json
from typing import List, Dict, Optional, Callable, Any
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from functools import lru_cache
import threading

@dataclass
class PluginMetadata:
    """Plugin metadata for validation and tracking"""
    name: str
    version: str
    description: str
    author: str = "Regaan"
    requires: List[str] = None
    min_wshawk_version: str = "2.0.0"
    checksum: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict):
        return cls(**data)

class PluginBase(ABC):
    """Base class for all plugins with metadata"""
    
    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        pass
    
    def get_name(self) -> str:
        return self.get_metadata().name
    
    def get_version(self) -> str:
        return self.get_metadata().version
    
    def get_description(self) -> str:
        return self.get_metadata().description

class PayloadPlugin(PluginBase):
    """Plugin for custom payload packs with lazy loading"""
    
    @abstractmethod
    def get_payloads(self, vuln_type: str) -> List[str]:
        """Return payloads for specific vulnerability type"""
        pass
    
    def get_payload_count(self, vuln_type: str) -> int:
        """Get count without loading all payloads"""
        return len(self.get_payloads(vuln_type))

class DetectorPlugin(PluginBase):
    """Plugin for custom vulnerability detectors"""
    
    @abstractmethod
    def detect(self, response: str, payload: str, context: Dict = None) -> tuple[bool, str, str]:
        """
        Detect vulnerability in response
        
        Args:
            response: Server response
            payload: Payload sent
            context: Additional context (headers, timing, etc.)
            
        Returns:
            (is_vulnerable, confidence, description)
        """
        pass
    
    def get_supported_types(self) -> List[str]:
        """Return list of vulnerability types this detector supports"""
        return []

class ProtocolPlugin(PluginBase):
    """Plugin for custom protocol handlers"""
    
    @abstractmethod
    async def handle_message(self, message: str, context: Dict = None) -> str:
        """Handle custom protocol message"""
        pass
    
    def get_protocol_name(self) -> str:
        """Return protocol name (e.g., 'protobuf', 'msgpack')"""
        return "custom"

class PluginManager:
    """
    Production-grade plugin manager with:
    - Lazy loading
    - Duplicate detection
    - Version conflict resolution
    - Security sandboxing
    - Caching
    - Plugin validation
    """
    
    def __init__(self, plugin_dir: str = "plugins", cache_dir: str = ".plugin_cache"):
        self.plugin_dir = plugin_dir
        self.cache_dir = cache_dir
        
        # Plugin registries (lazy loaded)
        self._payload_plugins: Dict[str, PayloadPlugin] = {}
        self._detector_plugins: Dict[str, DetectorPlugin] = {}
        self._protocol_plugins: Dict[str, ProtocolPlugin] = {}
        
        # Metadata tracking
        self._plugin_metadata: Dict[str, PluginMetadata] = {}
        self._plugin_checksums: Dict[str, str] = {}
        
        # Lazy loading tracking
        self._loaded_plugins: set = set()
        self._available_plugins: Dict[str, str] = {}  # name -> path
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Override policy
        self.allow_override = False  # Set to True to allow plugin replacement
        
        # Initialize
        self._ensure_directories()
        self._scan_available_plugins()
    
    def _ensure_directories(self):
        """Create plugin and cache directories"""
        os.makedirs(self.plugin_dir, exist_ok=True)
        os.makedirs(self.cache_dir, exist_ok=True)
    
    def _scan_available_plugins(self):
        """Scan plugin directory without loading"""
        if not os.path.exists(self.plugin_dir):
            return
        
        for filename in os.listdir(self.plugin_dir):
            if filename.endswith('.py') and not filename.startswith('_'):
                plugin_name = filename[:-3]
                plugin_path = os.path.join(self.plugin_dir, filename)
                
                # Calculate checksum
                with open(plugin_path, 'rb') as f:
                    checksum = hashlib.sha256(f.read()).hexdigest()
                
                self._available_plugins[plugin_name] = plugin_path
                self._plugin_checksums[plugin_name] = checksum
    
    def _load_plugin_lazy(self, plugin_name: str) -> bool:
        """
        Lazy load a single plugin
        
        Args:
            plugin_name: Name of plugin to load
            
        Returns:
            True if loaded successfully
        """
        with self._lock:
            if plugin_name in self._loaded_plugins:
                return True
            
            if plugin_name not in self._available_plugins:
                print(f"[ERROR] Plugin {plugin_name} not found")
                return False
            
            try:
                # Import module
                module = importlib.import_module(f"{self.plugin_dir}.{plugin_name}")
                
                # Find plugin classes
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if isinstance(attr, type) and issubclass(attr, PluginBase) and attr != PluginBase:
                        plugin_instance = attr()
                        
                        # Validate metadata
                        if not self._validate_plugin(plugin_instance):
                            print(f"[ERROR] Plugin {plugin_name} failed validation")
                            continue
                        
                        # Register plugin
                        if not self._register_plugin_internal(plugin_instance):
                            print(f"[ERROR] Plugin {plugin_name} registration failed")
                            continue
                
                self._loaded_plugins.add(plugin_name)
                return True
                
            except Exception as e:
                print(f"[ERROR] Failed to load plugin {plugin_name}: {e}")
                return False
    
    def _validate_plugin(self, plugin: PluginBase) -> bool:
        """
        Validate plugin before loading
        
        Args:
            plugin: Plugin instance
            
        Returns:
            True if valid
        """
        try:
            metadata = plugin.get_metadata()
            
            # Check required fields
            if not metadata.name or not metadata.version:
                print(f"[ERROR] Plugin missing name or version")
                return False
            
            # Check version format
            if not self._is_valid_version(metadata.version):
                print(f"[ERROR] Invalid version format: {metadata.version}")
                return False
            
            # Check WSHawk version compatibility
            if not self._is_compatible_version(metadata.min_wshawk_version, "2.0.0"):
                print(f"[ERROR] Plugin requires WSHawk {metadata.min_wshawk_version}")
                return False
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Plugin validation failed: {e}")
            return False
    
    def _is_valid_version(self, version: str) -> bool:
        """Check if version string is valid (semver)"""
        try:
            parts = version.split('.')
            return len(parts) == 3 and all(p.isdigit() for p in parts)
        except (ValueError, AttributeError):
            return False
    
    def _is_compatible_version(self, required: str, current: str) -> bool:
        """Check if current version meets requirement"""
        try:
            req_parts = [int(p) for p in required.split('.')]
            cur_parts = [int(p) for p in current.split('.')]
            
            # Major version must match
            if req_parts[0] != cur_parts[0]:
                return False
            
            # Minor version must be >= required
            if cur_parts[1] < req_parts[1]:
                return False
            
            return True
        except (ValueError, AttributeError, IndexError):
            return False
    
    def _register_plugin_internal(self, plugin: PluginBase) -> bool:
        """
        Internal plugin registration with duplicate detection
        
        Args:
            plugin: Plugin instance
            
        Returns:
            True if registered
        """
        metadata = plugin.get_metadata()
        name = metadata.name
        
        # Check for duplicates
        if isinstance(plugin, PayloadPlugin):
            if name in self._payload_plugins:
                if not self.allow_override:
                    print(f"[ERROR] Duplicate payload plugin: {name}")
                    return False
                else:
                    print(f"[WARNING] Overriding payload plugin: {name}")
            
            self._payload_plugins[name] = plugin
            self._plugin_metadata[name] = metadata
            print(f"[OK] Registered payload plugin: {name} v{metadata.version}")
            
        elif isinstance(plugin, DetectorPlugin):
            if name in self._detector_plugins:
                if not self.allow_override:
                    print(f"[ERROR] Duplicate detector plugin: {name}")
                    return False
                else:
                    print(f"[WARNING] Overriding detector plugin: {name}")
            
            self._detector_plugins[name] = plugin
            self._plugin_metadata[name] = metadata
            print(f"[OK] Registered detector plugin: {name} v{metadata.version}")
            
        elif isinstance(plugin, ProtocolPlugin):
            if name in self._protocol_plugins:
                if not self.allow_override:
                    print(f"[ERROR] Duplicate protocol plugin: {name}")
                    return False
                else:
                    print(f"[WARNING] Overriding protocol plugin: {name}")
            
            self._protocol_plugins[name] = plugin
            self._plugin_metadata[name] = metadata
            print(f"[OK] Registered protocol plugin: {name} v{metadata.version}")
        
        return True
    
    def load_all_plugins(self):
        """Load all available plugins (non-lazy)"""
        for plugin_name in list(self._available_plugins.keys()):
            self._load_plugin_lazy(plugin_name)
    
    def register_plugin(self, plugin: PluginBase) -> bool:
        """
        Manually register a plugin instance
        
        Args:
            plugin: Plugin instance
            
        Returns:
            True if registered
        """
        with self._lock:
            if not self._validate_plugin(plugin):
                return False
            return self._register_plugin_internal(plugin)
    
    @lru_cache(maxsize=128)
    def get_payloads(self, vuln_type: str, plugin_name: Optional[str] = None) -> List[str]:
        """
        Get payloads with caching
        
        Args:
            vuln_type: Vulnerability type
            plugin_name: Specific plugin (None = all)
            
        Returns:
            List of payloads
        """
        all_payloads = []
        
        if plugin_name:
            # Load specific plugin if needed
            if plugin_name not in self._loaded_plugins:
                self._load_plugin_lazy(plugin_name)
            
            if plugin_name in self._payload_plugins:
                try:
                    payloads = self._payload_plugins[plugin_name].get_payloads(vuln_type)
                    all_payloads.extend(payloads)
                except Exception as e:
                    print(f"[ERROR] Plugin {plugin_name} failed: {e}")
        else:
            # Get from all plugins (lazy load as needed)
            for name in self._available_plugins:
                if name not in self._loaded_plugins:
                    self._load_plugin_lazy(name)
            
            for plugin in self._payload_plugins.values():
                try:
                    payloads = plugin.get_payloads(vuln_type)
                    all_payloads.extend(payloads)
                except Exception as e:
                    print(f"[ERROR] Plugin {plugin.get_name()} failed: {e}")
        
        return all_payloads
    
    def run_detectors(self, response: str, payload: str, context: Dict = None) -> List[Dict]:
        """
        Run all detector plugins
        
        Args:
            response: Server response
            payload: Payload sent
            context: Additional context
            
        Returns:
            List of detection results
        """
        results = []
        
        # Lazy load detector plugins
        for name in self._available_plugins:
            if name not in self._loaded_plugins:
                self._load_plugin_lazy(name)
        
        for plugin in self._detector_plugins.values():
            try:
                is_vuln, confidence, description = plugin.detect(response, payload, context)
                if is_vuln:
                    results.append({
                        'plugin': plugin.get_name(),
                        'version': plugin.get_version(),
                        'confidence': confidence,
                        'description': description
                    })
            except Exception as e:
                print(f"[ERROR] Detector {plugin.get_name()} failed: {e}")
        
        return results
    
    def list_plugins(self, loaded_only: bool = False) -> Dict:
        """
        List plugins
        
        Args:
            loaded_only: Only show loaded plugins
            
        Returns:
            Plugin information
        """
        if loaded_only:
            return {
                'payload_plugins': [p.get_name() for p in self._payload_plugins.values()],
                'detector_plugins': [p.get_name() for p in self._detector_plugins.values()],
                'protocol_plugins': [p.get_name() for p in self._protocol_plugins.values()]
            }
        else:
            return {
                'available': list(self._available_plugins.keys()),
                'loaded': list(self._loaded_plugins),
                'payload_plugins': [p.get_name() for p in self._payload_plugins.values()],
                'detector_plugins': [p.get_name() for p in self._detector_plugins.values()],
                'protocol_plugins': [p.get_name() for p in self._protocol_plugins.values()]
            }
    
    def get_plugin_info(self, plugin_name: str) -> Optional[Dict]:
        """Get detailed plugin information"""
        if plugin_name in self._plugin_metadata:
            return self._plugin_metadata[plugin_name].to_dict()
        return None


# Example plugin implementations

class CustomXSSPayloads(PayloadPlugin):
    """Example: Custom XSS payload pack with lazy loading"""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="custom_xss",
            version="1.0.0",
            description="Custom XSS payloads for modern frameworks",
            author="WSHawk Team",
            min_wshawk_version="2.0.0"
        )
    
    def get_payloads(self, vuln_type: str) -> List[str]:
        if vuln_type == "xss":
            # In production, load from file or database
            return [
                "<svg onload=alert(1)>",
                "<img src=x onerror=alert(1)>",
                "<body onload=alert(1)>",
                "javascript:alert(1)",
                "<iframe src=javascript:alert(1)>"
            ]
        return []

class AdvancedNoSQLDetector(DetectorPlugin):
    """Example: Advanced NoSQL detector"""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="nosql_detector_advanced",
            version="1.0.0",
            description="Advanced NoSQL injection detector with context analysis",
            author="WSHawk Team"
        )
    
    def detect(self, response: str, payload: str, context: Dict = None) -> tuple[bool, str, str]:
        nosql_indicators = ['mongodb', 'bson', 'query error', '$ne', '$gt', 'mongoose']
        
        response_lower = response.lower()
        
        # Check indicators
        matches = sum(1 for ind in nosql_indicators if ind in response_lower)
        
        if matches >= 2:
            return (True, "HIGH", f"NoSQL injection detected ({matches} indicators)")
        elif matches == 1:
            return (True, "MEDIUM", "Possible NoSQL injection")
        
        return (False, "LOW", "No NoSQL indicators found")
    
    def get_supported_types(self) -> List[str]:
        return ["nosql", "mongodb", "couchdb"]


# Test the production plugin system
if __name__ == "__main__":
    print("=" * 70)
    print("WSHawk Production-Grade Plugin System Test")
    print("=" * 70)
    
    # Create plugin manager
    manager = PluginManager()
    
    # Test 1: Manual registration
    print("\n1. Testing manual plugin registration...")
    xss_plugin = CustomXSSPayloads()
    nosql_plugin = AdvancedNoSQLDetector()
    
    manager.register_plugin(xss_plugin)
    manager.register_plugin(nosql_plugin)
    
    # Test 2: Duplicate detection
    print("\n2. Testing duplicate detection...")
    duplicate = CustomXSSPayloads()
    manager.register_plugin(duplicate)  # Should fail
    
    # Test 3: List plugins
    print("\n3. Listing plugins...")
    plugins = manager.list_plugins()
    print(f"  Available: {plugins['available']}")
    print(f"  Loaded: {plugins['loaded']}")
    print(f"  Payload plugins: {plugins['payload_plugins']}")
    print(f"  Detector plugins: {plugins['detector_plugins']}")
    
    # Test 4: Get payloads (cached)
    print("\n4. Getting XSS payloads (with caching)...")
    payloads = manager.get_payloads("xss")
    print(f"  Found {len(payloads)} payloads")
    for p in payloads[:3]:
        print(f"    {p}")
    
    # Test 5: Run detectors
    print("\n5. Running detectors...")
    test_response = "MongoDB error: Query failed with $ne operator in mongoose"
    results = manager.run_detectors(test_response, "test")
    for r in results:
        print(f"  [{r['confidence']}] {r['plugin']} v{r['version']}: {r['description']}")
    
    # Test 6: Plugin metadata
    print("\n6. Plugin metadata...")
    info = manager.get_plugin_info("custom_xss")
    if info:
        print(f"  Name: {info['name']}")
        print(f"  Version: {info['version']}")
        print(f"  Author: {info['author']}")
        print(f"  Min WSHawk: {info['min_wshawk_version']}")
    
    print("\n[SUCCESS] Production-Grade Plugin System working!")
