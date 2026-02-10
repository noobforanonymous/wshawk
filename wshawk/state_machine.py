#!/usr/bin/env python3
"""
WSHawk State Machine Module
Handles WebSocket session state and authentication flows
"""

import asyncio
import json
import yaml
from typing import Dict, List, Optional, Callable, Any
from enum import Enum
from dataclasses import dataclass

class SessionState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTED = "connected"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    SUBSCRIBED = "subscribed"
    READY = "ready"
    ERROR = "error"

@dataclass
class StateTransition:
    """Represents a state transition"""
    from_state: SessionState
    to_state: SessionState
    trigger: str
    action: Optional[Callable] = None
    message_template: Optional[Dict] = None

class SessionStateMachine:
    """
    Manages WebSocket session state and authentication flows
    """
    
    def __init__(self):
        self.current_state = SessionState.DISCONNECTED
        self.state_history = []
        self.session_data = {}
        self.transitions = []
        self.message_sequence = []
        
    def add_transition(self, transition: StateTransition):
        """Add a state transition"""
        self.transitions.append(transition)
    
    def load_sequence_from_yaml(self, yaml_config: str):
        """
        Load authentication sequence from YAML config
        
        Example YAML:
        ```yaml
        sequence:
          - state: connect
            message: null
          
          - state: authenticate
            message:
              type: "auth"
              token: "${AUTH_TOKEN}"
            wait_for: "auth_success"
          
          - state: subscribe
            message:
              type: "subscribe"
              channel: "test"
        ```
        """
        try:
            config = yaml.safe_load(yaml_config)
            self.message_sequence = config.get('sequence', [])
        except Exception as e:
            print(f"Error loading YAML config: {e}")
    
    async def execute_sequence(self, websocket, variables: Optional[Dict] = None):
        """
        Execute the pre-configured message sequence
        """
        variables = variables or {}
        
        for step in self.message_sequence:
            state = step.get('state')
            message_template = step.get('message')
            wait_for = step.get('wait_for')
            delay = step.get('delay', 0)
            
            # Wait if specified
            if delay:
                await asyncio.sleep(delay)
            
            # Send message if specified
            if message_template:
                # Substitute variables
                message = self._substitute_variables(message_template, variables)
                await websocket.send(json.dumps(message))
                
                # Wait for expected response
                if wait_for:
                    response = await websocket.recv()
                    if wait_for not in response:
                        print(f"Warning: Expected '{wait_for}' not found in response")
                        return False
            
            # Update state
            self._update_state(state)
        
        return True
    
    def _substitute_variables(self, template: Any, variables: Dict) -> Any:
        """
        Substitute variables in message template
        Supports ${VAR_NAME} syntax
        """
        if isinstance(template, dict):
            return {k: self._substitute_variables(v, variables) 
                   for k, v in template.items()}
        elif isinstance(template, list):
            return [self._substitute_variables(item, variables) 
                   for item in template]
        elif isinstance(template, str):
            # Replace ${VAR} with actual value
            import re
            def replace_var(match):
                var_name = match.group(1)
                return str(variables.get(var_name, match.group(0)))
            
            return re.sub(r'\$\{([^}]+)\}', replace_var, template)
        else:
            return template
    
    def _update_state(self, new_state: str):
        """Update current state"""
        try:
            state_enum = SessionState[new_state.upper()]
            self.state_history.append(self.current_state)
            self.current_state = state_enum
        except KeyError:
            print(f"Warning: Unknown state '{new_state}'")
    
    def can_transition(self, to_state: SessionState) -> bool:
        """Check if transition is valid"""
        for transition in self.transitions:
            if (transition.from_state == self.current_state and 
                transition.to_state == to_state):
                return True
        return False
    
    def get_state(self) -> SessionState:
        """Get current state"""
        return self.current_state
    
    def is_ready(self) -> bool:
        """Check if session is ready for testing"""
        return self.current_state in [
            SessionState.AUTHENTICATED,
            SessionState.SUBSCRIBED,
            SessionState.READY
        ]
    
    def store_session_data(self, key: str, value: Any):
        """Store session-specific data"""
        self.session_data[key] = value
    
    def get_session_data(self, key: str, default: Any = None) -> Any:
        """Retrieve session data"""
        return self.session_data.get(key, default)
    
    def detect_auth_message(self, message: str) -> Optional[Dict]:
        """
        Auto-detect authentication message patterns
        """
        try:
            data = json.loads(message)
            
            # Common auth patterns
            auth_indicators = [
                'token', 'auth', 'login', 'authenticate',
                'session', 'credentials', 'api_key'
            ]
            
            # Check if message contains auth fields
            for key in data.keys():
                if any(indicator in key.lower() for indicator in auth_indicators):
                    return {
                        'type': 'auth_detected',
                        'field': key,
                        'message': data
                    }
        except (json.JSONDecodeError, ValueError):
            pass
        
        return None
    
    def create_replay_sequence(self) -> List[Dict]:
        """
        Create a replayable sequence of messages
        """
        return [
            {
                'state': state.value,
                'timestamp': i,
                'data': self.session_data.get(f'message_{i}')
            }
            for i, state in enumerate(self.state_history)
        ]
    
    def reset(self):
        """Reset state machine"""
        self.current_state = SessionState.DISCONNECTED
        self.state_history = []
        self.session_data = {}


class AuthenticationFlow:
    """
    Handles common authentication flows
    """
    
    @staticmethod
    def create_jwt_auth(token: str) -> Dict:
        """Create JWT authentication message"""
        return {
            "type": "auth",
            "token": token
        }
    
    @staticmethod
    def create_basic_auth(username: str, password: str) -> Dict:
        """Create basic authentication message"""
        return {
            "type": "login",
            "username": username,
            "password": password
        }
    
    @staticmethod
    def create_api_key_auth(api_key: str) -> Dict:
        """Create API key authentication message"""
        return {
            "type": "auth",
            "api_key": api_key
        }
    
    @staticmethod
    def create_session_auth(session_id: str) -> Dict:
        """Create session-based authentication message"""
        return {
            "type": "auth",
            "session_id": session_id
        }


# Example usage configuration
EXAMPLE_CONFIG = """
sequence:
  - state: connect
    message: null
  
  - state: authenticate
    message:
      type: "auth"
      token: "${AUTH_TOKEN}"
    wait_for: "authenticated"
    delay: 0.5
  
  - state: subscribe
    message:
      type: "subscribe"
      channel: "${CHANNEL_NAME}"
    wait_for: "subscribed"
  
  - state: ready
    message: null
"""
