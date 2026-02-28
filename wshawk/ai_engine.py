import os
import json
import asyncio
import aiohttp
from typing import List, Dict, Optional, Any
from .logger import get_logger

logger = get_logger("AIEngine")

class AIEngine:
    """
    AI-Enhanced Payload Generation Engine.
    Supports local LLMs (Ollama) and remote APIs (OpenAI, etc.).
    """
    
    def __init__(self, provider: str = "ollama", model: str = "codellama", 
                 base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.provider = provider.lower()
        self.model = model
        self.api_key = api_key or os.environ.get("WSHAWK_AI_KEY")
        
        # Default base URLs
        if base_url:
            self.base_url = base_url
        elif self.provider == "ollama":
            self.base_url = "http://127.0.0.1:11434/api/generate"
        elif self.provider == "openai":
            self.base_url = "https://api.openai.com/v1/chat/completions"
        else:
            self.base_url = base_url

    async def generate_payloads(self, context: str, vuln_type: str, count: int = 5) -> List[str]:
        """Generate high-intelligence payloads based on message context."""
        prompt = self._build_prompt(context, vuln_type, count)
        
        try:
            if self.provider == "ollama":
                return await self._call_ollama(prompt)
            elif self.provider in ("openai", "custom"):
                return await self._call_openai_compatible(prompt)
            else:
                logger.error(f"Unsupported AI provider: {self.provider}")
                return []
        except Exception as e:
            logger.error(f"AI Generation Error: {e}")
            return []

    def _build_prompt(self, context: str, vuln_type: str, count: int) -> str:
        """Construct a refined prompt for the LLM."""
        return f"""
        Act as an elite penetration tester specialized in WebSocket security.
        Analyze the following WebSocket message context and generate {count} highly creative, 
        effective, and context-aware payloads for testing {vuln_type} vulnerabilities.

        CONTEXT:
        {context}

        INSTRUCTIONS:
        - Payloads must be specifically tailored to the format (JSON, Binary, Custom) used in the context.
        - Avoid generic payloads; focus on bypasses, edge cases, and modern exploit techniques.
        - Return ONLY a raw JSON array of strings. No explanation, no markdown.
        
        VULNERABILITY TYPE: {vuln_type}
        """

    async def _call_ollama(self, prompt: str) -> List[str]:
        """Call local Ollama instance."""
        async with aiohttp.ClientSession() as session:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": "json"
            }
            async with session.post(self.base_url, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    response_text = data.get("response", "[]")
                    return self._parse_json_response(response_text)
                return []

    async def _call_openai_compatible(self, prompt: str) -> List[str]:
        """Call OpenAI or compatible API (Vultr, Groq, etc.)."""
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        async with aiohttp.ClientSession() as session:
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.7
            }
            async with session.post(self.base_url, json=payload, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    response_text = data['choices'][0]['message']['content']
                    return self._parse_json_response(response_text)
                return []

    def _parse_json_response(self, text: str) -> List[str]:
        """Safely parse JSON array from LLM response."""
        try:
            # Strip markdown if present
            clean_text = text.strip()
            if clean_text.startswith("```json"):
                clean_text = clean_text[7:-3].strip()
            elif clean_text.startswith("```"):
                clean_text = clean_text[3:-3].strip()
            
            data = json.loads(clean_text)
            if isinstance(data, list):
                return [str(item) for item in data]
            elif isinstance(data, dict) and "payloads" in data:
                return [str(item) for item in data["payloads"]]
            return []
        except Exception:
            # Fallback: line-by-line if JSON fails
            return [line.strip() for line in text.splitlines() if line.strip()][:5]
