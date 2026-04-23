"""
API Client Abstraction Layer
============================
Provides a unified interface for interacting with OpenAI-compatible LLM APIs.
Supports OpenAI, Anthropic (via compatibility shim), and Mistral.
Includes retry logic, error handling, and response normalization.
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

import httpx

logger = logging.getLogger(__name__)


class Provider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    MISTRAL = "mistral"
    CUSTOM = "custom"


@dataclass
class LLMResponse:
    """Normalized response from any LLM provider."""
    content: str
    model: str
    provider: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    raw: dict = field(default_factory=dict)
    error: Optional[str] = None
    latency_ms: float = 0.0


@dataclass
class LLMRequest:
    """Normalized request to any LLM provider."""
    messages: list[dict]
    system_prompt: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 512


class LLMClient:
    """
    Unified LLM client supporting OpenAI-compatible APIs and Anthropic natively.

    Usage:
        client = LLMClient(
            provider=Provider.OPENAI,
            api_key="sk-...",
            base_url="https://api.openai.com/v1",
            model="gpt-4o"
        )
        response = client.complete(request)
    """

    PROVIDER_DEFAULTS = {
        Provider.OPENAI: {
            "base_url": "https://api.openai.com/v1",
            "chat_endpoint": "/chat/completions",
        },
        Provider.ANTHROPIC: {
            "base_url": "https://api.anthropic.com",
            "chat_endpoint": "/v1/messages",
        },
        Provider.MISTRAL: {
            "base_url": "https://api.mistral.ai/v1",
            "chat_endpoint": "/chat/completions",
        },
        Provider.CUSTOM: {
            "base_url": None,
            "chat_endpoint": "/chat/completions",
        },
    }

    def __init__(
        self,
        provider: Provider,
        api_key: str,
        model: str,
        base_url: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 1.5,
    ):
        self.provider = provider
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        defaults = self.PROVIDER_DEFAULTS[provider]
        self.base_url = (base_url or defaults["base_url"]).rstrip("/")
        self.chat_endpoint = defaults["chat_endpoint"]

        self._http = httpx.Client(timeout=self.timeout)

    def _build_headers(self) -> dict:
        """Build provider-specific authentication headers."""
        if self.provider == Provider.ANTHROPIC:
            return {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
        else:
            return {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }

    def _build_payload(self, request: LLMRequest) -> dict:
        """Build provider-specific request payload."""
        if self.provider == Provider.ANTHROPIC:
            payload = {
                "model": self.model,
                "max_tokens": request.max_tokens,
                "messages": request.messages,
                "temperature": request.temperature,
            }
            if request.system_prompt:
                payload["system"] = request.system_prompt
            return payload
        else:
            # OpenAI-compatible format
            messages = []
            if request.system_prompt:
                messages.append({"role": "system", "content": request.system_prompt})
            messages.extend(request.messages)
            return {
                "model": self.model,
                "messages": messages,
                "temperature": request.temperature,
                "max_tokens": request.max_tokens,
            }

    def _parse_response(self, raw: dict) -> LLMResponse:
        """Normalize provider response into LLMResponse."""
        if self.provider == Provider.ANTHROPIC:
            content = raw.get("content", [{}])[0].get("text", "")
            usage = raw.get("usage", {})
            return LLMResponse(
                content=content,
                model=raw.get("model", self.model),
                provider=self.provider.value,
                prompt_tokens=usage.get("input_tokens", 0),
                completion_tokens=usage.get("output_tokens", 0),
                raw=raw,
            )
        else:
            choices = raw.get("choices", [{}])
            content = choices[0].get("message", {}).get("content", "") if choices else ""
            usage = raw.get("usage", {})
            return LLMResponse(
                content=content,
                model=raw.get("model", self.model),
                provider=self.provider.value,
                prompt_tokens=usage.get("prompt_tokens", 0),
                completion_tokens=usage.get("completion_tokens", 0),
                raw=raw,
            )

    def complete(self, request: LLMRequest) -> LLMResponse:
        """
        Send a completion request with retry logic.

        Retries on:
        - 429 (rate limit) — waits retry_delay * attempt
        - 500/502/503 (server errors)
        - Network timeouts

        Raises:
            RuntimeError: If all retries exhausted.
        """
        url = f"{self.base_url}{self.chat_endpoint}"
        headers = self._build_headers()
        payload = self._build_payload(request)
        last_error = None

        for attempt in range(1, self.max_retries + 1):
            try:
                t0 = time.monotonic()
                response = self._http.post(url, headers=headers, json=payload)
                latency = (time.monotonic() - t0) * 1000

                if response.status_code == 429:
                    wait = self.retry_delay * attempt
                    logger.warning(f"Rate limited. Waiting {wait}s (attempt {attempt})")
                    time.sleep(wait)
                    continue

                if response.status_code >= 500:
                    wait = self.retry_delay * attempt
                    logger.warning(f"Server error {response.status_code}. Retrying in {wait}s")
                    time.sleep(wait)
                    continue

                response.raise_for_status()
                parsed = self._parse_response(response.json())
                parsed.latency_ms = latency
                return parsed

            except httpx.TimeoutException as e:
                last_error = str(e)
                logger.warning(f"Timeout on attempt {attempt}: {e}")
                time.sleep(self.retry_delay)
            except httpx.HTTPStatusError as e:
                last_error = str(e)
                logger.error(f"HTTP error: {e.response.status_code} — {e.response.text}")
                break
            except Exception as e:
                last_error = str(e)
                logger.error(f"Unexpected error: {e}")
                break

        return LLMResponse(
            content="",
            model=self.model,
            provider=self.provider.value,
            error=f"All retries failed: {last_error}",
        )

    def close(self):
        """Close the underlying HTTP client."""
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
