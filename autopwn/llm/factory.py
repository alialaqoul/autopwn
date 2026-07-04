# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Build the configured LLM provider from config."""
from __future__ import annotations

from ..config import LLMConfig
from .base import LLMProvider
from .openai_compatible import OpenAICompatibleProvider

# Sensible default endpoints per provider keyword.
_DEFAULT_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "ollama": "http://localhost:11434/v1",
    "anythingllm": "http://localhost:3001/api/v1/openai",
    "lmstudio": "http://localhost:1234/v1",
    "openai_compatible": "http://localhost:8000/v1",
}


def build_provider(cfg: LLMConfig) -> LLMProvider:
    provider = cfg.provider.lower().strip()
    base_url = cfg.base_url or _DEFAULT_BASE_URLS.get(provider)
    if not base_url:
        raise ValueError(
            f"Unknown provider '{cfg.provider}' and no base_url set. "
            f"Known: {', '.join(_DEFAULT_BASE_URLS)}."
        )
    return OpenAICompatibleProvider(
        model=cfg.model,
        base_url=base_url,
        api_key=cfg.api_key,
        temperature=cfg.temperature,
        max_tokens=cfg.max_tokens,
        name=provider,
        timeout=cfg.request_timeout,
    )
