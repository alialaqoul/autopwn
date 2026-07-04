# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Configuration loading and validation."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field


class LLMConfig(BaseModel):
    provider: str = "ollama"
    model: str = "llama3.1:8b"
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    temperature: float = 0.2
    max_tokens: int = 2048
    # Read timeout (seconds) for a single completion. CPU-only local models can
    # take minutes per step, so this defaults high.
    request_timeout: float = 600.0


class AgentConfig(BaseModel):
    max_steps: int = 25
    confirm_active_actions: bool = True


class ToolsConfig(BaseModel):
    nmap_path: str = "nmap"
    nuclei_path: str = "nuclei"


class Config(BaseModel):
    llm: LLMConfig = Field(default_factory=LLMConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    scope_file: str = "scope.yaml"
    log_dir: str = "logs"

    @classmethod
    def load(cls, path: str | Path = "config.yaml") -> "Config":
        path = Path(path)
        data: dict = {}
        if path.exists():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        cfg = cls(**data)
        # Environment overrides win over the file so secrets stay out of configs.
        if env_key := os.environ.get("AUTOPWN_LLM_API_KEY"):
            cfg.llm.api_key = env_key
        if env_url := os.environ.get("AUTOPWN_LLM_BASE_URL"):
            cfg.llm.base_url = env_url
        if env_model := os.environ.get("AUTOPWN_LLM_MODEL"):
            cfg.llm.model = env_model
        return cfg
