"""LLM routing helpers with Claude -> HackGPT fallback."""
from __future__ import annotations

import os
from typing import Dict, List, Tuple

import requests


class LLMProviderError(RuntimeError):
    """Raised when a downstream LLM provider fails."""


def _call_provider(name: str, url: str, prompt: str) -> str:
    payload = {"prompt": prompt}
    api_key = os.getenv(f"{name.upper()}_API_KEY")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    response = requests.post(url, json=payload, headers=headers, timeout=30)
    response.raise_for_status()
    data: Dict[str, str] = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
    return data.get("response") or data.get("answer") or data.get("text") or response.text


def normalize_ollama_url(base_url: str) -> str:
    """Return a usable Ollama generate endpoint for the supplied base URL."""

    base_url = base_url.rstrip("/")
    if "/api" in base_url:
        if base_url.endswith("/generate"):
            return base_url
        return f"{base_url}/generate"
    return f"{base_url}/api/generate"


def _call_ollama(base_url: str, prompt: str) -> str:
    """Invoke a local Ollama instance using the configured model."""

    url = normalize_ollama_url(base_url)
    model = os.getenv("OLLAMA_MODEL", "llama3")
    payload = {"model": model, "prompt": prompt, "stream": False}
    response = requests.post(url, json=payload, timeout=30)
    response.raise_for_status()
    data: Dict[str, str] = (
        response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
    )
    return data.get("response") or data.get("output") or response.text


def call_llm_with_fallback(prompt: str) -> str:
    """Try Claude first, then HackGPT, finally return a placeholder."""

    order: List[Tuple[str, str]] = []
    claude_url = os.getenv("CLAUDE_API_URL")
    hackgpt_url = os.getenv("HACKGPT_API_URL")
    ollama_base = os.getenv("OLLAMA_API_URL") or os.getenv("OLLAMA_BASE_URL")
    if claude_url:
        order.append(("claude", claude_url))
    if hackgpt_url:
        order.append(("hackgpt", hackgpt_url))
    if ollama_base:
        order.append(("ollama", ollama_base))

    errors: List[str] = []
    for name, url in order:
        try:
            if name == "ollama":
                return _call_ollama(url, prompt)
            return _call_provider(name, url, prompt)
        except Exception as exc:  # pragma: no cover - network dependent
            errors.append(f"{name} failed: {exc}")
            continue

    if errors:
        raise LLMProviderError("; ".join(errors))

    return "LLM response placeholder. Configure CLAUDE_API_URL or HACKGPT_API_URL to enable live replies."
