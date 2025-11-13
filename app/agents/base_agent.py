"""Base LLM agent scaffolding for GooseStrike."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


def llm_call(prompt: str) -> str:
    """Placeholder LLM call."""
    return "LLM response placeholder. Configure llm_call() to talk to your provider."


@dataclass
class AgentResult:
    prompt: str
    raw_response: str
    recommendations: Dict[str, Any]


class BaseAgent:
    name = "base"

    def run(self, context: Dict[str, Any]) -> AgentResult:
        prompt = self.build_prompt(context)
        raw = llm_call(prompt)
        return AgentResult(prompt=prompt, raw_response=raw, recommendations=self.parse(raw))

    def build_prompt(self, context: Dict[str, Any]) -> str:
        raise NotImplementedError

    def parse(self, raw: str) -> Dict[str, Any]:
        return {"notes": raw.strip()}
