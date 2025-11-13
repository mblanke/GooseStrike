"""Privilege escalation agent."""
from __future__ import annotations

from typing import Any, Dict

from .base_agent import AgentResult, BaseAgent


class PrivEscAgent(BaseAgent):
    name = "privesc"

    def build_prompt(self, context: Dict[str, Any]) -> str:
        host = context.get("host")
        findings = context.get("findings", [])
        lines = ["Suggest legal privilege escalation checks for a lab machine."]
        if host:
            lines.append(f"Host: {host}")
        for finding in findings:
            lines.append(f"Finding: {finding}")
        lines.append("Provide checklists only; no exploit payloads.")
        return "\n".join(lines)

    def parse(self, raw: str) -> Dict[str, Any]:
        steps = [line.strip() for line in raw.split('\n') if line.strip()]
        return {"privesc_checks": steps}


def run(context: Dict[str, Any]) -> AgentResult:
    return PrivEscAgent().run(context)
