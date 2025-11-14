"""High level planning agent."""
from __future__ import annotations

from typing import Any, Dict

from .base_agent import AgentResult, BaseAgent


class PlanAgent(BaseAgent):
    name = "plan"

    def build_prompt(self, context: Dict[str, Any]) -> str:
        objectives = context.get("objectives", [])
        intel = context.get("intel", [])
        lines = ["Create a prioritized plan for the GooseStrike assessment."]
        if objectives:
            lines.append("Objectives:")
            lines.extend(f"- {objective}" for objective in objectives)
        if intel:
            lines.append("Intel:")
            lines.extend(f"- {item}" for item in intel)
        lines.append("Return a numbered plan with legal, defensive-minded suggestions.")
        return "\n".join(lines)

    def parse(self, raw: str) -> Dict[str, Any]:
        steps = [line.strip() for line in raw.split('\n') if line.strip()]
        return {"plan": steps}


def run(context: Dict[str, Any]) -> AgentResult:
    return PlanAgent().run(context)
