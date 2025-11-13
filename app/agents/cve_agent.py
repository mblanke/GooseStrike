"""CVE triage agent."""
from __future__ import annotations

from typing import Any, Dict

from .base_agent import AgentResult, BaseAgent


class CVEAgent(BaseAgent):
    name = "cve"

    def build_prompt(self, context: Dict[str, Any]) -> str:
        cves = context.get("cves", [])
        lines = ["You are prioritizing CVEs for a legal assessment."]
        for cve in cves:
            lines.append(
                f"{cve.get('cve_id')}: severity={cve.get('severity')} score={cve.get('score')} desc={cve.get('description','')[:120]}"
            )
        lines.append("Provide prioritized actions and validation steps. No exploit code.")
        return "\n".join(lines)

    def parse(self, raw: str) -> Dict[str, Any]:
        recommendations = [line.strip() for line in raw.split('\n') if line.strip()]
        return {"cve_actions": recommendations}


def run(context: Dict[str, Any]) -> AgentResult:
    return CVEAgent().run(context)
