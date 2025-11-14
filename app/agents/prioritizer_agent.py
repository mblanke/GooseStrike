"""Target prioritizer AI agent."""
from __future__ import annotations

from typing import Any, Dict, List

from .base_agent import AgentResult, BaseAgent


class PrioritizerAgent(BaseAgent):
    name = "prioritizer"

    def build_prompt(self, context: Dict[str, Any]) -> str:
        hosts: List[Dict[str, Any]] = context.get("assets", [])
        findings = []
        for asset in hosts:
            ip = asset.get("ip")
            severity = max(
                (vuln.get("severity", "") for svc in asset.get("services", []) for vuln in svc.get("vulnerabilities", [])),
                default="",
            )
            findings.append(f"Host {ip} exposes {len(asset.get('services', []))} services (max severity: {severity}).")
        prompt_lines = [
            "You are GooseStrike's targeting aide.",
            "Rank the following hosts for next actions using MITRE ATT&CK tactics.",
        ]
        prompt_lines.extend(findings or ["No assets supplied; recommend intel-gathering tasks."])
        prompt_lines.append("Return JSON with priorities, rationale, and suggested tactic per host.")
        return "\n".join(prompt_lines)

    def parse(self, raw: str) -> Dict[str, Any]:
        return {"priorities": raw.strip()}


def prioritize_targets(context: Dict[str, Any]) -> AgentResult:
    return PrioritizerAgent().run(context)
