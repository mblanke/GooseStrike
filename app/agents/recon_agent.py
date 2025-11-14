"""Reconnaissance agent."""
from __future__ import annotations

from typing import Any, Dict

from .base_agent import AgentResult, BaseAgent


class ReconAgent(BaseAgent):
    name = "recon"

    def build_prompt(self, context: Dict[str, Any]) -> str:
        hosts = context.get("hosts", [])
        lines = ["You are advising a legal CTF recon team."]
        for host in hosts:
            services = host.get("services", [])
            service_lines = ", ".join(
                f"{svc.get('proto')}/{svc.get('port')} {svc.get('product','?')} {svc.get('version','')}"
                for svc in services
            )
            lines.append(f"Host {host.get('ip')} services: {service_lines}")
        lines.append("Suggest safe recon next steps without exploit code.")
        return "\n".join(lines)

    def parse(self, raw: str) -> Dict[str, Any]:
        bullets = [line.strip('- ') for line in raw.split('\n') if line.strip()]
        return {"recon_steps": bullets}


def run(context: Dict[str, Any]) -> AgentResult:
    return ReconAgent().run(context)
