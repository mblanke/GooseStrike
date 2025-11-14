"""Lightweight MITRE ATT&CK suggestion helpers.

This module borrows ideas from community tooling such as OWASP Nettacker
and Exploitivator by correlating discovered services and CVEs with the
most relevant ATT&CK techniques. It does not attempt to be exhaustive;
instead it provides explainable heuristics that can be stored alongside
scan records so analysts always have context for next steps.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional


@dataclass
class MitreSuggestion:
    technique_id: str
    tactic: str
    name: str
    description: str
    related_cve: Optional[str]
    severity: str


@dataclass
class MitreRule:
    technique_id: str
    tactic: str
    name: str
    description: str
    ports: Optional[Iterable[int]] = None
    protocols: Optional[Iterable[str]] = None
    product_keywords: Optional[Iterable[str]] = None
    cve_required: bool = False


MITRE_RULES: List[MitreRule] = [
    MitreRule(
        technique_id="T1190",
        tactic="Initial Access",
        name="Exploit Public-Facing Application",
        description="HTTP/S service exposes attack surface that mirrors the"
        " public exploitation stage emphasized by Nettacker's web modules",
        ports={80, 443, 8080, 8443},
        protocols={"tcp"},
    ),
    MitreRule(
        technique_id="T1133",
        tactic="Initial Access",
        name="External Remote Services",
        description="SSH/RDP/VNC listeners enable credential attacks similar"
        " to Exploitivator's service runners.",
        ports={22, 3389, 5900},
        protocols={"tcp"},
    ),
    MitreRule(
        technique_id="T1047",
        tactic="Execution",
        name="Windows Management Instrumentation",
        description="SMB/RPC services align with remote execution and lateral"
        " movement playbooks.",
        ports={135, 139, 445},
        protocols={"tcp"},
    ),
    MitreRule(
        technique_id="T1068",
        tactic="Privilege Escalation",
        name="Exploitation for Privilege Escalation",
        description="Service exposes CVEs that can deliver privilege gains.",
        cve_required=True,
    ),
]


def _match_rule(rule: MitreRule, service: object, has_cve: bool) -> bool:
    proto = getattr(service, "proto", None)
    port = getattr(service, "port", None)
    product = (getattr(service, "product", None) or "").lower()
    if rule.protocols and proto not in rule.protocols:
        return False
    if rule.ports and port not in rule.ports:
        return False
    if rule.cve_required and not has_cve:
        return False
    if rule.product_keywords and not any(keyword in product for keyword in rule.product_keywords):
        return False
    return True


def generate_attack_suggestions(asset_label: str, services: Iterable[object]) -> List[MitreSuggestion]:
    """Return MITRE suggestions based on service metadata and CVE presence."""
    suggestions: List[MitreSuggestion] = []
    for service in services:
        cves = getattr(service, "cves", None) or []
        severity = "critical" if cves else "info"
        for rule in MITRE_RULES:
            if not _match_rule(rule, service, bool(cves)):
                continue
            suggestions.append(
                MitreSuggestion(
                    technique_id=rule.technique_id,
                    tactic=rule.tactic,
                    name=rule.name,
                    description=f"{rule.description} Observed on {asset_label}.",
                    related_cve=cves[0] if cves else None,
                    severity=severity,
                )
            )
    return suggestions
