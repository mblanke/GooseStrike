"""Wrapper around OWASP ZAP baseline scan."""
from __future__ import annotations

from typing import Any, Dict, List

from runner_utils import run_subprocess


def build_command(task: Dict[str, Any]) -> List[str]:
    target = task.get("target_url")
    if not target:
        raise ValueError("target_url is required")
    command = ["zap-baseline.py", "-t", target, "-m", "5", "-r", task.get("report", "zap_report.html")]
    for key, value in task.get("options", {}).items():
        flag = f"-{key}" if len(key) == 1 else f"--{key}"
        if isinstance(value, bool):
            if value:
                command.append(flag)
        else:
            command.extend([flag, str(value)])
    return command


def run_task(task: Dict[str, Any]) -> Dict[str, Any]:
    try:
        command = build_command(task)
    except ValueError as exc:
        return {"status": "error", "exit_code": None, "error": str(exc)}
    return run_subprocess(command, "zap")


if __name__ == "__main__":
    example = {"target_url": "http://example.com", "report": "example.html"}
    print(run_task(example))
