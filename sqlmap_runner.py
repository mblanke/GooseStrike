"""Wrapper for sqlmap tasks."""
from __future__ import annotations

from typing import Any, Dict, List

from runner_utils import run_subprocess


def build_command(task: Dict[str, Any]) -> List[str]:
    if not task.get("target_url"):
        raise ValueError("target_url is required")
    command = ["sqlmap", "-u", task["target_url"], "--batch"]
    options = task.get("options", {})
    for key, value in options.items():
        flag = f"--{key.replace('_', '-')}"
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
    return run_subprocess(command, "sqlmap")


if __name__ == "__main__":
    example = {"target_url": "http://example.com/vuln.php?id=1", "options": {"level": 2}}
    print(run_task(example))
