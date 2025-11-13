"""Wrapper for Hydra tasks."""
from __future__ import annotations

from typing import Any, Dict, List

from runner_utils import run_subprocess


def build_command(task: Dict[str, Any]) -> List[str]:
    service = task.get("service")
    target = task.get("target")
    if not service or not target:
        raise ValueError("service and target are required")
    command = ["hydra", "-t", str(task.get("threads", 4))]
    if task.get("username"):
        command.extend(["-l", task["username"]])
    if task.get("password"):
        command.extend(["-p", task["password"]])
    if task.get("username_list"):
        command.extend(["-L", task["username_list"]])
    if task.get("password_list"):
        command.extend(["-P", task["password_list"]])
    if task.get("options"):
        for opt in task["options"]:
            command.append(opt)
    command.extend([f"{target}", service])
    return command


def run_task(task: Dict[str, Any]) -> Dict[str, Any]:
    try:
        command = build_command(task)
    except ValueError as exc:
        return {"status": "error", "exit_code": None, "error": str(exc)}
    return run_subprocess(command, "hydra")


if __name__ == "__main__":
    example = {"service": "ssh", "target": "10.0.0.5", "username": "root", "password_list": "rockyou.txt"}
    print(run_task(example))
