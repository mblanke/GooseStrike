"""Run Metasploit tasks in a controlled way for GooseStrike."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from runner_utils import LOG_DIR, run_subprocess


def run_task(task: Dict[str, Any]) -> Dict[str, Any]:
    module = task.get("module") or task.get("options", {}).get("module")
    target = task.get("target") or task.get("options", {}).get("rhosts")
    if not module or not target:
        return {"status": "error", "exit_code": None, "error": "module and target required"}

    opts = task.get("options", {})
    rc_lines = [f"use {module}", f"set RHOSTS {target}"]
    for key, value in opts.items():
        if key.lower() == "module" or key.lower() == "rhosts":
            continue
        rc_lines.append(f"set {key.upper()} {value}")
    rc_lines.extend(["run", "exit"])

    rc_path = LOG_DIR / f"metasploit_{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.rc"
    rc_path.write_text("\n".join(rc_lines), encoding="utf-8")

    command = ["msfconsole", "-q", "-r", str(rc_path)]
    return run_subprocess(command, "metasploit")


if __name__ == "__main__":
    example = {
        "module": "auxiliary/scanner/portscan/tcp",
        "target": "127.0.0.1",
        "options": {"THREADS": 4},
    }
    print(run_task(example))
