"""Shared helpers for GooseStrike tool runners."""
from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

LOG_DIR = Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)


def run_subprocess(command: List[str], log_prefix: str, stdin: Optional[str] = None) -> Dict[str, Any]:
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    log_path = LOG_DIR / f"{log_prefix}_{timestamp}.log"
    with log_path.open("w", encoding="utf-8") as log_file:
        log_file.write(f"COMMAND: {' '.join(command)}\n")
        if stdin:
            log_file.write("STDIN:\n")
            log_file.write(stdin)
            log_file.write("\n--- END STDIN ---\n")
        try:
            proc = subprocess.run(
                command,
                input=stdin,
                text=True,
                capture_output=True,
                check=False,
            )
        except FileNotFoundError:
            log_file.write(f"ERROR: command not found: {command[0]}\n")
            return {
                "status": "error",
                "exit_code": None,
                "error": f"Command not found: {command[0]}",
                "log_path": str(log_path),
            }
        log_file.write("STDOUT:\n")
        log_file.write(proc.stdout)
        log_file.write("\nSTDERR:\n")
        log_file.write(proc.stderr)
    status = "success" if proc.returncode == 0 else "failed"
    return {
        "status": status,
        "exit_code": proc.returncode,
        "log_path": str(log_path),
    }
