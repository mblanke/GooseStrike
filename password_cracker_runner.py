"""Password cracking task runner for hashcat, John the Ripper, and rainbow tables."""
from __future__ import annotations

from typing import Any, Callable, Dict, List

from runner_utils import run_subprocess


def build_hashcat_command(task: Dict[str, Any]) -> List[str]:
    hash_file = task.get("hash_file")
    if not hash_file:
        raise ValueError("hash_file is required for hashcat tasks")

    command: List[str] = ["hashcat"]
    if task.get("mode") is not None:
        command.extend(["-m", str(task["mode"])])
    if task.get("attack_mode") is not None:
        command.extend(["-a", str(task["attack_mode"])])
    if task.get("workload") is not None:
        command.extend(["-w", str(task["workload"])])
    if task.get("session"):
        command.extend(["--session", task["session"]])
    if task.get("potfile"):
        command.extend(["--potfile-path", task["potfile"]])
    if task.get("rules"):
        for rule in task["rules"]:
            command.extend(["-r", rule])
    if task.get("extra_args"):
        command.extend(task["extra_args"])

    command.append(hash_file)
    if task.get("wordlist"):
        command.append(task["wordlist"])
    elif task.get("mask"):
        command.append(task["mask"])
    else:
        raise ValueError("hashcat tasks require either a wordlist or mask")
    return command


def build_john_command(task: Dict[str, Any]) -> List[str]:
    hash_file = task.get("hash_file")
    if not hash_file:
        raise ValueError("hash_file is required for john tasks")

    command: List[str] = ["john"]
    if task.get("wordlist"):
        command.append(f"--wordlist={task['wordlist']}")
    if task.get("format"):
        command.append(f"--format={task['format']}")
    if task.get("rules"):
        command.append(f"--rules={task['rules']}")
    if task.get("session"):
        command.append(f"--session={task['session']}")
    if task.get("potfile"):
        command.append(f"--pot={task['potfile']}")
    if task.get("incremental"):
        command.append("--incremental")
    if task.get("extra_args"):
        command.extend(task["extra_args"])

    command.append(hash_file)
    return command


def build_rainbow_command(task: Dict[str, Any]) -> List[str]:
    tables_path = task.get("tables_path")
    if not tables_path:
        raise ValueError("tables_path is required for rainbow table tasks")

    command: List[str] = ["rcrack", tables_path]
    if task.get("hash_value"):
        command.append(task["hash_value"])
    elif task.get("hash_file"):
        command.extend(["-f", task["hash_file"]])
    else:
        raise ValueError("Provide hash_value or hash_file for rainbow table tasks")
    if task.get("threads"):
        command.extend(["-t", str(task["threads"])])
    if task.get("extra_args"):
        command.extend(task["extra_args"])
    return command


COMMAND_BUILDERS: Dict[str, Callable[[Dict[str, Any]], List[str]]] = {
    "hashcat": build_hashcat_command,
    "john": build_john_command,
    "johntheripper": build_john_command,
    "rainbow": build_rainbow_command,
    "rcrack": build_rainbow_command,
}


def run_task(task: Dict[str, Any]) -> Dict[str, Any]:
    tool = task.get("crack_tool", task.get("tool", "hashcat")).lower()
    builder = COMMAND_BUILDERS.get(tool)
    if builder is None:
        return {
            "status": "error",
            "exit_code": None,
            "error": f"Unsupported password cracking tool: {tool}",
        }
    try:
        command = builder(task)
    except ValueError as exc:
        return {"status": "error", "exit_code": None, "error": str(exc)}
    log_prefix = f"crack_{tool}"
    return run_subprocess(command, log_prefix)


if __name__ == "__main__":
    demo_task = {
        "crack_tool": "hashcat",
        "hash_file": "hashes.txt",
        "wordlist": "/usr/share/wordlists/rockyou.txt",
        "mode": 0,
        "attack_mode": 0,
    }
    print(run_task(demo_task))
