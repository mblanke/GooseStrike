"""SQLite-backed task queue for GooseStrike."""
from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

DB_PATH = Path("db/tasks.db")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_tables() -> None:
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool TEXT NOT NULL,
                target TEXT,
                params_json TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                started_at TEXT,
                finished_at TEXT,
                result_json TEXT
            )
            """
        )
        conn.commit()


def enqueue_task(tool: str, target: Optional[str], params: Dict[str, Any]) -> int:
    ensure_tables()
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO tasks(tool, target, params_json) VALUES(?,?,?)",
            (tool, target, json.dumps(params)),
        )
        conn.commit()
        return cur.lastrowid


def fetch_next_task(tool: Optional[str] = None) -> Optional[Dict[str, Any]]:
    ensure_tables()
    with get_conn() as conn:
        query = "SELECT * FROM tasks WHERE status='pending'"
        params: tuple = ()
        if tool:
            query += " AND tool=?"
            params = (tool,)
        query += " ORDER BY created_at LIMIT 1"
        row = conn.execute(query, params).fetchone()
        if not row:
            return None
        conn.execute(
            "UPDATE tasks SET status='running', started_at=? WHERE id=?",
            (datetime.utcnow().isoformat(), row["id"]),
        )
        conn.commit()
        return dict(row)


def update_task_status(task_id: int, status: str, result: Optional[Dict[str, Any]] = None) -> None:
    ensure_tables()
    with get_conn() as conn:
        conn.execute(
            "UPDATE tasks SET status=?, finished_at=?, result_json=? WHERE id=?",
            (
                status,
                datetime.utcnow().isoformat(),
                json.dumps(result) if result is not None else None,
                task_id,
            ),
        )
        conn.commit()


def list_tasks() -> None:
    ensure_tables()
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, tool, target, status, created_at, started_at, finished_at FROM tasks ORDER BY id"
        ).fetchall()
        for row in rows:
            print(dict(row))


def cli(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="Manage GooseStrike task queue")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enqueue_cmd = sub.add_parser("enqueue", help="Enqueue a new task")
    enqueue_cmd.add_argument("tool")
    enqueue_cmd.add_argument("target", nargs="?")
    enqueue_cmd.add_argument("params", help="JSON string with parameters")

    sub.add_parser("list", help="List tasks")

    fetch_cmd = sub.add_parser("next", help="Fetch next task")
    fetch_cmd.add_argument("--tool")

    update_cmd = sub.add_parser("update", help="Update task status")
    update_cmd.add_argument("task_id", type=int)
    update_cmd.add_argument("status")
    update_cmd.add_argument("result", nargs="?", help="JSON result payload")

    args = parser.parse_args(argv)
    if args.cmd == "enqueue":
        params = json.loads(args.params)
        task_id = enqueue_task(args.tool, args.target, params)
        print(f"Enqueued task {task_id}")
    elif args.cmd == "list":
        list_tasks()
    elif args.cmd == "next":
        task = fetch_next_task(args.tool)
        print(task or "No pending tasks")
    elif args.cmd == "update":
        result = json.loads(args.result) if args.result else None
        update_task_status(args.task_id, args.status, result)
        print("Task updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
