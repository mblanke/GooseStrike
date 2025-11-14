"""Standalone FastAPI service exposing the CVE/exploit mirror."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

DB_PATH = Path("db/exploits.db")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="GooseStrike CVE API", version="0.1.0")


class CVEEntry(BaseModel):
    cve_id: str
    description: Optional[str]
    severity: Optional[str]
    score: Optional[float]
    exploits: List[dict]


class CVESearchResult(BaseModel):
    results: List[CVEEntry]


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.get("/cve/{cve_id}", response_model=CVEEntry)
async def fetch_cve(cve_id: str) -> CVEEntry:
    if not DB_PATH.exists():
        raise HTTPException(status_code=404, detail="CVE database missing")
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM cves WHERE cve_id=?", (cve_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="CVE not found")
        exploits = conn.execute(
            "SELECT source, title, reference, path FROM exploits WHERE cve_id=?", (cve_id,)
        ).fetchall()
        return CVEEntry(
            cve_id=row["cve_id"],
            description=row["description"],
            severity=row["severity"],
            score=row["score"],
            exploits=[dict(exp) for exp in exploits],
        )


@app.get("/search", response_model=CVESearchResult)
async def search_cves(q: str) -> CVESearchResult:
    if not DB_PATH.exists():
        return CVESearchResult(results=[])
    like = f"%{q}%"
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM cves WHERE cve_id LIKE ? OR description LIKE ? LIMIT 25",
            (like, like),
        ).fetchall()
        entries = []
        for row in rows:
            exploits = conn.execute(
                "SELECT source, title, reference, path FROM exploits WHERE cve_id=?",
                (row["cve_id"],),
            ).fetchall()
            entries.append(
                CVEEntry(
                    cve_id=row["cve_id"],
                    description=row["description"],
                    severity=row["severity"],
                    score=row["score"],
                    exploits=[dict(exp) for exp in exploits],
                )
            )
        return CVESearchResult(results=entries)


@app.get("/health")
async def health() -> dict:
    return {"ok": True, "ready": DB_PATH.exists()}
