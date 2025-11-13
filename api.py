"""FastAPI backend for GooseStrike."""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Generator, Iterable, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.requests import Request

from mitre_mapping import MitreSuggestion, generate_attack_suggestions
import task_queue

CORE_SNAPSHOT_DATA = {
    "title": "GooseStrike Core (Docker-ready)",
    "bullets": [
        "🔧 Nmap, Metasploit, SQLMap, Hydra, ZAP",
        "🧠 AI exploit assistant (Claude, HackGPT-ready)",
        "📚 Offline CVE mirroring with update_cve.sh",
        "🗂 ASCII banner, logo, branding kit (PDF)",
        "📜 CVE scan + JSON match script",
    ],
    "downloads": [
        "📦 goosestrike-cve-enabled.zip (download link)",
        "🧠 hackgpt-ai-stack.zip with README + architecture",
    ],
}

ROADMAP_DATA = [
    {"task": "🐳 Build `docker-compose.goosestrike-full.yml`", "status": "⏳ In progress"},
    {"task": "🧠 HackGPT API container (linked to n8n)", "status": "⏳ Next up"},
    {"task": "🌐 Local CVE API server", "status": "Pending"},
    {"task": "🧬 Claude + HackGPT fallback system", "status": "Pending"},
    {"task": "🔄 n8n workflow `.json` import", "status": "Pending"},
    {"task": "🎯 Target \"prioritizer\" AI agent", "status": "Pending"},
    {"task": "🧭 SVG architecture diagram", "status": "Pending"},
    {"task": "🖥 Dashboard frontend (Armitage-style)", "status": "Optional"},
    {"task": "🔐 C2 bridging to Mythic/Sliver", "status": "Optional"},
]

DB_PATH = Path("db/goosestrike.db")
EXPLOIT_DB_PATH = Path("db/exploits.db")
STATIC_DIR = Path("web/static")
UPLOAD_DIR = STATIC_DIR / "uploads"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def _resolve_logo_url() -> str:
    """Return the logo URL supplied by the user or fall back to the crest."""

    env_logo = os.getenv("GOOSESTRIKE_LOGO")
    if env_logo:
        return env_logo

    valid_exts = {".svg", ".png", ".jpg", ".jpeg", ".webp"}
    candidates: List[Path] = []
    if UPLOAD_DIR.exists():
        for candidate in UPLOAD_DIR.iterdir():
            if candidate.is_file() and candidate.suffix.lower() in valid_exts:
                candidates.append(candidate)

    if candidates:
        # Prefer the most recently touched file so new uploads override defaults.
        candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        chosen = candidates[0]
        relative = chosen.relative_to(STATIC_DIR)
        return f"/static/{relative.as_posix()}"

    default_logo = STATIC_DIR / "uploads" / "official_goosestrike_logo.svg"
    if default_logo.exists():
        relative = default_logo.relative_to(STATIC_DIR)
        return f"/static/{relative.as_posix()}"

    return "/static/goose_flag_logo.svg"

app = FastAPI(title="GooseStrike API", version="0.1.0")
app.mount("/static", StaticFiles(directory="web/static"), name="static")
templates = Jinja2Templates(directory="web/templates")
app.state.logo_url = _resolve_logo_url()


def dict_factory(cursor, row):
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


@contextmanager
def get_db(db_path: Optional[Path] = None) -> Generator[sqlite3.Connection, None, None]:
    path = db_path or DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = dict_factory
    try:
        yield conn
    finally:
        conn.close()


def initialize_db() -> None:
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                hostname TEXT,
                mac_address TEXT,
                mac_vendor TEXT
            );
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                proto TEXT NOT NULL,
                product TEXT,
                version TEXT,
                extra_json TEXT,
                UNIQUE(asset_id, port, proto),
                FOREIGN KEY(asset_id) REFERENCES assets(id)
            );
            CREATE TABLE IF NOT EXISTS service_cves (
                service_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                PRIMARY KEY(service_id, cve_id),
                FOREIGN KEY(service_id) REFERENCES services(id)
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                scan_uuid TEXT,
                scanner TEXT,
                mode TEXT,
                started_at TEXT,
                completed_at TEXT,
                notes TEXT,
                raw_payload TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(asset_id) REFERENCES assets(id)
            );
            CREATE TABLE IF NOT EXISTS scan_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_run_id INTEGER NOT NULL,
                port INTEGER,
                proto TEXT,
                product TEXT,
                version TEXT,
                extra_json TEXT,
                cves_json TEXT,
                FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id)
            );
            CREATE TABLE IF NOT EXISTS attack_suggestions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                scan_run_id INTEGER,
                technique_id TEXT NOT NULL,
                tactic TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                related_cve TEXT,
                severity TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(asset_id) REFERENCES assets(id),
                FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id)
            );
            """
        )
        _ensure_column(conn, "assets", "mac_address", "TEXT")
        _ensure_column(conn, "assets", "mac_vendor", "TEXT")
        conn.commit()


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


class ServiceIn(BaseModel):
    port: int
    proto: str = Field(..., regex=r"^[a-z0-9]+$")
    product: Optional[str] = None
    version: Optional[str] = None
    extra: dict = Field(default_factory=dict)
    cves: List[str] = Field(default_factory=list)


class ScanMetaIn(BaseModel):
    scan_id: Optional[str] = None
    scanner: Optional[str] = None
    mode: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    notes: Optional[str] = None


class ScanIn(BaseModel):
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = Field(default=None, regex=r"^[0-9A-Fa-f:]{12,17}$")
    mac_vendor: Optional[str] = None
    scan: ScanMetaIn = Field(default_factory=ScanMetaIn)
    services: List[ServiceIn]


class VulnerabilityOut(BaseModel):
    cve_id: str
    description: Optional[str]
    severity: Optional[str]
    score: Optional[float]


class ServiceOut(BaseModel):
    id: int
    port: int
    proto: str
    product: Optional[str]
    version: Optional[str]
    extra: dict
    cves: List[str]
    vulnerabilities: List[VulnerabilityOut]


class AssetOut(BaseModel):
    id: int
    ip: str
    hostname: Optional[str]
    mac_address: Optional[str]
    mac_vendor: Optional[str]
    services: List[ServiceOut]


class ScanServiceOut(BaseModel):
    port: int
    proto: str
    product: Optional[str]
    version: Optional[str]
    extra: dict
    cves: List[str]


class ScanRunOut(BaseModel):
    id: int
    asset_id: int
    asset_ip: str
    scan_id: Optional[str]
    scanner: Optional[str]
    mode: Optional[str]
    started_at: Optional[str]
    completed_at: Optional[str]
    created_at: str
    notes: Optional[str]
    services: List[ScanServiceOut]


class CoreSnapshotOut(BaseModel):
    title: str
    bullets: List[str]
    downloads: List[str]


class RoadmapItemOut(BaseModel):
    task: str
    status: str


class TaskCreateIn(BaseModel):
    tool: str = Field(..., description="Runner to execute (sqlmap, hashcat, etc.)")
    target: Optional[str] = Field(default=None, description="Human-friendly target reference")
    params: dict = Field(default_factory=dict, description="Tool-specific parameters")


class TaskOut(BaseModel):
    id: int
    tool: str
    target: Optional[str]
    params: dict
    status: str
    created_at: str
    started_at: Optional[str]
    finished_at: Optional[str]
    result: Optional[dict]


class TaskStatusUpdateIn(BaseModel):
    status: str
    result: Optional[dict] = None


class AttackSuggestionOut(BaseModel):
    id: int
    asset_id: int
    asset_ip: str
    scan_run_id: Optional[int]
    technique_id: str
    tactic: str
    name: str
    description: str
    related_cve: Optional[str]
    severity: Optional[str]
    created_at: str


class AlertOut(BaseModel):
    source: str
    payload: dict
    created_at: str


class MockDashboardOut(BaseModel):
    core_snapshot: CoreSnapshotOut
    roadmap: List[RoadmapItemOut]
    assets: List[AssetOut]
    scans: List[ScanRunOut]
    attack_suggestions: List[AttackSuggestionOut]
    tasks: List[TaskOut]
    alerts: List[AlertOut]


@app.on_event("startup")
async def startup_event() -> None:
    initialize_db()
    task_queue.ensure_tables()


def upsert_asset(conn: sqlite3.Connection, scan: ScanIn) -> int:
    conn.execute(
        "INSERT INTO assets(ip, hostname) VALUES(?, ?) ON CONFLICT(ip) DO UPDATE SET hostname=excluded.hostname",
        (scan.ip, scan.hostname),
    )
    conn.execute(
        "UPDATE assets SET mac_address=COALESCE(?, mac_address), mac_vendor=COALESCE(?, mac_vendor) WHERE ip=?",
        (scan.mac_address, scan.mac_vendor, scan.ip),
    )
    row = conn.execute("SELECT id FROM assets WHERE ip=?", (scan.ip,)).fetchone()
    return row["id"]


def upsert_service(conn: sqlite3.Connection, asset_id: int, service: ServiceIn) -> int:
    conn.execute(
        """
        INSERT INTO services(asset_id, port, proto, product, version, extra_json)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(asset_id, port, proto) DO UPDATE SET
            product=excluded.product,
            version=excluded.version,
            extra_json=excluded.extra_json
        """,
        (
            asset_id,
            service.port,
            service.proto,
            service.product,
            service.version,
            json.dumps(service.extra),
        ),
    )
    row = conn.execute(
        "SELECT id FROM services WHERE asset_id=? AND port=? AND proto=?",
        (asset_id, service.port, service.proto),
    ).fetchone()
    service_id = row["id"]
    conn.execute("DELETE FROM service_cves WHERE service_id=?", (service_id,))
    for cve_id in service.cves:
        conn.execute(
            "INSERT INTO service_cves(service_id, cve_id) VALUES(?, ?)",
            (service_id, cve_id),
        )
    return service_id


def record_scan_run(conn: sqlite3.Connection, asset_id: int, payload: ScanIn) -> int:
    scan_meta = payload.scan or ScanMetaIn()
    scan_uuid = scan_meta.scan_id or str(uuid.uuid4())
    cursor = conn.execute(
        """
        INSERT INTO scan_runs(asset_id, scan_uuid, scanner, mode, started_at, completed_at, notes, raw_payload)
        VALUES(?,?,?,?,?,?,?,?)
        """,
        (
            asset_id,
            scan_uuid,
            scan_meta.scanner,
            scan_meta.mode,
            scan_meta.started_at,
            scan_meta.completed_at,
            scan_meta.notes,
            json.dumps(payload.dict()),
        ),
    )
    scan_run_id = cursor.lastrowid
    for service in payload.services:
        conn.execute(
            """
            INSERT INTO scan_services(scan_run_id, port, proto, product, version, extra_json, cves_json)
            VALUES(?,?,?,?,?,?,?)
            """,
            (
                scan_run_id,
                service.port,
                service.proto,
                service.product,
                service.version,
                json.dumps(service.extra),
                json.dumps(service.cves),
            ),
        )
    return scan_run_id


def store_attack_suggestions(conn: sqlite3.Connection, asset_id: int, scan_run_id: int, payload: ScanIn) -> None:
    conn.execute(
        "DELETE FROM attack_suggestions WHERE asset_id=? AND scan_run_id=?",
        (asset_id, scan_run_id),
    )
    suggestions: List[MitreSuggestion] = generate_attack_suggestions(payload.ip, payload.services)
    for suggestion in suggestions:
        conn.execute(
            """
            INSERT INTO attack_suggestions(asset_id, scan_run_id, technique_id, tactic, name, description, related_cve, severity)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                asset_id,
                scan_run_id,
                suggestion.technique_id,
                suggestion.tactic,
                suggestion.name,
                suggestion.description,
                suggestion.related_cve,
                suggestion.severity,
            ),
        )


@app.post("/ingest/scan", response_model=AssetOut)
async def ingest_scan(payload: ScanIn) -> AssetOut:
    with get_db() as conn:
        asset_id = upsert_asset(conn, payload)
        services_out: List[ServiceOut] = []
        for service in payload.services:
            service_id = upsert_service(conn, asset_id, service)
            services_out.append(
                ServiceOut(
                    id=service_id,
                    port=service.port,
                    proto=service.proto,
                    product=service.product,
                    version=service.version,
                    extra=service.extra,
                    cves=service.cves,
                    vulnerabilities=_build_vulnerabilities(service.cves),
                )
            )
        scan_run_id = record_scan_run(conn, asset_id, payload)
        store_attack_suggestions(conn, asset_id, scan_run_id, payload)
        conn.commit()
        return AssetOut(
            id=asset_id,
            ip=payload.ip,
            hostname=payload.hostname,
            mac_address=payload.mac_address,
            mac_vendor=payload.mac_vendor,
            services=services_out,
        )


def _build_vulnerabilities(cve_ids: Iterable[str]) -> List[VulnerabilityOut]:
    details = fetch_cve_details(list(cve_ids))
    return [
        VulnerabilityOut(
            cve_id=cve_id,
            description=info.get("description"),
            severity=info.get("severity"),
            score=info.get("score"),
        )
        for cve_id, info in details.items()
    ]


def fetch_cve_details(cve_ids: List[str]) -> Dict[str, Dict[str, Optional[str]]]:
    if not cve_ids or not EXPLOIT_DB_PATH.exists():
        return {cve_id: {"description": None, "severity": None, "score": None} for cve_id in cve_ids}
    placeholders = ",".join("?" for _ in cve_ids)
    conn = sqlite3.connect(EXPLOIT_DB_PATH)
    conn.row_factory = dict_factory
    try:
        rows = conn.execute(
            f"SELECT cve_id, description, severity, score FROM cves WHERE cve_id IN ({placeholders})",
            cve_ids,
        ).fetchall()
    finally:
        conn.close()
    lookup = {row["cve_id"]: row for row in rows}
    return {
        cve_id: lookup.get(cve_id, {"description": None, "severity": None, "score": None})
        for cve_id in cve_ids
    }


def build_asset(conn: sqlite3.Connection, asset_row: dict) -> AssetOut:
    services = conn.execute(
        "SELECT * FROM services WHERE asset_id=? ORDER BY port",
        (asset_row["id"],),
    ).fetchall()
    service_models: List[ServiceOut] = []
    all_cves: List[str] = []
    for service in services:
        cves = [row["cve_id"] for row in conn.execute(
            "SELECT cve_id FROM service_cves WHERE service_id=?",
            (service["id"],),
        ).fetchall()]
        all_cves.extend(cves)
    cve_details = fetch_cve_details(all_cves)
    for service in services:
        cves = [row["cve_id"] for row in conn.execute(
            "SELECT cve_id FROM service_cves WHERE service_id=?",
            (service["id"],),
        ).fetchall()]
        service_models.append(
            ServiceOut(
                id=service["id"],
                port=service["port"],
                proto=service["proto"],
                product=service["product"],
                version=service["version"],
                extra=json.loads(service["extra_json"] or "{}"),
                cves=cves,
                vulnerabilities=[
                    VulnerabilityOut(
                        cve_id=cve,
                        description=cve_details[cve]["description"],
                        severity=cve_details[cve]["severity"],
                        score=cve_details[cve]["score"],
                    )
                    for cve in cves
                ],
            )
        )
    return AssetOut(
        id=asset_row["id"],
        ip=asset_row["ip"],
        hostname=asset_row["hostname"],
        mac_address=asset_row.get("mac_address"),
        mac_vendor=asset_row.get("mac_vendor"),
        services=service_models,
    )


@app.get("/assets", response_model=List[AssetOut])
async def list_assets() -> List[AssetOut]:
    with get_db() as conn:
        assets = conn.execute("SELECT * FROM assets ORDER BY ip").fetchall()
        return [build_asset(conn, asset) for asset in assets]


@app.get("/assets/{asset_id}", response_model=AssetOut)
async def get_asset(asset_id: int) -> AssetOut:
    with get_db() as conn:
        asset = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        return build_asset(conn, asset)


class CVEOut(BaseModel):
    cve_id: str
    description: Optional[str]
    severity: Optional[str]
    score: Optional[float]
    exploits: List[dict]


@app.get("/cve/{cve_id}", response_model=CVEOut)
async def get_cve(cve_id: str) -> CVEOut:
    if not EXPLOIT_DB_PATH.exists():
        raise HTTPException(status_code=404, detail="CVE database not initialized")
    conn = sqlite3.connect(EXPLOIT_DB_PATH)
    conn.row_factory = dict_factory
    try:
        cve = conn.execute("SELECT * FROM cves WHERE cve_id=?", (cve_id,)).fetchone()
        if not cve:
            raise HTTPException(status_code=404, detail="CVE not found")
        exploits = conn.execute(
            "SELECT source, title, reference, path FROM exploits WHERE cve_id=?",
            (cve_id,),
        ).fetchall()
        return CVEOut(
            cve_id=cve_id,
            description=cve.get("description"),
            severity=cve.get("severity"),
            score=cve.get("score"),
            exploits=exploits,
        )
    finally:
        conn.close()


@app.get("/bycve/{cve_id}/hosts", response_model=List[AssetOut])
async def hosts_by_cve(cve_id: str) -> List[AssetOut]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT assets.* FROM assets
            JOIN services ON services.asset_id = assets.id
            JOIN service_cves ON service_cves.service_id = services.id
            WHERE service_cves.cve_id = ?
            """,
            (cve_id,),
        ).fetchall()
        return [build_asset(conn, row) for row in rows]


class AlertIn(BaseModel):
    source: str
    payload: dict


@app.post("/webhook/n8n/scan_complete")
async def webhook_scan_complete(alert: AlertIn) -> dict:
    with get_db() as conn:
        conn.execute(
            "INSERT INTO alerts(source, payload_json) VALUES(?, ?)",
            (alert.source, json.dumps(alert.payload)),
        )
        conn.commit()
    return {"ok": True}


class CVEAlertIn(BaseModel):
    cve_id: str
    critical: bool = False


@app.post("/webhook/n8n/new_cve")
async def webhook_new_cve(alert: CVEAlertIn) -> dict:
    with get_db() as conn:
        conn.execute(
            "INSERT INTO alerts(source, payload_json) VALUES(?, ?)",
            (
                "n8n:new_cve",
                json.dumps({"cve_id": alert.cve_id, "critical": alert.critical}),
            ),
        )
        conn.commit()
    return {"ok": True}


def _row_to_task(row: sqlite3.Row) -> TaskOut:
    data = dict(row)
    return TaskOut(
        id=data["id"],
        tool=data["tool"],
        target=data.get("target"),
        params=json.loads(data.get("params_json") or "{}"),
        status=data["status"],
        created_at=data["created_at"],
        started_at=data.get("started_at"),
        finished_at=data.get("finished_at"),
        result=json.loads(data.get("result_json") or "null") if data.get("result_json") else None,
    )


@app.get("/tasks", response_model=List[TaskOut])
async def list_tasks_endpoint() -> List[TaskOut]:
    task_queue.ensure_tables()
    with task_queue.get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM tasks ORDER BY created_at DESC, id DESC LIMIT 200"
        ).fetchall()
        return [_row_to_task(row) for row in rows]


@app.get("/tasks/{task_id}", response_model=TaskOut)
async def get_task(task_id: int) -> TaskOut:
    task_queue.ensure_tables()
    with task_queue.get_conn() as conn:
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Task not found")
        return _row_to_task(row)


@app.post("/tasks", response_model=TaskOut, status_code=201)
async def create_task(task: TaskCreateIn) -> TaskOut:
    task_queue.ensure_tables()
    task_id = task_queue.enqueue_task(task.tool, task.target, task.params)
    with task_queue.get_conn() as conn:
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        return _row_to_task(row)


@app.post("/tasks/{task_id}/status", response_model=TaskOut)
async def update_task_status_endpoint(task_id: int, payload: TaskStatusUpdateIn) -> TaskOut:
    task_queue.ensure_tables()
    task_queue.update_task_status(task_id, payload.status, payload.result)
    with task_queue.get_conn() as conn:
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Task not found")
        return _row_to_task(row)


@app.get("/", response_class=HTMLResponse)
async def ui(request: Request):
    resolved_logo = getattr(app.state, "logo_url", "/static/goose_flag_logo.svg")
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "logo_url": resolved_logo,
            "spotlight_logo_url": resolved_logo,
        },
    )


@app.get("/core_snapshot", response_model=CoreSnapshotOut)
async def core_snapshot() -> CoreSnapshotOut:
    return CoreSnapshotOut(**CORE_SNAPSHOT_DATA)


@app.get("/roadmap", response_model=List[RoadmapItemOut])
async def roadmap() -> List[RoadmapItemOut]:
    return [RoadmapItemOut(**item) for item in ROADMAP_DATA]


@app.get("/mock/dashboard-data", response_model=MockDashboardOut)
async def mock_dashboard_data() -> MockDashboardOut:
    return build_mock_dashboard_data()


@app.get("/mockup", response_class=HTMLResponse)
async def mock_dashboard(request: Request):
    resolved_logo = getattr(app.state, "logo_url", "/static/goose_flag_logo.svg")
    mock_payload = build_mock_dashboard_data()
    return templates.TemplateResponse(
        "mock_dashboard.html",
        {
            "request": request,
            "logo_url": resolved_logo,
            "spotlight_logo_url": resolved_logo,
            "mock": mock_payload.dict(),
        },
    )


def build_scan_run(conn: sqlite3.Connection, row: dict) -> ScanRunOut:
    services = conn.execute(
        "SELECT * FROM scan_services WHERE scan_run_id=? ORDER BY port",
        (row["id"],),
    ).fetchall()
    return ScanRunOut(
        id=row["id"],
        asset_id=row["asset_id"],
        asset_ip=row["asset_ip"],
        scan_id=row.get("scan_uuid"),
        scanner=row.get("scanner"),
        mode=row.get("mode"),
        started_at=row.get("started_at"),
        completed_at=row.get("completed_at"),
        created_at=row.get("created_at"),
        notes=row.get("notes"),
        services=[
            ScanServiceOut(
                port=svc.get("port"),
                proto=svc.get("proto"),
                product=svc.get("product"),
                version=svc.get("version"),
                extra=json.loads(svc.get("extra_json") or "{}"),
                cves=json.loads(svc.get("cves_json") or "[]"),
            )
            for svc in services
        ],
    )


@app.get("/scans", response_model=List[ScanRunOut])
async def list_scans() -> List[ScanRunOut]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT scan_runs.*, assets.ip AS asset_ip FROM scan_runs
            JOIN assets ON assets.id = scan_runs.asset_id
            ORDER BY scan_runs.created_at DESC
            LIMIT 200
            """
        ).fetchall()
        return [build_scan_run(conn, row) for row in rows]


@app.get("/scans/{scan_run_id}", response_model=ScanRunOut)
async def get_scan(scan_run_id: int) -> ScanRunOut:
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT scan_runs.*, assets.ip AS asset_ip FROM scan_runs
            JOIN assets ON assets.id = scan_runs.asset_id
            WHERE scan_runs.id = ?
            """,
            (scan_run_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")
        return build_scan_run(conn, row)


def _build_attack_response(rows: List[dict]) -> List[AttackSuggestionOut]:
    return [
        AttackSuggestionOut(
            id=row["id"],
            asset_id=row["asset_id"],
            asset_ip=row["asset_ip"],
            scan_run_id=row.get("scan_run_id"),
            technique_id=row["technique_id"],
            tactic=row["tactic"],
            name=row["name"],
            description=row["description"],
            related_cve=row.get("related_cve"),
            severity=row.get("severity"),
            created_at=row.get("created_at"),
        )
        for row in rows
    ]


@app.get("/attack_suggestions", response_model=List[AttackSuggestionOut])
async def attack_suggestions() -> List[AttackSuggestionOut]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT attack_suggestions.*, assets.ip AS asset_ip FROM attack_suggestions
            JOIN assets ON assets.id = attack_suggestions.asset_id
            ORDER BY attack_suggestions.created_at DESC
            LIMIT 200
            """
        ).fetchall()
        return _build_attack_response(rows)


def build_mock_dashboard_data() -> MockDashboardOut:
    core_snapshot = CoreSnapshotOut(**CORE_SNAPSHOT_DATA)
    roadmap = [RoadmapItemOut(**item) for item in ROADMAP_DATA]
    assets = [
        AssetOut(
            id=1,
            ip="10.0.0.21",
            hostname="web-canary",
            mac_address="00:25:90:ab:cd:ef",
            mac_vendor="Northern Goose Labs",
            services=[
                ServiceOut(
                    id=1,
                    port=80,
                    proto="tcp",
                    product="nginx",
                    version="1.23.4",
                    extra={"transport": "tcp", "state": "open"},
                    cves=["CVE-2023-3124", "CVE-2022-3554"],
                    vulnerabilities=[
                        VulnerabilityOut(
                            cve_id="CVE-2023-3124",
                            description="Sample HTTP/2 request smuggling bug",
                            severity="High",
                            score=8.1,
                        ),
                        VulnerabilityOut(
                            cve_id="CVE-2022-3554",
                            description="Sample OpenSSL leak",
                            severity="Medium",
                            score=6.5,
                        ),
                    ],
                ),
                ServiceOut(
                    id=2,
                    port=443,
                    proto="tcp",
                    product="Envoy",
                    version="1.26",
                    extra={"alpn": "h2"},
                    cves=["CVE-2024-1234"],
                    vulnerabilities=[
                        VulnerabilityOut(
                            cve_id="CVE-2024-1234",
                            description="Sample TLS parsing issue",
                            severity="Critical",
                            score=9.4,
                        )
                    ],
                ),
            ],
        ),
        AssetOut(
            id=2,
            ip="10.0.0.45",
            hostname="db-honker",
            mac_address="58:8a:5a:01:23:45",
            mac_vendor="Canada Goose Compute",
            services=[
                ServiceOut(
                    id=3,
                    port=5432,
                    proto="tcp",
                    product="PostgreSQL",
                    version="14.9",
                    extra={"cluster": "atlas"},
                    cves=["CVE-2023-2454"],
                    vulnerabilities=[
                        VulnerabilityOut(
                            cve_id="CVE-2023-2454",
                            description="Sample privilege escalation",
                            severity="High",
                            score=8.5,
                        )
                    ],
                )
            ],
        ),
    ]

    scans = [
        ScanRunOut(
            id=501,
            asset_id=1,
            asset_ip="10.0.0.21",
            scan_id="mock-fast-001",
            scanner="GooseStrike",
            mode="fast",
            started_at="2024-02-07T12:00:00Z",
            completed_at="2024-02-07T12:05:00Z",
            created_at="2024-02-07T12:05:01Z",
            notes="Sample lab scan",
            services=[
                ScanServiceOut(
                    port=80,
                    proto="tcp",
                    product="nginx",
                    version="1.23.4",
                    extra={"transport": "tcp"},
                    cves=["CVE-2023-3124", "CVE-2022-3554"],
                ),
                ScanServiceOut(
                    port=443,
                    proto="tcp",
                    product="Envoy",
                    version="1.26",
                    extra={"alpn": "h2"},
                    cves=["CVE-2024-1234"],
                ),
            ],
        ),
        ScanRunOut(
            id=502,
            asset_id=2,
            asset_ip="10.0.0.45",
            scan_id="mock-full-001",
            scanner="GooseStrike",
            mode="full",
            started_at="2024-02-05T09:00:00Z",
            completed_at="2024-02-05T10:00:00Z",
            created_at="2024-02-05T10:00:02Z",
            notes="Baseline DB review",
            services=[
                ScanServiceOut(
                    port=5432,
                    proto="tcp",
                    product="PostgreSQL",
                    version="14.9",
                    extra={"ssl": "enabled"},
                    cves=["CVE-2023-2454"],
                ),
                ScanServiceOut(
                    port=22,
                    proto="tcp",
                    product="OpenSSH",
                    version="8.9",
                    extra={"auth": "password"},
                    cves=["CVE-2023-38408"],
                ),
            ],
        ),
    ]

    attack_suggestions = [
        AttackSuggestionOut(
            id=1,
            asset_id=1,
            asset_ip="10.0.0.21",
            scan_run_id=501,
            technique_id="T1190",
            tactic="Initial Access",
            name="Exploit Public-Facing Application",
            description="Use SQLMap or Burp to validate CVE-2023-3124",
            related_cve="CVE-2023-3124",
            severity="High",
            created_at="2024-02-07T12:05:03Z",
        ),
        AttackSuggestionOut(
            id=2,
            asset_id=2,
            asset_ip="10.0.0.45",
            scan_run_id=502,
            technique_id="T1059",
            tactic="Execution",
            name="Command Shell",
            description="Use Metasploit postgres payload to leverage CVE-2023-2454",
            related_cve="CVE-2023-2454",
            severity="Medium",
            created_at="2024-02-05T10:00:03Z",
        ),
    ]

    tasks = [
        TaskOut(
            id=88,
            tool="sqlmap",
            target="https://web-canary/login",
            params={"risk": 1, "level": 3},
            status="pending",
            created_at="2024-02-07T12:06:00Z",
            started_at=None,
            finished_at=None,
            result=None,
        ),
        TaskOut(
            id=89,
            tool="hashcat",
            target="lab-hashes",
            params={"hash_file": "hashes.txt", "wordlist": "rockyou.txt", "mode": 0},
            status="running",
            created_at="2024-02-07T12:06:15Z",
            started_at="2024-02-07T12:06:20Z",
            finished_at=None,
            result=None,
        ),
    ]

    alerts = [
        AlertOut(
            source="n8n:new_cve",
            payload={"cve_id": "CVE-2024-1234", "critical": True},
            created_at="2024-02-07T12:07:00Z",
        ),
        AlertOut(
            source="n8n:scan_complete",
            payload={"scan_id": "mock-fast-001", "status": "ok"},
            created_at="2024-02-07T12:05:05Z",
        ),
    ]

    return MockDashboardOut(
        core_snapshot=core_snapshot,
        roadmap=roadmap,
        assets=assets,
        scans=scans,
        attack_suggestions=attack_suggestions,
        tasks=tasks,
        alerts=alerts,
    )


@app.get("/assets/{asset_id}/attack_suggestions", response_model=List[AttackSuggestionOut])
async def asset_attack_suggestions(asset_id: int) -> List[AttackSuggestionOut]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT attack_suggestions.*, assets.ip AS asset_ip FROM attack_suggestions
            JOIN assets ON assets.id = attack_suggestions.asset_id
            WHERE assets.id = ?
            ORDER BY attack_suggestions.created_at DESC
            """,
            (asset_id,),
        ).fetchall()
        return _build_attack_response(rows)
