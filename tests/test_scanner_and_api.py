from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import api
import scanner
from app.agents import llm_router


NMAP_XML = """<?xml version='1.0'?>
<nmaprun startstr="2024-01-01 10:00 UTC">
  <host>
    <status state="up" />
    <address addr="192.168.1.10" addrtype="ipv4" />
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="TestVendor" />
    <hostnames>
      <hostname name="web" />
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="Apache httpd" version="2.4.57" />
      </port>
    </ports>
  </host>
  <runstats>
    <finished timestr="2024-01-01 10:01 UTC" />
  </runstats>
</nmaprun>
"""


def test_parse_nmap_xml():
    hosts, started, finished = scanner.parse_nmap_xml(NMAP_XML)
    assert len(hosts) == 1
    assert hosts[0].ip == "192.168.1.10"
    assert hosts[0].mac_address == "00:11:22:33:44:55"
    assert hosts[0].services[0].port == 80
    assert started.startswith("2024")
    assert finished.endswith("UTC")


def test_scanner_main_monkeypatched(monkeypatch):
    class DummyProcess:
        def __init__(self, stdout: str):
            self.stdout = stdout
            self.stderr = ""
            self.returncode = 0

    captured: dict[str, Any] = {}

    def fake_run(cmd: Any, check: bool, stdout, stderr, text):  # pylint: disable=unused-argument
        captured["cmd"] = cmd
        return DummyProcess(NMAP_XML)

    monkeypatch.setattr(scanner, "subprocess", type("S", (), {"run": staticmethod(fake_run)}))
    exit_code = scanner.main(
        ["192.168.1.0/24", "--no-upload", "--nmap-args", "-Pn --script vuln"]
    )
    assert exit_code == 0
    assert "-Pn" in captured["cmd"]
    assert "--script" in captured["cmd"]


def test_build_nmap_command_accepts_custom_args():
    cmd = scanner.build_nmap_command(
        "10.0.0.0/24", "standard", None, ["-Pn", "--script", "vuln"]
    )
    assert cmd[0] == "nmap"
    assert cmd[-1] == "10.0.0.0/24"
    assert cmd[1:4] == ["-Pn", "--script", "vuln"]


@pytest.fixture()
def temp_db(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "api.db"
    exploit_db = tmp_path / "exploits.db"
    tasks_db = tmp_path / "tasks.db"
    monkeypatch.setattr(api, "DB_PATH", db_path)
    monkeypatch.setattr(api, "EXPLOIT_DB_PATH", exploit_db)
    monkeypatch.setattr(api.task_queue, "DB_PATH", tasks_db)
    api.initialize_db()
    api.task_queue.ensure_tables()
    conn = sqlite3.connect(exploit_db)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cves (cve_id TEXT PRIMARY KEY, description TEXT, severity TEXT, score REAL)"
    )
    conn.execute(
        "INSERT OR REPLACE INTO cves(cve_id, description, severity, score) VALUES(?,?,?,?)",
        ("CVE-2023-12345", "Test vuln", "HIGH", 8.8),
    )
    conn.close()
    return db_path


def test_ingest_and_list_assets(temp_db):
    client = TestClient(api.app)
    payload = {
        "ip": "192.168.1.10",
        "hostname": "web",
        "mac_address": "00:11:22:33:44:55",
        "mac_vendor": "TestVendor",
        "scan": {"scan_id": "unit-test-scan", "scanner": "pytest", "mode": "fast"},
        "services": [
            {
                "port": 80,
                "proto": "tcp",
                "product": "Apache",
                "version": "2.4.57",
                "extra": {"name": "http"},
                "cves": ["CVE-2023-12345"],
            }
        ],
    }
    response = client.post("/ingest/scan", json=payload)
    assert response.status_code == 200
    asset = response.json()
    assert asset["mac_address"] == "00:11:22:33:44:55"

    list_response = client.get("/assets")
    assert list_response.status_code == 200
    assets = list_response.json()
    assert assets[0]["services"][0]["cves"] == ["CVE-2023-12345"]
    vuln = assets[0]["services"][0]["vulnerabilities"][0]
    assert vuln["severity"] == "HIGH"

    conn = sqlite3.connect(temp_db)
    rows = conn.execute("SELECT COUNT(*) FROM services").fetchone()[0]
    assert rows == 1
    scan_runs = conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0]
    assert scan_runs == 1
    conn.close()

    scans = client.get("/scans").json()
    assert scans[0]["scan_id"] == "unit-test-scan"

    suggestions = client.get("/attack_suggestions").json()
    assert any(item["technique_id"] == "T1068" for item in suggestions)


def test_task_queue_endpoints(temp_db):
    client = TestClient(api.app)
    response = client.post(
        "/tasks",
        json={
            "tool": "password_cracker",
            "target": "lab-hashes",
            "params": {"hash_file": "hashes.txt", "wordlist": "rockyou.txt"},
        },
    )
    assert response.status_code == 201
    task = response.json()
    assert task["tool"] == "password_cracker"

    list_response = client.get("/tasks")
    assert list_response.status_code == 200
    tasks = list_response.json()
    assert len(tasks) == 1
    assert tasks[0]["target"] == "lab-hashes"

    update_response = client.post(
        f"/tasks/{task['id']}/status",
        json={"status": "completed", "result": {"exit_code": 0}},
    )
    assert update_response.status_code == 200
    assert update_response.json()["status"] == "completed"


def test_n8n_workflow_import_and_list(temp_db):
    client = TestClient(api.app)
    payload = {"name": "demo-workflow", "workflow": {"nodes": ["scan", "alert"]}}
    response = client.post("/n8n/workflows/import", json=payload)
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "demo-workflow"
    listing = client.get("/n8n/workflows")
    assert listing.status_code == 200
    assert listing.json()[0]["name"] == "demo-workflow"


def test_armitage_data_endpoint_returns_graph(temp_db):
    client = TestClient(api.app)
    data = client.get("/armitage/data").json()
    assert "nodes" in data and "edges" in data
    assert any(node["type"] == "asset" for node in data["nodes"])


def test_n8n_integration_test_endpoint(temp_db, monkeypatch):
    client = TestClient(api.app)

    class DummyResponse:
        ok = True
        status_code = 200
        headers = {"content-type": "application/json"}

        def json(self):
            return {"echo": True}

        text = ""

    captured = {}

    def fake_post(url, json=None, timeout=None):  # pylint: disable=redefined-outer-name
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return DummyResponse()

    monkeypatch.setattr(api.requests, "post", fake_post)

    response = client.post(
        "/integrations/test/n8n",
        json={"url": "https://n8n.example/webhook", "payload": {"hello": "world"}, "timeout": 5},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert captured["json"]["hello"] == "world"
    assert captured["timeout"] == 5


def test_ollama_integration_test_endpoint(temp_db, monkeypatch):
    client = TestClient(api.app)

    class DummyResponse:
        ok = True
        status_code = 200
        headers = {"content-type": "application/json"}

        def json(self):
            return {"response": "pong"}

        text = ""

    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return DummyResponse()

    monkeypatch.setattr(api.requests, "post", fake_post)

    response = client.post(
        "/integrations/test/ollama",
        json={"url": "http://ollama.internal:11434", "model": "mock", "prompt": "ping"},
    )
    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert captured["json"]["model"] == "mock"
    assert captured["json"]["prompt"] == "ping"
    assert captured["url"].endswith("/api/generate")


def test_llm_router_falls_back_to_ollama(monkeypatch):
    monkeypatch.delenv("CLAUDE_API_URL", raising=False)
    monkeypatch.delenv("HACKGPT_API_URL", raising=False)
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://ollama.fleet:11434")
    monkeypatch.setenv("OLLAMA_MODEL", "mock-llm")

    class DummyResponse:
        headers = {"content-type": "application/json"}

        def __init__(self):
            self.ok = True
            self.status_code = 200

        def json(self):
            return {"response": "hello from ollama"}

        text = "hello"

        def raise_for_status(self):
            return None

    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return DummyResponse()

    monkeypatch.setattr(llm_router.requests, "post", fake_post)

    result = llm_router.call_llm_with_fallback("status?")
    assert "ollama" in captured["url"]
    assert captured["json"]["model"] == "mock-llm"
    assert "hello from ollama" in result
