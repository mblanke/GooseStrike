"""Index CVEs and public exploit references into SQLite for GooseStrike."""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
from pathlib import Path
from typing import List

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}")
DB_PATH = Path("db/exploits.db")


def ensure_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            severity TEXT,
            score REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS exploits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            title TEXT NOT NULL,
            reference TEXT,
            path TEXT,
            cve_id TEXT,
            FOREIGN KEY(cve_id) REFERENCES cves(cve_id)
        )
        """
    )
    conn.commit()


def ingest_nvd(directory: Path, conn: sqlite3.Connection) -> int:
    if not directory.exists():
        return 0
    count = 0
    for json_file in sorted(directory.glob("*.json")):
        with json_file.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        items = data.get("CVE_Items", [])
        for item in items:
            cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID")
            if not cve_id:
                continue
            description_nodes = item.get("cve", {}).get("description", {}).get("description_data", [])
            description = description_nodes[0]["value"] if description_nodes else ""
            metrics = item.get("impact", {})
            severity = None
            score = None
            for metric in (metrics.get("baseMetricV3"), metrics.get("baseMetricV2")):
                if metric:
                    data_metric = metric.get("cvssV3" if "cvssV3" in metric else "cvssV2", {})
                    severity = data_metric.get("baseSeverity") or metric.get("severity")
                    score = data_metric.get("baseScore") or metric.get("cvssV2", {}).get("baseScore")
                    break
            conn.execute(
                """
                INSERT INTO cves(cve_id, description, severity, score)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    description=excluded.description,
                    severity=excluded.severity,
                    score=excluded.score
                """,
                (cve_id, description, severity, score),
            )
            count += 1
    conn.commit()
    return count


def extract_cves_from_text(text: str) -> List[str]:
    return list(set(CVE_REGEX.findall(text)))


def ingest_directory(source: str, directory: Path, conn: sqlite3.Connection) -> int:
    if not directory.exists():
        return 0
    count = 0
    for file_path in directory.rglob("*"):
        if not file_path.is_file():
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        cves = extract_cves_from_text(content)
        title = file_path.stem.replace("_", " ")
        reference = str(file_path.relative_to(directory))
        if not cves:
            conn.execute(
                "INSERT INTO exploits(source, title, reference, path, cve_id) VALUES(?,?,?,?,?)",
                (source, title, reference, str(file_path), None),
            )
            count += 1
            continue
        for cve_id in cves:
            conn.execute(
                "INSERT INTO exploits(source, title, reference, path, cve_id) VALUES(?,?,?,?,?)",
                (source, title, reference, str(file_path), cve_id),
            )
            count += 1
    conn.commit()
    return count


def ingest_packetstorm(xml_file: Path, conn: sqlite3.Connection) -> int:
    if not xml_file.exists():
        return 0
    import xml.etree.ElementTree as ET

    tree = ET.parse(xml_file)
    root = tree.getroot()
    count = 0
    for item in root.findall("channel/item"):
        title = item.findtext("title") or "PacketStorm entry"
        link = item.findtext("link")
        description = item.findtext("description") or ""
        cves = extract_cves_from_text(description)
        if not cves:
            conn.execute(
                "INSERT INTO exploits(source, title, reference, path, cve_id) VALUES(?,?,?,?,?)",
                ("packetstorm", title, link, None, None),
            )
            count += 1
            continue
        for cve_id in cves:
            conn.execute(
                "INSERT INTO exploits(source, title, reference, path, cve_id) VALUES(?,?,?,?,?)",
                ("packetstorm", title, link, None, cve_id),
            )
            count += 1
    conn.commit()
    return count


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Index CVEs and exploits into SQLite")
    parser.add_argument("--nvd", default="data/nvd", help="Directory with NVD JSON dumps")
    parser.add_argument(
        "--exploitdb", default="data/exploitdb", help="Directory with Exploit-DB entries"
    )
    parser.add_argument(
        "--packetstorm", default="data/packetstorm.xml", help="PacketStorm RSS/Atom file"
    )
    args = parser.parse_args(argv)

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    with conn:
        ensure_tables(conn)
        nvd_count = ingest_nvd(Path(args.nvd), conn)
        edb_count = ingest_directory("exploitdb", Path(args.exploitdb), conn)
        ps_count = ingest_packetstorm(Path(args.packetstorm), conn)
    print(
        f"Indexed {nvd_count} CVEs, {edb_count} Exploit-DB entries, "
        f"{ps_count} PacketStorm entries"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
