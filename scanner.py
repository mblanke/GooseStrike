"""Subnet scanning utility for GooseStrike.

This module wraps nmap (and optionally masscan) to inventory services
across a CIDR range and forward the parsed results to the GooseStrike
FastAPI backend.
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET

import requests

API_DEFAULT = "http://localhost:8000"


def run_command(cmd: List[str]) -> str:
    """Execute a command and return stdout, raising on errors."""
    try:
        completed = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Required command not found: {cmd[0]}") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Command failed ({cmd}): {exc.stderr.strip() or exc.stdout.strip()}"
        ) from exc
    return completed.stdout


@dataclass
class ServiceResult:
    port: int
    proto: str
    product: Optional[str] = None
    version: Optional[str] = None
    extra: Dict[str, str] = field(default_factory=dict)


@dataclass
class HostResult:
    ip: str
    hostname: Optional[str]
    services: List[ServiceResult] = field(default_factory=list)
    mac_address: Optional[str] = None
    mac_vendor: Optional[str] = None


@dataclass
class ScanMetadata:
    scan_id: str
    started_at: Optional[str]
    finished_at: Optional[str]
    scanner: str
    mode: str
    notes: Optional[str]


def build_nmap_command(
    cidr: str, mode: str, rate: Optional[int], extra_args: Optional[List[str]] = None
) -> List[str]:
    """Construct the nmap command with optional mode/rate/custom arguments."""
    cmd: List[str] = ["nmap"]
    if mode == "fast":
        cmd.extend(["-T4", "-F"])
    elif mode == "full":
        cmd.extend(["-T4", "-p-"])
    if rate:
        cmd.extend(["--min-rate", str(rate)])
    if extra_args:
        cmd.extend(extra_args)
    cmd.extend(["-sV", "-oX", "-", cidr])
    return cmd


def parse_nmap_xml(xml_content: str) -> Tuple[List[HostResult], Optional[str], Optional[str]]:
    root = ET.fromstring(xml_content)
    hosts: List[HostResult] = []
    started_at = root.get("startstr")
    finished_el = root.find("runstats/finished")
    finished_at = finished_el.get("timestr") if finished_el is not None else None
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        address = host.find("address[@addrtype='ipv4']") or host.find("address[@addrtype='ipv6']")
        if address is None:
            continue
        ip = address.get("addr")
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None
        mac_el = host.find("address[@addrtype='mac']")
        mac_address = mac_el.get("addr") if mac_el is not None else None
        mac_vendor = mac_el.get("vendor") if mac_el is not None else None
        services: List[ServiceResult] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service_el = port.find("service")
            service = ServiceResult(
                port=int(port.get("portid", 0)),
                proto=port.get("protocol", "tcp"),
                product=service_el.get("product") if service_el is not None else None,
                version=service_el.get("version") if service_el is not None else None,
                extra={},
            )
            if service_el is not None:
                for key in ("name", "extrainfo", "ostype"):
                    value = service_el.get(key)
                    if value:
                        service.extra[key] = value
            services.append(service)
        if services:
            hosts.append(
                HostResult(
                    ip=ip,
                    hostname=hostname,
                    services=services,
                    mac_address=mac_address,
                    mac_vendor=mac_vendor,
                )
            )
    return hosts, started_at, finished_at


def send_to_api(hosts: List[HostResult], api_base: str, scan_meta: ScanMetadata) -> None:
    ingest_url = f"{api_base.rstrip('/')}/ingest/scan"
    session = requests.Session()
    for host in hosts:
        payload = {
            "ip": host.ip,
            "hostname": host.hostname,
            "mac_address": host.mac_address,
            "mac_vendor": host.mac_vendor,
            "scan": {
                "scan_id": scan_meta.scan_id,
                "scanner": scan_meta.scanner,
                "mode": scan_meta.mode,
                "started_at": scan_meta.started_at,
                "completed_at": scan_meta.finished_at,
                "notes": scan_meta.notes,
            },
            "services": [
                {
                    "port": s.port,
                    "proto": s.proto,
                    "product": s.product,
                    "version": s.version,
                    "extra": s.extra,
                }
                for s in host.services
            ],
        }
        response = session.post(ingest_url, json=payload, timeout=30)
        response.raise_for_status()


def scan_and_ingest(
    cidr: str,
    mode: str,
    rate: Optional[int],
    api_base: str,
    notes: Optional[str],
    scanner_name: str,
    scan_id: Optional[str],
    extra_args: Optional[List[str]] = None,
) -> None:
    cmd = build_nmap_command(cidr, mode, rate, extra_args)
    print(f"[+] Running {' '.join(cmd)}")
    xml_result = run_command(cmd)
    hosts, started_at, finished_at = parse_nmap_xml(xml_result)
    print(f"[+] Parsed {len(hosts)} hosts with open services")
    if not hosts:
        return
    meta = ScanMetadata(
        scan_id=scan_id or str(uuid.uuid4()),
        started_at=started_at,
        finished_at=finished_at,
        scanner=scanner_name,
        mode=mode,
        notes=notes,
    )
    send_to_api(hosts, api_base, meta)
    print("[+] Results sent to API")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="GooseStrike subnet scanner")
    parser.add_argument("cidr", help="CIDR range to scan, e.g. 10.0.0.0/24")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--fast", action="store_true", help="Fast top-port scan")
    mode_group.add_argument("--full", action="store_true", help="Full port scan")
    parser.add_argument("--rate", type=int, help="Optional nmap min rate")
    parser.add_argument("--api", default=API_DEFAULT, help="API base URL")
    parser.add_argument(
        "--no-upload",
        action="store_true",
        help="Skip uploading results (useful for local testing)",
    )
    parser.add_argument("--notes", help="Optional operator notes recorded with the scan")
    parser.add_argument("--scanner-name", default="GooseStrike nmap", help="Logical scanner identifier")
    parser.add_argument("--scan-id", help="Optional scan UUID for correlating uploads")
    parser.add_argument(
        "--nmap-args",
        help=(
            "Extra nmap arguments (quoted) to mirror advanced Recorded Future command "
            "examples, e.g. \"-sC --script vuln -Pn\""
        ),
    )
    args = parser.parse_args(argv)

    mode = "standard"
    if args.fast:
        mode = "fast"
    elif args.full:
        mode = "full"

    extra_args: Optional[List[str]] = None
    if args.nmap_args:
        extra_args = shlex.split(args.nmap_args)

    try:
        cmd = build_nmap_command(args.cidr, mode, args.rate, extra_args)
        xml_result = run_command(cmd)
        hosts, started_at, finished_at = parse_nmap_xml(xml_result)
        meta = ScanMetadata(
            scan_id=args.scan_id or str(uuid.uuid4()),
            started_at=started_at,
            finished_at=finished_at,
            scanner=args.scanner_name,
            mode=mode,
            notes=args.notes,
        )
        print(
            json.dumps(
                [
                    {
                        **host.__dict__,
                        "services": [service.__dict__ for service in host.services],
                    }
                    for host in hosts
                ],
                indent=2,
            )
        )
        if not args.no_upload and hosts:
            send_to_api(hosts, args.api, meta)
            print("[+] Uploaded results to API")
        return 0
    except Exception as exc:  # pylint: disable=broad-except
        print(f"[-] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
