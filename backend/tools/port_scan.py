"""Port scanner: TCP connect scan of common ports or a custom list (max 100).

A "connect scan" simply tries to open a normal TCP connection to each port. If
the connection succeeds, something is listening (open); if it is refused or
times out, the port counts as closed. Nothing is sent after connecting.
"""

import asyncio
import contextlib
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend import guard
from backend.auth import current_user
from backend.db import get_db
from backend.models import User
from backend.results import make_finding, save_scan
from backend.validation import Hostname

LABEL = "Port scan"
CONNECT_TIMEOUT = 2  # seconds per port
MAX_CONCURRENT = 50  # connections open at the same time

# port: (service name, finding category). The category picks the knowledge.json entry "port.<category>".
COMMON_PORTS = {
    21: ("FTP", "cleartext_service"),
    22: ("SSH", "ssh"),
    23: ("Telnet", "cleartext_service"),
    25: ("SMTP", "other"),
    53: ("DNS", "other"),
    80: ("HTTP", "web"),
    110: ("POP3", "cleartext_service"),
    135: ("Windows RPC", "file_sharing"),
    139: ("NetBIOS", "file_sharing"),
    143: ("IMAP", "cleartext_service"),
    443: ("HTTPS", "web"),
    445: ("SMB", "file_sharing"),
    993: ("IMAPS", "other"),
    995: ("POP3S", "other"),
    1433: ("Microsoft SQL Server", "database_exposed"),
    3306: ("MySQL", "database_exposed"),
    3389: ("Remote Desktop (RDP)", "remote_desktop"),
    5432: ("PostgreSQL", "database_exposed"),
    6379: ("Redis", "database_exposed"),
    8080: ("HTTP (alternate)", "web"),
    8443: ("HTTPS (alternate)", "web"),
    9200: ("Elasticsearch", "database_exposed"),
    27017: ("MongoDB", "database_exposed"),
}

router = APIRouter()


class PortScanRequest(BaseModel):
    target: Hostname
    # None means "scan the common ports list"
    ports: list[Annotated[int, Field(ge=1, le=65535)]] | None = Field(
        default=None, min_length=1, max_length=100
    )


def classify(port: int) -> tuple[str, str]:
    """(service name, finding key) for an open port."""
    service, category = COMMON_PORTS.get(port, ("Unknown service", "other"))
    return service, f"port.{category}"


async def is_open(ip: str, port: int, limit: asyncio.Semaphore) -> bool:
    async with limit:  # wait here if MAX_CONCURRENT connections are already open
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), CONNECT_TIMEOUT)
        except (OSError, TimeoutError):
            return False
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
        return True


async def scan(ip: str, ports: list[int]) -> list[int]:
    """Try all ports at once (at most MAX_CONCURRENT at a time) and return the open ones."""
    limit = asyncio.Semaphore(MAX_CONCURRENT)
    results = await asyncio.gather(*(is_open(ip, port, limit) for port in ports))
    return [port for port, open_ in zip(ports, results, strict=True) if open_]


def findings_for(open_ports: list[int]) -> list[dict]:
    findings = []
    for port in open_ports:
        service, key = classify(port)
        findings.append(make_finding(key, port=port, service=service))
    return findings


@router.post("/port-scan")
def port_scan(body: PortScanRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    guard.check_rate_limit(user)
    ip = guard.check_target(db, body.target)
    ports = sorted(set(body.ports)) if body.ports else sorted(COMMON_PORTS)
    # FastAPI runs this normal (non-async) route in a worker thread, so we can
    # start a small event loop here just for the concurrent connections.
    open_ports = asyncio.run(scan(ip, ports))

    summary = {
        "ip": ip,
        "ports_scanned": len(ports),
        "open": [{"port": port, "service": classify(port)[0]} for port in open_ports],
        "closed_count": len(ports) - len(open_ports),
    }
    guard.log_activity(db, user, "port_scan", f"{body.target} ({len(ports)} ports)")
    return save_scan(db, user, "port_scan", body.target, summary, findings_for(open_ports))
