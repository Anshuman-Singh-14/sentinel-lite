import asyncio
import socket

from backend.tools.port_scan import classify, findings_for, scan


def free_port() -> int:
    """A port with nothing listening on it (the OS picks one, then we close it)."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_classify_known_and_unknown_ports():
    assert classify(3306) == ("MySQL", "port.database_exposed")
    assert classify(22) == ("SSH", "port.ssh")
    assert classify(31337) == ("Unknown service", "port.other")


def test_open_database_port_is_high_and_ssh_is_low():
    findings = findings_for([22, 3306])
    assert [(f["details"]["port"], f["severity"]) for f in findings] == [(22, "low"), (3306, "high")]


def test_scan_finds_open_port_and_skips_closed_one():
    async def run():
        server = await asyncio.start_server(lambda reader, writer: writer.close(), "127.0.0.1", 0)
        open_port = server.sockets[0].getsockname()[1]
        closed_port = free_port()
        async with server:
            return open_port, await scan("127.0.0.1", [open_port, closed_port])

    open_port, result = asyncio.run(run())
    assert result == [open_port]


def test_more_than_100_ports_is_rejected(user_client):
    response = user_client.post("/api/tools/port-scan", json={"target": "example.com", "ports": list(range(1, 102))})
    assert response.status_code == 422
