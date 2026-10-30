import logging
import socket
import socketserver
import threading
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from dnslib import QTYPE, RR, A, DNSRecord

from adsink.blocklist import Blocklist
from adsink.resolver import Resolver, UdpUpstream
from adsink.server import DnsServer

Address = tuple[str, int]


@contextmanager
def running(server: socketserver.BaseServer) -> Iterator[Address]:
    """Run a server in a background thread and stop it afterwards."""
    # A short poll interval makes shutdown() return quickly.
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def ask(address: Address, data: bytes, timeout: float = 1.0) -> bytes:
    """Send a packet over UDP and wait for the answer."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(data, address)
        return sock.recv(65535)


def make_query(domain: str) -> bytes:
    return DNSRecord.question(domain).pack()


def answers(response: bytes) -> list[str]:
    return [str(rr.rdata) for rr in DNSRecord.parse(response).rr]


class FakeDnsHandler(socketserver.BaseRequestHandler):
    """A real UDP DNS server that stands in for 1.1.1.1."""

    def handle(self) -> None:
        data, sock = self.request
        reply = DNSRecord.parse(data).reply()
        reply.add_answer(RR(reply.q.qname, QTYPE.A, rdata=A("93.184.216.34"), ttl=300))
        sock.sendto(reply.pack(), self.client_address)


class BrokenResolver:
    def resolve(self, data: bytes) -> None:
        raise RuntimeError("something went wrong")


@pytest.fixture
def upstream_address() -> Iterator[Address]:
    # Port 0 asks the operating system for any free port.
    with running(socketserver.UDPServer(("127.0.0.1", 0), FakeDnsHandler)) as address:
        yield address


@pytest.fixture
def server_address(upstream_address: Address) -> Iterator[Address]:
    host, port = upstream_address
    resolver = Resolver(Blocklist(["doubleclick.net"]), UdpUpstream(host, port, timeout=1))
    with running(DnsServer(("127.0.0.1", 0), resolver)) as address:
        yield address


def test_answers_blocked_domain(server_address):
    response = ask(server_address, make_query("ads.doubleclick.net"))

    assert answers(response) == ["0.0.0.0"]


def test_forwards_allowed_domain_to_upstream(server_address):
    response = ask(server_address, make_query("publico.pt"))

    assert answers(response) == ["93.184.216.34"]


def test_ignores_invalid_packets_and_keeps_running(server_address):
    with pytest.raises(TimeoutError):
        ask(server_address, b"garbage", timeout=0.3)

    response = ask(server_address, make_query("ads.doubleclick.net"))
    assert answers(response) == ["0.0.0.0"]


def test_logs_each_query(server_address, caplog):
    caplog.set_level(logging.INFO, logger="adsink")

    ask(server_address, make_query("ads.doubleclick.net"))

    assert "blocked" in caplog.text
    assert "ads.doubleclick.net" in caplog.text


def test_survives_unexpected_errors(caplog):
    with running(DnsServer(("127.0.0.1", 0), BrokenResolver())) as address:
        for _ in range(2):
            with pytest.raises(TimeoutError):
                ask(address, make_query("publico.pt"), timeout=0.3)

    errors = [record for record in caplog.records if record.exc_info]
    assert len(errors) == 2