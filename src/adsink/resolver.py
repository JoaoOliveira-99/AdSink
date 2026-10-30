"""Decides how to answer each DNS query: block it or forward it upstream."""

import socket
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from dnslib import AAAA, QTYPE, RCODE, RR, A, DNSError, DNSRecord

from adsink.blocklist import Blocklist, normalize

BLOCKED_TTL = 60  # seconds a client may cache a blocked answer


class Upstream(Protocol):
    """Anything that can answer a raw DNS query."""

    def query(self, data: bytes) -> bytes: ...


class UdpUpstream:
    """Forwards queries to a real DNS server over UDP."""

    def __init__(self, host: str, port: int = 53, timeout: float = 3.0) -> None:
        self.address = (host, port)
        self.timeout = timeout

    def query(self, data: bytes) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(self.address)  # only accept replies from this server
            sock.send(data)
            return sock.recv(65535)


class Action(Enum):
    BLOCKED = "blocked"
    FORWARDED = "forwarded"
    FAILED = "failed"


@dataclass(frozen=True)
class Resolution:
    """The outcome of resolving one query."""

    domain: str
    action: Action
    response: bytes


class Resolver:
    def __init__(self, blocklist: Blocklist, upstream: Upstream) -> None:
        self._blocklist = blocklist
        self._upstream = upstream

    def resolve(self, data: bytes) -> Resolution | None:
        """Answer a raw DNS query.

        Returns None when the data is not a DNS query, since there is nothing
        sensible to reply to.
        """
        try:
            request = DNSRecord.parse(data)
        except DNSError:
            return None
        if request.header.qr or not request.questions:
            return None  # a response, or a query that asks nothing

        domain = normalize(str(request.q.qname))

        if self._blocklist.is_blocked(domain):
            return Resolution(domain, Action.BLOCKED, _blocked_reply(request))

        try:
            response = self._upstream.query(data)
        except OSError:  # includes timeouts and unreachable networks
            return Resolution(domain, Action.FAILED, _error_reply(request, RCODE.SERVFAIL))
        return Resolution(domain, Action.FORWARDED, response)


def _blocked_reply(request: DNSRecord) -> bytes:
    """Reply with an address nobody can connect to.

    Other record types (HTTPS, MX, ...) get an empty answer.
    """
    reply = request.reply()
    qname, qtype = request.q.qname, request.q.qtype
    if qtype == QTYPE.A:
        reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=BLOCKED_TTL))
    elif qtype == QTYPE.AAAA:
        reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=BLOCKED_TTL))
    return reply.pack()


def _error_reply(request: DNSRecord, rcode: int) -> bytes:
    reply = request.reply()
    reply.header.rcode = rcode
    return reply.pack()