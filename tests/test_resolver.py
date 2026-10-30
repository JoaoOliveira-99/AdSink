import pytest
from dnslib import QTYPE, RCODE, RR, A, DNSRecord

from adsink.blocklist import Blocklist
from adsink.resolver import Action, Resolver


def make_query(domain: str, qtype: str = "A") -> bytes:
    return DNSRecord.question(domain, qtype).pack()


class FakeUpstream:
    """Pretends to be a real DNS server: always answers with the same IP."""

    def __init__(self, ip: str = "93.184.216.34") -> None:
        self.ip = ip
        self.queries: list[bytes] = []

    def query(self, data: bytes) -> bytes:
        self.queries.append(data)
        request = DNSRecord.parse(data)
        reply = request.reply()
        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(self.ip), ttl=300))
        return reply.pack()


class FailingUpstream:
    """Pretends to be a DNS server that never answers."""

    def query(self, data: bytes) -> bytes:
        raise TimeoutError("upstream did not answer")


@pytest.fixture
def upstream() -> FakeUpstream:
    return FakeUpstream()


@pytest.fixture
def resolver(upstream: FakeUpstream) -> Resolver:
    return Resolver(Blocklist(["doubleclick.net"]), upstream)


class TestBlockedDomains:
    def test_answers_ipv4_with_zero_address(self, resolver):
        result = resolver.resolve(make_query("ads.doubleclick.net", "A"))

        assert result.action is Action.BLOCKED
        answers = DNSRecord.parse(result.response).rr
        assert [str(rr.rdata) for rr in answers] == ["0.0.0.0"]

    def test_answers_ipv6_with_unspecified_address(self, resolver):
        result = resolver.resolve(make_query("ads.doubleclick.net", "AAAA"))

        answers = DNSRecord.parse(result.response).rr
        assert [str(rr.rdata) for rr in answers] == ["::"]

    @pytest.mark.parametrize("qtype", ["HTTPS", "MX", "TXT"])
    def test_answers_other_types_with_no_records(self, resolver, qtype):
        result = resolver.resolve(make_query("doubleclick.net", qtype))

        reply = DNSRecord.parse(result.response)
        assert reply.header.rcode == RCODE.NOERROR
        assert reply.rr == []

    def test_reply_has_same_id_as_query(self, resolver):
        query = make_query("doubleclick.net")

        result = resolver.resolve(query)

        assert DNSRecord.parse(result.response).header.id == DNSRecord.parse(query).header.id

    def test_never_reaches_upstream(self, resolver, upstream):
        resolver.resolve(make_query("doubleclick.net"))

        assert upstream.queries == []


class TestAllowedDomains:
    def test_forwards_query_unchanged(self, resolver, upstream):
        query = make_query("publico.pt")

        result = resolver.resolve(query)

        assert result.action is Action.FORWARDED
        assert upstream.queries == [query]

    def test_returns_upstream_answer(self, resolver):
        result = resolver.resolve(make_query("publico.pt"))

        answers = DNSRecord.parse(result.response).rr
        assert [str(rr.rdata) for rr in answers] == ["93.184.216.34"]

    def test_returns_servfail_when_upstream_fails(self):
        resolver = Resolver(Blocklist(), FailingUpstream())

        result = resolver.resolve(make_query("publico.pt"))

        assert result.action is Action.FAILED
        assert DNSRecord.parse(result.response).header.rcode == RCODE.SERVFAIL


class TestInvalidInput:
    @pytest.mark.parametrize("data", [b"", b"garbage", b"\xff" * 40])
    def test_ignores_data_that_is_not_dns(self, resolver, data):
        assert resolver.resolve(data) is None

    def test_ignores_query_without_question(self, resolver):
        assert resolver.resolve(DNSRecord().pack()) is None

    def test_ignores_responses(self, resolver):
        response = DNSRecord.question("publico.pt").reply().pack()

        assert resolver.resolve(response) is None


def test_reports_normalized_domain(resolver):
    result = resolver.resolve(make_query("Ads.DoubleClick.NET"))

    assert result.domain == "ads.doubleclick.net"