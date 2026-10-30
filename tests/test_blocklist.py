import pytest

from adsink.blocklist import Blocklist, extract_domains


class TestExtractDomains:
    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("doubleclick.net", ["doubleclick.net"]),
            ("  DoubleClick.NET.  ", ["doubleclick.net"]),
            ("0.0.0.0 ads.example.com", ["ads.example.com"]),
            ("127.0.0.1 ads.example.com", ["ads.example.com"]),
            ("ads.example.com  # comment", ["ads.example.com"]),
            ("0.0.0.0 a.com b.com", ["a.com", "b.com"]),
            ("127.0.0.1 localhost ads.example.com", ["ads.example.com"]),
        ],
    )
    def test_valid_lines(self, line, expected):
        assert extract_domains(line) == expected

    @pytest.mark.parametrize(
        "line",
        [
            "",
            "   ",
            "# just a comment",
            "127.0.0.1 localhost",
            "127.0.0.1 localhost.localdomain",
            "255.255.255.255 broadcasthost",
            "::1 ip6-localhost",
            "0.0.0.0 0.0.0.0",
            "0.0.0.0",
        ],
    )
    def test_ignored_lines(self, line):
        assert extract_domains(line) == []


class TestBlocklist:
    def test_blocks_exact_domain(self):
        blocklist = Blocklist(["doubleclick.net"])
        assert blocklist.is_blocked("doubleclick.net")

    def test_blocks_subdomains(self):
        blocklist = Blocklist(["doubleclick.net"])
        assert blocklist.is_blocked("stats.g.doubleclick.net")

    def test_does_not_block_similar_names(self):
        blocklist = Blocklist(["doubleclick.net"])
        assert not blocklist.is_blocked("notdoubleclick.net")

    def test_does_not_block_parent_domain(self):
        blocklist = Blocklist(["ads.example.com"])
        assert not blocklist.is_blocked("example.com")

    def test_ignores_case_and_trailing_dot(self):
        blocklist = Blocklist(["doubleclick.net"])
        assert blocklist.is_blocked("Ads.DoubleClick.NET.")

    @pytest.mark.parametrize("domain", ["", "localhost", "com", "1.2.3.4"])
    def test_rejects_invalid_domains(self, domain):
        with pytest.raises(ValueError):
            Blocklist([domain])

    def test_does_not_store_duplicates(self):
        blocklist = Blocklist(["a.com", "A.com", "b.com"])
        assert len(blocklist) == 2

    def test_loads_from_file(self, tmp_path):
        file = tmp_path / "blocklist.txt"
        lines = [
            "# comment",
            "0.0.0.0 ads.example.com",
            "tracker.net",
            "",
            "127.0.0.1 localhost",
        ]
        file.write_text("\n".join(lines), encoding="utf-8")

        blocklist = Blocklist.from_file(file)

        assert len(blocklist) == 2
        assert blocklist.is_blocked("x.tracker.net")
        assert not blocklist.is_blocked("localhost")

    def test_loads_from_file_with_bom(self, tmp_path):
        file = tmp_path / "blocklist.txt"
        file.write_text("0.0.0.0 ads.example.com", encoding="utf-8-sig")

        blocklist = Blocklist.from_file(file)

        assert blocklist.is_blocked("ads.example.com")
