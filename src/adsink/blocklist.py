"""Blocked domains list.

Blocking a domain also blocks all of its subdomains:
"doubleclick.net" matches "ads.doubleclick.net".
"""

import ipaddress
from collections.abc import Iterable
from pathlib import Path
from typing import Self

# Special names found in hosts-format lists that must never be blocked.
IGNORED_NAMES = frozenset({"localhost", "localhost.localdomain", "local", "broadcasthost"})


def normalize(domain: str) -> str:
    """Return the canonical form of a domain: "Ads.COM. " -> "ads.com"."""
    return domain.strip().lower().rstrip(".")


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _is_blockable(domain: str) -> bool:
    """Return True if a normalized name is a real domain that may be blocked."""
    return "." in domain and not _is_ip(domain) and domain not in IGNORED_NAMES


def extract_domains(line: str) -> list[str]:
    """Extract the domains from a single blocklist line.

    Accepts "domain.com" and the hosts format "0.0.0.0 a.com b.com".
    Blank lines, comments and names that are not domains yield nothing.
    """
    parts = line.split("#", 1)[0].split()
    if parts and _is_ip(parts[0]):
        parts = parts[1:]  # hosts format: the domains come after the IP

    domains = (normalize(part) for part in parts)
    return [domain for domain in domains if _is_blockable(domain)]


class Blocklist:
    """A set of blocked domains."""

    def __init__(self, domains: Iterable[str] = ()) -> None:
        self._domains: set[str] = set()
        for domain in domains:
            self.add(domain)

    @classmethod
    def from_file(cls, path: Path) -> Self:
        """Build a blocklist from a file, reading it line by line."""
        with path.open(encoding="utf-8-sig") as file:
            return cls(domain for line in file for domain in extract_domains(line))

    def add(self, domain: str) -> None:
        """Add a domain to the list, raising ValueError if it cannot be blocked."""
        normalized = normalize(domain)
        if not _is_blockable(normalized):
            raise ValueError(f"not a blockable domain: {domain!r}")
        self._domains.add(normalized)

    def is_blocked(self, domain: str) -> bool:
        """Return True if the domain, or any of its parent domains, is in the list."""
        parts = normalize(domain).split(".")
        return any(".".join(parts[i:]) in self._domains for i in range(len(parts)))

    def __len__(self) -> int:
        return len(self._domains)
