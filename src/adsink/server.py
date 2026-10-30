"""UDP server: receives DNS queries and sends back the resolver's answers."""

import logging
import socketserver

from adsink.resolver import Action, Resolver

logger = logging.getLogger(__name__)


class DnsServer(socketserver.ThreadingUDPServer):
    """Answers each query in its own thread, so one slow query never blocks the others."""

    daemon_threads = True  # don't wait for queries in progress when shutting down

    def __init__(self, address: tuple[str, int], resolver: Resolver) -> None:
        super().__init__(address, _DnsHandler)
        self.resolver = resolver

    def handle_error(self, request, client_address) -> None:
        """Log unexpected errors instead of printing them, and keep serving."""
        logger.exception("Unexpected error while answering %s", client_address[0])


class _DnsHandler(socketserver.BaseRequestHandler):
    """Handles a single query. A new one is created for every packet."""

    server: DnsServer

    def handle(self) -> None:
        data, sock = self.request
        client_ip = self.client_address[0]

        result = self.server.resolver.resolve(data)
        if result is None:
            logger.debug("Ignored invalid packet from %s", client_ip)
            return

        level = logging.WARNING if result.action is Action.FAILED else logging.INFO
        logger.log(level, "%-15s %-9s %s", client_ip, result.action.value, result.domain)
        sock.sendto(result.response, self.client_address)