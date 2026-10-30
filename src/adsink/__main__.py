"""Entry point: `python -m adsink` or `adsink`."""

import logging
import sys
from pathlib import Path

from adsink.blocklist import Blocklist
from adsink.resolver import Resolver, UdpUpstream
from adsink.server import DnsServer

# Temporary settings: lesson 5 moves these into proper configuration.
HOST = "0.0.0.0"
PORT = 5300
UPSTREAM = "1.1.1.1"
BLOCKLIST_FILE = Path("blocklist.txt")

logger = logging.getLogger("adsink")


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    try:
        blocklist = Blocklist.from_file(BLOCKLIST_FILE)
    except OSError as error:
        logger.error("Cannot read blocklist %s: %s", BLOCKLIST_FILE, error.strerror or error)
        return 1
    logger.info("Loaded %d blocked domains from %s", len(blocklist), BLOCKLIST_FILE)
    resolver = Resolver(blocklist, UdpUpstream(UPSTREAM))

    try:
        server = DnsServer((HOST, PORT), resolver)
    except OSError as error:  # port in use, or no permission to bind it
        logger.error("Cannot listen on %s:%d: %s", HOST, PORT, error.strerror or error)
        return 1

    with server:
        logger.info("Listening on %s:%d (Ctrl+C to stop)", HOST, PORT)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())