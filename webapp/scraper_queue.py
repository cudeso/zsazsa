"""Publish items to the misp-scraper Redis channel.

The misp-scraper 'subscribe' service consumes this channel, fetches each URL and
creates the MISP event. We only PUBLISH here; nothing in zsazsa scrapes or
creates events. Connection settings live in config (SCRAPER_REDIS_*) and are
edited under Configuration > Collection sources.
"""

import json
import logging
import socket

import config
from webapp.redis_client import RedisError, read_reply, send_command

logger = logging.getLogger(__name__)


def publish(message: dict) -> int:
    """Publish one message to the scraper channel.

    Returns the number of subscribers that received it (0 means the scraper's
    'subscribe' service is not listening, so the message was dropped). Raises
    OSError on a connection problem or RedisError on a protocol/AUTH error.
    """
    host = getattr(config, "SCRAPER_REDIS_HOST", "127.0.0.1")
    port = int(getattr(config, "SCRAPER_REDIS_PORT", 6379) or 6379)
    password = getattr(config, "SCRAPER_REDIS_PASSWORD", "")
    channel = getattr(config, "SCRAPER_REDIS_CHANNEL", "urls") or "urls"

    sock = socket.create_connection((host, port), timeout=5)
    try:
        if password:
            send_command(sock, "AUTH", password)
            read_reply(sock)
        send_command(sock, "PUBLISH", channel, json.dumps(message))
        received = read_reply(sock)
        return received if isinstance(received, int) else 0
    finally:
        sock.close()
