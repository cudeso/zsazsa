"""Read the logged-in user out of MISP's shared PHP session.

MISP (CakePHP) stores sessions in Redis under the key
``PHPREDIS_SESSION:<session id>``, where ``<session id>`` is the value of
the ``MISP-<uuid>`` cookie. The value is PHP's "php" session serialize
format: a sequence of ``key|value`` pairs where each value is itself
PHP-serialized. After login, CakePHP's AuthComponent stores the full user
record under the ``Auth`` key as ``Auth.User``.

This module talks to that Redis instance directly over a plain socket
(no redis-py dependency) and parses just enough of the PHP serialize
format to pull out ``Auth.User``.
"""

import logging
import socket

from flask import g, request

import config

logger = logging.getLogger(__name__)

DEFAULT_USER_EMAIL = "admin@admin.test"


class RedisError(Exception):
    """Raised on a Redis protocol error (e.g. failed AUTH)."""


def _send_command(sock, *args):
    parts = [f"*{len(args)}\r\n".encode()]
    for arg in args:
        if not isinstance(arg, bytes):
            arg = str(arg).encode()
        parts.append(b"$%d\r\n%s\r\n" % (len(arg), arg))
    sock.sendall(b"".join(parts))


def _read_line(sock):
    buf = b""
    while not buf.endswith(b"\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise RedisError("connection closed by Redis")
        buf += chunk
    return buf[:-2]


def _read_reply(sock):
    line = _read_line(sock)
    kind, rest = line[:1], line[1:]
    if kind == b"+":
        return rest
    if kind == b"-":
        raise RedisError(rest.decode("utf-8", "replace"))
    if kind == b":":
        return int(rest)
    if kind == b"$":
        length = int(rest)
        if length == -1:
            return None
        data = b""
        while len(data) < length + 2:
            data += sock.recv(length + 2 - len(data))
        return data[:-2]
    raise RedisError(f"unexpected Redis reply: {line!r}")


def _redis_get(key):
    """Fetch a single key from MISP's session Redis. Returns bytes or None."""
    host = getattr(config, "MISP_SESSION_REDIS_HOST", "127.0.0.1")
    port = getattr(config, "MISP_SESSION_REDIS_PORT", 6379)
    db = getattr(config, "MISP_SESSION_REDIS_DB", 0)
    username = getattr(config, "MISP_SESSION_REDIS_USERNAME", "")
    password = getattr(config, "MISP_SESSION_REDIS_PASSWORD", "")

    sock = socket.create_connection((host, port), timeout=2)
    try:
        if password:
            if username:
                _send_command(sock, "AUTH", username, password)
            else:
                _send_command(sock, "AUTH", password)
            _read_reply(sock)
        if db:
            _send_command(sock, "SELECT", db)
            _read_reply(sock)
        _send_command(sock, "GET", key)
        return _read_reply(sock)
    finally:
        sock.close()


def _parse_php_value(data, pos):
    """Parse one PHP serialize() value from `data` starting at `pos`.

    Returns (value, next_pos). Covers the types CakePHP uses in session
    data: N (null), b (bool), i (int), d (float), s (string), a (array).
    """
    kind = data[pos:pos + 1]
    if kind == b"N":
        return None, pos + 2
    if kind == b"b":
        end = data.index(b";", pos)
        return data[pos + 2:end] == b"1", end + 1
    if kind == b"i":
        end = data.index(b";", pos)
        return int(data[pos + 2:end]), end + 1
    if kind == b"d":
        end = data.index(b";", pos)
        return float(data[pos + 2:end]), end + 1
    if kind == b"s":
        colon = data.index(b":", pos + 2)
        length = int(data[pos + 2:colon])
        start = colon + 2  # skip ':"'
        end = start + length
        return data[start:end].decode("utf-8", "replace"), end + 2  # skip '";'
    if kind == b"a":
        colon = data.index(b":", pos + 2)
        count = int(data[pos + 2:colon])
        pos = colon + 2  # skip ':{'
        result = {}
        for _ in range(count):
            item_key, pos = _parse_php_value(data, pos)
            item_value, pos = _parse_php_value(data, pos)
            result[item_key] = item_value
        return result, pos + 1  # skip '}'
    raise ValueError(f"unsupported PHP serialize type {kind!r} at offset {pos}")


def _parse_php_session(data):
    """Parse PHP's 'php' session serialize format into a dict of top-level keys."""
    result = {}
    pos = 0
    while pos < len(data):
        sep = data.index(b"|", pos)
        key = data[pos:sep].decode("ascii")
        value, pos = _parse_php_value(data, sep + 1)
        result[key] = value
    return result


def get_misp_user(session_id):
    """Return the MISP Auth.User dict for a session ID, or None.

    This reflects whatever CakePHP wrote to the session at login time, not
    necessarily the live database state (e.g. a user disabled after login
    keeps a session until MISP itself re-checks and rewrites it).
    """
    if not session_id:
        return None

    try:
        raw = _redis_get(f"PHPREDIS_SESSION:{session_id}")
    except (OSError, RedisError) as e:
        logger.warning("could not read MISP session from Redis: %s", e)
        return None

    if raw is None:
        return None

    try:
        session = _parse_php_session(raw)
    except (ValueError, IndexError) as e:
        logger.warning("could not parse MISP session data: %s", e)
        return None

    user = session.get("Auth", {}).get("User")
    if not user or user.get("disabled"):
        return None

    return user


def load_request_user():
    """Look up the MISP user for the current request and cache it on flask.g."""
    cookie_name = getattr(config, "MISP_SESSION_COOKIE_NAME", "")
    session_id = request.cookies.get(cookie_name)
    g.misp_user = get_misp_user(session_id)


def current_user_email():
    """Email of the MISP user identified for this request, or a fallback.

    Also used by standalone scripts that call into webapp.misp_store outside
    of a Flask request, where there is no flask.g to read from at all.
    """
    try:
        user = getattr(g, "misp_user", None)
    except RuntimeError:
        return DEFAULT_USER_EMAIL
    return user["email"] if user else DEFAULT_USER_EMAIL


def login_redirect_url():
    """MISP login URL to redirect to, or None if the request can proceed.

    Only returns a URL when MISP_SESSION_REDIRECT_TO_LOGIN is enabled and no
    valid MISP session was found for this request.
    """
    if not getattr(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False):
        return None
    if getattr(g, "misp_user", None):
        return None
    return f"{config.MISP_URL}/users/login"
