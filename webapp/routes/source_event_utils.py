"""Helpers for parsing and normalising MISP source event references."""

import re
from urllib.parse import urlparse

from flask import jsonify

import config as _cfg
from webapp import misp_store

_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")


def extract_uuid(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    match = _UUID_RE.search(text)
    return match.group(0).lower() if match else ""


def source_id_from_event_ref(event_ref: str) -> str:
    raw = (event_ref or "").strip()
    if not raw.startswith(("http://", "https://")):
        return ""
    try:
        host = (urlparse(raw).hostname or "").lower()
    except Exception:
        return ""
    if not host:
        return ""

    try:
        scraper_host = (urlparse(_cfg.MISP_URL).hostname or "").lower()
    except Exception:
        scraper_host = ""
    if scraper_host and host == scraper_host:
        return "scraper"

    for server in getattr(_cfg, "MISP_SERVERS", []) or []:
        source_id = (server.get("id") or server.get("label") or "").strip()
        source_url = (server.get("url") or "").strip()
        if not source_id or not source_url:
            continue
        try:
            server_host = (urlparse(source_url).hostname or "").lower()
        except Exception:
            server_host = ""
        if server_host and host == server_host:
            return source_id

    try:
        webapp_host = (urlparse(_cfg.MISP_WEBAPP_URL).hostname or "").lower()
    except Exception:
        webapp_host = ""
    if webapp_host and host == webapp_host:
        return "webapp"

    return ""


def normalise_source_event_rows(event_refs: list[str], server_hints: list[str]) -> tuple[list[str], dict[str, str]]:
    source_uuids = []
    source_hints = {}
    seen = set()
    for index, raw in enumerate(event_refs or []):
        uuid = extract_uuid(raw)
        if not uuid:
            continue
        if uuid not in seen:
            seen.add(uuid)
            source_uuids.append(uuid)
        source_id = (server_hints[index] or "").strip() if index < len(server_hints or []) else ""
        if not source_id:
            source_id = source_id_from_event_ref(raw)
        if source_id and not source_hints.get(uuid):
            source_hints[uuid] = source_id
    return source_uuids, source_hints


def parse_source_tokens(tokens: list[str]) -> tuple[list[str], dict[str, str], list[tuple[str, str]]]:
    """Parse "<uuid-or-url>[|<source_id>]" tokens from URL or multi-select forms.

    Returns deduplicated UUIDs, a UUID->source_id hint map (URL host inferred when no
    explicit hint), and the original (uuid, source_id) pairs in input order.
    """
    source_uuids = []
    source_hints = {}
    source_pairs = []
    seen = set()
    for raw in tokens or []:
        token = (raw or "").strip()
        if not token:
            continue
        ref, _, sid = token.partition("|")
        source_id = sid.strip()
        if not source_id:
            source_id = source_id_from_event_ref(ref)
        uuid = extract_uuid(ref)
        if not uuid:
            continue
        if uuid not in seen:
            seen.add(uuid)
            source_uuids.append(uuid)
        if source_id and not source_hints.get(uuid):
            source_hints[uuid] = source_id
        source_pairs.append((uuid, source_id))
    return source_uuids, source_hints, source_pairs


def lookup_source_event_meta(request_args):
    """Shared handler body for the /source-event-meta AJAX endpoint."""
    event_ref = (request_args.get("event") or request_args.get("uuid") or "").strip()
    uuid = extract_uuid(event_ref)
    if not uuid:
        return jsonify({"ok": False, "error": "event URL or UUID is required"}), 400
    source_id = (request_args.get("server") or "").strip() or source_id_from_event_ref(event_ref)
    hints = {uuid: source_id} if source_id else None
    events = misp_store.fetch_source_events([uuid], hints, strict_source=bool(source_id))
    if not events:
        return jsonify({"ok": False, "error": "Event not found", "uuid": uuid}), 404
    ev = events[0]
    return jsonify({
        "ok": True,
        "uuid": uuid,
        "source_id": ev.get("source_id", ""),
        "source_label": ev.get("source_label", ""),
        "info": ev.get("info", ""),
        "orgc": ev.get("orgc", ""),
        "date": ev.get("date", ""),
    })
