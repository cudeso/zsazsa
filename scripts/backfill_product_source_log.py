#!/usr/bin/env python3
"""Backfill the analyser log with the source events of existing products.

The pipeline's "By collection source" is built from the analyser event_log.
Products composed by hand (briefings, flash intel, VEAs) did not record their
source events until source logging was added, so products created before then
are missing from that view. This script logs each existing product's source
events as a product creation, skipping any (source event + product) pair that
is already logged so nothing is double counted.

By default it runs as a dry-run and only reports what would be added.
Use --apply to write the entries.

Examples:
    .venv/bin/python scripts/backfill_product_source_log.py
    .venv/bin/python scripts/backfill_product_source_log.py --apply
"""
from __future__ import annotations

import argparse
import pathlib
import sqlite3
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import config
from analyser import tagger
from core.db import init_db, log_event
from webapp import collection_cache, misp_store


def _collect_pairs() -> list[tuple[str, str]]:
    """Return (source_event_uuid, product_label) pairs from all existing products."""
    pairs = []
    try:
        for b in misp_store.list_briefings() or []:
            for s in getattr(b, "stories", []) or []:
                uuid = (getattr(s, "source_event_uuid", "") or "").strip()
                if uuid:
                    pairs.append((uuid, "daily-briefing"))
    except Exception as exc:
        print(f"  ! could not list briefings: {exc}")
    try:
        for f in misp_store.list_fias() or []:
            for uuid in getattr(f, "source_event_uuids", []) or []:
                uuid = (uuid or "").strip()
                if uuid:
                    pairs.append((uuid, "flash-intel"))
    except Exception as exc:
        print(f"  ! could not list flash intel: {exc}")
    try:
        for v in misp_store.list_veas() or []:
            uuids = list(getattr(v, "source_event_uuids", []) or [])
            if not uuids and getattr(v, "source_event_uuid", ""):
                uuids = [v.source_event_uuid]
            for uuid in uuids:
                uuid = (uuid or "").strip()
                if uuid:
                    pairs.append((uuid, "vea"))
    except Exception as exc:
        print(f"  ! could not list VEAs: {exc}")
    return pairs


def _already_logged() -> set[tuple[str, str]]:
    """(event_uuid, detail) pairs already present as product_created entries."""
    keys = set()
    try:
        with sqlite3.connect(config.DB_FILE) as conn:
            for event_uuid, detail in conn.execute(
                "SELECT event_uuid, detail FROM event_log WHERE outcome = 'product_created'"
            ):
                keys.add((event_uuid, detail or ""))
    except sqlite3.Error as exc:
        print(f"  ! could not read event_log: {exc}")
    return keys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="Write the entries. Without this flag, run as dry-run.")
    args = parser.parse_args()

    init_db()

    unique = list(dict.fromkeys(_collect_pairs()))
    existing = _already_logged()
    to_add = [pair for pair in unique if pair not in existing]

    print(f"Unique product source links: {len(unique)}.")
    print(f"Already logged: {len(unique) - len(to_add)}. To add: {len(to_add)}.")
    by_label: dict[str, int] = {}
    for _uuid, label in to_add:
        by_label[label] = by_label.get(label, 0) + 1
    for label, n in sorted(by_label.items()):
        print(f"  {label}: {n}")

    if not to_add:
        print("Nothing to backfill.")
        return 0
    if not args.apply:
        print("\nDry-run only. Re-run with --apply to write these entries.")
        return 0

    rows = {r["uuid"]: r for r in collection_cache.get_events_by_uuids(sorted({u for u, _ in to_add}))}
    for uuid, label in to_add:
        row = rows.get(uuid, {})
        log_event(
            event_uuid=uuid,
            event_info=row.get("info", ""),
            source_feed=tagger.source_feed_from_tags(row.get("tags", [])),
            outcome="product_created",
            detail=label,
        )
    print(f"\nApplied: wrote {len(to_add)} event_log entries.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
