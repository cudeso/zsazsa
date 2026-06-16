#!/usr/bin/env python3
"""Convert zsazsa-namespace tag attachments from global to local in MISP.

Everything zsazsa sets in the ``zsazsa:`` namespace (zsazsa:type, zsazsa:ctiproduct,
zsazsa:collection, zsazsa:source, zsazsa:source-type, zsazsa:product) must be a
local tag so it never syncs to connected MISP instances. Tags embedded when an
event is created are attached globally even when flagged local, so older events
created before the fix carry these tags as global attachments. This script finds
those attachments and re-applies them locally (untag, then tag with local=True).

It targets the webapp MISP (MISP_WEBAPP_URL), where stakeholders, PIRs, GIRs,
RFIs, products, collection sources and manual entries live. Scraper source events
on the scraper MISP that carry zsazsa:product/zsazsa:source tags are written
locally by the application already and are not touched here.

By default this script runs in dry-run mode and only reports what would change.
Use --apply to actually convert the tags.

Examples:
    /home/koenv/Documents/zsazsa/.venv/bin/python scripts/make_zsazsa_tags_local.py
    /home/koenv/Documents/zsazsa/.venv/bin/python scripts/make_zsazsa_tags_local.py --apply
"""

from __future__ import annotations

import argparse
import pathlib
import sys

# Ensure repository root is importable when running this script directly.
ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import config
from pymisp import PyMISP

NAMESPACE = "zsazsa:"

# Wildcards covering every zsazsa-namespace tag the application writes.
SEARCH_TAGS = [
    'zsazsa:type="%"',
    'zsazsa:ctiproduct="%"',
    'zsazsa:collection="%"',
    'zsazsa:source="%"',
    'zsazsa:source-type="%"',
    'zsazsa:product="%"',
]


def _misp() -> PyMISP:
    return PyMISP(
        config.MISP_WEBAPP_URL,
        config.MISP_WEBAPP_KEY,
        config.MISP_WEBAPP_VERIFYCERT,
        False,
    )


def _global_zsazsa_tags(event):
    """Yield names of zsazsa-namespace tags attached globally to the event."""
    for tag in (getattr(event, "tags", []) or []):
        name = getattr(tag, "name", "") or ""
        if name.startswith(NAMESPACE) and getattr(tag, "local", False) is False:
            yield name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes. Without this flag, run as dry-run.",
    )
    args = parser.parse_args()

    misp = _misp()
    events = misp.search(tags=SEARCH_TAGS, limit=10000, pythonify=True)
    if not events or isinstance(events, dict):
        print("No zsazsa-tagged events found or search failed.")
        return 0

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"Mode: {mode}")

    found = 0
    changed = 0

    for event in events:
        event_id = getattr(event, "id", "?")
        event_uuid = getattr(event, "uuid", "?")
        for name in _global_zsazsa_tags(event):
            found += 1
            print(f"- event={event_uuid} ({event_id}) tag={name!r} global -> local")
            if args.apply:
                misp.untag(event_uuid, name)
                r = misp.tag(event_uuid, name, local=True)
                if isinstance(r, dict) and "errors" in r:
                    print(f"  ERROR re-tagging: {r['errors']}")
                    continue
                changed += 1

    print(f"Global zsazsa tags found: {found}, converted: {changed}")
    if not args.apply:
        print("Dry-run only. Re-run with --apply to convert these tags to local.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
