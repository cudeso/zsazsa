#!/usr/bin/env python3
"""Remove legacy deliverable-tlp attributes from PIR and GIR objects in MISP.

By default this script runs in dry-run mode and only reports what would change.
Use --apply to actually delete attributes.

Examples:
    /home/koenv/Documents/zsazsa/.venv/bin/python scripts/remove_requirement_tlp.py
    /home/koenv/Documents/zsazsa/.venv/bin/python scripts/remove_requirement_tlp.py --apply
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

REQ_TAGS = (config.TAG_PIR, config.TAG_GIR)
REQ_OBJECTS = {"zsazsa-pir", "zsazsa-gir"}
TARGET_RELATION = "deliverable-tlp"


def _misp() -> PyMISP:
    return PyMISP(
        config.MISP_WEBAPP_URL,
        config.MISP_WEBAPP_KEY,
        config.MISP_WEBAPP_VERIFYCERT,
        False,
    )


def _iter_targets(event):
    for obj in (getattr(event, "objects", []) or []):
        if getattr(obj, "name", "") not in REQ_OBJECTS:
            continue
        for attr in (getattr(obj, "attributes", []) or []):
            if (getattr(attr, "object_relation", "") or "") == TARGET_RELATION:
                yield obj, attr


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes. Without this flag, run as dry-run.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit number of matching attributes to process (0 = no limit).",
    )
    args = parser.parse_args()

    misp = _misp()
    events = misp.search(tags=list(REQ_TAGS), limit=10000, pythonify=True)
    if not events or isinstance(events, dict):
        print("No PIR/GIR events found or search failed.")
        return 0

    found = 0
    changed = 0

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"Mode: {mode}")

    for event in events:
        event_id = getattr(event, "id", "?")
        event_uuid = getattr(event, "uuid", "?")
        event_info = getattr(event, "info", "") or ""

        for obj, attr in _iter_targets(event):
            found += 1
            obj_name = getattr(obj, "name", "")
            attr_id = getattr(attr, "id", None)
            attr_uuid = getattr(attr, "uuid", None)
            attr_ref = attr_uuid or attr_id
            attr_value = getattr(attr, "value", "")

            print(
                f"- event={event_uuid} ({event_id}) object={obj_name} "
                f"attr={attr_ref} value={attr_value!r} info={event_info!r}"
            )

            if args.apply:
                misp.delete_attribute(attr_ref)
                changed += 1

            if args.limit and found >= args.limit:
                print("Reached --limit, stopping early.")
                print(f"Found: {found}, Changed: {changed}")
                return 0

    print(f"Found: {found}, Changed: {changed}")
    if not args.apply:
        print("Dry-run only. Re-run with --apply to delete these attributes.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
