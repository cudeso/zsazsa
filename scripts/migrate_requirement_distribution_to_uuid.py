#!/usr/bin/env python3
"""Migrate PIR and GIR distribution values from stakeholder names to UUIDs.

The distribution relation historically stored stakeholder names. The current
application stores stakeholder UUIDs. This script rewrites existing PIR/GIR
object distribution arrays to UUIDs when a unique stakeholder match exists.

Default mode is dry-run.

Examples:
    /home/koenv/Documents/zsazsa/.venv/bin/python scripts/migrate_requirement_distribution_to_uuid.py
    /home/koenv/Documents/zsazsa/.venv/bin/python scripts/migrate_requirement_distribution_to_uuid.py --apply
    /home/koenv/Documents/zsazsa/.venv/bin/python scripts/migrate_requirement_distribution_to_uuid.py --verify
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from collections import defaultdict

# Ensure repository root is importable when running this script directly.
ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import config
from pymisp import PyMISP

REQ_TAGS = (config.TAG_PIR, config.TAG_GIR)
REQ_OBJECTS = {"zsazsa-pir", "zsazsa-gir"}
STAKEHOLDER_OBJECT = "zsazsa-stakeholder"
DISTRIBUTION_RELATION = "distribution"
NAME_RELATION = "name"
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}$"
)


def _misp() -> PyMISP:
    return PyMISP(
        config.MISP_WEBAPP_URL,
        config.MISP_WEBAPP_KEY,
        config.MISP_WEBAPP_VERIFYCERT,
        False,
    )


def _obj_attr(obj, relation: str):
    attrs = obj.get_attributes_by_relation(relation)
    return attrs[0].value if attrs else None


def _iter_distribution_attrs(event):
    for obj in (getattr(event, "objects", []) or []):
        if getattr(obj, "name", "") not in REQ_OBJECTS:
            continue
        for attr in (getattr(obj, "attributes", []) or []):
            if (getattr(attr, "object_relation", "") or "") == DISTRIBUTION_RELATION:
                yield obj, attr


def _parse_distribution(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    raw = str(value).strip()
    if not raw:
        return []
    try:
        decoded = json.loads(raw)
        if isinstance(decoded, list):
            return [str(v).strip() for v in decoded if str(v).strip()]
    except Exception:
        pass
    return [raw]


def _stakeholder_maps(misp: PyMISP):
    events = misp.search(tags=[config.TAG_STAKEHOLDER], limit=10000, pythonify=True)
    if not events or isinstance(events, dict):
        return {}, {}

    by_uuid = {}
    by_name = defaultdict(list)

    for event in events:
        event_uuid = getattr(event, "uuid", "") or ""
        if not event_uuid:
            continue
        for obj in (getattr(event, "objects", []) or []):
            if getattr(obj, "name", "") != STAKEHOLDER_OBJECT:
                continue
            name = (_obj_attr(obj, NAME_RELATION) or "").strip()
            if not name:
                continue
            by_uuid[event_uuid] = name
            by_name[name].append(event_uuid)
            break

    return by_uuid, by_name


def _convert(values, stakeholder_uuids, stakeholder_name_to_uuids):
    converted = []
    changed = False
    ambiguous = []
    unresolved = []
    seen = set()

    for raw in values:
        item = (raw or "").strip()
        if not item:
            continue

        out = item
        if UUID_RE.match(item):
            out = item
        else:
            matches = stakeholder_name_to_uuids.get(item, [])
            if len(matches) == 1:
                out = matches[0]
                changed = True
            elif len(matches) > 1:
                ambiguous.append(item)
            else:
                unresolved.append(item)

        if out not in seen:
            seen.add(out)
            converted.append(out)

    return converted, changed, ambiguous, unresolved


def _run_verify(misp: PyMISP, stakeholder_uuids: dict[str, str]) -> int:
    events = misp.search(tags=list(REQ_TAGS), limit=10000, pythonify=True)
    if not events or isinstance(events, dict):
        print("No PIR/GIR events found or search failed.")
        return 0

    bad_entries = 0
    checked_attrs = 0

    for event in events:
        event_uuid = getattr(event, "uuid", "?")
        info = getattr(event, "info", "") or ""
        for obj, attr in _iter_distribution_attrs(event):
            checked_attrs += 1
            values = _parse_distribution(getattr(attr, "value", ""))
            non_uuid = [v for v in values if not UUID_RE.match(v)]
            unknown_uuid = [v for v in values if UUID_RE.match(v) and v not in stakeholder_uuids]
            if non_uuid or unknown_uuid:
                bad_entries += 1
                print(
                    f"- event={event_uuid} object={getattr(obj, 'name', '')} "
                    f"attr={getattr(attr, 'uuid', getattr(attr, 'id', '?'))} info={info!r}"
                )
                if non_uuid:
                    print(f"  non_uuid={non_uuid}")
                if unknown_uuid:
                    print(f"  unknown_uuid={unknown_uuid}")

    print(f"Checked distribution attributes: {checked_attrs}")
    print(f"Attributes with remaining non-UUID or unknown UUID entries: {bad_entries}")
    return 1 if bad_entries else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply updates. Without this flag, run as dry-run.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify-only mode. Report remaining non-UUID distribution values.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit number of changed attributes to process (0 = no limit).",
    )
    args = parser.parse_args()

    misp = _misp()
    stakeholder_uuids, stakeholder_name_to_uuids = _stakeholder_maps(misp)
    print(
        f"Loaded stakeholders: {len(stakeholder_uuids)} unique UUIDs, "
        f"{len(stakeholder_name_to_uuids)} unique names"
    )

    if args.verify:
        return _run_verify(misp, stakeholder_uuids)

    events = misp.search(tags=list(REQ_TAGS), limit=10000, pythonify=True)
    if not events or isinstance(events, dict):
        print("No PIR/GIR events found or search failed.")
        return 0

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"Mode: {mode}")

    seen_attrs = 0
    changed_attrs = 0
    updated_attrs = 0
    unresolved_total = 0
    ambiguous_total = 0

    for event in events:
        event_uuid = getattr(event, "uuid", "?")
        event_info = getattr(event, "info", "") or ""

        for obj, attr in _iter_distribution_attrs(event):
            seen_attrs += 1
            old_values = _parse_distribution(getattr(attr, "value", ""))
            new_values, changed, ambiguous, unresolved = _convert(
                old_values,
                stakeholder_uuids,
                stakeholder_name_to_uuids,
            )

            ambiguous_total += len(ambiguous)
            unresolved_total += len(unresolved)

            if not changed:
                continue

            changed_attrs += 1
            attr_ref = getattr(attr, "uuid", None) or getattr(attr, "id", None) or "?"
            print(
                f"- event={event_uuid} object={getattr(obj, 'name', '')} attr={attr_ref} "
                f"old={old_values} new={new_values} info={event_info!r}"
            )
            if ambiguous:
                print(f"  ambiguous_name_matches={sorted(set(ambiguous))}")
            if unresolved:
                print(f"  unresolved_values={sorted(set(unresolved))}")

            if args.apply:
                attr.value = json.dumps(new_values)
                misp.update_attribute(attr)
                updated_attrs += 1

            if args.limit and changed_attrs >= args.limit:
                print("Reached --limit, stopping early.")
                print(
                    f"Seen attrs: {seen_attrs}, Changed attrs: {changed_attrs}, "
                    f"Updated attrs: {updated_attrs}"
                )
                return 0

    print(f"Seen distribution attrs: {seen_attrs}")
    print(f"Changed attrs: {changed_attrs}")
    print(f"Updated attrs: {updated_attrs}")
    print(f"Ambiguous name matches encountered: {ambiguous_total}")
    print(f"Unresolved values encountered: {unresolved_total}")

    if not args.apply:
        print("Dry-run only. Re-run with --apply to write updates.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
