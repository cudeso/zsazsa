#!/usr/bin/env python3
"""Rename the "Vulnerability exploitation advisory" product to "Vulnerability advisory".

The VEA product type was renamed to the shorter "Vulnerability advisory". The new
name is used everywhere in config and code, but stakeholder subscriptions stored in
MISP before the rename still reference the old name and would no longer match the
product. This script rewrites the old name to the new one in every stakeholder's
subscription list and subscription modes.

By default this script runs in dry-run mode and only reports what would change.
Use --apply to actually rewrite the subscriptions.

Examples:
    /home/koenv/Documents/zsazsa/.venv/bin/python scripts/rename_vea_subscription_product.py
    /home/koenv/Documents/zsazsa/.venv/bin/python scripts/rename_vea_subscription_product.py --apply
"""

from __future__ import annotations

import argparse
import pathlib
import sys

# Ensure repository root is importable when running this script directly.
ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from webapp import misp_store

OLD_NAME = "Vulnerability exploitation advisory"
NEW_NAME = "Vulnerability advisory"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes. Without this flag, run as dry-run.",
    )
    args = parser.parse_args()

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"Mode: {mode}")
    print(f"Renaming {OLD_NAME!r} -> {NEW_NAME!r} in stakeholder subscriptions")

    affected = misp_store.rename_subscription_product(OLD_NAME, NEW_NAME, apply=args.apply)

    for name in affected:
        print(f"- {name}")
    print(f"Stakeholders affected: {len(affected)}")
    if not args.apply:
        print("Dry-run only. Re-run with --apply to rewrite these subscriptions.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
