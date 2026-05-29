#!/usr/bin/env python3
"""Download the MITRE ATT&CK pattern galaxy from the MISP galaxy repository
and store a local cache in data/mitre-attack-pattern.json.

Run once, then re-run periodically to pick up new techniques:
    python scripts/fetch_mitre_galaxy.py
"""
import json
import pathlib
import urllib.request

URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-attack-pattern.json"
OUT = pathlib.Path(__file__).parent.parent / "data" / "mitre-attack-pattern.json"


def main():
    print(f"Fetching {URL} ...")
    with urllib.request.urlopen(URL, timeout=30) as response:
        data = json.load(response)
    values = sorted(v["value"] for v in data["values"] if v.get("value"))
    OUT.write_text(json.dumps(values, indent=2), encoding="utf-8")
    print(f"Saved {len(values)} techniques to {OUT}")


if __name__ == "__main__":
    main()
