"""Parsers for security newsletters pasted into the collection importer.

Each parser turns a pasted newsletter into a list of article dicts so the
importer can show them for selection. Parsing is pure text work; nothing here
touches MISP or the network. New newsletters are added by writing a parser and
registering it in PARSERS.
"""

import re

_PRIORITY_RE = re.compile(r'^Priority:\s*(\d)\s*-\s*(.+?)\s*$', re.IGNORECASE)
_RELEVANCE_RE = re.compile(r'^Relevance:\s*(.+?)\s*$', re.IGNORECASE)
_URL_RE = re.compile(r'https?://\S+')
# A "Quick overview" row: a section name followed by three counts.
_OVERVIEW_ROW_RE = re.compile(r'^(.+?)[ \t]+\d+[ \t]+\d+[ \t]+\d+\s*$')
_TLP_RE = re.compile(r'TLP:\s*(CLEAR|WHITE|GREEN|AMBER\+STRICT|AMBER|RED)', re.IGNORECASE)

_PRIORITY_KEYS = {1: "critical", 2: "urgent", 3: "important"}


def _clean_url(token: str) -> str:
    return token.strip().strip("<>").rstrip(">.,);")


def _strip_quotes(text: str) -> str:
    return text.strip().strip('"').strip('“”').strip()


def _etda_section_names(lines: list[str]) -> list[str]:
    """Section names in order, read from the 'Quick overview' table."""
    names = []
    in_overview = False
    for line in lines:
        if line.strip().lower().startswith("quick overview"):
            in_overview = True
            continue
        if in_overview:
            match = _OVERVIEW_ROW_RE.match(line.strip())
            if match:
                names.append(match.group(1).strip())
            elif names:
                break
    return names


def _etda_body_start(lines: list[str]) -> int:
    """Index of the first line after the 'Quick overview' table."""
    seen_row = False
    for idx, line in enumerate(lines):
        if _OVERVIEW_ROW_RE.match(line.strip()):
            seen_row = True
        elif seen_row:
            return idx
    return 0


def parse_etda(text: str) -> dict:
    """Parse an ETDA CTI Robot newsletter into report metadata and articles."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")

    sections = set(_etda_section_names(lines))
    tlp_match = _TLP_RE.search(text)
    tlp = tlp_match.group(1).lower() if tlp_match else ""

    report_title = ""
    for line in lines[:20]:
        if "cyber threat intelligence" in line.lower():
            report_title = line.strip()
            break

    articles = []
    current_section = ""
    pending = []  # lines gathered before a Priority line: [title, intro lines...]

    body = lines[_etda_body_start(lines):]
    i = 0
    while i < len(body):
        line = body[i].strip()
        i += 1
        if not line or line == "↑":  # blank or back-to-top arrow
            if line == "↑":
                pending = []
            continue
        if line in sections:
            current_section = line
            pending = []
            continue

        priority = _PRIORITY_RE.match(line)
        if not priority:
            pending.append(line)
            continue

        title = pending[0] if pending else ""
        intro = _strip_quotes(" ".join(pending[1:])) if len(pending) > 1 else ""
        pending = []

        relevance = ""
        urls = []
        while i < len(body):
            nxt = body[i].strip()
            rel = _RELEVANCE_RE.match(nxt)
            if rel:
                relevance = rel.group(1).strip()
                i += 1
            elif _URL_RE.search(nxt):
                urls.extend(_clean_url(u) for u in _URL_RE.findall(nxt))
                i += 1
            elif not nxt:
                i += 1
            else:
                break  # next title, section header or arrow

        if not title:
            continue
        rank = int(priority.group(1))
        articles.append({
            "section": current_section,
            "title": title,
            "intro": intro,
            "priority_rank": rank,
            "priority_label": priority.group(2).strip(),
            "priority_key": _PRIORITY_KEYS.get(rank, "important"),
            "relevance": relevance,
            "primary_url": urls[0] if urls else "",
            "related_urls": urls[1:],
        })

    return {"report_title": report_title, "tlp": tlp, "articles": articles}


PARSERS = {
    "ETDA CTI Robot": parse_etda,
}


def available_sources() -> list[str]:
    return sorted(PARSERS)


def parse(source_name: str, text: str) -> dict:
    parser = PARSERS.get(source_name)
    if parser is None:
        raise ValueError(f"No parser for newsletter source {source_name!r}")
    return parser(text or "")
