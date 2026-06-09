import json
import logging
import time
from pathlib import Path

import config

logger = logging.getLogger(__name__)


def _load_state() -> dict:
    path = Path(config.STATE_FILE)
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        logger.warning("State file unreadable, starting fresh")
        return {}


def _save_state(state: dict) -> None:
    path = Path(config.STATE_FILE)
    path.parent.mkdir(exist_ok=True)
    with open(path, "w") as f:
        json.dump(state, f)


def load_last_run() -> int | None:
    return _load_state().get("analyser_last_run")


def save_last_run(timestamp: int) -> None:
    state = _load_state()
    state["analyser_last_run"] = timestamp
    _save_state(state)


def get_new_scraper_events(misp) -> list:
    last_run = load_last_run()
    lookback = int(time.time()) - (config.POLL_WINDOW_HOURS * 3600)
    since = max(last_run, lookback) if last_run else lookback

    # MISP REST treats multi-tag filters as OR. Search by the marker only,
    # then keep events that also carry workflow:state="incomplete".
    events = misp.search(
        tags=[config.SCRAPER_MARKER_TAG],
        timestamp=since,
        limit=getattr(config, "MISP_SCRAPER_LIMIT", 500),
        page=1,
        pythonify=True,
    )

    if isinstance(events, dict) and "errors" in events:
        logger.error("MISP search failed: %s", events["errors"])
        return []

    needed = 'workflow:state="incomplete"'
    filtered = [
        e for e in (events or [])
        if any(getattr(t, "name", "") == needed for t in (getattr(e, "tags", []) or []))
    ]

    logger.info("Found %d scraper events to process", len(filtered))
    return filtered
