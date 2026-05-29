import logging
import logging.handlers
import time
import warnings
from pathlib import Path

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import config
from analyser.products.flash_intel import process as process_flash_intel
from analyser.reader import get_new_scraper_events, save_last_run
from core.db import init_db, log_event
from core.misp_client import get_misp


def setup_logging() -> None:
    Path(config.LOG_FILE).parent.mkdir(exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    root = logging.getLogger()
    root.setLevel(getattr(logging, config.LOG_LEVEL))

    file_handler = logging.handlers.RotatingFileHandler(
        config.LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    root.addHandler(stream_handler)


def load_focus_points() -> dict:
    return {
        "geographies": list(getattr(config, "FOCUS_POINTS_GEOGRAPHIES", []) or []),
        "sectors": list(getattr(config, "FOCUS_POINTS_SECTORS", []) or []),
        "technologies": list(getattr(config, "FOCUS_POINTS_TECHNOLOGIES", []) or []),
        "threat_types": list(getattr(config, "FOCUS_POINTS_THREAT_TYPES", []) or []),
        "threat_actors": list(getattr(config, "FOCUS_POINTS_THREAT_ACTORS", []) or []),
    }


def main() -> None:
    setup_logging()
    logger = logging.getLogger(__name__)
    run_start = int(time.time())
    logger.info("Analyser started")

    init_db()

    try:
        misp = get_misp()
        focus_points = load_focus_points()
        events = get_new_scraper_events(misp)
    except Exception as e:
        logger.error("Startup failed: %s", e)
        raise

    counts = {"product_created": 0, "not_relevant": 0, "http_error": 0, "no_content": 0, "error": 0}

    for event in events:
        try:
            result = process_flash_intel(misp, event, focus_points)
            outcome = result["outcome"]
            counts[outcome] = counts.get(outcome, 0) + 1

            log_event(
                event_uuid=event.uuid,
                event_info=event.info,
                source_feed=result.get("source_feed", "unknown"),
                outcome=outcome,
                detail=result.get("detail"),
            )

            # Drafts now require manual review/approval in the webapp. The
            # Mattermost alert is sent from the approval endpoint, not here.

        except Exception as e:
            logger.error("Failed to process event %s: %s", event.uuid, e)
            counts["error"] = counts.get("error", 0) + 1
            log_event(
                event_uuid=event.uuid,
                event_info=getattr(event, "info", ""),
                source_feed="unknown",
                outcome="error",
                detail=f"{type(e).__name__}: {e}",
            )

    save_last_run(run_start)
    logger.info(
        "Analyser complete: %d events - %d products, %d not relevant, %d HTTP errors, %d no content, %d errors",
        len(events),
        counts["product_created"],
        counts["not_relevant"],
        counts["http_error"],
        counts["no_content"],
        counts.get("error", 0),
    )


if __name__ == "__main__":
    main()
