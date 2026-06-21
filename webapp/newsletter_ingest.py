"""Shared newsletter ingest: publish selected article URLs to the scraper queue.

Used by the manual paste flow (data_collection routes), the automated IMAP
collector, and the pending-review approval, so all three build the same
misp-scraper messages and report the same delivery counts. Archiving the
newsletter itself stays in misp_store.create_newsletter_event.
"""

import logging

from webapp import misp_store, scraper_queue
from webapp.redis_client import RedisError

logger = logging.getLogger(__name__)


def _message(source: str, article: dict) -> dict:
    """Build one misp-scraper publish payload from a parsed article."""
    feed_tags = []
    section = (article.get("section") or "").strip()
    if section:
        feed_tags.append(f'zsazsa:newsletter-section="{misp_store.source_slug(section)}"')
    priority = (article.get("priority") or "").strip()
    if priority:
        feed_tags.append(f'zsazsa:newsletter-priority="{priority}"')
    return {
        "link": (article.get("url") or "").strip(),
        "title": (article.get("title") or "").strip(),
        "feed_title": source,
        "feed": source,
        "feed_tags": feed_tags,
    }


def publish_articles(source: str, articles: list[dict]) -> dict:
    """Publish each article's URL to the scraper channel.

    `articles` is a list of dicts with keys url, title, section, priority.
    Returns {"published", "failed", "no_subscriber"} counts. Articles without a
    URL are skipped.
    """
    published = failed = no_subscriber = 0
    for article in articles:
        if not (article.get("url") or "").strip():
            continue
        try:
            receivers = scraper_queue.publish(_message(source, article))
        except (OSError, RedisError) as exc:
            failed += 1
            logger.warning("scraper publish failed for %s: %s", article.get("url"), exc)
        else:
            published += 1
            if receivers == 0:
                no_subscriber += 1
    return {"published": published, "failed": failed, "no_subscriber": no_subscriber}


def articles_from_parsed(parsed: dict) -> list[dict]:
    """Map parser output (newsletter_parsers.parse) to publish-ready article dicts."""
    out = []
    for a in parsed.get("articles", []):
        url = (a.get("primary_url") or "").strip()
        if not url:
            continue
        out.append({
            "url": url,
            "title": a.get("title", ""),
            "section": a.get("section", ""),
            "priority": a.get("priority_key", ""),
        })
    return out
