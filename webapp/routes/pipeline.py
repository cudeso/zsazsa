import logging
import os
import sqlite3
from datetime import date, timedelta

from flask import Blueprint, flash, redirect, render_template, url_for

import config
from core.db import get_recent_pipeline_runs, get_latest_pipeline_run, event_counts_by_source
from webapp import misp_store

logger = logging.getLogger(__name__)
bp = Blueprint("pipeline", __name__)


def _pipeline_stats():
    if not os.path.exists(config.DB_FILE):
        return None
    try:
        con = sqlite3.connect(config.DB_FILE)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        total = cur.execute("SELECT COUNT(*) FROM event_log").fetchone()[0]

        by_source = event_counts_by_source()

        by_outcome = [
            dict(r) for r in cur.execute(
                "SELECT outcome, COUNT(*) AS n FROM event_log"
                " GROUP BY outcome ORDER BY n DESC"
            ).fetchall()
        ]

        last_7d = cur.execute(
            "SELECT COUNT(*) FROM event_log"
            " WHERE processed_at >= datetime('now', '-7 days')"
        ).fetchone()[0]

        last_30d = cur.execute(
            "SELECT COUNT(*) FROM event_log"
            " WHERE processed_at >= datetime('now', '-30 days')"
        ).fetchone()[0]

        recent_raw = [
            dict(r) for r in cur.execute(
                "SELECT processed_at, event_uuid, event_info, source_feed, outcome, detail"
                " FROM event_log ORDER BY processed_at DESC LIMIT 120"
            ).fetchall()
        ]

        recent = recent_raw
        try:
            candidate_uuids = [r.get("event_uuid") for r in recent_raw if r.get("event_uuid")]
            existing = misp_store.scraper_existing_uuids(candidate_uuids)
            recent = [
                r for r in recent_raw
                if not r.get("event_uuid") or r["event_uuid"] in existing
            ]
        except Exception:
            recent = recent_raw

        con.close()
        return {
            "total": total,
            "by_source": by_source,
            "by_outcome": by_outcome,
            "last_7d": last_7d,
            "last_30d": last_30d,
            "recent": recent[:25],
        }
    except Exception:
        return None


_IOC_TYPES = frozenset({
    "ip-src", "ip-dst", "ip-src|port", "ip-dst|port",
    "domain", "hostname", "url", "uri",
    "md5", "sha1", "sha256", "sha512", "filename|md5", "filename|sha256",
    "email-src", "email-dst",
    "vulnerability",
    "btc", "xmr",
})


def _indicator_stats():
    try:
        misp = misp_store._misp()
        raw = misp.attributes_statistics("type", percentage=False)
        if not isinstance(raw, dict) or "errors" in raw:
            return {"ok": False, "by_type": {}, "total_ioc": 0, "all_total": 0}
        by_type = {k: int(v) for k, v in raw.items() if k in _IOC_TYPES and int(v) > 0}
        return {
            "ok": True,
            "by_type": dict(sorted(by_type.items(), key=lambda x: x[1], reverse=True)),
            "total_ioc": sum(by_type.values()),
            "all_total": sum(int(v) for v in raw.values()),
        }
    except Exception as exc:
        logger.warning("indicator stats failed: %s", exc)
        return {"ok": False, "by_type": {}, "total_ioc": 0, "all_total": 0}


def _source_health():
    from webapp.routes.data_collection import _sources
    from pymisp import PyMISP
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    results = []
    for src in _sources():
        if src["kind"] == "manual":
            results.append({
                "label": src["label"], "url": "", "kind": "manual",
                "ok": True, "version": "", "error": "",
                "last_event_date": "", "event_count": None, "manual": True,
            })
            continue

        row = {"label": src["label"], "url": src.get("url", ""), "kind": src["kind"]}
        if src["kind"] == "scraper":
            conn = misp_store.test_scraper_misp()
        else:
            conn = misp_store._test_connection(
                src.get("url", ""), src.get("api_key", ""), src.get("verify_tls", True),
            )
        row["ok"] = conn.get("ok", False)
        row["version"] = conn.get("version", "")
        row["error"] = conn.get("error", "")

        if row["ok"]:
            try:
                if src["kind"] == "scraper":
                    misp = misp_store._scraper_misp()
                    search_kwargs = dict(tags=[config.SCRAPER_MARKER_TAG], limit=1, page=1, metadata=True, pythonify=True)
                    count_kwargs = dict(tags=[config.SCRAPER_MARKER_TAG], limit=1, page=1, metadata=True, return_format="count")
                else:
                    misp = PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False,
                                  timeout=misp_store.HEALTH_CHECK_TIMEOUT)
                    search_kwargs = dict(limit=1, page=1, metadata=True, pythonify=True)
                    count_kwargs = dict(limit=1, page=1, metadata=True, return_format="count")
                    if src.get("tags"):
                        search_kwargs["tags"] = src["tags"]
                        count_kwargs["tags"] = src["tags"]
                    if src.get("since_days"):
                        cutoff = (date.today() - timedelta(days=int(src["since_days"]))).isoformat()
                        search_kwargs["date_from"] = cutoff

                recent = misp.search(**search_kwargs)
                row["last_event_date"] = str(recent[0].date) if recent and not isinstance(recent, dict) and recent[0].date else ""

                count_resp = misp.search(**count_kwargs)
                if isinstance(count_resp, dict) and "count" in count_resp:
                    row["event_count"] = count_resp["count"]
                elif isinstance(count_resp, int):
                    row["event_count"] = count_resp
                else:
                    row["event_count"] = None
            except Exception as exc:
                logger.debug("source health check failed for %s: %s", src["label"], exc)
                row["last_event_date"] = ""
                row["event_count"] = None
        else:
            row["last_event_date"] = ""
            row["event_count"] = None

        results.append(row)
    return results


def _purge_orphaned_rows():
    if not os.path.exists(config.DB_FILE):
        return 0, 0
    con = sqlite3.connect(config.DB_FILE)
    try:
        cur = con.cursor()
        rows = cur.execute(
            "SELECT DISTINCT event_uuid FROM event_log"
            " WHERE event_uuid IS NOT NULL AND event_uuid != ''"
        ).fetchall()
        candidates = [r[0] for r in rows]
        if not candidates:
            return 0, 0
        existing = misp_store.scraper_existing_uuids(candidates)
        orphans = [u for u in candidates if u not in existing]
        if not orphans:
            return 0, len(candidates)
        deleted = 0
        for i in range(0, len(orphans), 500):
            part = orphans[i:i + 500]
            placeholders = ",".join("?" * len(part))
            cur.execute(f"DELETE FROM event_log WHERE event_uuid IN ({placeholders})", part)
            deleted += cur.rowcount or 0
        con.commit()
        return deleted, len(candidates)
    finally:
        con.close()


def _imap_mailbox_status():
    """Per-mailbox last-poll status, from the most recent IMAP collector run."""
    mailboxes = getattr(config, "IMAP_SOURCES", []) or []
    if not mailboxes:
        return []
    latest = get_latest_pipeline_run("imap-collector")
    polled_at = latest.get("started_at") if latest else None
    by_id = {}
    if latest and latest.get("result"):
        for mb in latest["result"].get("mailboxes", []):
            by_id[mb.get("id")] = mb
    rows = []
    for m in mailboxes:
        record = by_id.get(m.get("id"))
        rows.append({
            "name": m.get("name") or m.get("id"),
            "enabled": m.get("enabled", True),
            "mode": m.get("mode", "auto"),
            "last_polled": polled_at if record else None,
            "status": record.get("status") if record else None,
            "message": record.get("message") if record else None,
        })
    return rows


@bp.route("/pipeline")
def index():
    pipeline = _pipeline_stats()
    recent_runs = get_recent_pipeline_runs(20)
    imap_mailboxes = _imap_mailbox_status()
    scraper_misp = misp_store.test_scraper_misp()
    webapp_misp = misp_store.test_webapp_misp()
    source_health = []
    try:
        source_health = _source_health()
    except Exception as exc:
        logger.warning("source health check failed: %s", exc)
    indicator_stats = _indicator_stats()
    return render_template(
        "pipeline.html",
        pipeline=pipeline,
        recent_runs=recent_runs,
        imap_mailboxes=imap_mailboxes,
        scraper_misp=scraper_misp,
        webapp_misp=webapp_misp,
        source_health=source_health,
        indicator_stats=indicator_stats,
    )


@bp.route("/pipeline/purge-orphaned", methods=["POST"])
def purge_orphaned():
    try:
        deleted, scanned = _purge_orphaned_rows()
        if scanned == 0:
            flash("No analyser history to reconcile.", "info")
        elif deleted == 0:
            flash(f"Reconciled {scanned} entries; nothing to purge.", "info")
        else:
            flash(f"Purged {deleted} orphaned entries (scanned {scanned}).", "success")
    except Exception as exc:
        flash(f"Purge failed: {exc}", "warning")
    return redirect(url_for("pipeline.index"))
