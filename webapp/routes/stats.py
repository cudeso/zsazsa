import logging
import os
import sqlite3
from collections import Counter
from datetime import date, datetime, timezone

from flask import render_template, redirect, url_for, flash
from flask import Blueprint

import config
from webapp import misp_store

logger = logging.getLogger(__name__)
bp = Blueprint("stats", __name__)


def _purge_orphaned_rows():
    """Delete event_log rows whose event_uuid is no longer present in scraper MISP.

    Returns (deleted, scanned). No-op when DB does not exist.
    """
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
        chunk = 500
        for i in range(0, len(orphans), chunk):
            part = orphans[i:i + chunk]
            placeholders = ",".join("?" * len(part))
            cur.execute(
                f"DELETE FROM event_log WHERE event_uuid IN ({placeholders})",
                part,
            )
            deleted += cur.rowcount or 0
        con.commit()
        return deleted, len(candidates)
    finally:
        con.close()


def _pipeline_stats():
    if not os.path.exists(config.DB_FILE):
        return None
    try:
        con = sqlite3.connect(config.DB_FILE)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        total = cur.execute("SELECT COUNT(*) FROM event_log").fetchone()[0]

        by_source = [
            dict(r) for r in cur.execute(
                "SELECT source_feed, COUNT(*) AS n FROM event_log"
                " GROUP BY source_feed ORDER BY n DESC"
            ).fetchall()
        ]

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

        recent = recent[:25]

        con.close()
        return {
            "total": total,
            "by_source": by_source,
            "by_outcome": by_outcome,
            "last_7d": last_7d,
            "last_30d": last_30d,
            "recent": recent,
        }
    except Exception:
        return None


def _program_metrics(pirs, girs):
    """Aggregate CTI program health metrics for the leadership view."""
    metrics = {
        "rfis": {"total": 0, "by_status": {}, "open": 0, "overdue": 0,
                  "feedback_collected": 0, "feedback_met": 0,
                  "feedback_on_time": 0},
        "products": {"total": 0, "by_type": {}, "with_pir_link": 0,
                      "with_feedback": 0, "last_30d": 0, "last_7d": 0},
        "intel_levels": {"pir": Counter(), "gir": Counter()},
        "stakeholder_coverage": {"with_pir": 0, "without_pir": 0},
        "pir_coverage": {"covered": 0, "uncovered": 0, "pct": 0.0},
        "collection_gaps": {
            "pirs_with_sources": 0, "pirs_without_sources": 0,
            "girs_with_sources": 0, "girs_without_sources": 0,
        },
    }

    # ── RFIs ─────────────────────────────────────────────────────────────
    try:
        rfis = misp_store.list_rfis()
    except Exception:
        rfis = []
    today = date.today()
    for r in rfis:
        metrics["rfis"]["total"] += 1
        metrics["rfis"]["by_status"][r.status] = (
            metrics["rfis"]["by_status"].get(r.status, 0) + 1
        )
        if r.status not in ("Delivered", "Closed"):
            metrics["rfis"]["open"] += 1
            if r.due_date and r.due_date < today:
                metrics["rfis"]["overdue"] += 1
        if r.feedback_requirement_met or r.feedback_on_time or r.feedback_usefulness:
            metrics["rfis"]["feedback_collected"] += 1
        if r.feedback_requirement_met == "Yes":
            metrics["rfis"]["feedback_met"] += 1
        if r.feedback_on_time == "Yes":
            metrics["rfis"]["feedback_on_time"] += 1

    # ── Products ────────────────────────────────────────────────────────
    try:
        misp = misp_store._misp()
        events = misp.search(
            tags=['zsazsa:ctiproduct="%"'], limit=500,
            metadata=False, pythonify=True,
        )
        if isinstance(events, dict):
            events = []
    except Exception:
        events = []

    pir_ids = {p.pir_id for p in pirs if p.pir_id}
    now_ts = datetime.now(timezone.utc).timestamp()
    pirs_covered = set()
    for ev in events or []:
        ev_tags = [t.name for t in (getattr(ev, "tags", []) or [])]
        ptype = ""
        for t in ev_tags:
            if t.startswith('zsazsa:ctiproduct='):
                ptype = t.split('=', 1)[1].strip('"')
                break
        metrics["products"]["total"] += 1
        if ptype:
            metrics["products"]["by_type"][ptype] = (
                metrics["products"]["by_type"].get(ptype, 0) + 1
            )
        info = ev.info or ""
        matched_pirs = [pid for pid in pir_ids if pid in info]
        if matched_pirs:
            metrics["products"]["with_pir_link"] += 1
            pub_ts = getattr(ev, "publish_timestamp", None) or getattr(ev, "timestamp", None)
            try:
                pub_ts = int(pub_ts)
            except (TypeError, ValueError):
                pub_ts = 0
            if pub_ts and (now_ts - pub_ts) <= 90 * 86400:
                pirs_covered.update(matched_pirs)
        if 'curation:feedback' in ev_tags:
            metrics["products"]["with_feedback"] += 1
        pub_ts = getattr(ev, "publish_timestamp", None) or getattr(ev, "timestamp", None)
        try:
            pub_ts = int(pub_ts)
        except (TypeError, ValueError):
            pub_ts = 0
        if pub_ts:
            age_days = (now_ts - pub_ts) / 86400
            if age_days <= 7:
                metrics["products"]["last_7d"] += 1
            if age_days <= 30:
                metrics["products"]["last_30d"] += 1

    active_pir_ids = {p.pir_id for p in pirs if p.pir_id and getattr(p, "status", "") == "Active"}
    metrics["pir_coverage"]["covered"] = len(pirs_covered & active_pir_ids)
    metrics["pir_coverage"]["uncovered"] = len(active_pir_ids - pirs_covered)

    # ── Intel level coverage ────────────────────────────────────────────
    for p in pirs:
        _il = getattr(p, "intel_level", None)
        lvl = (_il[0] if isinstance(_il, list) and _il else _il) or "Unspecified"
        metrics["intel_levels"]["pir"][lvl] += 1
    for g in girs:
        _il = getattr(g, "intel_level", None)
        lvl = (_il[0] if isinstance(_il, list) and _il else _il) or "Unspecified"
        metrics["intel_levels"]["gir"][lvl] += 1

    # ── Collection source mapping gaps ──────────────────────────────────
    for p in pirs:
        if getattr(p, "status", "") == "Active":
            if getattr(p, "collection_sources", None):
                metrics["collection_gaps"]["pirs_with_sources"] += 1
            else:
                metrics["collection_gaps"]["pirs_without_sources"] += 1
    for g in girs:
        if getattr(g, "status", "") == "Active":
            if getattr(g, "collection_sources", None):
                metrics["collection_gaps"]["girs_with_sources"] += 1
            else:
                metrics["collection_gaps"]["girs_without_sources"] += 1

    # ── Stakeholder coverage ────────────────────────────────────────────
    pir_owners = {p.owner_uuid for p in pirs if p.owner_uuid}
    try:
        stakeholders = misp_store.list_stakeholders()
    except Exception:
        stakeholders = []
    for s in stakeholders:
        if s.id in pir_owners:
            metrics["stakeholder_coverage"]["with_pir"] += 1
        else:
            metrics["stakeholder_coverage"]["without_pir"] += 1

    # ── Derived ratios ──────────────────────────────────────────────────
    def _pct(num, den):
        return round(100.0 * num / den, 1) if den else 0.0

    metrics["products"]["pct_with_pir_link"] = _pct(
        metrics["products"]["with_pir_link"], metrics["products"]["total"]
    )
    metrics["products"]["pct_with_feedback"] = _pct(
        metrics["products"]["with_feedback"], metrics["products"]["total"]
    )
    metrics["rfis"]["pct_feedback_collected"] = _pct(
        metrics["rfis"]["feedback_collected"], metrics["rfis"]["total"]
    )
    metrics["rfis"]["pct_on_time"] = _pct(
        metrics["rfis"]["feedback_on_time"], metrics["rfis"]["feedback_collected"]
    )
    metrics["stakeholder_coverage"]["pct_covered"] = _pct(
        metrics["stakeholder_coverage"]["with_pir"],
        metrics["stakeholder_coverage"]["with_pir"] + metrics["stakeholder_coverage"]["without_pir"],
    )
    metrics["pir_coverage"]["pct"] = _pct(
        metrics["pir_coverage"]["covered"],
        metrics["pir_coverage"]["covered"] + metrics["pir_coverage"]["uncovered"],
    )

    return metrics


_IOC_TYPES = frozenset({
    "ip-src", "ip-dst", "ip-src|port", "ip-dst|port",
    "domain", "hostname", "url", "uri",
    "md5", "sha1", "sha256", "sha512", "filename|md5", "filename|sha256",
    "email-src", "email-dst",
    "vulnerability",
    "btc", "xmr",
})


def _indicator_stats():
    """Return attribute type counts from MISP, filtered to common IoC types."""
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


def _maturity_signals(program, pirs, girs, stakeholder_count, source_health):
    """Derive observable CTI-CMM maturity signals from zsazsa data.

    Returns a list of domain dicts with indicative maturity levels. These are
    observable signals only, not a definitive CMM score.
    """
    level_label = {0: "CTI0", 1: "CTI1", 2: "CTI2", 3: "CTI3"}
    level_color = {0: "secondary", 1: "warning", 2: "primary", 3: "success"}

    def _signal(domain, level, observed, gaps):
        return {
            "domain": domain,
            "level": level_label[level],
            "color": level_color[level],
            "observed": observed,
            "gaps": gaps,
        }

    active_pirs = sum(1 for p in pirs if getattr(p, "status", "") == "Active")
    active_girs = sum(1 for g in girs if getattr(g, "status", "") == "Active")
    by_type = program["products"]["by_type"]
    pct_feedback = program["products"]["pct_with_feedback"]
    pct_pir_link = program["products"]["pct_with_pir_link"]
    pir_cov_pct = program["pir_coverage"]["pct"]
    pct_rfi_feedback = program["rfis"]["pct_feedback_collected"]
    sources_ok = sum(1 for s in source_health if s.get("ok"))
    pirs_with_sources = program["collection_gaps"]["pirs_with_sources"]
    fi_count = by_type.get("flash-intel", 0)
    vea_count = by_type.get("vea", 0)
    tlr_count = by_type.get("threat-landscape-report", 0)
    feedback_count = program["products"]["with_feedback"]

    results = []

    # PROGRAM domain: governance, requirements, stakeholder alignment
    if stakeholder_count > 0 and (active_pirs > 0 or active_girs > 0):
        if active_pirs >= 3 and pct_pir_link >= 50 and pir_cov_pct > 0:
            if pct_feedback >= 30 and pir_cov_pct >= 75:
                level = 3
                observed = [
                    f"{stakeholder_count} stakeholders defined",
                    f"{active_pirs} active PIRs",
                    f"{pct_pir_link}% products linked to requirements",
                    f"{pct_feedback}% products have feedback",
                    f"{pir_cov_pct}% PIR coverage",
                ]
                gaps = []
            else:
                level = 2
                observed = [
                    f"{stakeholder_count} stakeholders defined",
                    f"{active_pirs} active PIRs",
                    f"{pct_pir_link}% products linked to requirements",
                ]
                gaps = []
                if pct_feedback < 30:
                    gaps.append(f"Feedback rate below 30% (currently {pct_feedback}%)")
                if pir_cov_pct < 75:
                    gaps.append(f"PIR coverage below 75% (currently {pir_cov_pct}%)")
        else:
            level = 1
            observed = [
                f"{stakeholder_count} stakeholders defined",
                f"{active_pirs} active PIRs / {active_girs} active GIRs",
            ]
            gaps = []
            if active_pirs < 3:
                gaps.append(f"Fewer than 3 active PIRs (currently {active_pirs})")
            if pct_pir_link < 50:
                gaps.append(f"Products linked to PIRs below 50% (currently {pct_pir_link}%)")
    else:
        level = 0
        observed = []
        gaps = ["No stakeholders or intelligence requirements defined"]
    results.append(_signal("Program", level, observed, gaps))

    # SITUATION domain: collection sources, PIR-source mapping, landscape reporting
    if sources_ok > 0:
        if tlr_count > 0 and pirs_with_sources > 0:
            if pir_cov_pct >= 75:
                level = 3
                observed = [
                    f"{sources_ok} active collection sources",
                    f"{pirs_with_sources} PIRs mapped to sources",
                    f"{tlr_count} threat landscape reports",
                    f"{pir_cov_pct}% PIR coverage",
                ]
                gaps = []
            else:
                level = 2
                observed = [
                    f"{sources_ok} active collection sources",
                    f"{pirs_with_sources} PIRs mapped to sources",
                    f"{tlr_count} threat landscape reports",
                ]
                gaps = [f"PIR coverage below 75% (currently {pir_cov_pct}%)"]
        else:
            level = 1
            observed = [f"{sources_ok} active collection sources"]
            gaps = []
            if tlr_count == 0:
                gaps.append("No threat landscape reports produced yet")
            if pirs_with_sources == 0:
                gaps.append("No PIRs mapped to collection sources")
    else:
        level = 0
        observed = []
        gaps = ["No active collection sources configured"]
    results.append(_signal("Situation", level, observed, gaps))

    # THREAT domain: intelligence production volume and requirement linkage
    if fi_count > 0 or vea_count > 0:
        if fi_count >= 3 and vea_count >= 3:
            if pct_pir_link >= 75:
                level = 3
                observed = [
                    f"{fi_count} flash intel alerts",
                    f"{vea_count} vulnerability assessments",
                    f"{pct_pir_link}% products linked to requirements",
                ]
                gaps = []
            else:
                level = 2
                observed = [
                    f"{fi_count} flash intel alerts",
                    f"{vea_count} vulnerability assessments",
                ]
                gaps = [f"Products linked to PIRs below 75% (currently {pct_pir_link}%)"]
        else:
            level = 1
            observed = [x for x in [
                f"{fi_count} flash intel alerts" if fi_count > 0 else "",
                f"{vea_count} vulnerability assessments" if vea_count > 0 else "",
            ] if x]
            gaps = []
            if fi_count < 3:
                gaps.append(f"Fewer than 3 flash intel alerts (currently {fi_count})")
            if vea_count < 3:
                gaps.append(f"Fewer than 3 vulnerability assessments (currently {vea_count})")
    else:
        level = 0
        observed = []
        gaps = ["No intelligence products (flash intel or VEAs) produced"]
    results.append(_signal("Threat", level, observed, gaps))

    # RESPONSE domain: feedback collection and continuous improvement loop
    if feedback_count > 0:
        if pct_feedback >= 60 and pct_rfi_feedback >= 50:
            level = 3
            observed = [
                f"{pct_feedback}% of products have feedback",
                f"{pct_rfi_feedback}% of RFIs have feedback",
            ]
            gaps = []
        elif pct_feedback >= 30:
            level = 2
            observed = [f"{pct_feedback}% of products have feedback"]
            gaps = []
            if pct_feedback < 60:
                gaps.append(f"Feedback rate below 60% (currently {pct_feedback}%)")
            if pct_rfi_feedback < 50:
                gaps.append(f"RFI feedback rate below 50% (currently {pct_rfi_feedback}%)")
        else:
            level = 1
            observed = [f"{feedback_count} products with feedback collected"]
            gaps = [f"Feedback rate below 30% (currently {pct_feedback}%)"]
    else:
        level = 0
        observed = []
        gaps = ["No feedback collected on any intelligence product"]
    results.append(_signal("Response", level, observed, gaps))

    return results


def _product_counts_by_threat_actor_type():
    """Count products by threat actor type for briefings and flash intel.

    Counts are per product, not per story occurrence: if a briefing has the
    same actor type on multiple stories, it contributes 1 to that type.
    """
    briefing_counter = Counter()
    fia_counter = Counter()

    try:
        briefings = misp_store.list_briefings()
    except Exception:
        briefings = []
    try:
        fias = misp_store.list_fias()
    except Exception:
        fias = []

    for briefing in briefings or []:
        types = set()
        for story in getattr(briefing, "stories", []) or []:
            for actor_type in getattr(story, "threat_actor_types", []) or []:
                cleaned = (actor_type or "").strip()
                if cleaned:
                    types.add(cleaned)
        if not types:
            types = {"Unspecified"}
        for actor_type in types:
            briefing_counter[actor_type] += 1

    for fia in fias or []:
        types = {
            (actor_type or "").strip()
            for actor_type in (getattr(fia, "actor_types", []) or [])
            if (actor_type or "").strip()
        }
        if not types:
            types = {"Unspecified"}
        for actor_type in types:
            fia_counter[actor_type] += 1

    all_types = sorted(
        set(briefing_counter.keys()) | set(fia_counter.keys()),
        key=lambda x: (x.lower() == "unspecified", x.lower()),
    )

    rows = []
    for actor_type in all_types:
        briefing_n = briefing_counter.get(actor_type, 0)
        fia_n = fia_counter.get(actor_type, 0)
        rows.append(
            {
                "actor_type": actor_type,
                "daily_briefings": briefing_n,
                "flash_intel_alerts": fia_n,
                "total": briefing_n + fia_n,
            }
        )
    return rows


def _source_health():
    """Check connectivity and event volume for each configured collection source.

    Returns a list of dicts suitable for rendering in the source health card.
    """
    from webapp.routes.data_collection import _sources
    from pymisp import PyMISP
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    results = []
    for src in _sources():
        if src["kind"] == "manual":
            results.append({
                "label": src["label"],
                "url": "",
                "kind": "manual",
                "ok": True,
                "version": "",
                "error": "",
                "last_event_date": "",
                "event_count": None,
                "manual": True,
            })
            continue

        row = {
            "label": src["label"],
            "url": src.get("url", ""),
            "kind": src["kind"],
        }
        if src["kind"] == "scraper":
            conn = misp_store.test_scraper_misp()
        else:
            conn = misp_store._test_connection(
                src.get("url", ""), src.get("api_key", ""),
                src.get("verify_tls", True),
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
                    misp = PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False)
                    search_kwargs = dict(limit=1, page=1, metadata=True, pythonify=True)
                    count_kwargs = dict(limit=1, page=1, metadata=True, return_format="count")
                    if src.get("tags"):
                        search_kwargs["tags"] = src["tags"]
                        count_kwargs["tags"] = src["tags"]
                    if src.get("since_days"):
                        from datetime import timedelta
                        cutoff = (date.today() - timedelta(days=int(src["since_days"]))).isoformat()
                        search_kwargs["date_from"] = cutoff

                recent = misp.search(**search_kwargs)
                if recent and not isinstance(recent, dict):
                    ev = recent[0]
                    row["last_event_date"] = str(ev.date) if ev.date else ""
                else:
                    row["last_event_date"] = ""

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


@bp.route("/stats")
def index():
    pipeline = _pipeline_stats()

    try:
        c = misp_store.counts()
        pir_count = c["pir"]
        gir_count = c["gir"]
        stakeholder_count = c["stakeholder"]

        pirs = misp_store.list_pirs()
        girs = misp_store.list_girs()
        active_pir_count = sum(1 for p in pirs if p.status == "Active")
        active_gir_count = sum(1 for g in girs if g.status == "Active")
        pirs_no_fp = sum(1 for p in pirs if p.status == "Active" and not p.focus_points)
        girs_no_fp = sum(1 for g in girs if g.status == "Active" and not g.focus_points)
    except Exception:
        pir_count = gir_count = stakeholder_count = 0
        active_pir_count = active_gir_count = 0
        pirs_no_fp = girs_no_fp = 0
        pirs, girs = [], []

    program = _program_metrics(pirs, girs)

    scraper_misp = misp_store.test_scraper_misp()
    webapp_misp = misp_store.test_webapp_misp()

    source_health = []
    try:
        source_health = _source_health()
    except Exception as exc:
        logger.warning("source health check failed: %s", exc)

    indicator_stats = _indicator_stats()
    actor_type_product_counts = _product_counts_by_threat_actor_type()

    maturity_signals = _maturity_signals(program, pirs, girs, stakeholder_count, source_health)

    return render_template(
        "stats.html",
        pipeline=pipeline,
        pir_count=pir_count,
        gir_count=gir_count,
        stakeholder_count=stakeholder_count,
        active_pir_count=active_pir_count,
        active_gir_count=active_gir_count,
        pirs_no_fp=pirs_no_fp,
        girs_no_fp=girs_no_fp,
        scraper_misp=scraper_misp,
        webapp_misp=webapp_misp,
        program=program,
        source_health=source_health,
        indicator_stats=indicator_stats,
        actor_type_product_counts=actor_type_product_counts,
        maturity_signals=maturity_signals,
    )


@bp.route("/stats/purge-orphaned", methods=["POST"])
def purge_orphaned():
    """Drop event_log rows whose source MISP event no longer exists.

    The analyser writes a row per processed event into the local SQLite DB.
    When events are later removed from the scraper MISP, those rows linger
    and skew the aggregates. This action reconciles the log with current MISP.
    """
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
    return redirect(url_for("stats.index"))
