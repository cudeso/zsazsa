import logging
from collections import Counter
from datetime import date, datetime, timezone

from flask import Blueprint, render_template

from webapp import misp_store

logger = logging.getLogger(__name__)
bp = Blueprint("stats", __name__)


def _program_metrics(pirs, girs):
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

    for p in pirs:
        _il = getattr(p, "intel_level", None)
        lvl = (_il[0] if isinstance(_il, list) and _il else _il) or "Unspecified"
        metrics["intel_levels"]["pir"][lvl] += 1
    for g in girs:
        _il = getattr(g, "intel_level", None)
        lvl = (_il[0] if isinstance(_il, list) and _il else _il) or "Unspecified"
        metrics["intel_levels"]["gir"][lvl] += 1

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


def _maturity_signals(program, pirs, girs, stakeholder_count, source_health):
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


@bp.route("/stats")
def index():
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
    actor_type_product_counts = misp_store.product_counts_by_threat_actor_type()

    from webapp.routes.pipeline import _source_health
    source_health = []
    try:
        source_health = _source_health()
    except Exception as exc:
        logger.warning("source health check failed: %s", exc)

    maturity_signals = _maturity_signals(program, pirs, girs, stakeholder_count, source_health)

    return render_template(
        "stats.html",
        pir_count=pir_count,
        gir_count=gir_count,
        stakeholder_count=stakeholder_count,
        active_pir_count=active_pir_count,
        active_gir_count=active_gir_count,
        pirs_no_fp=pirs_no_fp,
        girs_no_fp=girs_no_fp,
        program=program,
        actor_type_product_counts=actor_type_product_counts,
        maturity_signals=maturity_signals,
    )
