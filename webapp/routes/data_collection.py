"""Browse MISP collection events without opening MISP.

The list page reads from the local SQLite cache populated by
webapp.collection_cache (background worker). The detail page fetches
one event live - a single event fetch is fast; querying hundreds is not.
"""

import concurrent.futures
import logging
import re
import time
from collections import Counter

_TECH_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')

import urllib3
import datetime

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from pymisp import PyMISP, MISPEventReport

import config
from webapp import audit, collection_cache, matching as _matching, misp_store
from webapp.rate_limit import rate_limited
from webapp.utils import json_body as _json_object

_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

bp = Blueprint("data_collection", __name__, url_prefix="/collection")

_DEFAULT_LIMIT = 100
_SCRAPER_SOURCE_ID = "scraper"

_THREAT_LEVELS = {1: "High", 2: "Medium", 3: "Low", 4: "Undefined"}
_ANALYSIS_STATES = {0: "Initial", 1: "Ongoing", 2: "Completed"}


def _split_tags(s: str) -> list[str]:
    if not s:
        return []
    parts = []
    for chunk in s.split(","):
        for tok in chunk.split():
            tok = tok.strip()
            if tok:
                parts.append(tok)
    return parts


def _source_slug(name: str) -> str:
    return name.lower().replace(" ", "-").replace("/", "-")


def _sources() -> list[dict]:
    out = [{
        "id": _SCRAPER_SOURCE_ID,
        "label": "MISP scraper",
        "kind": "scraper",
        "url": config.MISP_URL,
    }]
    for s in getattr(config, "MISP_SERVERS", []) or []:
        if not s.get("enabled", True):
            continue
        out.append({
            "id": s.get("id") or s.get("label"),
            "label": s.get("label") or s.get("id"),
            "kind": "misp",
            "url": s.get("url"),
            "api_key": s.get("api_key"),
            "verify_tls": s.get("verify_tls", True),
            "tags": _split_tags(s.get("tags", "")),
            "tags_and": _split_tags(s.get("tags_and", "")),
            "tags_not": _split_tags(s.get("tags_not", "")),
            "org_filter_type": s.get("org_filter_type", "") or "",
            "org_filter": _split_tags(s.get("org_filter", "")),
            "since_days": int(s.get("since_days") or 7),
        })
    try:
        for src in misp_store.list_collection_sources():
            if src.enabled:
                slug = _source_slug(src.name)
                out.append({
                    "id": f"manual-{slug}",
                    "label": src.name,
                    "kind": "manual",
                    "url": config.MISP_WEBAPP_URL,
                    "source_uuid": src.uuid,
                })
    except Exception as exc:
        logger.warning("Could not load manual collection sources from MISP: %s", exc)
    return out


def _find_source(source_id: str) -> dict | None:
    for s in _sources():
        if s["id"] == source_id:
            return s
    return None


def _extract_event_detail(event) -> dict:
    """Pull rich display fields from a fully-loaded MISPEvent object."""
    org_name = orgc_name = ""
    org_obj = getattr(event, "Org", None) or getattr(event, "org", None)
    orgc_obj = getattr(event, "Orgc", None) or getattr(event, "orgc", None)
    if org_obj:
        org_name = getattr(org_obj, "name", "") or ""
    if orgc_obj:
        orgc_name = getattr(orgc_obj, "name", "") or ""

    tags = []
    for t in getattr(event, "tags", []) or []:
        tags.append({"name": t.name, "colour": getattr(t, "colour", "#aaa") or "#aaa"})

    galaxies = []
    for g in getattr(event, "galaxies", []) or []:
        clusters = []
        for cl in getattr(g, "clusters", []) or []:
            clusters.append({
                "value": getattr(cl, "value", "") or "",
                "description": (getattr(cl, "description", "") or "")[:200],
            })
        if clusters:
            galaxies.append({"name": getattr(g, "name", "") or "", "clusters": clusters})

    attributes = []
    for a in getattr(event, "attributes", []) or []:
        attributes.append({
            "type": a.type,
            "category": getattr(a, "category", "") or "",
            "value": a.value,
            "comment": getattr(a, "comment", "") or "",
            "to_ids": bool(getattr(a, "to_ids", False)),
        })

    objects = []
    for obj in getattr(event, "objects", []) or []:
        obj_attrs = []
        for a in getattr(obj, "attributes", []) or []:
            obj_attrs.append({
                "relation": getattr(a, "object_relation", "") or "",
                "type": a.type,
                "value": a.value,
                "comment": getattr(a, "comment", "") or "",
            })
        objects.append({
            "name": getattr(obj, "name", "") or "",
            "meta_category": getattr(obj, "meta_category", "") or "",
            "comment": getattr(obj, "comment", "") or "",
            "attributes": obj_attrs,
        })

    return {
        "uuid": event.uuid,
        "id": event.id,
        "info": event.info,
        "date": str(event.date) if event.date else "",
        "org": org_name,
        "orgc": orgc_name,
        "tags": tags,
        "galaxies": galaxies,
        "attributes": attributes,
        "objects": objects,
        "threat_level": _THREAT_LEVELS.get(int(getattr(event, "threat_level_id", 4) or 4), "Undefined"),
        "analysis": _ANALYSIS_STATES.get(int(getattr(event, "analysis", 0) or 0), "Initial"),
        "attribute_count": int(getattr(event, "attribute_count", 0) or 0),
    }


@bp.route("/")
def index():
    try:
        limit = max(1, min(int(request.args.get("limit", _DEFAULT_LIMIT)), 500))
    except ValueError:
        limit = _DEFAULT_LIMIT

    sources = _sources()
    label_map = {s["id"]: s["label"] for s in sources}
    all_source_ids = [s["id"] for s in sources]

    # Always load a large set from cache; the limit is applied client-side.
    events = collection_cache.get_events(all_source_ids, [], 2000)
    kind_map = {s["id"]: s["kind"] for s in sources}
    for ev in events:
        ev["source_label"] = label_map.get(ev["source_id"], ev["source_id"])
        ev["source_kind"] = kind_map.get(ev["source_id"], "misp")

    # PIR/GIR relevance matching
    try:
        pirs, girs = _matching.get_requirements()
        req_matches = _matching.match_events(events, pirs, girs)
        for ev in events:
            ev["req_matches"] = req_matches.get(ev["uuid"], [])
    except Exception as exc:
        logger.warning("PIR/GIR matching error: %s", exc)
        for ev in events:
            ev["req_matches"] = []

    # Cache status per source
    cache_status = collection_cache.get_source_status()
    source_errors = {sid: st["error"] for sid, st in cache_status.items() if st.get("error")}
    now = time.time()
    cache_ages = {}
    for sid, st in cache_status.items():
        if st.get("last_fetch"):
            cache_ages[sid] = int((now - st["last_fetch"]) / 60)

    # Tag frequency map
    counter = Counter()
    for ev in events:
        for t in ev["tags"]:
            if t and t != config.SCRAPER_MARKER_TAG:
                counter[t] += 1
    all_tags = sorted(counter.keys(), key=str.casefold)

    # Org list: {org_name: {source_id: source_label}} - only non-empty orgs
    org_map: dict[str, dict[str, str]] = {}
    for ev in events:
        org = (ev.get("orgc") or "").strip()
        if org:
            if org not in org_map:
                org_map[org] = {}
            sid = ev["source_id"]
            org_map[org][sid] = label_map.get(sid, sid)
    org_list = sorted(
        [{"name": k, "sources": v} for k, v in org_map.items()],
        key=lambda x: x["name"].lower(),
    )

    total_reports = sum(ev.get("report_count", 0) for ev in events)
    has_manual_sources = any(s.get("kind") == "manual" for s in sources)

    followup_tag = getattr(config, "TAG_COLLECTION_FOLLOWUP", 'zsazsa:collection="follow-up"')

    return render_template(
        "data_collection/list.html",
        events=events,
        all_tags=all_tags,
        org_list=org_list,
        limit=limit,
        marker_tag=config.SCRAPER_MARKER_TAG,
        followup_tag=followup_tag,
        total_reports=total_reports,
        sources=sources,
        has_manual_sources=has_manual_sources,
        source_errors=source_errors,
        cache_ages=cache_ages,
        cache_status=cache_status,
    )


@bp.route("/refresh", methods=["POST"])
def refresh():
    collection_cache.trigger_refresh()
    return jsonify({"ok": True, "message": "Refresh triggered"})


_PULL_TIMEOUT = 10  # seconds


def _resolve_pull_source(source_id: str):
    """Build source info from config only - no MISP network calls."""
    if source_id == _SCRAPER_SOURCE_ID:
        return {"id": source_id, "kind": "scraper"}
    for s in getattr(config, "MISP_SERVERS", []) or []:
        if not s.get("enabled", True):
            continue
        sid = s.get("id") or s.get("label")
        if sid == source_id:
            return {
                "id": sid, "kind": "misp",
                "url": s.get("url"), "api_key": s.get("api_key"),
                "verify_tls": s.get("verify_tls", True),
            }
    return None


def _fetch_event_timed(misp, uuid, timeout):
    """Run get_event + get_event_reports in a thread with a hard wall-clock timeout."""
    def _work():
        event = misp.get_event(uuid, pythonify=True)
        if not event or isinstance(event, dict):
            return None, []
        try:
            reports = misp.get_event_reports(event.id, pythonify=True) or []
        except Exception:
            reports = []
        return event, reports

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_work)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise TimeoutError(f"MISP did not respond within {timeout}s")


@bp.route("/pull", methods=["POST"])
@rate_limited("collection_pull", limit=30, window_s=60)
def pull():
    data, err = _json_object()
    if err:
        return err
    uuid = (data.get("uuid") or "").strip()
    source_id = (data.get("source_id") or "").strip()

    if not uuid:
        return jsonify({"ok": False, "error": "UUID is required"}), 400
    if not source_id:
        return jsonify({"ok": False, "error": "Source is required"}), 400
    if not _UUID_RE.match(uuid):
        return jsonify({"ok": False, "error": f"'{uuid}' is not a valid MISP UUID"}), 400

    src = _resolve_pull_source(source_id)
    if src is None:
        return jsonify({"ok": False, "error": "Unknown or unsupported source"}), 400

    logger.info("pull: requesting %s from source '%s'", uuid, source_id)

    if src["kind"] == "misp":
        if not src.get("api_key"):
            return jsonify({"ok": False, "error": "Source not configured (missing API key)"}), 502
        try:
            misp = PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False,
                          timeout=_PULL_TIMEOUT)
        except Exception as exc:
            logger.warning("pull: could not connect to %s: %s", source_id, exc)
            return jsonify({"ok": False, "error": "Could not connect to source."}), 502
    else:
        misp = misp_store._scraper_misp()

    try:
        event, reports = _fetch_event_timed(misp, uuid, _PULL_TIMEOUT)
    except TimeoutError as exc:
        logger.warning("pull: %s from %s: %s", uuid, source_id, exc)
        return jsonify({"ok": False, "error": str(exc)}), 504
    except Exception as exc:
        logger.warning("pull: %s from %s failed: %s", uuid, source_id, exc)
        return jsonify({"ok": False, "error": "Could not fetch event."}), 502

    if event is None:
        return jsonify({"ok": False, "error": "Event not found"}), 404

    row = collection_cache._extract_row(event, source_id)
    row["report_count"] = len(reports)
    collection_cache.insert_event(row)

    audit.record(
        "pull", "misp-event",
        entity_id=uuid,
        entity_label=event.info or uuid,
        details=f"Manually pulled into cache from source '{source_id}'",
    )

    return jsonify({"ok": True, "message": f"Event '{event.info}' pulled into cache", "uuid": uuid})


@bp.route("/<string:uuid>")
def detail(uuid):
    source_id = request.args.get("source") or _SCRAPER_SOURCE_ID
    src = _find_source(source_id)
    if src and src["kind"] == "manual":
        misp = misp_store._misp()
        misp_url_base = config.MISP_WEBAPP_URL.rstrip("/")
    elif src and src["kind"] == "misp":
        if not src.get("api_key"):
            return "Source not configured (missing API key)", 502
        try:
            misp = PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False)
        except Exception as exc:
            logger.warning("Could not connect to MISP server %s: %s", source_id, exc)
            return "Source not available", 502
        misp_url_base = src["url"].rstrip("/")
    else:
        misp = misp_store._scraper_misp()
        misp_url_base = config.MISP_URL.rstrip("/")

    try:
        event = misp.get_event(uuid, pythonify=True)
    except Exception as exc:
        logger.warning("MISP get_event %s failed: %s", uuid, exc)
        return "Event not available", 502

    if not event or isinstance(event, dict):
        return "Event not found", 404

    try:
        reports = misp.get_event_reports(event.id, pythonify=True) or []
    except Exception as exc:
        logger.warning("Could not load event reports for %s: %s", uuid, exc)
        reports = []

    report_views = []
    for r in reports:
        report_views.append({
            "name": getattr(r, "name", "") or "Report",
            "content": getattr(r, "content", "") or "",
            "tags": [t.name for t in getattr(r, "tags", []) or []],
        })

    event_data = _extract_event_detail(event)
    misp_url = f"{misp_url_base}/events/view/{event.uuid}"
    source_label = (src or {}).get("label", source_id)

    return render_template(
        "data_collection/detail.html",
        event=event_data,
        reports=report_views,
        misp_url=misp_url,
        source_label=source_label,
        source_id=source_id,
    )


def _parse_scope_from_summary(text):
    """Extract sectors, geo names, and MITRE T-numbers from the LLM summary output."""
    sectors, geo, techniques = [], [], []
    for line in text.split('\n'):
        s = line.strip()
        sl = s.lower()
        if sl.startswith('- targeted sector'):
            val = s.split(':', 1)[1].strip() if ':' in s else ''
            if val and val.lower() != 'none identified':
                sectors = [v.strip() for v in val.split(',') if v.strip()]
        elif sl.startswith('- geographic scope'):
            val = s.split(':', 1)[1].strip() if ':' in s else ''
            if val and val.lower() != 'none identified':
                geo = [v.strip() for v in val.split(',') if v.strip()]
        elif sl.startswith('- mitre att'):
            val = s.split(':', 1)[1].strip() if ':' in s else ''
            if val and val.lower() != 'none identified':
                techniques = _TECH_RE.findall(val)
    return sectors, geo, techniques


def _apply_scope_tags(misp, event, sectors, geo, techniques):
    """Resolve extracted scope values to MISP galaxy tags and tag the event."""
    existing = {t.name for t in getattr(event, 'tags', []) or []}
    tags_to_apply = misp_store._build_scope_tags({
        'geographic_scope': geo,
        'sectors': sectors,
    })
    # Resolve MITRE T-numbers to galaxy tag names
    if techniques:
        mitre_map = misp_store._galaxy_tag_map(misp_store.GALAXY_MITRE_ATTACK)
        for cluster_value, tag_name in mitre_map.items():
            m = _TECH_RE.search(cluster_value)
            if m and m.group(0) in techniques:
                tags_to_apply.append(tag_name)
    applied = []
    for tag_name in tags_to_apply:
        if tag_name and tag_name not in existing:
            try:
                misp.tag(event, tag_name)
                existing.add(tag_name)
                applied.append(tag_name)
            except Exception as exc:
                logger.warning("Could not apply tag '%s' to %s: %s", tag_name, event.uuid, exc)
    return applied


@bp.route("/<string:uuid>/summarise", methods=["POST"])
@rate_limited("collection_summarise", limit=15, window_s=60)
def summarise(uuid):
    data, err = _json_object()
    if err:
        return err
    source_id = data.get("source") or _SCRAPER_SOURCE_ID
    if source_id != _SCRAPER_SOURCE_ID:
        return jsonify({"ok": False, "error": "Summarisation is only available for scraper events"}), 400

    misp = misp_store._scraper_misp()
    try:
        event = misp.get_event(uuid, pythonify=True)
    except Exception as exc:
        logger.warning("MISP get_event %s failed: %s", uuid, exc)
        return jsonify({"ok": False, "error": "Could not fetch event from MISP"}), 502

    if not event or isinstance(event, dict):
        return jsonify({"ok": False, "error": "Event not found"}), 404

    try:
        reports = misp.get_event_reports(event.id, pythonify=True) or []
    except Exception as exc:
        logger.warning("Could not load reports for %s: %s", uuid, exc)
        return jsonify({"ok": False, "error": "Could not load event reports"}), 502

    if not reports:
        return jsonify({"ok": False, "error": "No reports attached to this event"}), 400

    report_content = getattr(reports[0], "content", "") or ""
    if not report_content.strip():
        return jsonify({"ok": False, "error": "First report has no content"}), 400

    ev_tags = [t.name for t in getattr(event, "tags", []) or []]

    try:
        from analyser import llm
        summary = llm.summarise_report(report_content, event_info=event.info or "", tags=ev_tags)
    except Exception as exc:
        logger.warning("LLM summarise failed for %s: %s", uuid, exc)
        return jsonify({"ok": False, "error": "Failed to generate summary."}), 502

    if summary.upper().startswith("QUALITY:"):
        return jsonify({"ok": False, "error": summary}), 400

    try:
        er = MISPEventReport()
        er.name = f"[AI-Summary] {(event.info or uuid)[:80]}"
        er.content = summary
        er.distribution = 5
        misp.add_event_report(event.id, er)
    except Exception as exc:
        logger.warning("Could not add summary report to %s: %s", uuid, exc)
        return jsonify({"ok": False, "error": "Could not save summary to MISP."}), 502

    collection_cache.mark_ai_summary(uuid, source_id)

    try:
        from analyser import tagger
        tagger.set_workflow_state(misp, event, "draft")
    except Exception as exc:
        logger.warning("Could not update workflow state for %s: %s", uuid, exc)

    sectors, geo, techniques = _parse_scope_from_summary(summary)
    applied_tags = []
    if sectors or geo or techniques:
        try:
            applied_tags = _apply_scope_tags(misp, event, sectors, geo, techniques)
            if applied_tags:
                logger.info("Applied scope tags to %s: %s", uuid, applied_tags)
        except Exception as exc:
            logger.warning("Could not apply scope tags to %s: %s", uuid, exc)

    # Refresh cache row so new tags/galaxies are immediately visible without a manual refresh
    try:
        fresh = misp.get_event(uuid, pythonify=True)
        if fresh and not isinstance(fresh, dict):
            row = collection_cache._extract_row(fresh, source_id)
            row["has_ai_summary"] = True
            collection_cache.insert_event(row)
    except Exception as exc:
        logger.warning("Could not refresh cache for %s after summarise: %s", uuid, exc)

    tag_note = f"; tagged: {', '.join(applied_tags)}" if applied_tags else ""
    audit.record(
        "summarise", "misp-event",
        entity_id=uuid,
        entity_label=event.info or uuid,
        details=f"LLM summary created from first MISP report; workflow state updated to draft{tag_note}",
    )

    return jsonify({"ok": True, "message": "Summary created and added to MISP event"})


@bp.route("/<string:uuid>/preview")
def preview(uuid):
    source_id = request.args.get("source") or _SCRAPER_SOURCE_ID
    src = _find_source(source_id)
    if src and src["kind"] == "manual":
        misp = misp_store._misp()
        misp_url_base = config.MISP_WEBAPP_URL.rstrip("/")
    elif src and src["kind"] == "misp":
        if not src.get("api_key"):
            return jsonify({"ok": False, "error": "Source not configured"}), 502
        try:
            misp = PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False)
        except Exception as exc:
            logger.warning("preview: could not connect to source %s: %s", source_id, exc)
            return jsonify({"ok": False, "error": "Source not available"}), 502
        misp_url_base = src["url"].rstrip("/")
    else:
        misp = misp_store._scraper_misp()
        misp_url_base = config.MISP_URL.rstrip("/")

    try:
        event = misp.get_event(uuid, pythonify=True)
    except Exception as exc:
        logger.warning("preview: get_event %s failed: %s", uuid, exc)
        return jsonify({"ok": False, "error": "Could not fetch event."}), 502

    if not event or isinstance(event, dict):
        return jsonify({"ok": False, "error": "Event not found"}), 404

    try:
        reports = misp.get_event_reports(event.id, pythonify=True) or []
    except Exception:
        reports = []

    report_views = [
        {
            "name": getattr(r, "name", "") or "Report",
            "content": getattr(r, "content", "") or "",
            "tags": [t.name for t in getattr(r, "tags", []) or []],
        }
        for r in reports
    ]

    event_data = _extract_event_detail(event)
    src_label = (src or {}).get("label", source_id)

    return jsonify({
        "ok": True,
        "event": event_data,
        "reports": report_views,
        "misp_url": f"{misp_url_base}/events/view/{uuid}",
        "detail_url": f"/collection/{uuid}?source={source_id}",
        "source_label": src_label,
    })


@bp.route("/manual/new", methods=["GET", "POST"])
def manual_new():
    manual_sources = []
    try:
        manual_sources = [
            src.name.strip()
            for src in misp_store.list_collection_sources()
            if src.enabled and (src.name or "").strip()
        ]
    except Exception as exc:
        logger.warning("Could not load manual collection sources: %s", exc)

    if not manual_sources:
        flash("No enabled manual sources configured. Add them under Configuration > Collection sources > Manual sources.", "warning")
        return redirect(url_for("data_collection.index"))

    if request.method == "POST":
        selected_source = (request.form.get("source", "") or "").strip()
        data = {
            "source": selected_source,
            "title": request.form.get("title", "").strip(),
            "date": request.form.get("date", "").strip() or str(datetime.date.today()),
            "tlp": request.form.get("tlp", "amber"),
            "source_reference": request.form.get("source_reference", "").strip(),
            "source_provider": request.form.get("source_provider", "").strip(),
            "summary": request.form.get("summary", "").strip(),
            "description": request.form.get("description", ""),
            "references": [u for u in request.form.getlist("reference") if u.strip()],
            "geographic_scope": request.form.getlist("geographic_scope"),
            "sectors": request.form.getlist("sectors"),
            "threat_types": request.form.getlist("threat_types"),
            "threat_actors": request.form.getlist("threat_actors"),
        }
        if selected_source not in manual_sources:
            flash("Please select a valid enabled manual source.", "warning")
        elif not data["title"]:
            flash("Title is required.", "warning")
        else:
            try:
                uuid = misp_store.create_manual_collection_event(data)
                audit.record("create", "manual-collection-event", entity_id=uuid, entity_label=data["title"])
                flash(f"Event '{data['title']}' created. You can add attachments below.", "success")
                return redirect(url_for("data_collection.manual_detail", uuid=uuid))
            except Exception as exc:
                logger.exception("manual_new failed")
                audit.record("create", "manual-collection-event", entity_label=data["title"], details="failed")
                flash("Could not create event.", "warning")

    ctx = {
        "manual_sources": manual_sources,
        "today": str(datetime.date.today()),
        "tlp_levels": misp_store.FIA_TLP_LEVELS,
        "galaxy_countries": misp_store.galaxy_geography(),
        "galaxy_sectors": misp_store.galaxy_sectors(),
        "galaxy_threat_actors": misp_store.galaxy_threat_actors(),
    }
    return render_template("data_collection/manual_entry.html", **ctx)


@bp.route("/manual/<string:uuid>")
def manual_detail(uuid):
    event = misp_store.get_manual_collection_event(uuid)
    if event is None:
        return "Event not found", 404
    misp_url = f"{config.MISP_WEBAPP_URL.rstrip('/')}/events/view/{uuid}"
    return render_template("data_collection/manual_detail.html", event=event, misp_url=misp_url)


@bp.route("/manual/<string:uuid>/attach", methods=["POST"])
def manual_attach(uuid):
    f = request.files.get("attachment")
    if not f or not f.filename:
        flash("No file selected.", "warning")
        return redirect(url_for("data_collection.manual_detail", uuid=uuid))
    try:
        file_bytes = f.read()
        misp_store.add_manual_collection_attachment(uuid, f.filename, file_bytes)
        audit.record("attach", "manual-collection-event", entity_id=uuid, entity_label=f.filename)
        flash(f"Attachment '{f.filename}' added.", "success")
    except Exception as exc:
        logger.exception("manual_attach failed for %s", uuid)
        audit.record("attach", "manual-collection-event", entity_id=uuid, entity_label=f.filename, details="failed")
        flash("Could not add attachment.", "warning")
    return redirect(url_for("data_collection.manual_detail", uuid=uuid))


_CTI_EVAL_NAMESPACE = "cti-evaluation"
_CTI_EVAL_PREDICATES = [
    "overall-score", "relevance", "accuracy", "timeliness", "clarity",
    "specificity", "usefulness", "format-validity", "conversion-fidelity",
    "source-reliability", "evidence-strength", "confidence",
]
_CTI_EVAL_VALUES = ["very-low", "low", "moderate", "high", "very-high"]


def _misp_for_source(source_id):
    """Return a connected PyMISP instance for the given source_id, or None on error."""
    src = _find_source(source_id)
    if src is None:
        return None, "Unknown source"
    if src["kind"] == "misp":
        if not src.get("api_key"):
            return None, "Source not configured (missing API key)"
        try:
            return PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False), None
        except Exception as exc:
            logger.warning("_misp_for_source %s: %s", source_id, exc)
            return None, "Could not connect to source"
    return misp_store._scraper_misp(), None


@bp.route("/<string:uuid>/cti-tag", methods=["POST"])
def cti_tag(uuid):
    """Apply a cti-evaluation taxonomy tag to a MISP event.

    POST JSON: {"source": "...", "predicate": "relevance", "value": "high"}
    The tag is pushed as a non-local tag so it syncs to the source MISP server.
    """
    data, err = _json_object()
    if err:
        return err
    source_id = data.get("source") or _SCRAPER_SOURCE_ID
    predicate = (data.get("predicate") or "").strip().lower()
    value = (data.get("value") or "").strip().lower()
    if predicate not in _CTI_EVAL_PREDICATES:
        return jsonify({"ok": False, "error": f"Unknown predicate: {predicate!r}"}), 400
    if value not in _CTI_EVAL_VALUES:
        return jsonify({"ok": False, "error": f"Unknown value: {value!r}"}), 400

    misp, err_msg = _misp_for_source(source_id)
    if misp is None:
        return jsonify({"ok": False, "error": err_msg}), 502

    tag_name = f'{_CTI_EVAL_NAMESPACE}:{predicate}="{value}"'
    try:
        r = misp.tag(uuid, tag_name, local=False)
        if isinstance(r, dict) and "errors" in r:
            return jsonify({"ok": False, "error": str(r["errors"])}), 400
    except Exception as exc:
        logger.warning("cti_tag failed for %s (%s): %s", uuid, tag_name, exc)
        return jsonify({"ok": False, "error": "Could not apply tag."}), 502

    # Refresh this event in local cache so the new CTI-evaluation tag appears immediately.
    try:
        fresh = misp.get_event(uuid, pythonify=True)
        if fresh and not isinstance(fresh, dict):
            row = collection_cache._extract_row(fresh, source_id)
            collection_cache.insert_event(row)
    except Exception as exc:
        logger.warning("Could not refresh cache for %s after cti_tag: %s", uuid, exc)

    audit.record("tag", "misp-event", entity_id=uuid, details=tag_name)
    return jsonify({"ok": True, "tag": tag_name})


@bp.route("/<string:uuid>/flag", methods=["POST"])
def flag_for_review(uuid):
    data, err = _json_object()
    if err:
        return err
    source_id = data.get("source") or _SCRAPER_SOURCE_ID
    src = _find_source(source_id)
    tag = getattr(config, "TAG_COLLECTION_FOLLOWUP", 'zsazsa:collection="follow-up"')
    if src and src["kind"] == "misp":
        if not src.get("api_key"):
            return jsonify({"ok": False, "error": "Source not configured"}), 502
        try:
            misp = PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False)
        except Exception as exc:
            logger.warning("flag_for_review: source connection failed: %s", exc)
            return jsonify({"ok": False, "error": "Source not available"}), 502
    else:
        misp = misp_store._scraper_misp()
    try:
        r = misp.tag(uuid, tag, local=True)
        if isinstance(r, dict) and "errors" in r:
            return jsonify({"ok": False, "error": str(r["errors"])}), 400
    except Exception as exc:
        logger.warning("flag_for_review failed for %s: %s", uuid, exc)
        return jsonify({"ok": False, "error": "Could not flag event."}), 502
    audit.record("flag", "misp-event", entity_id=uuid)
    return jsonify({"ok": True})
