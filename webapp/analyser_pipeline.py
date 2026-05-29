"""Dashboard-triggered collection analyser actions.

This module provides three manual analyser actions used from the dashboard:
- daily briefing draft generation
- flash intel draft generation (for PIR/GIR matched events)
- vulnerability advisory draft generation (for CVE-matched events)
"""

import logging
import re
from datetime import datetime, timezone

import config
from analyser import llm, tagger
from pymisp import MISPEventReport
from webapp import collection_cache, matching as req_matching, misp_store
from webapp.collection_cache import AI_SUMMARY_PREFIX

logger = logging.getLogger(__name__)

_HTTP_ERROR_PREFIX = "misp-scraper:HTTP="
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_BRIEFING_REJECTION_PREFIX = "zsazsa:daily-briefing-rejection"


def _daily_briefing_title_exclusions() -> list[str]:
    raw = getattr(config, "DAILY_BRIEFING_TITLE_EXCLUSIONS", [])
    if isinstance(raw, str):
        raw = raw.splitlines()
    return [str(p).strip().lower() for p in (raw or []) if str(p).strip()]


def _matches_title_exclusion(title: str, patterns: list[str]) -> bool:
    haystack = (title or "").strip().lower()
    if not haystack:
        return False
    return any(p in haystack for p in patterns)


def _event_or_report_title_excluded(event, reports, patterns: list[str]) -> bool:
    if not patterns:
        return False
    if _matches_title_exclusion(getattr(event, "info", "") or "", patterns):
        return True
    for report in reports or []:
        if _matches_title_exclusion(getattr(report, "name", "") or "", patterns):
            return True
    return False


def _emit(progress, step: str, state: str, message: str = "") -> None:
    if progress is None:
        return
    try:
        progress(step=step, state=state, message=message)
    except Exception:
        # Progress reporting should never break pipeline execution.
        pass


def _refresh_scraper_cache() -> None:
    # Run a blocking refresh so the action always works from current scraper state.
    collection_cache.refresh_source({"id": "scraper", "kind": "scraper"})


def _today_incomplete_scraper_events():
    misp = misp_store._scraper_misp()
    today = datetime.now(timezone.utc).date().isoformat()
    events = misp.search(
        tags=[config.SCRAPER_MARKER_TAG],
        date_from=today,
        limit=getattr(config, "MISP_SCRAPER_LIMIT", 500),
        page=1,
        pythonify=True,
    )
    if not events or isinstance(events, dict):
        return misp, []

    needed = 'workflow:state="incomplete"'
    filtered = []
    for event in events:
        tags = [getattr(t, "name", "") for t in (getattr(event, "tags", []) or [])]
        if needed in tags:
            filtered.append(event)
    return misp, filtered


def _event_http_error(event) -> bool:
    for tag in getattr(event, "tags", []) or []:
        if (getattr(tag, "name", "") or "").startswith(_HTTP_ERROR_PREFIX):
            return True
    return False


def _extract_source_url(event) -> str:
    feed_suffixes = (".xml", ".rss", ".atom", ".json")
    links = [
        a.value
        for a in (getattr(event, "attributes", []) or [])
        if a.type in ("url", "link")
        and not any((a.value or "").lower().endswith(s) for s in feed_suffixes)
    ]
    return links[-1] if links else ""


def _event_reports(misp, event):
    try:
        return misp.get_event_reports(event.id, pythonify=True) or []
    except Exception:
        return []


def _first_non_empty_report_content(reports) -> str:
    for report in reports:
        content = (getattr(report, "content", "") or "").strip()
        if content:
            return content
    return ""


def _extract_ai_summary(reports) -> str:
    for report in reports:
        name = (getattr(report, "name", "") or "")
        if name.startswith(AI_SUMMARY_PREFIX):
            return (getattr(report, "content", "") or "").strip()
    return ""


def _add_briefing_rejection_note(misp, event, reason: str, report_title: str = "") -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    note = MISPEventReport()
    note.name = f"{_BRIEFING_REJECTION_PREFIX} {ts}"
    lines = [
        "Decision: rejected for daily briefing relevance",
        f"Time (UTC): {ts}",
        f"Event: {(event.info or '').strip()}",
    ]
    if report_title:
        lines.append(f"Report title: {report_title}")
    if reason:
        lines.append(f"Reason: {reason}")
    note.content = "\n".join(lines)
    note.distribution = 5
    try:
        misp.add_event_report(event.id, note)
    except Exception as exc:
        logger.warning("Could not add daily briefing rejection note for %s: %s", event.uuid, exc)


def _ensure_ai_summary(misp, event, reports) -> tuple[str, bool]:
    existing = _extract_ai_summary(reports)
    if existing:
        return existing, False

    content = _first_non_empty_report_content(reports)
    if not content:
        return "", False

    event_tags = [getattr(t, "name", "") for t in (getattr(event, "tags", []) or [])]
    summary = llm.summarise_report(content, event_info=event.info or "", tags=event_tags)
    if not summary or summary.upper().startswith("QUALITY:"):
        return "", False

    report = MISPEventReport()
    report.name = f"{AI_SUMMARY_PREFIX} {(event.info or event.uuid)[:80]}"
    report.content = summary
    report.distribution = 5
    misp.add_event_report(event.id, report)
    try:
        collection_cache.mark_ai_summary(event.uuid, "scraper")
    except Exception:
        pass
    return summary, True


def _extract_admiralty(event, prefix: str) -> str:
    for tag in getattr(event, "tags", []) or []:
        name = (getattr(tag, "name", "") or "")
        if name.startswith(prefix):
            return name.split("=", 1)[1].strip('"')
    return ""


def _extract_cves(event) -> list[str]:
    values = []
    for attr in getattr(event, "attributes", []) or []:
        if getattr(attr, "type", "") == "vulnerability":
            v = (getattr(attr, "value", "") or "").strip().upper()
            if v:
                values.append(v)
    for obj in getattr(event, "objects", []) or []:
        for attr in getattr(obj, "attributes", []) or []:
            if getattr(attr, "type", "") == "vulnerability":
                v = (getattr(attr, "value", "") or "").strip().upper()
                if v:
                    values.append(v)
    if not values:
        values.extend(m.upper() for m in _CVE_RE.findall(getattr(event, "info", "") or ""))
    return list(dict.fromkeys(values))


def _common_candidate_events(progress=None) -> tuple:
    _emit(progress, "refresh-cache", "in_progress", "Refreshing scraper cache...")
    _refresh_scraper_cache()
    _emit(progress, "refresh-cache", "completed", "Scraper cache refreshed.")

    _emit(progress, "collect-events", "in_progress", "Collecting today's incomplete scraper events...")
    misp, events = _today_incomplete_scraper_events()
    _emit(progress, "collect-events", "completed", f"Loaded {len(events)} incomplete event(s) for today.")

    hard_rejected = 0
    kept = []
    summaries = {}
    summary_created = 0

    _emit(progress, "filter-events", "in_progress", "Filtering hard negatives (HTTP errors / empty reports)...")

    for event in events:
        reports = _event_reports(misp, event)
        first_report = _first_non_empty_report_content(reports)

        if _event_http_error(event) or not first_report:
            hard_rejected += 1
            try:
                tagger.set_workflow_state(misp, event, "rejected")
            except Exception as exc:
                logger.warning("Could not mark %s as rejected: %s", event.uuid, exc)
            continue

        summary, created = _ensure_ai_summary(misp, event, reports)
        if created:
            summary_created += 1
        summaries[event.uuid] = summary
        kept.append(event)

    _emit(progress, "filter-events", "completed", f"Hard-negative filtering complete: kept {len(kept)}, rejected {hard_rejected}.")
    _emit(progress, "generate-summaries", "in_progress", "Ensuring AI summaries exist for eligible events...")
    _emit(progress, "generate-summaries", "completed", f"AI summary pass complete: created {summary_created} new summary report(s).")

    return misp, kept, summaries, {
        "total_incomplete_today": len(events),
        "hard_rejected": hard_rejected,
        "summary_created": summary_created,
    }


def run_daily_briefing_action(progress=None) -> dict:
    misp, events, summaries, stats = _common_candidate_events(progress=progress)

    exclusions = _daily_briefing_title_exclusions()
    excluded_by_title = 0
    if exclusions:
        _emit(progress, "exclude-titles", "in_progress", "Applying title exclusions to daily briefing candidates...")
        kept = []
        for event in events:
            reports = _event_reports(misp, event)
            if _event_or_report_title_excluded(event, reports, exclusions):
                excluded_by_title += 1
                continue
            kept.append(event)
        events = kept
        _emit(progress, "exclude-titles", "completed", f"Title exclusions applied: excluded {excluded_by_title}, kept {len(events)}.")
    else:
        _emit(progress, "exclude-titles", "completed", "No title exclusions configured.")

    rejected_by_relevance = 0
    _emit(progress, "review-relevance", "in_progress", "Reviewing daily briefing relevance of candidate stories...")
    kept = []
    for event in events:
        reports = _event_reports(misp, event)
        first_report = _first_non_empty_report_content(reports)
        report_title = (getattr(reports[0], "name", "") or "") if reports else ""
        decision = llm.review_briefing_relevance(
            event_title=event.info or "",
            report_title=report_title,
            content=first_report,
        )
        if not decision.get("include", True):
            rejected_by_relevance += 1
            try:
                tagger.set_workflow_state(misp, event, "rejected")
            except Exception as exc:
                logger.warning("Could not mark %s as rejected after relevance review: %s", event.uuid, exc)
            _add_briefing_rejection_note(
                misp,
                event,
                reason=(decision.get("reason") or "").strip(),
                report_title=report_title,
            )
            continue
        kept.append(event)
    events = kept
    _emit(progress, "review-relevance", "completed", f"Relevance review complete: kept {len(events)}, rejected {rejected_by_relevance}.")

    _emit(progress, "build-briefing", "in_progress", "Building daily briefing stories from eligible events...")
    stories = []
    for event in events:
        story_text = (summaries.get(event.uuid) or "").strip()
        if not story_text:
            reports = _event_reports(misp, event)
            story_text = _first_non_empty_report_content(reports)
        stories.append({
            "title": event.info or "",
            "content": story_text,
            "source_url": _extract_source_url(event),
            "source_event_uuid": event.uuid,
            "correlation": "",
        })
    _emit(progress, "build-briefing", "completed", f"Prepared {len(stories)} story candidate(s).")

    overlap_pairs = 0
    dropped = 0
    if len(stories) >= 2:
        _emit(progress, "check-overlap", "in_progress", "Checking overlap between stories and removing duplicates...")
        try:
            overlap = llm.detect_story_overlaps(stories)
            raw = overlap.get("overlaps", []) if isinstance(overlap, dict) else []
            candidates = []
            for item in raw:
                if not isinstance(item, dict):
                    continue
                try:
                    a = int(item.get("a", 0))
                    b = int(item.get("b", 0))
                    score = float(item.get("score", 0))
                except (TypeError, ValueError):
                    continue
                if a > 0 and b > 0 and a != b and score >= 0.65:
                    candidates.append((a, b, score))
            overlap_pairs = len(candidates)
            to_drop = set()
            for a, b, _score in sorted(candidates, key=lambda x: x[2], reverse=True):
                if a in to_drop or b in to_drop:
                    continue
                to_drop.add(max(a, b))
            if to_drop:
                stories = [s for i, s in enumerate(stories, start=1) if i not in to_drop]
                dropped = len(to_drop)
        except Exception as exc:
            logger.warning("Daily briefing overlap check failed: %s", exc)
        _emit(progress, "check-overlap", "completed", f"Overlap check complete: {overlap_pairs} pair(s), dropped {dropped} duplicate story(s).")
    else:
        _emit(progress, "check-overlap", "completed", "Not enough stories for overlap checking.")

    if not stories:
        _emit(progress, "create-drafts", "completed", "No daily briefing draft created (no eligible stories).")
        return {
            "ok": True,
            "action": "daily-briefing",
            "created": 0,
            "message": "No eligible events to include in a daily briefing draft.",
            **stats,
            "excluded_by_title": excluded_by_title,
            "rejected_by_relevance": rejected_by_relevance,
            "overlap_pairs": overlap_pairs,
            "overlap_dropped": dropped,
        }

    data = {
        "date": datetime.now(timezone.utc).date().isoformat(),
        "title": "",
        "author": "analyser",
        "tlp": "clear",
        "escalations": "",
        "notes": "",
        "review_state": misp_store.BRIEFING_REVIEW_DRAFT,
        "stories": stories,
    }
    _emit(progress, "create-drafts", "in_progress", "Creating daily briefing draft...")
    briefing_uuid = misp_store.create_briefing(data)
    _emit(progress, "create-drafts", "completed", f"Daily briefing draft created ({briefing_uuid}).")

    return {
        "ok": True,
        "action": "daily-briefing",
        "created": 1,
        "briefing_uuid": briefing_uuid,
        "stories_included": len(stories),
        "message": f"Daily briefing draft created with {len(stories)} stories.",
        **stats,
        "excluded_by_title": excluded_by_title,
        "rejected_by_relevance": rejected_by_relevance,
        "overlap_pairs": overlap_pairs,
        "overlap_dropped": dropped,
    }


def run_flash_intel_action(progress=None) -> dict:
    _misp, events, summaries, stats = _common_candidate_events(progress=progress)

    _emit(progress, "match-requirements", "in_progress", "Matching eligible events against active PIR/GIR scope...")
    match_events = []
    for event in events:
        galaxies = []
        for galaxy in getattr(event, "galaxies", []) or []:
            for cluster in getattr(galaxy, "clusters", []) or []:
                value = getattr(cluster, "value", "") or ""
                if value:
                    galaxies.append(value)
        match_events.append({
            "uuid": event.uuid,
            "info": event.info or "",
            "tags": [getattr(t, "name", "") for t in (getattr(event, "tags", []) or [])],
            "galaxy_names": galaxies,
        })

    pirs, girs = req_matching.get_requirements()
    match_map = req_matching.match_events(match_events, pirs, girs)
    matched_count = sum(1 for event in events if match_map.get(event.uuid))
    _emit(progress, "match-requirements", "completed", f"Requirement matching complete: {matched_count} event(s) matched.")

    created = 0
    _emit(progress, "create-drafts", "in_progress", "Creating flash intel draft(s) for matched events...")
    for event in events:
        matches = match_map.get(event.uuid, [])
        if not matches:
            continue
        top = matches[0]
        linked_pir_uuid = top.get("uuid", "") if top.get("type") == "pir" else ""

        data = {
            "title": event.info or "Untitled",
            "audience": "",
            "tlp": "amber",
            "summary": (summaries.get(event.uuid) or "").strip(),
            "action_required": "Review and decide whether publication is required.",
            "what_happened": [],
            "source_description": f"Auto-created from source event {event.uuid}; top match: {top.get('id', 'n/a')}",
            "source_reliability": _extract_admiralty(event, "admiralty-scale:source-reliability="),
            "information_credibility": _extract_admiralty(event, "admiralty-scale:information-credibility="),
            "likely_impact": "",
            "affected_assets": "",
            "actor_context": "",
            "geographic_scope": [],
            "sectors": [],
            "threat_actors": [],
            "threat_types": [],
            "technology": [],
            "vendor": [],
            "incident": [],
            "campaign": [],
            "actions_immediate": [],
            "actions_near_term": [],
            "mitre_techniques": [],
            "hunting_hypotheses": [],
            "external_references": [],
            "feedback_deadline": "",
            "author": "analyser",
            "source_event_uuids": [event.uuid],
            "context_tags": [f"match:{m.get('id', '')}" for m in matches[:3] if m.get("id")],
            "linked_pir_uuid": linked_pir_uuid,
            "review_state": misp_store.FIA_REVIEW_DRAFT,
        }
        misp_store.create_fia(data)
        created += 1
    _emit(progress, "create-drafts", "completed", f"Created {created} flash intel draft(s).")

    return {
        "ok": True,
        "action": "flash-intel",
        "created": created,
        "message": f"Created {created} flash intel draft(s) from PIR/GIR matched events.",
        **stats,
    }


def run_vea_action(progress=None) -> dict:
    _misp, events, summaries, stats = _common_candidate_events(progress=progress)

    _emit(progress, "detect-cves", "in_progress", "Detecting CVE matches in eligible events...")
    cve_match_count = 0
    cve_map = {}
    for event in events:
        cves = _extract_cves(event)
        cve_map[event.uuid] = cves
        if cves:
            cve_match_count += 1
    _emit(progress, "detect-cves", "completed", f"CVE detection complete: {cve_match_count} event(s) with CVE match.")

    created = 0
    _emit(progress, "create-drafts", "in_progress", "Creating vulnerability advisory draft(s) for CVE-matched events...")
    for event in events:
        cves = cve_map.get(event.uuid, [])
        if not cves:
            continue

        data = {
            "cve_id": "\n".join(cves),
            "summary": (summaries.get(event.uuid) or "").strip(),
            "cvss": "",
            "cwe": "",
            "title": event.info or "",
            "tlp": "amber",
            "author": "analyser",
            "audience": "",
            "affected_product": "",
            "affected_versions": "",
            "fixed_version": "",
            "exposure": "",
            "observed_exploitation": "",
            "exploit_availability": "",
            "exploitation_complexity": "",
            "threat_actor_interest": "",
            "cisa_kev": "",
            "source_description": f"Auto-created from source event {event.uuid}",
            "source_reliability": _extract_admiralty(event, "admiralty-scale:source-reliability="),
            "information_credibility": _extract_admiralty(event, "admiralty-scale:information-credibility="),
            "worst_case": "",
            "most_likely": "",
            "immediate_actions": [],
            "patch_sla_internet": "",
            "patch_sla_internal": "",
            "target_patch_version": "",
            "exploitation_indicators": [],
            "detection_rules": [],
            "references": [],
            "context_tags": [f"cve:{c}" for c in cves],
            "review_state": misp_store.VEA_REVIEW_DRAFT,
            "source_event_uuid": event.uuid,
            "linked_pir_uuid": "",
        }
        misp_store.create_vea(data)
        created += 1
    _emit(progress, "create-drafts", "completed", f"Created {created} vulnerability advisory draft(s).")

    return {
        "ok": True,
        "action": "vea",
        "created": created,
        "message": f"Created {created} vulnerability advisory draft(s) from CVE-matched events.",
        **stats,
    }
