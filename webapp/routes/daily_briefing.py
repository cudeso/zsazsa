"""Daily Threat Briefing routes.

Workflow: analyst opens the triage page (shows recent scraper events),
selects relevant stories, drafts a 5-line summary per story (optionally
with LLM assistance), then publishes the briefing.
"""

import base64
import logging
import mimetypes
import os
from datetime import datetime
from pathlib import Path

import config
import weasyprint
from flask import Blueprint, Response, flash, jsonify, redirect, render_template, request, url_for

from webapp import audit, misp_store
from webapp.collection_cache import AI_SUMMARY_PREFIX

logger = logging.getLogger(__name__)
bp = Blueprint("daily_briefing", __name__, url_prefix="/briefing")

_DEFAULT_TRIAGE_LIMIT = 50


def _render_briefing_form(
    *,
    stories,
    date: str,
    title: str,
    author: str,
    tlp: str,
    escalations: str,
    notes: str,
    mode: str,
    form_action: str,
    cancel_url: str,
):
    is_edit = mode == "edit"
    return render_template(
        "daily_briefing/form.html",
        stories=stories,
        briefing_date=date,
        briefing_title=title,
        briefing_author=author,
        briefing_tlp=tlp,
        briefing_escalations=escalations,
        briefing_notes=notes,
        page_mode=mode,
        page_title_text=(f"Edit briefing {date or '(no date)'}" if is_edit else "Compose daily briefing"),
        browser_title=(f"Edit briefing {date or '(no date)'}" if is_edit else "Compose briefing"),
        form_action=form_action,
        save_label=("Save" if is_edit else "Save draft"),
        cancel_url=cancel_url,
        cancel_label=("Cancel" if is_edit else "Back to triage"),
        story_title_exclusions=(getattr(config, "DAILY_BRIEFING_TITLE_EXCLUSIONS", []) or []),
    )


def _extract_source_url(event) -> str:
    """Return the article URL from a MISP scraper event's link attributes.

    Scraper events carry two link attributes: the RSS feed URL first, then the
    article URL. We skip anything that looks like a feed (ends with .xml/.rss/.atom)
    and return the last remaining link.
    """
    feed_suffixes = (".xml", ".rss", ".atom", ".json")
    links = [
        a.value
        for a in (getattr(event, "attributes", []) or [])
        if a.type in ("url", "link")
        and not any((a.value or "").lower().endswith(s) for s in feed_suffixes)
    ]
    return links[-1] if links else ""


def _extract_ai_summary(event) -> str:
    """Return the AI-generated summary report content if one exists on this event."""
    for r in (getattr(event, "event_reports", []) or []):
        if (getattr(r, "name", "") or "").startswith(AI_SUMMARY_PREFIX):
            return (getattr(r, "content", "") or "").strip()
    return ""


def _triage_events(limit=_DEFAULT_TRIAGE_LIMIT):
    """Return recent scraper events for the triage queue."""
    import config
    misp = misp_store._scraper_misp()
    try:
        events = misp.search(
            tags=[config.SCRAPER_MARKER_TAG],
            limit=limit,
            page=1,
            pythonify=True,
        )
    except Exception as exc:
        logger.warning("Scraper MISP search for triage failed: %s", exc)
        return []
    if not events or isinstance(events, dict):
        return []
    rows = []
    for e in events:
        ev_tags = [t.name for t in getattr(e, "tags", []) or []]
        rows.append({
            "uuid": e.uuid,
            "info": e.info or "",
            "date": str(e.date) if e.date else "",
            "tags": ev_tags,
            "report_count": len(getattr(e, "event_reports", []) or []),
        })
    return rows


def _parse_stories_from_form(form):
    """Extract story dicts from a POST form with indexed story fields."""
    stories = []
    i = 1
    while True:
        title = form.get(f"story_{i}_title", "").strip()
        if not title and not form.get(f"story_{i}_source_event_uuid", "").strip():
            break
        stories.append({
            "title": title,
            "content": form.get(f"story_{i}_content", "").strip(),
            "source_url": form.get(f"story_{i}_source_url", "").strip(),
            "source_event_uuid": form.get(f"story_{i}_source_event_uuid", "").strip(),
            "correlation": form.get(f"story_{i}_correlation", "").strip(),
        })
        i += 1
    return stories


def _briefing_markdown(briefing, preview_url: str = "") -> str:
    company = getattr(config, "BRAND_COMPANY", "")
    dept = getattr(config, "BRAND_DEPARTMENT", "")
    sender = " · ".join(p for p in [company, dept] if p) or "zsazsa CTI"
    lines = [
        f"# Daily threat briefing {briefing.date or ''}".strip(),
        f"*{sender}*",
        "",
        f"**Date:** {briefing.date or '-'}",
        f"**Author:** {briefing.author or '-'}",
        f"**TLP:** TLP:{(briefing.tlp or 'amber').upper()}",
        f"**Stories:** {len(briefing.stories or [])}",
    ]
    if briefing.title:
        lines.append(f"**Title:** {briefing.title}")

    for idx, story in enumerate(briefing.stories or [], start=1):
        lines += [
            "",
            f"## Story {idx}: {story.title or '(untitled)'}",
            "",
            story.content or "(no content)",
        ]
        if story.source_url:
            lines.append(f"Source: {story.source_url}")
        if story.source_event_uuid:
            lines.append(f"MISP event: {story.source_event_uuid}")
        if story.correlation:
            lines.append(f"Correlation: {story.correlation}")

    if briefing.escalations:
        lines += ["", "## Escalations", "", briefing.escalations]
    if briefing.notes:
        lines += ["", "## Notes", "", briefing.notes]
    if preview_url:
        lines += ["", f"[Open briefing]({preview_url})"]

    return "\n".join(lines)


def _notify_briefing_stakeholders(briefing, preview_url: str = "") -> int:
    from notifier import mattermost

    stakeholders = misp_store.stakeholders_subscribed_to("Daily threat briefing")
    markdown = _briefing_markdown(briefing, preview_url=preview_url)
    sent_ok = mattermost.send_daily_briefing_notification(briefing, markdown, stakeholders=stakeholders)
    return len(stakeholders), bool(sent_ok)


def _latest_notify_status(entity_id: str):
    row = audit.latest_event("notify", "daily-briefing", entity_id=entity_id)
    if row is None:
        return None
    details = (row["details"] or "")
    lower = details.lower()
    if "result=ok" in lower or lower.startswith("ok"):
        tone = "success"
        label = "Delivered"
    elif "skip" in lower:
        tone = "warning"
        label = "Skipped"
    elif "fail" in lower:
        tone = "danger"
        label = "Failed"
    else:
        tone = "secondary"
        label = "Unknown"
    return {
        "tone": tone,
        "label": label,
        "timestamp": row["timestamp"],
        "details": details,
    }


@bp.route("/")
def list_briefings():
    briefings = misp_store.list_briefings()
    return render_template("daily_briefing/list.html", briefings=briefings)


@bp.route("/triage")
def triage():
    """Redirect to the collection page in briefing mode."""
    return redirect(url_for("data_collection.index", briefing_mode=1))


@bp.route("/compose", methods=["GET", "POST"])
def compose():
    """Build the briefing: one text area per selected story, with LLM draft buttons."""
    if request.method == "POST":
        # Submitted from the triage page: create a blank briefing shell with
        # selected events pre-loaded as story stubs, then redirect to edit.
        selected_uuids = request.form.getlist("selected_events")
        bdate = request.form.get("date", "").strip() or datetime.utcnow().strftime("%Y-%m-%d")
        btitle = request.form.get("title", "").strip()
        author = request.form.get("author", "").strip()
        tlp = request.form.get("tlp", "clear")

        stories = []
        if selected_uuids:
            misp = misp_store._scraper_misp()
            for ev_uuid in selected_uuids[:8]:
                try:
                    ev = misp.get_event(ev_uuid, pythonify=True)
                    if ev and not isinstance(ev, dict):
                        stories.append({
                            "title": ev.info or "",
                            "content": "",
                            "source_url": _extract_source_url(ev),
                            "source_event_uuid": ev.uuid,
                            "correlation": "",
                            "ai_summary": _extract_ai_summary(ev),
                        })
                except Exception as exc:
                    logger.warning("Could not fetch event %s for briefing: %s", ev_uuid, exc)

        return _render_briefing_form(
            stories=stories,
            date=bdate,
            title=btitle,
            author=author,
            tlp=tlp,
            escalations="",
            notes="",
            mode="create",
            form_action=url_for("daily_briefing.save"),
            cancel_url=url_for("daily_briefing.triage"),
        )

    # GET: show empty compose form, optionally pre-seeded with one source event
    today = datetime.utcnow().strftime("%Y-%m-%d")
    stories = []
    seed_uuid = (request.args.get("source") or "").strip()
    if seed_uuid:
        try:
            misp = misp_store._scraper_misp()
            ev = misp.get_event(seed_uuid, pythonify=True)
            if ev and not isinstance(ev, dict):
                stories = [{
                    "title": ev.info or "",
                    "content": "",
                    "source_url": _extract_source_url(ev),
                    "source_event_uuid": ev.uuid,
                    "correlation": "",
                    "ai_summary": _extract_ai_summary(ev),
                }]
        except Exception as exc:
            logger.warning("Could not seed briefing from event %s: %s", seed_uuid, exc)
    return _render_briefing_form(
        stories=stories,
        date=today,
        title="",
        author="",
        tlp="clear",
        escalations="",
        notes="",
        mode="create",
        form_action=url_for("daily_briefing.save"),
        cancel_url=url_for("daily_briefing.triage"),
    )


@bp.route("/save", methods=["POST"])
def save():
    """Save the composed briefing draft to MISP."""
    stories = _parse_stories_from_form(request.form)
    data = {
        "date": request.form.get("date", "").strip() or datetime.utcnow().strftime("%Y-%m-%d"),
        "title": request.form.get("title", "").strip(),
        "author": request.form.get("author", "").strip(),
        "tlp": request.form.get("tlp", "clear"),
        "escalations": request.form.get("escalations", "").strip(),
        "notes": request.form.get("notes", "").strip(),
        "review_state": misp_store.BRIEFING_REVIEW_DRAFT,
        "stories": stories,
    }
    if not stories:
        flash("Add at least one story before saving.", "warning")
        return redirect(url_for("daily_briefing.compose"))
    try:
        uuid = misp_store.create_briefing(data)
        label = data["title"] or f"Daily briefing {data['date']}"
        audit.record("create", "daily-briefing", entity_id=uuid, entity_label=label)
        flash(f"{label} saved as draft.", "success")
        return redirect(url_for("daily_briefing.detail", id=uuid))
    except Exception as exc:
        flash(f"Could not save briefing: {exc}", "warning")
        return redirect(url_for("daily_briefing.compose"))


@bp.route("/<string:id>")
def detail(id):
    briefing = misp_store.get_briefing(id)
    if briefing is None:
        return "Briefing not found", 404
    feedback = misp_store.list_product_feedback(briefing.uuid)
    recipients = misp_store.stakeholders_subscribed_to("Daily threat briefing")
    notify_status = _latest_notify_status(id)
    return render_template(
        "daily_briefing/detail.html",
        briefing=briefing,
        feedback=feedback,
        recipients=recipients,
        notify_status=notify_status,
    )


_UPLOADS_DIR = Path(__file__).parent.parent.parent / "data" / "uploads"


def _logo_data_uri():
    logo = getattr(config, "BRAND_LOGO", "")
    if not logo:
        return ""
    path = _UPLOADS_DIR / logo
    if not path.exists():
        return ""
    mime = mimetypes.guess_type(str(path))[0] or "image/png"
    return f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode()}"


@bp.route("/<string:id>/pdf")
def pdf(id):
    briefing = misp_store.get_briefing(id)
    if briefing is None:
        return "Briefing not found", 404
    css_path = os.path.join(os.path.dirname(__file__), "..", "static", "css", "briefing_pdf.css")
    css_url = "file://" + os.path.abspath(css_path)
    brand = {
        "company": getattr(config, "BRAND_COMPANY", ""),
        "department": getattr(config, "BRAND_DEPARTMENT", ""),
        "color1": getattr(config, "BRAND_COLOR_1", "#0f2d52"),
        "color2": getattr(config, "BRAND_COLOR_2", "#0078f1"),
        "color3": getattr(config, "BRAND_COLOR_3", "#64748b"),
        "logo_uri": _logo_data_uri(),
    }
    html = render_template("daily_briefing/pdf.html", briefing=briefing, css_url=css_url, brand=brand)
    pdf_bytes = weasyprint.HTML(string=html).write_pdf()
    filename = f"briefing-{briefing.date or 'draft'}.pdf"
    return Response(pdf_bytes, mimetype="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@bp.route("/<string:id>/feedback", methods=["POST"])
def add_feedback(id):
    briefing = misp_store.get_briefing(id)
    if briefing is None:
        return "Briefing not found", 404
    author = request.form.get("author", "").strip()
    rating = request.form.get("rating", "").strip()
    comment = request.form.get("comment", "").strip()
    try:
        misp_store.add_product_feedback(briefing.uuid, author, rating, comment)
        audit.record("create", "briefing_feedback", entity_id=id,
                     entity_label=f"Daily briefing {briefing.date}")
        flash("Feedback recorded.", "success")
    except Exception as exc:
        logger.warning("add_feedback briefing %s failed: %s", id, exc)
        flash(f"Could not record feedback: {exc}", "warning")
    return redirect(url_for("daily_briefing.detail", id=id))


@bp.route("/<string:id>/edit", methods=["GET", "POST"])
def edit(id):
    briefing = misp_store.get_briefing(id)
    if briefing is None:
        return "Briefing not found", 404
    if request.method == "POST":
        stories = _parse_stories_from_form(request.form)
        data = {
            "date": request.form.get("date", briefing.date).strip(),
            "title": request.form.get("title", briefing.title).strip(),
            "author": request.form.get("author", briefing.author).strip(),
            "tlp": request.form.get("tlp", briefing.tlp),
            "escalations": request.form.get("escalations", "").strip(),
            "notes": request.form.get("notes", "").strip(),
            "review_state": briefing.review_state,
            "stories": stories,
        }
        try:
            misp_store.update_briefing(id, data)
            audit.record("update", "daily-briefing", entity_id=id,
                         entity_label=f"Daily briefing {data['date']}")
            flash("Briefing updated.", "success")
            return redirect(url_for("daily_briefing.detail", id=id))
        except Exception as exc:
            flash(f"Could not update briefing: {exc}", "warning")
    return _render_briefing_form(
        stories=briefing.stories,
        date=briefing.date,
        title=briefing.title or "",
        author=briefing.author or "",
        tlp=briefing.tlp or "clear",
        escalations=briefing.escalations or "",
        notes=briefing.notes or "",
        mode="edit",
        form_action=url_for("daily_briefing.edit", id=briefing.uuid),
        cancel_url=url_for("daily_briefing.detail", id=briefing.uuid),
    )


@bp.route("/<string:id>/publish", methods=["POST"])
def publish(id):
    briefing = misp_store.get_briefing(id)
    if briefing is None:
        return "Briefing not found", 404
    try:
        misp_store.publish_briefing(id)
        audit.record("publish", "daily-briefing", entity_id=id,
                     entity_label=f"Daily briefing {briefing.date}")
        notification_sent = True
        try:
            preview_url = url_for("daily_briefing.detail", id=id, _external=True)
            recipient_count, notification_sent = _notify_briefing_stakeholders(briefing, preview_url=preview_url)
            audit.record(
                "notify",
                "daily-briefing",
                entity_id=id,
                entity_label=f"Daily briefing {briefing.date}",
                details=(
                    f"publish full briefing to stakeholders; recipients={recipient_count}; "
                    f"result={'ok' if notification_sent else 'failed'}"
                ),
            )
        except Exception as exc:
            logger.warning("mattermost notify failed for briefing %s: %s", id, exc)
            notification_sent = False
            audit.record(
                "notify",
                "daily-briefing",
                entity_id=id,
                entity_label=f"Daily briefing {briefing.date}",
                details=f"publish full briefing to stakeholders; result=failed; error={exc}",
            )
        if notification_sent:
            flash(f"Daily briefing {briefing.date} published.", "success")
        else:
            flash(
                f"Daily briefing {briefing.date} published, but notification failed. Check notification channel settings/logs.",
                "warning",
            )
    except Exception as exc:
        flash(f"Could not publish briefing: {exc}", "warning")
    return redirect(url_for("daily_briefing.detail", id=id))


@bp.route("/<string:id>/resend", methods=["POST"])
def resend(id):
    briefing = misp_store.get_briefing(id)
    if briefing is None:
        return "Briefing not found", 404
    if getattr(briefing, "review_state", None) != misp_store.BRIEFING_REVIEW_PUBLISHED:
        flash("Only published briefings can be resent.", "warning")
        return redirect(url_for("daily_briefing.list_briefings"))
    try:
        preview_url = url_for("daily_briefing.detail", id=id, _external=True)
        recipient_count, sent_ok = _notify_briefing_stakeholders(briefing, preview_url=preview_url)
        audit.record(
            "notify",
            "daily-briefing",
            entity_id=id,
            entity_label=f"Daily briefing {briefing.date}",
            details=(
                f"resend full briefing to stakeholders; recipients={recipient_count}; "
                f"result={'ok' if sent_ok else 'failed'}"
            ),
        )
        if sent_ok:
            flash("Briefing resent to stakeholders.", "success")
        else:
            flash("Briefing resend failed. Check notification channel settings/logs.", "warning")
    except Exception as exc:
        logger.warning("resend briefing %s failed: %s", id, exc)
        flash(f"Could not resend briefing: {exc}", "warning")
    return redirect(url_for("daily_briefing.list_briefings"))


@bp.route("/<string:id>/delete", methods=["POST"])
def delete(id):
    briefing = misp_store.get_briefing(id)
    label = f"Daily briefing {briefing.date}" if briefing else id
    if briefing and getattr(briefing, "review_state", None) == misp_store.BRIEFING_REVIEW_PUBLISHED:
        flash(f"{label} is published and cannot be deleted.", "warning")
        return redirect(url_for("daily_briefing.list_briefings"))
    try:
        misp_store.delete_briefing(id)
        audit.record("delete", "daily-briefing", entity_id=id, entity_label=label)
        flash(f"{label} deleted.", "success")
    except Exception as exc:
        flash(f"Could not delete briefing: {exc}", "warning")
    return redirect(url_for("daily_briefing.list_briefings"))
