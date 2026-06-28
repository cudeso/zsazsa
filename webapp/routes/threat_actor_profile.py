"""Threat actor profile product: analyst write-ups of a threat actor combining
the MISP threat-actor galaxy with the analyst's own investigation."""

import logging
from datetime import datetime

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for

import config
from webapp import audit, misp_store
from webapp.utils import sort_products
from notifier import dispatcher

logger = logging.getLogger(__name__)

bp = Blueprint("threat_actor_profile", __name__, url_prefix="/products/threat-actor-profile")

PRODUCT_NAME = "Threat actor profile"
STATES = ["Draft", "Published"]


def _form_data(form, tap_id=""):
    return {
        "tap_id": tap_id,
        "title": (form.get("title") or "").strip(),
        "summary": (form.get("summary") or "").strip(),
        "threat_actors": [v.strip() for v in form.getlist("threat_actors") if v.strip()],
        "audience": ", ".join(form.getlist("audience")),
        "tlp": form.get("tlp", "amber"),
        "linked_pir_uuid": (form.get("linked_pir_uuid") or "").strip(),
        "source_reliability": (form.get("source_reliability") or "").strip(),
        "source_credibility": (form.get("source_credibility") or "").strip(),
        "attribution_rationale": (form.get("attribution_rationale") or "").strip(),
        "actor_types": form.getlist("actor_types"),
        "synonyms": (form.get("synonyms") or "").strip(),
        "capabilities": (form.get("capabilities") or "").strip(),
        "mode_of_operation": (form.get("mode_of_operation") or "").strip(),
        "geographic_scope": form.getlist("geographic_scope"),
        "sectors": form.getlist("sectors"),
        "mitre_attack_techniques": form.getlist("mitre_attack_techniques"),
        "threat_types": form.getlist("threat_types"),
        "time_frame": (form.get("time_frame") or "").strip(),
        "technology": form.getlist("technology"),
        "vendor": form.getlist("vendor"),
        "external_references": [r.strip() for r in misp_store._split_lines(form.get("external_references")) if r.strip()],
        "feedback_deadline": (form.get("feedback_deadline") or "").strip(),
        "author": (form.get("author") or "").strip(),
    }


def _form_context(tap=None):
    return {
        "tap": tap,
        "audiences": misp_store.FIA_AUDIENCES,
        "tlp_levels": misp_store.FIA_TLP_LEVELS,
        "reliabilities": misp_store.FIA_RELIABILITIES,
        "credibilities": misp_store.FIA_CREDIBILITIES,
        "threat_actor_items": misp_store.galaxy_threat_actors(),
        "threat_actor_types": getattr(config, "THREAT_ACTOR_TYPES", []),
        "geo_items": misp_store.galaxy_geography(),
        "galaxy_sectors": misp_store.galaxy_sectors(),
        "galaxy_mitre_attack": misp_store.galaxy_mitre_attack_patterns(),
        "pirs": misp_store.list_pirs(),
    }


@bp.route("/")
def review():
    state_filter = (request.args.get("state") or "").strip() or None
    sort = (request.args.get("sort") or "").strip()
    direction = (request.args.get("dir") or "asc").strip()
    taps = misp_store.list_threat_actor_profiles(status=state_filter)
    sort_products(taps, sort, direction)
    return render_template(
        "threat_actor_profile/review.html",
        taps=taps,
        state_filter=state_filter or "",
        states=STATES,
        sort=sort,
        dir=direction,
    )


@bp.route("/galaxy-enrich", methods=["POST"])
def galaxy_enrich():
    """Return threat-actor galaxy context for the selected actors, for the
    'Complete profile with MISP galaxy data' button to fill the form fields."""
    actors = request.form.getlist("threat_actors")
    data = misp_store.galaxy_enrichment(actors)
    return jsonify({
        "capabilities": data["capabilities"],
        "mode_of_operation": data["mode_of_operation"],
        "synonyms": data["synonyms"],
        "refs": data["refs"],
    })


@bp.route("/recipients-preview", methods=["POST"])
def recipients_preview():
    """Render the recipients preview for the audience/TLP currently selected on
    the form, before the profile is saved."""
    tlp = request.form.get("tlp", "amber")
    audience = ", ".join(request.form.getlist("audience"))
    recipients = misp_store.recipient_preview(PRODUCT_NAME, tlp, audience)
    return render_template("threat_actor_profile/_recipients.html",
                           recipients=recipients, tlp_label=tlp, audience_label=audience)


def _validate(data):
    errors = []
    if not data["title"]:
        errors.append("Title is required.")
    if not data["audience"]:
        errors.append("Select at least one audience.")
    return errors


@bp.route("/new", methods=["GET", "POST"])
def new():
    if request.method == "POST":
        data = _form_data(request.form)
        errors = _validate(data)
        if errors:
            for e in errors:
                flash(e, "warning")
            return render_template("threat_actor_profile/form.html",
                                   **_form_context(), form_values=data)
        uuid = misp_store.create_threat_actor_profile(data)
        tap = misp_store.get_threat_actor_profile(uuid)
        audit.record("create", "threat-actor-profile", entity_id=uuid, entity_label=tap.tap_id)
        flash(f"{tap.tap_id} created.", "success")
        return redirect(url_for("threat_actor_profile.detail", id=uuid))
    return render_template("threat_actor_profile/form.html", **_form_context(), form_values=None)


@bp.route("/<string:id>")
def detail(id):
    tap = misp_store.get_threat_actor_profile(id)
    if tap is None:
        return "Threat actor profile not found", 404
    recipients = misp_store.recipient_preview(PRODUCT_NAME, tap.tlp, tap.audience)
    pir = misp_store.get_pir(tap.linked_pir_uuid) if tap.linked_pir_uuid else None
    feedback = misp_store.list_product_feedback(tap.uuid)
    return render_template("threat_actor_profile/detail.html",
                           tap=tap, recipients=recipients, pir=pir, feedback=feedback)


@bp.route("/<string:id>/edit", methods=["GET", "POST"])
def edit(id):
    tap = misp_store.get_threat_actor_profile(id)
    if tap is None:
        return "Threat actor profile not found", 404
    if tap.status == "Published":
        flash("Published profiles cannot be edited.", "warning")
        return redirect(url_for("threat_actor_profile.detail", id=id))
    if request.method == "POST":
        data = _form_data(request.form, tap_id=tap.tap_id)
        errors = _validate(data)
        if errors:
            for e in errors:
                flash(e, "warning")
            return render_template("threat_actor_profile/form.html",
                                   **_form_context(tap), form_values=data)
        misp_store.update_threat_actor_profile(id, data)
        audit.record("update", "threat-actor-profile", entity_id=id, entity_label=tap.tap_id)
        flash(f"{tap.tap_id} updated.", "success")
        return redirect(url_for("threat_actor_profile.detail", id=id))
    return render_template("threat_actor_profile/form.html", **_form_context(tap), form_values=None)


@bp.route("/<string:id>/publish", methods=["POST"])
def publish(id):
    tap = misp_store.get_threat_actor_profile(id)
    if tap is None:
        return "Threat actor profile not found", 404
    try:
        misp_store.publish_threat_actor_profile(id)
        audit.record("update", "threat-actor-profile", entity_id=id, entity_label=tap.tap_id, details="published")
        flash(f"{tap.tap_id} published.", "success")
    except Exception as exc:
        flash(f"Could not publish: {exc}", "warning")
    return redirect(url_for("threat_actor_profile.detail", id=id))


@bp.route("/<string:id>/notify", methods=["POST"])
def notify(id):
    tap = misp_store.get_threat_actor_profile(id)
    if tap is None:
        return "Threat actor profile not found", 404
    if tap.status != "Published":
        flash("Publish the profile before notifying recipients.", "warning")
        return redirect(url_for("threat_actor_profile.detail", id=id))
    # Deliver to the green set: subscribed, TLP cleared, audience match.
    green = {r["uuid"] for r in misp_store.recipient_preview(PRODUCT_NAME, tap.tlp, tap.audience)
             if r["status"] == "green" and r.get("uuid")}
    recipients = [s for s in misp_store.list_stakeholders() if s.uuid in green]
    markdown = _markdown(tap)
    try:
        summary = dispatcher.send_threat_actor_profile(tap, markdown, recipients)
        ok, message = dispatcher.delivery_outcome(summary)
        audit.record("notify", "threat-actor-profile", entity_id=id, entity_label=tap.tap_id, details=message)
        flash(f"{tap.tap_id}: {message}.", "success" if ok else "warning")
    except Exception as exc:
        flash(f"Could not notify: {exc}", "warning")
    return redirect(url_for("threat_actor_profile.detail", id=id))


@bp.route("/<string:id>/delete", methods=["POST"])
def delete(id):
    tap = misp_store.get_threat_actor_profile(id)
    label = tap.tap_id if tap else id
    if tap and tap.status == "Published":
        flash("Published profiles cannot be deleted.", "warning")
        return redirect(url_for("threat_actor_profile.detail", id=id))
    try:
        misp_store.delete_threat_actor_profile(id)
        audit.record("delete", "threat-actor-profile", entity_id=id, entity_label=label)
        flash(f"{label} deleted.", "info")
    except Exception as exc:
        flash(f"Could not delete: {exc}", "warning")
    return redirect(url_for("threat_actor_profile.review"))


@bp.route("/<string:id>/feedback", methods=["POST"])
def add_feedback(id):
    tap = misp_store.get_threat_actor_profile(id)
    if tap is None:
        return "Threat actor profile not found", 404
    author = request.form.get("author", "").strip()
    rating = request.form.get("rating", "").strip()
    comment = request.form.get("comment", "").strip()
    try:
        misp_store.add_product_feedback(tap.uuid, author, rating, comment)
        audit.record("create", "threat-actor-profile-feedback", entity_id=id, entity_label=tap.tap_id)
        flash("Feedback recorded.", "success")
    except Exception as exc:
        flash(f"Could not record feedback: {exc}", "warning")
    return redirect(url_for("threat_actor_profile.detail", id=id))


@bp.route("/<string:id>/notes", methods=["POST"])
def note_add(id):
    tap = misp_store.get_threat_actor_profile(id)
    if tap is None:
        return "Threat actor profile not found", 404
    title = (request.form.get("note_title") or "").strip()
    content = (request.form.get("note_content") or "").strip()
    if not title:
        flash("Note title is required.", "warning")
        return redirect(url_for("threat_actor_profile.edit", id=id))
    try:
        misp_store.add_rfi_note(id, title, content)
        audit.record("update", "threat-actor-profile", entity_id=id, entity_label=tap.tap_id)
        flash(f"Note '{title}' added.", "success")
    except Exception as exc:
        flash(f"Could not add note: {exc}", "warning")
    return redirect(url_for("threat_actor_profile.edit", id=id))


@bp.route("/<string:id>/notes/<string:report_id>/delete", methods=["POST"])
def note_delete(id, report_id):
    tap = misp_store.get_threat_actor_profile(id)
    label = tap.tap_id if tap else id
    try:
        misp_store.delete_rfi_note(report_id)
        audit.record("update", "threat-actor-profile", entity_id=id, entity_label=label)
        flash("Note deleted.", "success")
    except Exception as exc:
        flash(f"Could not delete note: {exc}", "warning")
    return redirect(url_for("threat_actor_profile.edit", id=id))


def _markdown(tap):
    """Build the notification body for a threat actor profile."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"# {tap.title}", "", f"*{tap.tap_id} - TLP:{tap.tlp.upper()} - as of {now}*", ""]
    if tap.threat_actors:
        lines += ["**Threat actors:** " + ", ".join(tap.threat_actors), ""]
    if tap.summary:
        lines += ["## Summary", "", tap.summary, ""]
    if tap.attribution_rationale:
        lines += ["## Attribution", "", tap.attribution_rationale, ""]
    return "\n".join(lines)
