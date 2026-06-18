"""RFI (Request for Information) workflow routes.

Implements the RFI lifecycle described in the TI program template:
intake → acknowledge → triage → respond → feedback. RFIs are stored as
MISP events tagged 'zsazsa:type="rfi"' and 'zsazsa:ctiproduct="rfi"'.
"""

import json
import logging
from datetime import date, timedelta
from urllib.parse import quote

import config
from flask import Blueprint, Response, flash, redirect, render_template, request, url_for

from webapp import audit, misp_store
from webapp.models import cti_products, TLP_LEVELS

logger = logging.getLogger(__name__)

bp = Blueprint("rfi", __name__, url_prefix="/rfis")

RFI_PRIORITIES = ["High", "Medium", "Low"]
RFI_STATUSES = ["New", "Acknowledged", "In Progress", "Delivered", "Closed"]
FEEDBACK_REQUIREMENT = ["", "Yes", "Partially", "No"]
FEEDBACK_ON_TIME = ["", "Yes", "No"]
FEEDBACK_USEFULNESS = ["", "Very useful", "Somewhat useful", "Not useful"]


def _sla_status(rfi):
    """Return ('green' | 'amber' | 'red' | 'done', days_remaining_or_None)."""
    if rfi.status in ("Delivered", "Closed"):
        return ("done", None)
    if not rfi.due_date:
        return ("amber", None)
    today = date.today()
    delta = (rfi.due_date - today).days
    if delta < 0:
        return ("red", delta)
    if delta <= 1:
        return ("amber", delta)
    return ("green", delta)


def _form_data(form, rfi_id):
    formats = form.getlist("output_format_item")
    tlps = form.getlist("output_format_tlp")
    if len(formats) != len(tlps):
        raise ValueError("Invalid output format payload.")
    fmt_list = [{"format": f, "tlp": t} for f, t in zip(formats, tlps) if f.strip()]
    return {
        "rfi_id": rfi_id,
        "question": form["question"],
        "context": form.get("context"),
        "requester_name": form.get("requester_name"),
        "requester_team": form.get("requester_team"),
        "owner_uuid": form.get("owner_uuid") or "",
        "owner_name": form.get("owner_name") or "",
        "priority": form.get("priority", "Medium"),
        "status": form.get("status", "New"),
        "assigned_analyst": form.get("assigned_analyst"),
        "due_date": form.get("due_date") or None,
        "linked_pir_uuid": form.get("linked_pir_uuid") or "",
        "linked_gir_uuid": form.get("linked_gir_uuid") or "",
        "output_format_list": fmt_list,
        "response": form.get("response"),
        "feedback_requirement_met": form.get("feedback_requirement_met"),
        "feedback_on_time": form.get("feedback_on_time"),
        "feedback_usefulness": form.get("feedback_usefulness"),
        "feedback_suggestions": form.get("feedback_suggestions"),
    }


def _suggested_due_date(priority):
    days = misp_store.RFI_SLA_DAYS.get(priority, 5)
    return (date.today() + timedelta(days=days)).isoformat()


def _rfi_data_from_store(rfi, status: str | None = None) -> dict:
    return {
        "rfi_id": rfi.rfi_id,
        "question": rfi.question,
        "context": rfi.context or "",
        "requester_name": rfi.requester_name or "",
        "requester_team": rfi.requester_team or "",
        "owner_uuid": rfi.owner_uuid or "",
        "owner_name": rfi.owner_name or "",
        "priority": rfi.priority,
        "status": status or rfi.status,
        "assigned_analyst": rfi.assigned_analyst or "",
        "due_date": rfi.due_date.isoformat() if rfi.due_date else None,
        "linked_pir_uuid": rfi.linked_pir_uuid or "",
        "linked_gir_uuid": rfi.linked_gir_uuid or "",
        "output_format_list": list(rfi.output_format_list),
        "response": rfi.response or "",
        "feedback_requirement_met": rfi.feedback_requirement_met or "",
        "feedback_on_time": rfi.feedback_on_time or "",
        "feedback_usefulness": rfi.feedback_usefulness or "",
        "feedback_suggestions": rfi.feedback_suggestions or "",
    }


def _rfi_notify_recipients(rfi):
    stakeholders = misp_store.list_stakeholders()
    if rfi.owner_uuid:
        s = next((x for x in stakeholders if x.id == rfi.owner_uuid), None)
        return [s] if s else []
    if rfi.owner_name:
        s = next((x for x in stakeholders if x.name == rfi.owner_name), None)
        return [s] if s else []
    return []


@bp.route("/")
def rfi_list():
    rfis = misp_store.list_rfis()
    status_filter = (request.args.get("status") or "").strip()
    if status_filter:
        rfis = [r for r in rfis if r.status == status_filter]
    sla_map = {r.id: _sla_status(r) for r in rfis}
    return render_template(
        "rfi/list.html",
        rfis=rfis,
        sla_map=sla_map,
        statuses=RFI_STATUSES,
        status_filter=status_filter,
    )


@bp.route("/new", methods=["GET", "POST"])
def rfi_new():
    stakeholders = misp_store.list_stakeholders()
    pirs = misp_store.list_pirs()
    girs = misp_store.list_girs()
    if request.method == "POST":
        # The id is a placeholder; create_rfi allocates the authoritative
        # rfi_id atomically and writes it back into data.
        data = _form_data(request.form, "")
        # Resolve owner_name from selected stakeholder
        if data["owner_uuid"]:
            owner = next((s for s in stakeholders if s.id == data["owner_uuid"]), None)
            if owner:
                data["owner_name"] = owner.name
        if not data.get("due_date"):
            data["due_date"] = _suggested_due_date(data["priority"])
        try:
            uuid = misp_store.create_rfi(data)
            rfi_id = data["rfi_id"]
            audit.record("create", "rfi", entity_id=uuid, entity_label=rfi_id)
            flash(f"{rfi_id} created.", "success")
            return redirect(url_for("rfi.rfi_detail", id=uuid))
        except Exception as exc:
            flash(f"Could not create RFI: {exc}", "warning")

    return render_template(
        "rfi/form.html",
        rfi=None,
        stakeholders=stakeholders,
        pirs=pirs,
        girs=girs,
        priorities=RFI_PRIORITIES,
        statuses=RFI_STATUSES,
        output_formats=cti_products(),
        tlp_levels=TLP_LEVELS,
        feedback_requirement=FEEDBACK_REQUIREMENT,
        feedback_on_time=FEEDBACK_ON_TIME,
        feedback_usefulness=FEEDBACK_USEFULNESS,
        sla_days=misp_store.RFI_SLA_DAYS,
        is_edit=False,
    )


@bp.route("/<string:id>")
def rfi_detail(id):
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return "RFI not found", 404
    sla_state, days_remaining = _sla_status(rfi)
    linked_pir = misp_store.get_pir(rfi.linked_pir_uuid) if rfi.linked_pir_uuid else None
    linked_gir = misp_store.get_gir(rfi.linked_gir_uuid) if rfi.linked_gir_uuid else None
    feedback = misp_store.list_product_feedback(rfi.id)
    auto_acknowledged = audit.has_event(
        "acknowledge",
        "rfi",
        entity_id=id,
        details_contains="auto via notify",
    )
    return render_template(
        "rfi/detail.html",
        rfi=rfi,
        sla_state=sla_state,
        days_remaining=days_remaining,
        linked_pir=linked_pir,
        linked_gir=linked_gir,
        feedback=feedback,
        auto_acknowledged=auto_acknowledged,
        feedback_requirement=FEEDBACK_REQUIREMENT,
        feedback_on_time=FEEDBACK_ON_TIME,
        feedback_usefulness=FEEDBACK_USEFULNESS,
    )


@bp.route("/<string:id>/feedback", methods=["POST"])
def rfi_feedback(id):
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return "RFI not found", 404
    data = {
        "feedback_requirement_met": request.form.get("feedback_requirement_met", ""),
        "feedback_on_time": request.form.get("feedback_on_time", ""),
        "feedback_usefulness": request.form.get("feedback_usefulness", ""),
        "feedback_suggestions": request.form.get("feedback_suggestions", "").strip(),
    }
    update_data = {
        "question": rfi.question, "context": rfi.context or "",
        "requester_name": rfi.requester_name or "", "requester_team": rfi.requester_team or "",
        "owner_uuid": rfi.owner_uuid or "", "owner_name": rfi.owner_name or "",
        "priority": rfi.priority, "assigned_analyst": rfi.assigned_analyst or "",
        "due_date": rfi.due_date.isoformat() if rfi.due_date else None,
        "linked_pir_uuid": rfi.linked_pir_uuid or "", "linked_gir_uuid": rfi.linked_gir_uuid or "",
        "output_format_list": list(rfi.output_format_list),
        "response": rfi.response or "",
        "status": rfi.status,
        **data,
    }
    try:
        misp_store.update_rfi(id, update_data)
        audit.record("update", "rfi_feedback", entity_id=id, entity_label=rfi.rfi_id)
        flash("Feedback saved.", "success")
    except Exception as exc:
        logger.warning("rfi_feedback %s failed: %s", id, exc)
        flash(f"Could not save feedback: {exc}", "warning")
    return redirect(url_for("rfi.rfi_detail", id=id))


@bp.route("/<string:id>/edit", methods=["GET", "POST"])
def rfi_edit(id):
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return "RFI not found", 404
    stakeholders = misp_store.list_stakeholders()
    pirs = misp_store.list_pirs()
    girs = misp_store.list_girs()
    if request.method == "POST":
        data = _form_data(request.form, rfi.rfi_id)
        if data["owner_uuid"]:
            owner = next((s for s in stakeholders if s.id == data["owner_uuid"]), None)
            if owner:
                data["owner_name"] = owner.name
        try:
            new_id = misp_store.update_rfi(id, data)
            audit.record("update", "rfi", entity_id=id, entity_label=rfi.rfi_id)
            flash(f"{rfi.rfi_id} updated.", "success")
            return redirect(url_for("rfi.rfi_detail", id=new_id))
        except Exception as exc:
            flash(f"Could not update RFI: {exc}", "warning")

    return render_template(
        "rfi/form.html",
        rfi=rfi,
        stakeholders=stakeholders,
        pirs=pirs,
        girs=girs,
        priorities=RFI_PRIORITIES,
        statuses=RFI_STATUSES,
        output_formats=cti_products(),
        tlp_levels=TLP_LEVELS,
        feedback_requirement=FEEDBACK_REQUIREMENT,
        feedback_on_time=FEEDBACK_ON_TIME,
        feedback_usefulness=FEEDBACK_USEFULNESS,
        sla_days=misp_store.RFI_SLA_DAYS,
        is_edit=True,
    )


@bp.route("/<string:id>/delete", methods=["POST"])
def rfi_delete(id):
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return "RFI not found", 404
    label = rfi.rfi_id if rfi else id
    try:
        misp_store.delete_rfi(id)
        audit.record("delete", "rfi", entity_id=id, entity_label=label)
        flash(f"{label} deleted.", "success")
    except Exception as exc:
        logger.warning("rfi_delete %s failed: %s", id, exc)
        flash(f"Could not delete {label}: {exc}", "warning")
    return redirect(url_for("rfi.rfi_list"))


@bp.route("/<string:id>/status", methods=["POST"])
def rfi_status_update(id):
    from flask import jsonify
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return jsonify({"error": "RFI not found"}), 404
    new_status = request.form.get("status", "").strip()
    if new_status not in RFI_STATUSES:
        return jsonify({"error": "Invalid status"}), 400
    data = _rfi_data_from_store(rfi, status=new_status)
    try:
        misp_store.update_rfi(id, data)
        audit.record("update", "rfi", entity_id=id, entity_label=rfi.rfi_id)
        return jsonify({"ok": True, "status": new_status})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/<string:id>/notify", methods=["GET", "POST"])
def rfi_notify(id):
    from datetime import date
    from flask import jsonify
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return "RFI not found", 404
    preview_url = url_for("rfi.rfi_detail", id=id, _external=True)
    today = date.today().strftime('%d-%m-%Y')
    lines = [
        f"# {rfi.rfi_id}: Request for Information",
        f"",
        f"**Date:** {today}",
        f"**Status:** {rfi.status}",
        f"**Priority:** {rfi.priority}",
        f"**TLP:** TLP:{(rfi.deliverable_tlp or 'AMBER').upper()}",
        f"",
        f"## Question",
        f"",
        f"{rfi.question}",
    ]
    if rfi.context:
        lines += ["", f"**Context:** {rfi.context}"]
    if rfi.requester_name:
        lines += ["", f"**Requester:** {rfi.requester_name}" + (f" ({rfi.requester_team})" if rfi.requester_team else "")]
    if rfi.due_date:
        lines += [f"**Due:** {rfi.due_date.strftime('%d-%m-%Y')}"]
    if rfi.response:
        lines += ["", "## Response", "", rfi.response]
    lines += ["", "[Open RFI preview](" + preview_url + ")", "", "---", f"*Sent from zsazsa CTI on {today}*"]
    md = "\n".join(lines)
    recipients = _rfi_notify_recipients(rfi)

    if request.method == "POST":
        try:
            from notifier import dispatcher

            message_md = request.form.get("markdown", "").strip() or md
            logger.info("RFI notify requested: rfi=%s recipients=%d", rfi.rfi_id, len(recipients))
            result = dispatcher.send_rfi_preview(
                rfi,
                preview_url=preview_url,
                markdown=message_md,
                stakeholders=recipients,
            )
            if result["sent_types"]:
                if rfi.status == "New":
                    misp_store.update_rfi(id, _rfi_data_from_store(rfi, status="Acknowledged"))
                    logger.info("RFI auto-acknowledged after notify: rfi=%s", rfi.rfi_id)
                    audit.record(
                        "acknowledge",
                        "rfi",
                        entity_id=id,
                        entity_label=rfi.rfi_id,
                        details="auto via notify",
                    )
                logger.info(
                    "RFI notify sent: rfi=%s sent_types=%s recipients=%d",
                    rfi.rfi_id,
                    ",".join(result["sent_types"]),
                    result["recipients"],
                )
                audit.record(
                    "notify",
                    "rfi",
                    entity_id=id,
                    entity_label=rfi.rfi_id,
                    details=f"ok via {', '.join(result['sent_types'])}; recipients={result['recipients']}",
                )
                flash(
                    f"Notification sent to {result['recipients']} stakeholder(s) via {', '.join(result['sent_types'])}.",
                    "success",
                )
            else:
                logger.warning("RFI notify skipped: rfi=%s recipients=%d no channels", rfi.rfi_id, result["recipients"])
                audit.record(
                    "notify",
                    "rfi",
                    entity_id=id,
                    entity_label=rfi.rfi_id,
                    details=f"skipped; recipients={result['recipients']}; no eligible channels",
                )
                flash("No notification sent, no eligible stakeholder channels configured.", "warning")
        except Exception as exc:
            logger.exception("RFI notify failed: rfi=%s", rfi.rfi_id)
            audit.record("notify", "rfi", entity_id=id, entity_label=rfi.rfi_id, details=f"failed: {exc}")
            flash(f"Notification failed: {exc}", "warning")
        return redirect(url_for("rfi.rfi_detail", id=id))
    from notifier import dispatcher
    diagnostics = dispatcher.describe_delivery(recipients)
    return jsonify({
        "markdown": md,
        "preview_url": preview_url,
        "recipient_count": diagnostics["recipients"],
        "recipient_names": diagnostics["recipient_names"],
        "channel_types": diagnostics["channel_types"],
        "channels_by_type": diagnostics["channels_by_type"],
    })


@bp.route("/<string:id>/attachments", methods=["POST"])
def rfi_attachment_add(id):
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return "RFI not found", 404
    f = request.files.get("attachment")
    if not f or not f.filename:
        flash("No file selected.", "warning")
        return redirect(url_for("rfi.rfi_detail", id=id))
    try:
        misp_store.add_rfi_attachment(id, f.filename, f.read())
        audit.record("update", "rfi", entity_id=id, entity_label=rfi.rfi_id)
        flash(f"Attachment '{f.filename}' added.", "success")
    except Exception as exc:
        flash(f"Could not add attachment: {exc}", "warning")
    return redirect(url_for("rfi.rfi_detail", id=id))


@bp.route("/<string:id>/attachments/<string:attr_uuid>/delete", methods=["POST"])
def rfi_attachment_delete(id, attr_uuid):
    rfi = misp_store.get_rfi(id)
    label = rfi.rfi_id if rfi else id
    try:
        misp_store.delete_rfi_attachment(attr_uuid)
        audit.record("update", "rfi", entity_id=id, entity_label=label)
        flash("Attachment deleted.", "success")
    except Exception as exc:
        flash(f"Could not delete attachment: {exc}", "warning")
    return redirect(url_for("rfi.rfi_detail", id=id))


@bp.route("/<string:id>/attachments/<string:attr_uuid>/download")
def rfi_attachment_download(id, attr_uuid):
    try:
        content, filename = misp_store.get_rfi_attachment_content(attr_uuid)
        return Response(
            content,
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}"},
            mimetype="application/octet-stream",
        )
    except Exception as exc:
        flash(f"Download failed: {exc}", "warning")
        return redirect(url_for("rfi.rfi_detail", id=id))


@bp.route("/<string:id>/notes", methods=["POST"])
def rfi_note_add(id):
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return "RFI not found", 404
    title = (request.form.get("note_title") or "").strip()
    content = (request.form.get("note_content") or "").strip()
    if not title:
        flash("Note title is required.", "warning")
        return redirect(url_for("rfi.rfi_detail", id=id))
    try:
        misp_store.add_rfi_note(id, title, content)
        audit.record("update", "rfi", entity_id=id, entity_label=rfi.rfi_id)
        flash(f"Note '{title}' added.", "success")
    except Exception as exc:
        flash(f"Could not add note: {exc}", "warning")
    return redirect(url_for("rfi.rfi_detail", id=id))


@bp.route("/<string:id>/notes/<string:report_id>/delete", methods=["POST"])
def rfi_note_delete(id, report_id):
    rfi = misp_store.get_rfi(id)
    label = rfi.rfi_id if rfi else id
    try:
        misp_store.delete_rfi_note(report_id)
        audit.record("update", "rfi", entity_id=id, entity_label=label)
        flash("Note deleted.", "success")
    except Exception as exc:
        flash(f"Could not delete note: {exc}", "warning")
    return redirect(url_for("rfi.rfi_detail", id=id))
