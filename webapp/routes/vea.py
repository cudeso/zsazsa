"""Vulnerability Exploitation Advisory (VEA) routes."""

import logging
import re

import config as _cfg
from flask import Blueprint, flash, redirect, render_template, request, url_for

_CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)

from webapp import audit, collection_cache, misp_store

logger = logging.getLogger(__name__)
bp = Blueprint("vea", __name__, url_prefix="/products/vea")


def _form_data(form, vea_id=""):
    return {
        "vea_id": vea_id,
        "cve_id": ", ".join(l.strip() for l in form.get("cve_id", "").splitlines() if l.strip()),
        "summary": form.get("summary", "").strip(),
        "cvss": form.get("cvss", "").strip(),
        "cwe": form.get("cwe", "").strip(),
        "title": form.get("title", "").strip(),
        "tlp": form.get("tlp", "amber"),
        "author": form.get("author", ""),
        "audience": ", ".join(form.getlist("audience")),
        "affected_product": form.get("affected_product", ""),
        "affected_versions": form.get("affected_versions", ""),
        "fixed_version": form.get("fixed_version", ""),
        "exposure": form.get("exposure", ""),
        "observed_exploitation": form.get("observed_exploitation", ""),
        "exploit_availability": form.get("exploit_availability", ""),
        "exploitation_complexity": form.get("exploitation_complexity", ""),
        "threat_actor_interest": form.get("threat_actor_interest", ""),
        "cisa_kev": form.get("cisa_kev", ""),
        "source_description": form.get("source_description", ""),
        "source_reliability": form.get("source_reliability", ""),
        "information_credibility": form.get("information_credibility", ""),
        "worst_case": form.get("worst_case", ""),
        "most_likely": form.get("most_likely", ""),
        "immediate_actions": misp_store._split_lines(form.get("immediate_actions")),
        "patch_sla_internet": form.get("patch_sla_internet", ""),
        "patch_sla_internal": form.get("patch_sla_internal", ""),
        "target_patch_version": form.get("target_patch_version", ""),
        "exploitation_indicators": misp_store._split_lines(form.get("exploitation_indicators")),
        "detection_rules": misp_store._split_lines(form.get("detection_rules")),
        "references": misp_store._split_lines(form.get("references")),
        "context_tags": form.getlist("context_tags"),
        "review_state": form.get("review_state", misp_store.VEA_REVIEW_DRAFT),
        "source_event_uuid": form.get("source_event_uuid", ""),
        "linked_pir_uuid": form.get("linked_pir_uuid", ""),
    }


def _wizard_context(vea=None, source_events=None):
    return {
        "vea": vea,
        "audiences": misp_store.FIA_AUDIENCES,
        "tlp_levels": misp_store.FIA_TLP_LEVELS,
        "reliabilities": misp_store.FIA_RELIABILITIES,
        "credibilities": misp_store.FIA_CREDIBILITIES,
        "review_states": misp_store.VEA_REVIEW_STATES,
        "exploit_availability_options": misp_store.VEA_EXPLOIT_AVAILABILITY,
        "exploit_complexity_options": misp_store.VEA_EXPLOIT_COMPLEXITY,
        "actor_interest_options": misp_store.VEA_ACTOR_INTEREST,
        "cisa_kev_options": misp_store.VEA_CISA_KEV,
        "pirs": misp_store.list_pirs(),
        "action_presets": getattr(_cfg, "RECOMMENDED_ACTIONS_IMMEDIATE", []),
        "source_event_tags": sorted({t for ev in (source_events or []) for t in ev.get("tags", [])}),
    }


def _eligible_vea_recipients(vea):
    allowed = {
        r.get("uuid")
        for r in misp_store.recipient_preview(
            "Vulnerability exploitation advisory",
            vea.tlp,
            vea.audience,
        )
        if r.get("status") == "green" and r.get("uuid")
    }
    if not allowed:
        return []
    return [s for s in misp_store.list_stakeholders() if getattr(s, "uuid", None) in allowed]


def _latest_notify_status(entity_id: str):
    row = audit.latest_event("notify", "vea", entity_id=entity_id)
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


def _vea_markdown(vea, preview_url: str = "") -> str:
    lines = [
        f"# {vea.vea_id}: Vulnerability exploitation advisory",
        "",
        f"**CVE:** {vea.cve_id or '-'}",
        f"**Title:** {vea.title or '-'}",
        f"**TLP:** TLP:{(vea.tlp or 'amber').upper()}",
        f"**Author:** {vea.author or '-'}",
        f"**Audience:** {vea.audience or '-'}",
        "",
        "## Summary",
        "",
        vea.summary or "(no summary)",
        "",
        "## Affected technology",
        "",
        f"Product: {vea.affected_product or '-'}",
        f"Affected versions: {vea.affected_versions or '-'}",
        f"Fixed version: {vea.fixed_version or '-'}",
        f"Exposure: {vea.exposure or '-'}",
        "",
        "## Exploitation status",
        "",
        f"Observed exploitation: {vea.observed_exploitation or '-'}",
        f"Exploit availability: {vea.exploit_availability or '-'}",
        f"Exploitation complexity: {vea.exploitation_complexity or '-'}",
        f"Threat actor interest: {vea.threat_actor_interest or '-'}",
        f"CISA KEV: {vea.cisa_kev or '-'}",
    ]
    if vea.immediate_actions:
        lines += ["", "## Immediate actions", ""]
        for action in vea.immediate_actions:
            if action:
                lines.append(f"- {action}")
    if vea.references:
        lines += ["", "## References", ""]
        for ref in vea.references:
            if ref:
                lines.append(f"- {ref}")
    if preview_url:
        lines += ["", f"[Open advisory]({preview_url})"]
    return "\n".join(lines)


def _publish_and_notify(uuid):
    misp_store.publish_vea(uuid)
    vea = misp_store.get_vea(uuid)
    if vea is None:
        return False
    try:
        from notifier import mattermost

        stakeholders = misp_store.stakeholders_subscribed_to("Vulnerability exploitation advisory")
        preview_url = url_for("vea.detail", id=uuid, _external=True)
        markdown = _vea_markdown(vea, preview_url=preview_url)
        return bool(mattermost.send_vea_notification(vea, markdown, stakeholders=stakeholders))
    except Exception as exc:
        logger.warning("mattermost notify failed for VEA %s: %s", uuid, exc)
        return False


@bp.route("/")
def review():
    state_filter = (request.args.get("state") or "").strip() or None
    veas = misp_store.list_veas(review_state=state_filter)
    return render_template(
        "vea/review.html",
        veas=veas,
        state_filter=state_filter or "",
        review_states=misp_store.VEA_REVIEW_STATES,
    )


@bp.route("/new", methods=["GET", "POST"])
def wizard_new():
    if request.method == "POST":
        data = _form_data(request.form)
        if not data["cve_id"] and not data["title"]:
            flash("CVE ID or title is required.", "warning")
            return render_template("vea/wizard.html", is_edit=False,
                                   source_events=[], **_wizard_context())
        action = request.form.get("action", "save")
        data["review_state"] = (misp_store.VEA_REVIEW_PENDING
                                if action == "submit" else misp_store.VEA_REVIEW_DRAFT)
        try:
            uuid, vea_id = misp_store.create_vea(data)
            audit.record("create", "vea", entity_id=uuid, entity_label=vea_id)
            flash(f"{vea_id} {'submitted for review' if action == 'submit' else 'saved as draft'}.", "success")
            return redirect(url_for("vea.detail", id=uuid))
        except Exception as exc:
            flash(f"Could not create VEA: {exc}", "warning")
    # Parse "uuid|source_id" pairs from ?source= params
    raw_sources = [u.strip() for u in request.args.getlist("source") if u.strip()]
    source_pairs = []
    for s in raw_sources:
        if "|" in s:
            uuid_part, sid_part = s.split("|", 1)
            source_pairs.append((uuid_part.strip(), sid_part.strip()))
        else:
            source_pairs.append((s, ""))
    source_uuids = [p[0] for p in source_pairs]
    source_hints = {p[0]: p[1] for p in source_pairs if p[1]}
    source_events = misp_store.fetch_source_events(source_uuids, source_hints=source_hints) if source_uuids else []
    seed = None
    if source_uuids:
        from types import SimpleNamespace
        def _all_attrs(ev):
            attrs = list(ev.get("attributes", []))
            for obj in ev.get("objects", []):
                attrs.extend(obj.get("attributes", []))
            return attrs

        cve_ids = list(dict.fromkeys(
            a["value"].strip()
            for ev in source_events
            for a in _all_attrs(ev)
            if a.get("type") == "vulnerability" and a.get("value", "").strip()
        ))
        # Also scan event titles - some sources (e.g. CERT.be) only embed CVEs in the title
        for ev in source_events:
            for m in _CVE_RE.findall(ev.get("info", "")):
                cve = m.upper()
                if cve not in cve_ids:
                    cve_ids.append(cve)
        cached_rows = None
        if not cve_ids:
            # MISP fetch may have failed or returned no attributes; fall back to cache
            cached_rows = collection_cache.get_events_by_uuids(source_uuids)
            for row in cached_rows:
                for vid in row.get("vulnerability_ids", []):
                    if vid and vid not in cve_ids:
                        cve_ids.append(vid)

        labels = list(dict.fromkeys(ev["source_label"] for ev in source_events if ev.get("source_label")))
        # Extract worst-case Admiralty values from source event tags
        reliability_letters, credibility_numbers = [], []
        tag_sources = source_events or cached_rows or collection_cache.get_events_by_uuids(source_uuids)
        for ev in tag_sources:
            for t in ev.get("tags", []):
                if 'admiralty-scale:source-reliability=' in t:
                    v = t.split('"')[1] if '"' in t else ''
                    if v: reliability_letters.append(v.upper())
                elif 'admiralty-scale:information-credibility=' in t:
                    v = t.split('"')[1] if '"' in t else ''
                    if v.isdigit(): credibility_numbers.append(int(v))
        worst_reliability = max(reliability_letters) if reliability_letters else ""
        worst_credibility = str(max(credibility_numbers)) if credibility_numbers else ""
        first_title = (source_events[0]["info"] if source_events
                       else (collection_cache.get_events_by_uuids([source_uuids[0]]) or [{}])[0].get("info", ""))

        # Build references: one URL per source MISP event + one per CVE on CIRCL VL
        _source_url_map = {"scraper": _cfg.MISP_URL, "webapp": _cfg.MISP_WEBAPP_URL}
        for _s in getattr(_cfg, "MISP_SERVERS", []) or []:
            _sid = _s.get("id") or _s.get("label") or ""
            if _sid and _s.get("url"):
                _source_url_map[_sid] = _s["url"].rstrip("/")
        references = []
        for uuid, sid in source_pairs:
            base = _source_url_map.get(sid, _cfg.MISP_WEBAPP_URL).rstrip("/")
            references.append(f"{base}/events/view/{uuid}")
        for cve in cve_ids:
            references.append(f"https://vulnerability.circl.lu/vuln/{cve}")

        seed = SimpleNamespace(
            vea_id="",
            cve_id="\n".join(cve_ids),
            title=first_title,
            summary="", cvss="", cwe="",
            tlp="amber", author="", audience="",
            affected_product="", affected_versions="", fixed_version="", exposure="",
            observed_exploitation="", exploit_availability="", exploitation_complexity="",
            threat_actor_interest="", cisa_kev="",
            source_description=", ".join(labels),
            source_reliability=worst_reliability, information_credibility=worst_credibility,
            worst_case="", most_likely="",
            immediate_actions=[], patch_sla_internet="", patch_sla_internal="",
            target_patch_version="", exploitation_indicators=[], detection_rules=[],
            references=references, review_state=misp_store.VEA_REVIEW_DRAFT,
            rejection_reason="", source_event_uuid=source_uuids[0], linked_pir_uuid="",
            context_tags=[],
        )
    return render_template("vea/wizard.html", is_edit=False,
                           source_events=source_events, **_wizard_context(seed, source_events))


@bp.route("/<string:id>")
def detail(id):
    vea = misp_store.get_vea(id)
    if vea is None:
        return "VEA not found", 404
    feedback = misp_store.list_product_feedback(vea.uuid)
    recipients = misp_store.recipient_preview("Vulnerability exploitation advisory", vea.tlp, vea.audience)
    notify_status = _latest_notify_status(id)
    return render_template(
        "vea/detail.html",
        vea=vea,
        feedback=feedback,
        recipients=recipients,
        notify_status=notify_status,
    )


@bp.route("/<string:id>/edit", methods=["GET", "POST"])
def wizard_edit(id):
    vea = misp_store.get_vea(id)
    if vea is None:
        return "VEA not found", 404
    if request.method == "POST":
        data = _form_data(request.form, vea_id=vea.vea_id)
        action = request.form.get("action", "save")
        if action == "submit":
            data["review_state"] = misp_store.VEA_REVIEW_PENDING
        elif action == "publish":
            data["review_state"] = misp_store.VEA_REVIEW_APPROVED
        else:
            data["review_state"] = vea.review_state or misp_store.VEA_REVIEW_DRAFT
        try:
            misp_store.update_vea(id, data)
            audit.record("update", "vea", entity_id=id, entity_label=vea.vea_id)
            if action == "publish":
                sent_ok = _publish_and_notify(id)
                audit.record(
                    "notify",
                    "vea",
                    entity_id=id,
                    entity_label=vea.vea_id,
                    details=f"publish notification; result={'ok' if sent_ok else 'failed'}",
                )
                if sent_ok:
                    flash(f"{vea.vea_id} published.", "success")
                else:
                    flash(f"{vea.vea_id} published, but notification failed.", "warning")
            else:
                flash(f"{vea.vea_id} saved.", "success")
            return redirect(url_for("vea.detail", id=id))
        except Exception as exc:
            flash(f"Could not update VEA: {exc}", "warning")
    return render_template("vea/wizard.html", is_edit=True,
                           source_events=[], **_wizard_context(vea, []))


@bp.route("/<string:id>/approve", methods=["POST"])
def approve(id):
    vea = misp_store.get_vea(id)
    if vea is None:
        return "VEA not found", 404
    try:
        sent_ok = _publish_and_notify(id)
        audit.record("publish", "vea", entity_id=id, entity_label=vea.vea_id)
        audit.record(
            "notify",
            "vea",
            entity_id=id,
            entity_label=vea.vea_id,
            details=f"publish notification; result={'ok' if sent_ok else 'failed'}",
        )
        if sent_ok:
            flash(f"{vea.vea_id} approved and published.", "success")
        else:
            flash(f"{vea.vea_id} approved and published, but notification failed.", "warning")
    except Exception as exc:
        flash(f"Could not publish VEA: {exc}", "warning")
    return redirect(url_for("vea.detail", id=id))


@bp.route("/<string:id>/reject", methods=["POST"])
def reject(id):
    vea = misp_store.get_vea(id)
    if vea is None:
        return "VEA not found", 404
    reason = request.form.get("reason", "").strip()
    try:
        misp_store.reject_vea(id, reason=reason)
        audit.record("reject", "vea", entity_id=id, entity_label=vea.vea_id)
        flash(f"{vea.vea_id} rejected.", "info")
    except Exception as exc:
        flash(f"Could not reject VEA: {exc}", "warning")
    return redirect(url_for("vea.detail", id=id))


@bp.route("/<string:id>/delete", methods=["POST"])
def delete(id):
    vea = misp_store.get_vea(id)
    label = vea.vea_id if vea else id
    try:
        misp_store.delete_vea(id)
        audit.record("delete", "vea", entity_id=id, entity_label=label)
        flash(f"{label} deleted.", "success")
    except Exception as exc:
        flash(f"Could not delete VEA: {exc}", "warning")
    return redirect(url_for("vea.review"))


@bp.route("/<string:id>/resend", methods=["POST"])
def resend(id):
    vea = misp_store.get_vea(id)
    if vea is None:
        return "VEA not found", 404
    if getattr(vea, "review_state", "") != misp_store.VEA_REVIEW_APPROVED:
        flash("Only published advisories can be resent.", "warning")
        return redirect(url_for("vea.review"))
    try:
        from notifier import mattermost

        stakeholders = _eligible_vea_recipients(vea)
        preview_url = url_for("vea.detail", id=id, _external=True)
        markdown = _vea_markdown(vea, preview_url=preview_url)
        sent_ok = mattermost.send_vea_notification(vea, markdown, stakeholders=stakeholders)
        audit.record(
            "notify",
            "vea",
            entity_id=id,
            entity_label=vea.vea_id,
            details=(
                f"resend to stakeholders; recipients={len(stakeholders)}; "
                f"result={'ok' if sent_ok else 'failed'}"
            ),
        )
        if sent_ok:
            flash(f"{vea.vea_id} resent to stakeholders.", "success")
        else:
            flash(f"{vea.vea_id} resend failed. Check notification channels/logs.", "warning")
    except Exception as exc:
        flash(f"Could not resend {vea.vea_id}: {exc}", "warning")
    return redirect(url_for("vea.review"))


@bp.route("/<string:id>/feedback", methods=["POST"])
def add_feedback(id):
    vea = misp_store.get_vea(id)
    if vea is None:
        return "VEA not found", 404
    author = request.form.get("author", "").strip()
    rating = request.form.get("rating", "").strip()
    comment = request.form.get("comment", "").strip()
    try:
        misp_store.add_product_feedback(vea.uuid, author, rating, comment)
        audit.record("create", "vea_feedback", entity_id=id, entity_label=vea.vea_id)
        flash("Feedback recorded.", "success")
    except Exception as exc:
        logger.warning("add_feedback VEA %s failed: %s", id, exc)
        flash(f"Could not record feedback: {exc}", "warning")
    return redirect(url_for("vea.detail", id=id))
