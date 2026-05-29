from flask import Blueprint, flash, redirect, render_template, request, url_for

from webapp import audit, org_store

bp = Blueprint("community", __name__, url_prefix="/community")


@bp.route("/organisations")
def organisations():
    orgs = org_store.list_organisations()
    return render_template("community/organisations.html", orgs=orgs)


@bp.route("/organisations/add", methods=["POST"])
def organisations_add():
    uuid = (request.form.get("uuid") or "").strip()
    try:
        org = org_store.add_organisation(uuid)
        audit.record("create", "organisation", entity_id=org.uuid, entity_label=org.name)
        flash(f'Organisation "{org.name}" added.', "success")
    except ValueError as exc:
        flash(str(exc), "warning")
    return redirect(url_for("community.organisations"))


@bp.route("/organisations/<string:uuid>/delete", methods=["POST"])
def organisations_delete(uuid):
    org = org_store.get_organisation(uuid)
    name = org.name if org else uuid
    try:
        org_store.delete_organisation(uuid)
        audit.record("delete", "organisation", entity_id=uuid, entity_label=name)
        flash(f'Organisation "{name}" removed.', "info")
    except ValueError as exc:
        flash(str(exc), "warning")
    return redirect(url_for("community.organisations"))


@bp.route("/organisations/<string:uuid>/sync", methods=["POST"])
def organisations_sync(uuid):
    org = org_store.get_organisation(uuid)
    name = org.name if org else uuid
    try:
        updated = org_store.sync_organisation(uuid)
        audit.record("update", "organisation", entity_id=updated.uuid, entity_label=updated.name)
        flash(f'Organisation "{name}" synced from MISP.', "success")
    except ValueError as exc:
        flash(str(exc), "warning")
    return redirect(url_for("community.organisations"))


@bp.route("/organisations/sync-all", methods=["POST"])
def organisations_sync_all():
    updated_count, failed_count = org_store.sync_all_organisations()
    audit.record(
        "update",
        "organisation",
        entity_id="all",
        entity_label=f"sync-all updated={updated_count} failed={failed_count}",
    )
    if failed_count:
        flash(
            f"Synced {updated_count} organisations from MISP, {failed_count} failed.",
            "warning",
        )
    else:
        flash(f"Synced {updated_count} organisations from MISP.", "success")
    return redirect(url_for("community.organisations"))


@bp.route("/users")
def users():
    return render_template("community/users.html")


@bp.route("/roles")
def roles():
    return render_template("community/roles.html")
