import config as _config

from flask import Blueprint, flash, redirect, render_template, request, url_for

from webapp import audit, misp_store, org_store
from webapp.models import CTI_PRODUCTS, STAKEHOLDER_ROLES, TLP_LEVELS
from webapp.utils import normalize_notification_channels, product_detail_url


def _active_notification_channels() -> list[dict]:
    """Return enabled notification channels from config, migrating legacy single-webhook if needed."""
    channels = normalize_notification_channels(
        getattr(_config, "NOTIFICATION_CHANNELS", []),
        legacy_url=getattr(_config, "MATTERMOST_WEBHOOK_URL", ""),
        legacy_enabled=getattr(_config, "MATTERMOST_ENABLED", False),
    )
    return [c for c in channels if c.get("enabled")]

bp = Blueprint("stakeholders", __name__)


def _parse_contacts(form):
    """Build a list of contact dicts from the multi-row contacts form fields."""
    types = form.getlist("contact_type")
    values = form.getlist("contact_value")
    preferred_idx = form.get("contact_preferred", "")
    contacts = []
    for i, (t, v) in enumerate(zip(types, values)):
        v = v.strip()
        if not v:
            continue
        contacts.append({
            "type": t,
            "value": v,
            "preferred": (str(i) == preferred_idx),
        })
    if contacts and not any(c["preferred"] for c in contacts):
        contacts[0]["preferred"] = True
    return contacts


def _parse_subscriptions(form):
    """Return (products_list, product_modes_dict) from form fields.

    For each product type the form sends ``products=<name>`` (when checked)
    and ``mode__<name>`` set to one of SUBSCRIPTION_MODES.
    """
    selected = form.getlist("products")
    modes = {}
    for p in selected:
        m = form.get(f"mode__{p}", misp_store.DEFAULT_SUBSCRIPTION_MODE)
        if m not in misp_store.SUBSCRIPTION_MODES:
            m = misp_store.DEFAULT_SUBSCRIPTION_MODE
        modes[p] = m
    return selected, modes


def _parse_notification_channels(form) -> list[str]:
    allowed = {
        (channel.get("id") or "").strip()
        for channel in normalize_notification_channels(
            getattr(_config, "NOTIFICATION_CHANNELS", []),
            legacy_url=getattr(_config, "MATTERMOST_WEBHOOK_URL", ""),
            legacy_enabled=getattr(_config, "MATTERMOST_ENABLED", False),
        )
        if (channel.get("id") or "").strip()
    }
    return [channel_id for channel_id in form.getlist("notification_channels") if channel_id in allowed]


@bp.route("/", endpoint="list")
def list_stakeholders():
    stakeholders = misp_store.list_stakeholders()
    return render_template("stakeholders/list.html", stakeholders=stakeholders, org_map=org_store.org_map())


@bp.route("/new", methods=["GET", "POST"])
def new():
    if request.method == "POST":
        products, product_modes = _parse_subscriptions(request.form)
        data = {
            "name": request.form["name"],
            "role": request.form.get("role"),
            "organization": request.form.get("organization"),
            "stakeholder_type": request.form.get("stakeholder_type", "External"),
            "contacts": _parse_contacts(request.form),
            "tlp_clearance": request.form.get("tlp_clearance", "amber"),
            "notes": request.form.get("notes"),
            "products": products,
            "product_modes": product_modes,
            "notification_channels": _parse_notification_channels(request.form),
        }
        try:
            uuid = misp_store.create_stakeholder(data)
            audit.record("create", "stakeholder", entity_id=uuid, entity_label=data['name'])
            flash(f"Stakeholder {data['name']} created.", "success")
            return redirect(url_for("stakeholders.detail", id=uuid))
        except Exception as exc:
            flash(f"Could not create stakeholder: {exc}", "warning")

    return render_template(
        "stakeholders/form.html",
        stakeholder=None,
        roles=STAKEHOLDER_ROLES,
        products=CTI_PRODUCTS,
        tlp_levels=TLP_LEVELS,
        subscription_modes=misp_store.SUBSCRIPTION_MODES,
        default_subscription_mode=misp_store.DEFAULT_SUBSCRIPTION_MODE,
        notification_channels=_active_notification_channels(),
        organisations=org_store.list_organisations(),
    )


@bp.route("/<string:id>")
def detail(id):
    stakeholder = misp_store.get_stakeholder(id)
    if stakeholder is None:
        return "Stakeholder not found", 404
    owned_pirs = misp_store.pirs_for_stakeholder(id)
    distributed_pirs = misp_store.pirs_distributed_to_stakeholder(
        id,
        stakeholder_name=getattr(stakeholder, "name", ""),
        stakeholder_email=getattr(stakeholder, "email", ""),
    )
    owned_girs = misp_store.girs_for_stakeholder(id)
    distributed_girs = misp_store.girs_distributed_to_stakeholder(
        id,
        stakeholder_name=getattr(stakeholder, "name", ""),
        stakeholder_email=getattr(stakeholder, "email", ""),
    )
    recent_products = misp_store.products_for_stakeholder(
        id,
        stakeholder_name=getattr(stakeholder, "name", ""),
        stakeholder_email=getattr(stakeholder, "email", ""),
    )
    for ev in recent_products:
        ev.app_url = product_detail_url(getattr(ev, "product_type", ""), getattr(ev, "uuid", ""), fallback_url=getattr(ev, "misp_url", ""))
    return render_template(
        "stakeholders/detail.html",
        stakeholder=stakeholder,
        owned_pirs=owned_pirs,
        distributed_pirs=distributed_pirs,
        owned_girs=owned_girs,
        distributed_girs=distributed_girs,
        recent_products=recent_products,
        org_map=org_store.org_map(),
    )


@bp.route("/<string:id>/edit", methods=["GET", "POST"])
def edit(id):
    stakeholder = misp_store.get_stakeholder(id)
    if stakeholder is None:
        return "Stakeholder not found", 404
    if request.method == "POST":
        products, product_modes = _parse_subscriptions(request.form)
        data = {
            "name": request.form["name"],
            "role": request.form.get("role"),
            "organization": request.form.get("organization"),
            "stakeholder_type": request.form.get("stakeholder_type", "External"),
            "contacts": _parse_contacts(request.form),
            "tlp_clearance": request.form.get("tlp_clearance", "amber"),
            "notes": request.form.get("notes"),
            "products": products,
            "product_modes": product_modes,
            "notification_channels": _parse_notification_channels(request.form),
        }
        try:
            new_id = misp_store.update_stakeholder(id, data)
            audit.record("update", "stakeholder", entity_id=id, entity_label=data['name'])
            flash(f"Stakeholder {data['name']} updated.", "success")
            return redirect(url_for("stakeholders.detail", id=new_id))
        except Exception as exc:
            flash(f"Could not update stakeholder: {exc}", "warning")

    return render_template(
        "stakeholders/form.html",
        stakeholder=stakeholder,
        roles=STAKEHOLDER_ROLES,
        products=CTI_PRODUCTS,
        tlp_levels=TLP_LEVELS,
        subscription_modes=misp_store.SUBSCRIPTION_MODES,
        default_subscription_mode=misp_store.DEFAULT_SUBSCRIPTION_MODE,
        notification_channels=_active_notification_channels(),
        organisations=org_store.list_organisations(),
    )


@bp.route("/<string:id>/delete", methods=["POST"])
def delete(id):
    stakeholder = misp_store.get_stakeholder(id)
    name = stakeholder.name if stakeholder else id
    try:
        misp_store.delete_stakeholder(id)
        audit.record("delete", "stakeholder", entity_id=id, entity_label=name)
        flash(f"Stakeholder {name} deleted.", "info")
    except Exception as exc:
        flash(f"Could not delete stakeholder: {exc}", "warning")
    return redirect(url_for("stakeholders.list"))
