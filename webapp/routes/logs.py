from flask import Blueprint, render_template, request

from webapp import audit

bp = Blueprint("logs", __name__)


@bp.route("/logs")
def index():
    selected_action = (request.args.get("action") or "").strip()
    selected_type = (request.args.get("type") or "").strip()
    entries = audit.get_logs(action=selected_action or None, entity_type=selected_type or None)
    filters = audit.log_filters()
    return render_template(
        "logs.html",
        entries=entries,
        actions=filters["actions"],
        types=filters["types"],
        selected_action=selected_action,
        selected_type=selected_type,
    )
