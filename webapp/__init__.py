import os
import secrets

from flask import Flask, abort, request, session

import config
from webapp import audit, org_store, collection_cache


def create_app():
    app = Flask(__name__)

    secret_key = os.environ.get("SECRET_KEY") or getattr(config, "SECRET_KEY", None)
    if not secret_key:
        raise RuntimeError("SECRET_KEY is not configured")
    app.config["SECRET_KEY"] = secret_key
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    audit.init()
    org_store.init_db()
    from core.db import init_db as _init_core_db
    _init_core_db()
    collection_cache.start_worker()

    def _csrf_token():
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_hex(32)
        return session["_csrf_token"]

    @app.before_request
    def _validate_csrf():
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not token or token != session.get("_csrf_token"):
                abort(403)

    app.jinja_env.globals["csrf_token"] = _csrf_token

    @app.context_processor
    def _inject_misp_url():
        return {"misp_webapp_url": config.MISP_WEBAPP_URL}

    @app.template_filter("slug")
    def _slug(s):
        if not s:
            return ""
        return (
            s.lower()
            .replace("'", "")
            .replace("+", "-")
            .replace(":", "")
            .replace(" ", "-")
        )

    from webapp.routes.dashboard import bp as dashboard_bp
    from webapp.routes.stakeholders import bp as stakeholders_bp
    from webapp.routes.requirements import bp as requirements_bp
    from webapp.routes.stats import bp as stats_bp
    from webapp.routes.export import bp as export_bp
    from webapp.routes.logs import bp as logs_bp
    from webapp.routes.config_page import bp as config_page_bp
    from webapp.routes.data_collection import bp as data_collection_bp
    from webapp.routes.rfi import bp as rfi_bp
    from webapp.routes.products import bp as products_bp
    from webapp.routes.flash_intel import bp as flash_intel_bp
    from webapp.routes.community import bp as community_bp
    from webapp.routes.vea import bp as vea_bp
    from webapp.routes.daily_briefing import bp as daily_briefing_bp
    from webapp.routes.threat_landscape import bp as threat_landscape_bp
    from webapp.routes.api import bp as api_bp
    from webapp.routes.collection_sources import bp as collection_sources_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(stakeholders_bp, url_prefix="/stakeholders")
    app.register_blueprint(requirements_bp)
    app.register_blueprint(stats_bp)
    app.register_blueprint(export_bp, url_prefix="/export")
    app.register_blueprint(logs_bp)
    app.register_blueprint(config_page_bp)
    app.register_blueprint(data_collection_bp)
    app.register_blueprint(rfi_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(flash_intel_bp)
    app.register_blueprint(vea_bp)
    app.register_blueprint(daily_briefing_bp)
    app.register_blueprint(threat_landscape_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(community_bp)
    app.register_blueprint(collection_sources_bp)

    return app
