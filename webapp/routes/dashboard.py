import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from flask import Blueprint, jsonify, render_template

import config
from analyser.reader import save_last_run
from webapp import analyser_pipeline
from webapp import misp_store
from webapp.utils import json_body as _json_object

logger = logging.getLogger(__name__)
bp = Blueprint("dashboard", __name__)


_PIPELINE_JOBS = {}
_PIPELINE_JOBS_LOCK = threading.Lock()


def _steps_for_action(action: str) -> list[dict]:
    common = [
        {"id": "refresh-cache", "label": "Refresh scraper cache", "state": "pending"},
        {"id": "collect-events", "label": "Load today's incomplete events", "state": "pending"},
        {"id": "filter-events", "label": "Filter hard negatives", "state": "pending"},
        {"id": "generate-summaries", "label": "Generate missing LLM summaries", "state": "pending"},
    ]
    if action == "daily-briefing":
        common.extend([
            {"id": "review-relevance", "label": "Review relevance and usefulness", "state": "pending"},
            {"id": "build-briefing", "label": "Build briefing story set", "state": "pending"},
            {"id": "check-overlap", "label": "Check overlap and remove duplicates", "state": "pending"},
            {"id": "create-drafts", "label": "Create daily briefing draft", "state": "pending"},
        ])
    elif action == "flash-intel":
        common.extend([
            {"id": "match-requirements", "label": "Match events to PIR/GIR", "state": "pending"},
            {"id": "create-drafts", "label": "Create flash intel draft(s)", "state": "pending"},
        ])
    elif action == "vea":
        common.extend([
            {"id": "detect-cves", "label": "Detect CVE matches", "state": "pending"},
            {"id": "create-drafts", "label": "Create vulnerability advisory draft(s)", "state": "pending"},
        ])
    return common


def _new_pipeline_job(action: str) -> dict:
    job_id = uuid4().hex
    now = time.time()
    job = {
        "id": job_id,
        "action": action,
        "status": "queued",
        "message": "Queued",
        "steps": _steps_for_action(action),
        "created_at": now,
        "updated_at": now,
        "result": None,
        "error": None,
        "log": [{"timestamp": now, "message": "Job queued."}],
    }
    with _PIPELINE_JOBS_LOCK:
        _PIPELINE_JOBS[job_id] = job
        # Keep memory bounded.
        if len(_PIPELINE_JOBS) > 40:
            oldest = sorted(_PIPELINE_JOBS.values(), key=lambda j: j.get("created_at", 0))[:10]
            for item in oldest:
                _PIPELINE_JOBS.pop(item["id"], None)
    return job


def _update_job(job_id: str, **fields) -> None:
    with _PIPELINE_JOBS_LOCK:
        job = _PIPELINE_JOBS.get(job_id)
        if not job:
            return
        job.update(fields)
        job["updated_at"] = time.time()


def _append_job_log(job_id: str, message: str) -> None:
    with _PIPELINE_JOBS_LOCK:
        job = _PIPELINE_JOBS.get(job_id)
        if not job:
            return
        job.setdefault("log", []).append({"timestamp": time.time(), "message": message})
        # Keep recent log lines only.
        if len(job["log"]) > 50:
            job["log"] = job["log"][-50:]
        job["updated_at"] = time.time()


def _update_job_step(job_id: str, step: str, state: str, message: str = "") -> None:
    with _PIPELINE_JOBS_LOCK:
        job = _PIPELINE_JOBS.get(job_id)
        if not job:
            return
        for row in job.get("steps", []):
            if row.get("id") == step:
                row["state"] = state
                break
        if message:
            job["message"] = message
            job.setdefault("log", []).append({"timestamp": time.time(), "message": message})
            if len(job["log"]) > 50:
                job["log"] = job["log"][-50:]
        job["updated_at"] = time.time()


def _run_pipeline_job(job_id: str) -> None:
    with _PIPELINE_JOBS_LOCK:
        job = _PIPELINE_JOBS.get(job_id)
        if not job:
            return
        action = job["action"]
    handlers = {
        "daily-briefing": analyser_pipeline.run_daily_briefing_action,
        "flash-intel": analyser_pipeline.run_flash_intel_action,
        "vea": analyser_pipeline.run_vea_action,
    }
    handler = handlers.get(action)
    if handler is None:
        _update_job(job_id, status="failed", error="Unknown pipeline action.", message="Unknown pipeline action.")
        return

    _update_job(job_id, status="running", message="Running...")
    _append_job_log(job_id, f"Started action '{action}'.")

    def _progress(*, step: str, state: str, message: str = ""):
        _update_job_step(job_id, step=step, state=state, message=message)

    try:
        result = handler(progress=_progress)
        # Keep dashboard pipeline freshness in sync with manual runs.
        save_last_run(int(time.time()))
        with _PIPELINE_JOBS_LOCK:
            job = _PIPELINE_JOBS.get(job_id)
            if job:
                for row in job.get("steps", []):
                    if row.get("state") == "in_progress":
                        row["state"] = "completed"
        _update_job(
            job_id,
            status="completed",
            result=result,
            message=(result or {}).get("message") or "Completed.",
            error=None,
        )
        _append_job_log(job_id, "Action completed.")
    except Exception as exc:
        _update_job(job_id, status="failed", error=str(exc), message=f"Failed: {exc}")
        _append_job_log(job_id, f"Action failed: {exc}")
        logger.exception("Pipeline job %s failed", job_id)


def _pipeline_status():
    """Return scraper / analyser pipeline status for the dashboard panel.

    - ``last_run`` (datetime | None): when the analyser last completed a run,
      from ``data/state.json``.
    - ``minutes_since`` (int | None): age in minutes of that timestamp.
    - ``stale`` (bool): True if the last run is older than 90 minutes.
    - ``processed_24h`` (dict): counts per outcome from ``event_log`` over
      the last 24h.
    - ``pending`` (int | None): scraper events still tagged
      ``workflow:state="incomplete"`` and waiting for the analyser.
    """
    status = {
        "last_run": None, "minutes_since": None, "stale": True,
        "processed_24h": {}, "total_24h": 0, "pending": None,
    }

    # Last analyser run
    try:
        state = json.loads(Path(config.STATE_FILE).read_text())
        ts = state.get("analyser_last_run")
        if ts:
            dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
            status["last_run"] = dt
            age = (datetime.now(tz=timezone.utc) - dt).total_seconds() / 60
            status["minutes_since"] = int(age)
            status["stale"] = age > 90
    except Exception:
        logger.exception("Failed to read pipeline state from %s", config.STATE_FILE)

    # Outcomes over the last 24h from analyser DB
    try:
        with sqlite3.connect(config.DB_FILE) as conn:
            rows = conn.execute(
                "SELECT outcome, COUNT(*) FROM event_log "
                "WHERE processed_at >= datetime('now', '-1 day') "
                "GROUP BY outcome"
            ).fetchall()
        status["processed_24h"] = {outcome: n for outcome, n in rows}
        status["total_24h"] = sum(status["processed_24h"].values())
    except Exception:
        logger.exception("Failed to query analyser DB for 24h event counts")

    # Pending scraper events (workflow incomplete). MISP tag filters are OR,
    # so search by the scraper marker and AND-filter the workflow tag locally.
    try:
        misp = misp_store._scraper_misp()
        pending = misp.search(
            tags=[config.SCRAPER_MARKER_TAG],
            limit=500, metadata=True, pythonify=True,
        )
        if pending and not isinstance(pending, dict):
            needed = 'workflow:state="incomplete"'
            status["pending"] = sum(
                1 for e in pending
                if any(getattr(t, "name", "") == needed for t in (getattr(e, "tags", []) or []))
            )
    except Exception:
        logger.exception("Failed to query pending scraper events from MISP")

    return status


@bp.route("/")
def index():
    try:
        c = misp_store.counts()
        pir_count = c["pir"]
        gir_count = c["gir"]
        stakeholder_count = c["stakeholder"]

        active_pirs = [
            p for p in misp_store.list_pirs()
            if p.status in ("Active", "In Development", "Under Evaluation")
        ]
        active_girs = [g for g in misp_store.list_girs() if g.status == "Active"]
    except Exception:
        pir_count = gir_count = stakeholder_count = 0
        active_pirs = active_girs = []

    pipeline = _pipeline_status()

    misp_servers = []
    for s in getattr(config, "MISP_SERVERS", []) or []:
        if s.get("enabled", True) and s.get("url"):
            misp_servers.append({
                "label": s.get("label") or s.get("id") or "MISP",
                "url": s["url"],
            })

    return render_template(
        "dashboard.html",
        pir_count=pir_count,
        gir_count=gir_count,
        stakeholder_count=stakeholder_count,
        active_pirs=active_pirs,
        active_girs=active_girs,
        pipeline=pipeline,
        misp_servers=misp_servers,
    )


@bp.route("/pipeline/run", methods=["POST"])
def run_pipeline_action():
    body, err = _json_object()
    if err:
        return jsonify({"ok": False, "error": "Invalid JSON payload."}), 400

    action = (body.get("action") or "").strip().lower()
    if action not in {"daily-briefing", "flash-intel", "vea"}:
        return jsonify({"ok": False, "error": "Unknown pipeline action."}), 400

    job = _new_pipeline_job(action)
    t = threading.Thread(target=_run_pipeline_job, args=(job["id"],), daemon=True, name=f"pipeline-{action}")
    t.start()
    return jsonify({"ok": True, "job_id": job["id"], "action": action})


@bp.route("/pipeline/run/<string:job_id>", methods=["GET"])
def pipeline_job_status(job_id: str):
    with _PIPELINE_JOBS_LOCK:
        job = _PIPELINE_JOBS.get(job_id)
        if not job:
            return jsonify({"ok": False, "error": "Job not found."}), 404
        payload = dict(job)
        payload["steps"] = [dict(s) for s in job.get("steps", [])]
        payload["log"] = [dict(l) for l in job.get("log", [])]
    return jsonify({"ok": True, "job": payload})
