import json
import logging
from pathlib import Path

import openai
import config

logger = logging.getLogger(__name__)
_client = None


def _api_key() -> str:
    return getattr(config, "OPENAI_API_KEY", getattr(config, "ANTHROPIC_API_KEY", ""))


def _default_model() -> str:
    return getattr(config, "OPENAI_MODEL", getattr(config, "ANTHROPIC_MODEL", ""))


def _get_client() -> openai.OpenAI:
    global _client
    if _client is None:
        _client = openai.OpenAI(api_key=_api_key())
    return _client


def _build_system_prompt(prompt_file: str, extra: str = "") -> str:
    base = Path(prompt_file).read_text()
    return f"{base}\n\n{extra}".strip() if extra else base


def _resolve_prompt(filename: str) -> str:
    """Convert a bare filename to its prompts/ path."""
    if "/" in filename or "\\" in filename:
        return filename
    return str(Path("prompts") / filename)


def _call(system: str, user: str, max_tokens: int, feature: str = "unknown", model: str = None) -> str:
    effective_model = (model or "").strip() or _default_model()
    response = _get_client().chat.completions.create(
        model=effective_model,
        max_tokens=max_tokens,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    usage = response.usage
    if usage:
        try:
            from core.db import log_llm_usage
            log_llm_usage(feature, effective_model,
                          usage.prompt_tokens, usage.completion_tokens, usage.total_tokens)
        except Exception as exc:
            logger.warning("Could not record LLM usage: %s", exc)
    return response.choices[0].message.content.strip()


def _feature_cfg(feature_id: str) -> dict:
    try:
        from core.ai_config import get_feature
        return get_feature(feature_id)
    except Exception as exc:
        logger.warning("ai_config unavailable for %s: %s", feature_id, exc)
        return {}


def check_relevance(article_content: str, focus_points: dict, source_reliability: str) -> dict:
    fc = _feature_cfg("check_relevance")
    system = _build_system_prompt(
        _resolve_prompt(fc.get("prompt") or "flash_intel_relevance.md"),
        f"Focus points:\n{json.dumps(focus_points, indent=2)}\n\nSource reliability (Admiralty Scale): {source_reliability}",
    )
    text = _call(system, article_content[:10000], 512, feature="check_relevance", model=fc.get("model"))
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.error("Relevance check returned invalid JSON: %s", text[:200])
        return {"relevant": False, "reason": "LLM response parse error"}


def generate_flash_intel(
    article_content: str,
    focus_points: dict,
    matched_points: list,
    source_reliability: str,
    event_date: str,
) -> str:
    fc = _feature_cfg("generate_flash_intel")
    system = _build_system_prompt(
        _resolve_prompt(fc.get("prompt") or "flash_intel_generate.md"),
        f"Focus points configured:\n{json.dumps(focus_points, indent=2)}",
    )
    user_message = (
        f"Matched focus points: {json.dumps(matched_points)}\n"
        f"Source reliability (Admiralty Scale): {source_reliability}\n"
        f"Event date: {event_date}\n\n"
        f"Article content:\n{article_content[:12000]}"
    )
    return _call(system, user_message, 2048, feature="generate_flash_intel", model=fc.get("model"))


def generate_fia_draft(
    content: str,
    event_info: str = "",
    event_date: str = "",
    source_reliability: str = "",
) -> str:
    """Generate a Flash Intel Alert draft from article content."""
    focus_points = {
        "geographies": list(getattr(config, "FOCUS_POINTS_GEOGRAPHIES", []) or []),
        "sectors": list(getattr(config, "FOCUS_POINTS_SECTORS", []) or []),
        "technologies": list(getattr(config, "FOCUS_POINTS_TECHNOLOGIES", []) or []),
        "threat_types": list(getattr(config, "FOCUS_POINTS_THREAT_TYPES", []) or []),
        "threat_actors": list(getattr(config, "FOCUS_POINTS_THREAT_ACTORS", []) or []),
    }
    fc = _feature_cfg("generate_fia_draft")
    system = _build_system_prompt(
        _resolve_prompt(fc.get("prompt") or "flash_intel_generate.md"),
        f"Focus points configured:\n{json.dumps(focus_points, indent=2)}" if focus_points else "",
    )
    user_message = (
        f"Event title: {event_info}\n"
        f"Event date: {event_date or 'unknown'}\n"
        f"Source reliability (Admiralty Scale): {source_reliability or 'unknown'}\n\n"
        f"Article content:\n{content[:12000]}"
    )
    return _call(system, user_message, 2048, feature="generate_fia_draft", model=fc.get("model"))


def draft_briefing_story(article_content: str, focus_points: dict = None) -> str:
    fc = _feature_cfg("draft_briefing_story")
    system = _build_system_prompt(
        _resolve_prompt(fc.get("prompt") or "daily_briefing_story.md"),
        f"Organisation focus points:\n{json.dumps(focus_points or {}, indent=2)}" if focus_points else "",
    )
    return _call(system, article_content[:10000], 512, feature="draft_briefing_story", model=fc.get("model"))


def review_briefing_relevance(event_title: str, report_title: str, content: str) -> dict:
    """Decide if a source story should be included in the daily briefing."""
    fc = _feature_cfg("review_briefing_relevance")
    system = _build_system_prompt(
        _resolve_prompt(fc.get("prompt") or "daily_briefing_relevance.md")
    )
    payload = {
        "event_title": (event_title or "").strip(),
        "report_title": (report_title or "").strip(),
        "content": (content or "")[:12000],
    }
    text = _call(system, json.dumps(payload, ensure_ascii=True), 256, feature="review_briefing_relevance", model=fc.get("model"))
    try:
        parsed = json.loads(text)
        return {
            "include": bool(parsed.get("include", True)),
            "reason": (parsed.get("reason") or "").strip(),
        }
    except json.JSONDecodeError:
        logger.warning("review_briefing_relevance returned invalid JSON")
        return {"include": True, "reason": "fallback include on parse error"}


def detect_story_overlaps(stories: list[dict]) -> dict:
    """Detect potentially duplicate daily briefing stories.

    Returns a dict with keys:
    - overlaps: list of {a, b, score, reason}
    - summary: short operator-facing guidance
    """
    fc = _feature_cfg("detect_story_overlaps")
    system = _build_system_prompt(
        _resolve_prompt(fc.get("prompt") or "daily_briefing_overlap.md")
    )
    payload = {
        "stories": [
            {
                "index": idx + 1,
                "title": (s.get("title") or "").strip(),
                "content": (s.get("content") or "").strip(),
                "source_url": (s.get("source_url") or "").strip(),
            }
            for idx, s in enumerate(stories or [])
        ]
    }
    text = _call(system, json.dumps(payload, ensure_ascii=True), 1024, feature="detect_story_overlaps", model=fc.get("model"))
    try:
        parsed = json.loads(text)
        overlaps = parsed.get("overlaps") if isinstance(parsed, dict) else []
        if not isinstance(overlaps, list):
            overlaps = []
        cleaned = []
        for item in overlaps:
            if not isinstance(item, dict):
                continue
            try:
                a = int(item.get("a", 0))
                b = int(item.get("b", 0))
                score = float(item.get("score", 0))
            except (TypeError, ValueError):
                continue
            if a <= 0 or b <= 0 or a == b:
                continue
            cleaned.append({
                "a": a,
                "b": b,
                "score": max(0.0, min(1.0, score)),
                "reason": (item.get("reason") or "").strip(),
            })
        return {
            "overlaps": cleaned,
            "summary": (parsed.get("summary") or "").strip() if isinstance(parsed, dict) else "",
        }
    except json.JSONDecodeError:
        # Deterministic fallback: crude title token overlap only.
        def _tokens(v: str) -> set[str]:
            return {t for t in (v or "").lower().replace("/", " ").replace("-", " ").split() if len(t) > 3}

        items = [((s.get("title") or "").strip(), (s.get("content") or "").strip()) for s in (stories or [])]
        overlaps = []
        for i in range(len(items)):
            ti, ci = items[i]
            set_i = _tokens(ti) | _tokens(ci[:220])
            if not set_i:
                continue
            for j in range(i + 1, len(items)):
                tj, cj = items[j]
                set_j = _tokens(tj) | _tokens(cj[:220])
                if not set_j:
                    continue
                inter = len(set_i & set_j)
                union = len(set_i | set_j)
                if union <= 0:
                    continue
                score = inter / union
                if score >= 0.35:
                    overlaps.append({
                        "a": i + 1,
                        "b": j + 1,
                        "score": round(score, 2),
                        "reason": "High lexical overlap in title/opening text.",
                    })
        return {
            "overlaps": overlaps,
            "summary": "Fallback overlap check used.",
        }


def summarise_report(report_content: str, event_info: str = "", tags: list = None) -> str:
    """Summarise a MISP event report. Returns structured text or 'QUALITY: ...' if content is unusable."""
    fc = _feature_cfg("summarise_report")
    system = _build_system_prompt(_resolve_prompt(fc.get("prompt") or "summarise_misp_report.md"))
    ctx_lines = []
    if event_info:
        ctx_lines.append(f"Event title: {event_info}")
    if tags:
        ctx_lines.append(f"Event tags: {', '.join(tags)}")
    prefix = "\n".join(ctx_lines)
    user_message = f"{prefix}\n\nReport content:\n{report_content[:12000]}" if prefix else f"Report content:\n{report_content[:12000]}"
    return _call(system, user_message, 1024, feature="summarise_report", model=fc.get("model"))


def draft_vea_sections(cve_id: str, product_info: str = "", article_content: str = "") -> dict:
    """Draft VEA structured sections from CVE and article information."""
    fc = _feature_cfg("draft_vea_sections")
    system = _build_system_prompt(_resolve_prompt(fc.get("prompt") or "vea_draft.md"))
    user_message = "\n\n".join(filter(None, [
        f"CVE: {cve_id}" if cve_id else "",
        f"Product/context: {product_info}" if product_info else "",
        f"Article/advisory content:\n{article_content[:10000]}" if article_content else "",
    ]))
    text = _call(system, user_message, 1024, feature="draft_vea_sections", model=fc.get("model"))
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.error("VEA draft returned invalid JSON: %s", text[:200])
        return {}
