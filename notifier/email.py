import logging
import smtplib
from contextlib import contextmanager
from email.message import EmailMessage

import config
from webapp.utils import md_to_html, normalize_notification_channels

logger = logging.getLogger(__name__)


@contextmanager
def _smtp_session(host: str, port: int, use_tls: bool, username: str, password: str):
    """Open an authenticated SMTP session, closed automatically on exit."""
    with smtplib.SMTP(host, port or 587, timeout=20) as server:
        if use_tls:
            server.starttls()
        if username:
            server.login(username, password)
        yield server


def _settings() -> dict:
    """SMTP server settings, shared by all email channels."""
    return {
        "host": (getattr(config, "SMTP_HOST", "") or "").strip(),
        "port": int(getattr(config, "SMTP_PORT", 587) or 587),
        "use_tls": bool(getattr(config, "SMTP_USE_TLS", True)),
        "username": (getattr(config, "SMTP_USERNAME", "") or "").strip(),
        "password": getattr(config, "SMTP_PASSWORD", "") or "",
        "sender": (getattr(config, "SMTP_FROM", "") or "").strip(),
    }


def _recipients(channel_ids: list | None = None) -> list[str]:
    """Resolve enabled email channels to recipient addresses.

    If channel_ids is given, only those channels are considered; otherwise all
    enabled email channels are used. Addresses are de-duplicated.
    """
    channels = normalize_notification_channels(getattr(config, "NOTIFICATION_CHANNELS", []))
    seen: set[str] = set()
    recipients: list[str] = []
    for ch in channels:
        if (ch.get("type") or "").strip().lower() != "email" or not ch.get("enabled"):
            continue
        if channel_ids is not None and ch.get("id") not in channel_ids:
            continue
        addr = (ch.get("recipient") or "").strip()
        if addr and addr not in seen:
            seen.add(addr)
            recipients.append(addr)
    return recipients


def test_connection(host: str, port: int, use_tls: bool, username: str, password: str) -> dict:
    """Check SMTP connectivity and, if a username is given, authentication.

    Does not send any mail. Returns {"ok": bool, "error": str} for the UI.
    """
    if not host:
        return {"ok": False, "error": "SMTP host is required"}
    try:
        with _smtp_session(host, port, use_tls, username, password):
            pass
        return {"ok": True}
    except (smtplib.SMTPException, OSError) as e:
        return {"ok": False, "error": str(e)}


def _html_document(markdown: str) -> str:
    """Wrap rendered Markdown in a minimal styled HTML document for email clients."""
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8"><style>'
        "body{font-family:Arial,Helvetica,sans-serif;color:#1a1a1a;line-height:1.5;"
        "max-width:720px;margin:0 auto;padding:16px;}"
        "h1,h2,h3{color:#0f2d52;}a{color:#0078f1;}"
        "code,pre{background:#f4f6f8;border-radius:4px;padding:2px 4px;}"
        "table{border-collapse:collapse;}td,th{border:1px solid #ddd;padding:6px;}"
        "</style></head><body>"
        f"{md_to_html(markdown)}"
        "</body></html>"
    )


def send_email(recipients: list[str], subject: str, markdown: str, label: str,
               attachments: list[tuple] | None = None) -> bool:
    """Send one multipart (plaintext + HTML) email to the given recipients.

    `attachments` is an optional list of (filename, bytes, mime_subtype) tuples,
    attached as text/<mime_subtype> (e.g. ("feed.csv", b"...", "csv")).
    """
    if not recipients:
        logger.debug("No email recipients for %s", label)
        return False
    cfg = _settings()
    if not cfg["host"] or not cfg["sender"]:
        logger.error("SMTP not configured (host/from missing) - cannot send %s", label)
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["sender"]
    # With several recipients, keep their addresses private from one another: the
    # visible To is the sender and delivery happens via the explicit list below.
    msg["To"] = recipients[0] if len(recipients) == 1 else cfg["sender"]
    msg.set_content(markdown or "")
    msg.add_alternative(_html_document(markdown), subtype="html")
    for filename, data, subtype in attachments or []:
        msg.add_attachment(data, maintype="text", subtype=subtype, filename=filename)

    try:
        with _smtp_session(cfg["host"], cfg["port"], cfg["use_tls"], cfg["username"], cfg["password"]) as server:
            server.send_message(msg, to_addrs=recipients)
        logger.info("Email notification sent (%s) to %d recipient(s)", label, len(recipients))
        return True
    except (smtplib.SMTPException, OSError) as e:
        logger.error("Email notification failed (%s): %s", label, e)
        return False


# Per-product senders. The markdown already carries the product content (and any
# preview link), so each only needs to build a subject line. Signatures match the
# calls the dispatcher makes for each product type.

def send_pir_notification(pir, markdown: str, channel_ids: list[str] | None = None) -> bool:
    subject = f"[CTI] {pir.pir_id}: {(getattr(pir, 'question', '') or '')[:80]}"
    return send_email(_recipients(channel_ids), subject, markdown, f"PIR {pir.pir_id}")


def send_gir_notification(gir, markdown: str, channel_ids: list[str] | None = None) -> bool:
    subject = f"[CTI] {gir.gir_id}: {(getattr(gir, 'topic', '') or '')[:80]}"
    return send_email(_recipients(channel_ids), subject, markdown, f"GIR {gir.gir_id}")


def send_rfi_notification(rfi, markdown: str, channel_ids: list[str] | None = None) -> bool:
    subject = f"[CTI] {rfi.rfi_id}: {(getattr(rfi, 'question', '') or '')[:80]}"
    return send_email(_recipients(channel_ids), subject, markdown, f"RFI {rfi.rfi_id}")


def send_daily_briefing_notification(briefing, markdown: str, channel_ids: list[str] | None = None) -> bool:
    date = getattr(briefing, "date", "")
    title = getattr(briefing, "title", "") or ""
    subject = f"[CTI] Daily briefing {date}" + (f": {title}" if title else "")
    return send_email(_recipients(channel_ids), subject, markdown, f"Daily briefing {date}")


def send_vea_notification(vea, markdown: str, channel_ids: list[str] | None = None) -> bool:
    vea_id = getattr(vea, "vea_id", "")
    descriptor = ", ".join(p for p in (getattr(vea, "cve_id", ""), getattr(vea, "title", "")) if p)
    subject = f"[CTI] {vea_id}: {descriptor}" if descriptor else f"[CTI] {vea_id}"
    return send_email(_recipients(channel_ids), subject, markdown, f"VEA {vea_id}")


def send_flash_intel_alert(fia_id: str, content: str, channel_ids: list[str] | None = None) -> bool:
    subject = f"[CTI] {fia_id}: Flash Intel Alert"
    return send_email(_recipients(channel_ids), subject, content, fia_id)


def send_indicator_feed_notification(feed, markdown: str, channel_ids: list[str] | None = None,
                                     csv_bytes: bytes | None = None) -> bool:
    feed_id = getattr(feed, "feed_id", "")
    name = getattr(feed, "name", "") or ""
    subject = f"[CTI] {feed_id}: {name}" if name else f"[CTI] {feed_id}"
    attachments = None
    if csv_bytes:
        slug = (name or feed_id or "indicator-feed").lower().replace(" ", "-")
        attachments = [(f"{slug}.csv", csv_bytes, "csv")]
    return send_email(_recipients(channel_ids), subject, markdown, f"Indicator feed {feed_id}", attachments)
