import logging
from collections import defaultdict

import config

from notifier import mattermost, email
from webapp.utils import normalize_notification_channels

logger = logging.getLogger(__name__)


def _channels_by_type(stakeholders: list) -> dict[str, set[str]]:
    """Return channel-id sets grouped by channel type from stakeholder preferences."""
    from core import flowintel_client

    configured = {
        (c.get("id") or "").strip(): (c.get("type") or "mattermost").strip().lower()
        for c in normalize_notification_channels(
            getattr(config, "NOTIFICATION_CHANNELS", []),
            legacy_url=getattr(config, "MATTERMOST_WEBHOOK_URL", ""),
            legacy_enabled=getattr(config, "MATTERMOST_ENABLED", False),
        )
        if isinstance(c, dict)
    }
    for c in flowintel_client.notification_channels():
        cid = (c.get("id") or "").strip()
        if cid:
            configured[cid] = (c.get("type") or "flowintel").strip().lower()
    grouped: dict[str, set[str]] = defaultdict(set)
    for s in stakeholders or []:
        for channel_id in (getattr(s, "notification_channels", None) or []):
            if not isinstance(channel_id, str):
                continue
            cid = channel_id.strip()
            if cid:
                ctype = configured.get(cid, "mattermost")
                grouped[ctype].add(cid)
    return grouped


def describe_delivery(stakeholders: list) -> dict:
    channels = _channels_by_type(stakeholders)
    return {
        "recipients": len(stakeholders or []),
        "recipient_names": [getattr(s, "name", "") for s in stakeholders or [] if getattr(s, "name", "")],
        "channel_types": sorted(channels.keys()),
        "channels_by_type": {k: len(v) for k, v in channels.items()},
    }


def describe_pir_delivery(stakeholders: list) -> dict:
    return describe_delivery(stakeholders)


def _dispatch(stakeholders: list, senders: dict, entity_label: str, entity_id: str) -> dict:
    """Deliver to stakeholder channels grouped by type, using a type->sender map.

    `senders` maps a channel type to a callable(channel_ids) -> bool. Channel
    types present on stakeholders but without a sender here are reported as
    skipped, never silently dropped. This is the single dispatch model shared by
    the preview and full-content paths.

    Note on flowintel: a flowintel case is created per product from the template
    configured for that product on the instance, so it is driven by the
    VEA/flash-intel publish flows via flowintel_client.send_to_eligible_instances,
    not from here. RFI/PIR/GIR have no flowintel sender, so a stakeholder's
    flowintel channel is reported as skipped on those paths by design.
    """
    channels = _channels_by_type(stakeholders)
    summary = describe_delivery(stakeholders)
    summary.update({
        "attempted_types": sorted(channels.keys()),
        "sent_types": [], "failed_types": [], "skipped_types": [],
    })

    for ctype, ids in channels.items():
        sender = senders.get(ctype)
        if sender is None:
            # No sender on this path (e.g. flowintel, handled by the publish flows).
            summary["skipped_types"].append(ctype)
            logger.info("No sender for channel type %s (%s %s)", ctype, entity_label, entity_id)
            continue
        try:
            delivered = sender(sorted(ids))
        except Exception as exc:
            delivered = False
            logger.warning("Delivery to %s raised for %s %s: %s", ctype, entity_label, entity_id, exc)
        if delivered:
            summary["sent_types"].append(ctype)
        else:
            summary["failed_types"].append(ctype)
            logger.warning("Delivery to %s failed for %s %s (see channel logs above)",
                           ctype, entity_label, entity_id)

    if not summary["attempted_types"]:
        logger.info("No notification channels configured for %s %s recipients", entity_label, entity_id)

    return summary


def delivery_outcome(summary: dict) -> tuple[bool, str]:
    """Turn a dispatch summary into (ok, message) for UI flashes and audit detail.

    `ok` is True only when at least one message channel accepted the product and
    none failed. Flowintel is delivered outside this dispatch and reported
    separately, so it never appears here. The message names the channels reached
    and the ones that could not be, pointing to the log for the underlying cause.
    """
    sent = summary.get("sent_types") or []
    failed = summary.get("failed_types") or []
    if not summary.get("recipients"):
        return False, "no eligible recipients (check the product's audience and TLP)"
    if not sent and not failed:
        return False, "the recipients have no message channels configured"
    parts = []
    if sent:
        parts.append("sent via " + ", ".join(sorted(sent)))
    if failed:
        parts.append("could not reach " + ", ".join(sorted(failed)) + " (see the application log)")
    return (bool(sent) and not failed), "; ".join(parts)


def _send_preview(entity, preview_url: str, markdown: str, stakeholders: list,
                  mattermost_fn, email_fn, entity_label: str, entity_id_attr: str) -> dict:
    names = [getattr(s, "name", "") for s in stakeholders or [] if getattr(s, "name", "")]
    senders = {
        "mattermost": lambda channel_ids: bool(mattermost_fn(
            entity,
            markdown,
            preview_url=preview_url,
            channel_ids=channel_ids,
            stakeholder_names=names,
        )),
        "email": lambda channel_ids: bool(email_fn(entity, markdown, channel_ids=channel_ids)),
    }
    return _dispatch(stakeholders, senders, entity_label, getattr(entity, entity_id_attr, ""))


def send_pir_preview(pir, preview_url: str, markdown: str, stakeholders: list) -> dict:
    """Send PIR preview notifications to stakeholder-configured channels.

    Returns a small delivery summary that callers can surface in UI flashes/logging.
    """
    return _send_preview(
        pir,
        preview_url,
        markdown,
        stakeholders,
        mattermost.send_pir_notification,
        email.send_pir_notification,
        "PIR",
        "pir_id",
    )


def send_rfi_preview(rfi, preview_url: str, markdown: str, stakeholders: list) -> dict:
    """Send RFI preview notifications to stakeholder-configured channels."""
    return _send_preview(
        rfi,
        preview_url,
        markdown,
        stakeholders,
        mattermost.send_rfi_notification,
        email.send_rfi_notification,
        "RFI",
        "rfi_id",
    )


def send_gir_preview(gir, preview_url: str, markdown: str, stakeholders: list) -> dict:
    """Send GIR preview notifications to stakeholder-configured channels."""
    return _send_preview(
        gir,
        preview_url,
        markdown,
        stakeholders,
        mattermost.send_gir_notification,
        email.send_gir_notification,
        "GIR",
        "gir_id",
    )


def send_daily_briefing(briefing, markdown: str, stakeholders: list) -> dict:
    """Deliver a full daily briefing to stakeholder channels across all channel types."""
    senders = {
        "mattermost": lambda channel_ids: bool(
            mattermost.send_daily_briefing_notification(briefing, markdown, channel_ids=channel_ids)
        ),
        "email": lambda channel_ids: bool(
            email.send_daily_briefing_notification(briefing, markdown, channel_ids=channel_ids)
        ),
    }
    return _dispatch(stakeholders, senders, "daily briefing", getattr(briefing, "date", ""))


def send_vea(vea, markdown: str, stakeholders: list) -> dict:
    """Deliver a VEA to stakeholder channels across all channel types."""
    senders = {
        "mattermost": lambda channel_ids: bool(
            mattermost.send_vea_notification(vea, markdown, channel_ids=channel_ids)
        ),
        "email": lambda channel_ids: bool(
            email.send_vea_notification(vea, markdown, channel_ids=channel_ids)
        ),
    }
    return _dispatch(stakeholders, senders, "VEA", getattr(vea, "vea_id", ""))


def send_flash_intel(product_event, fia_id: str, content: str, stakeholders: list) -> dict:
    """Deliver a Flash Intel Alert to stakeholder channels across all channel types."""
    senders = {
        "mattermost": lambda channel_ids: bool(
            mattermost.send_flash_intel_alert(product_event, fia_id, content, channel_ids=channel_ids)
        ),
        "email": lambda channel_ids: bool(
            email.send_flash_intel_alert(fia_id, content, channel_ids=channel_ids)
        ),
    }
    return _dispatch(stakeholders, senders, "flash intel", fia_id)
