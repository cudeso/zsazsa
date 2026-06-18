import logging
from collections import defaultdict

import config

from notifier import mattermost
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
    summary.update({"attempted_types": sorted(channels.keys()), "sent_types": [], "skipped_types": []})

    for ctype, ids in channels.items():
        sender = senders.get(ctype)
        if sender is None:
            summary["skipped_types"].append(ctype)
            logger.info("No sender for channel type %s (%s %s)", ctype, entity_label, entity_id)
            continue
        if sender(sorted(ids)):
            summary["sent_types"].append(ctype)
        else:
            summary["skipped_types"].append(ctype)

    if not summary["attempted_types"]:
        logger.info("No notification channels configured for %s %s recipients", entity_label, entity_id)

    return summary


def _send_preview(entity, preview_url: str, markdown: str, stakeholders: list,
                  send_fn, entity_label: str, entity_id_attr: str) -> dict:
    names = [getattr(s, "name", "") for s in stakeholders or [] if getattr(s, "name", "")]
    senders = {
        "mattermost": lambda channel_ids: bool(send_fn(
            entity,
            markdown,
            preview_url=preview_url,
            channel_ids=channel_ids,
            stakeholder_names=names,
        )),
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
        "GIR",
        "gir_id",
    )


def send_daily_briefing(briefing, markdown: str, stakeholders: list) -> dict:
    """Deliver a full daily briefing to stakeholder channels across all channel types.

    Today only Mattermost is wired up; Teams and email add a sender entry here.
    """
    senders = {
        "mattermost": lambda channel_ids: bool(
            mattermost.send_daily_briefing_notification(briefing, markdown, channel_ids=channel_ids)
        ),
    }
    return _dispatch(stakeholders, senders, "daily briefing", getattr(briefing, "date", ""))
