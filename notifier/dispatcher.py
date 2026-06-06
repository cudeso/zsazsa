import logging
from collections import defaultdict

import config

from notifier import mattermost
from webapp.utils import normalize_notification_channels

logger = logging.getLogger(__name__)


def _channels_by_type(stakeholders: list) -> dict[str, set[str]]:
    """Return channel-id sets grouped by channel type from stakeholder preferences."""
    configured = {
        (c.get("id") or "").strip(): (c.get("type") or "mattermost").strip().lower()
        for c in normalize_notification_channels(
            getattr(config, "NOTIFICATION_CHANNELS", []),
            legacy_url=getattr(config, "MATTERMOST_WEBHOOK_URL", ""),
            legacy_enabled=getattr(config, "MATTERMOST_ENABLED", False),
        )
        if isinstance(c, dict)
    }
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


def _send_preview(entity, preview_url: str, markdown: str, stakeholders: list,
                  send_fn, entity_label: str, entity_id_attr: str) -> dict:
    names = [getattr(s, "name", "") for s in stakeholders or [] if getattr(s, "name", "")]
    channels = _channels_by_type(stakeholders)
    summary = describe_delivery(stakeholders)
    summary.update({"attempted_types": sorted(channels.keys()), "sent_types": [], "skipped_types": []})

    mm_ids = sorted(channels.get("mattermost", set()))
    if mm_ids:
        if send_fn(
            entity,
            markdown,
            preview_url=preview_url,
            channel_ids=mm_ids,
            stakeholder_names=names,
        ):
            summary["sent_types"].append("mattermost")
        else:
            summary["skipped_types"].append("mattermost")

    if not summary["attempted_types"]:
        logger.info(
            "No notification channels configured for %s %s recipients",
            entity_label,
            getattr(entity, entity_id_attr, ""),
        )

    return summary


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
