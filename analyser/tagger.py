import logging

logger = logging.getLogger(__name__)

_WORKFLOW_PREFIX = "workflow:state="
_FEED_TAG_PREFIX = "scraper:data-collection-source:"


def source_feed_from_tags(tag_names) -> str:
    """Return the collection-source feed from a list of tag name strings."""
    for name in tag_names or []:
        if name and name.startswith(_FEED_TAG_PREFIX):
            return name[len(_FEED_TAG_PREFIX):]
    return "unknown"


def get_source_feed(event) -> str:
    return source_feed_from_tags(
        [getattr(t, "name", "") for t in (getattr(event, "tags", []) or [])]
    )


def set_workflow_state(misp, event, state: str) -> None:
    for tag in event.tags:
        if tag.name.startswith(_WORKFLOW_PREFIX):
            misp.untag(event, tag.name)
    misp.tag(event, f'{_WORKFLOW_PREFIX}"{state}"', local=True)


def add_tag(misp, entity, tag_name: str) -> None:
    misp.tag(entity, tag_name, local=True)
