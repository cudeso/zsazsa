import logging

logger = logging.getLogger(__name__)

_WORKFLOW_PREFIX = "workflow:state="
_FEED_TAG_PREFIX = "scraper:data-collection-source:"


def get_source_feed(event) -> str:
    for tag in getattr(event, "tags", []) or []:
        name = getattr(tag, "name", "") or ""
        if name.startswith(_FEED_TAG_PREFIX):
            return name[len(_FEED_TAG_PREFIX):]
    return "unknown"


def set_workflow_state(misp, event, state: str) -> None:
    for tag in event.tags:
        if tag.name.startswith(_WORKFLOW_PREFIX):
            misp.untag(event, tag.name)
    misp.tag(event, f'{_WORKFLOW_PREFIX}"{state}"', local=True)


def add_tag(misp, entity, tag_name: str) -> None:
    misp.tag(entity, tag_name, local=True)
