# zsazsa CTI

zsazsa is a **CTI program** management and production platform built around [MISP](https://www.misp-project.org/). It links collection, triage, analyst workflows, requirement management, publishing and stakeholder delivery in one place.

It is designed for teams that want to run threat intelligence as an operational capability, not as loose documents and disconnected scripts. In one workflow, analysts can move from source events to validated intelligence products, align output to PIR and GIR priorities, distribute to stakeholders with channel and TLP controls, and feed stakeholder response back into measurable program maturity signals.

## Platform snapshots

T### Overview

![zsazsa CTI Overview](docs/zsazsa-overview.png)

### Intelligence Flow

![zsazsa CTI Intelligence Flow](docs/zsazsa-intelligence-flow.png)

### CTI Program

![zsazsa CTI Program Capability Map](docs/zsazsa-cti-program.png)

It is named after one of my cats. The name stayed because it was memorable, and because it sounded like a project that would absolutely chase indicators at 03:00.

## What the application covers

The web app is split into practical operational areas.

The **dashboard** gives a live program snapshot. It shows active PIRs and GIRs, stakeholder counts, analyser pipeline freshness, 24-hour processing outcomes and pending scraper events waiting for analysis.

**Stakeholder management** stores who consumes CTI output, with role, organisation, contact details, TLP clearance, per-product subscription modes, and notification channel preferences. Each stakeholder can be assigned one or more named notification channels (configured under Settings), so products are pushed to the channels that stakeholder is monitored on. The detail view also shows what the stakeholder owns and what products are linked to their requirements.

**Requirement management** supports both PIRs and GIRs with full lifecycle editing. Records include decision context, priority, status, scope, delivery settings and owner fields. Scope fields are synchronised with focus points, and galaxy-backed categories can be synced directly from MISP cluster values.

Focus points are first-class data. They can be added, removed, synchronised and previewed against recent scraper events, while organisation-wide AI focus points are configured centrally in Settings under the Products tab.

**RFI workflow** is implemented end to end, from intake to closure. RFIs include SLA-aware due dates, owner assignment, links to PIR or GIR, response capture and feedback tracking.

**Data collection** pages provide a local cached view of events from the scraper MISP and optional additional MISP servers. Analysts can browse events and reports, view details, trigger cache refresh, and generate an LLM summary report directly back into MISP. Events can be flagged for follow-up. Manual collection entries can be created directly from the UI for intelligence gathered from sources that are not auto-collected (newsletters, partner portals and similar). Each manual entry supports a Markdown description with live preview, scope fields (geography, sectors, threat actors, threat types), external references, file attachments, and direct links to create a Flash Intel Alert or VEA from that entry as a source event.

**Product** pages provide a searchable catalogue of published outputs tagged as CTI products. Analysts can filter by product type and linked PIR, inspect event reports and store feedback as report entries.

**Flash Intel Alert** supports manual drafting, review queue handling, approval and publishing. Drafts can be seeded from one or more source events. Source event accordions in the wizard show reports with rendered Markdown, attributes with one-click append to the observed facts table, and object attributes. Observed facts and exploitation indicators added via the source-event buttons are formatted as Markdown tables. Recommended immediate and near-term actions can be configured as organisation-wide presets and are shown as one-click insert buttons. Context tags from source events can be selected and carried into the product. Publishing can notify Mattermost.

**Vulnerability Exploitation Advisory** has an equivalent draft, review and publish flow, including multi-CVE input, CVE-focused fields, PIR linking, source event accordion, indicator table building, and action presets.

**Daily threat briefing** includes a triage queue from scraper events, guided story composition, draft save, edit and publish flow, plus notification on publish.

**Threat landscape report** is a periodic strategic product for leadership audiences. It covers top threats, trending threat actors, key incidents, recommendations and an outlook section. Reports follow the same draft/publish workflow as other products and are stored as MISP objects.

**Statistics** pages include pipeline and program views. They aggregate source and outcome trends, RFI and feedback KPIs, product production metrics, PIR coverage checks and MISP source health. There is also a purge action for orphaned analyser log rows. The program statistics page includes a **CTI-CMM maturity signal** panel, which derives observable maturity indicators across five domains (Program, Situation, Analytical production, Operational delivery, and Feedback) from the live program data. These signals map to CTI-CMM levels CTI0 through CTI3 and highlight measurable gaps, giving the team a quick orientation of where the program sits and what to address next.

Community pages provide a local registry of organisations validated against MISP UUIDs and reusable across stakeholder records.

## MISP model and tagging approach

The platform stores each business entity as one MISP event, with data held inside a custom MISP object. Custom object templates live in `webapp/misp_objects/`.

Entity type to MISP object mapping:

| Entity | MISP object |
|---|---|
| Stakeholder | zsazsa-stakeholder |
| PIR | zsazsa-pir |
| GIR | zsazsa-gir |
| RFI | zsazsa-rfi |
| Flash Intel Alert | zsazsa-flash-intel |
| VEA | zsazsa-vea |
| Daily briefing | zsazsa-daily-briefing |
| Threat landscape report | zsazsa-threat-landscape-report |
| Collection source | zsazsa-collection-source |

Every entity event carries a type tag so it can be searched and filtered independently of the object. The default tag values in use are:

```
TAG_STAKEHOLDER  = zsazsa:type="stakeholder"
TAG_PIR          = zsazsa:type="pir"
TAG_GIR          = zsazsa:type="gir"
TAG_RFI          = zsazsa:type="rfi"
TAG_FLASH_INTEL  = zsazsa:ctiproduct="flash-intel"
TAG_VEA          = zsazsa:ctiproduct="vea"
TAG_BRIEFING     = zsazsa:ctiproduct="daily-briefing"
```

Product events additionally carry `curation:ctiproduct` tags so they can be searched and grouped consistently across the product catalogue.

Manual collection entries are stored on the webapp MISP server. They carry the scraper marker tag (`zsazsa:source="misp-scraper"` by default), a TLP tag, `zsazsa:source-type="manual"`, and a local `zsazsa:source="<source-name>"` tag linking the entry to the configured manual source. Galaxy-backed scope tags (geography, sector, threat actor, MITRE ATT&CK) are applied as regular MISP tags. The entry description is stored as a MISP event report in Markdown. File attachments are added as attachment attributes in the External analysis category.

Events that need analyst follow-up are flagged with `zsazsa:collection="follow-up"` as a local tag.

Focus points are stored as event-level text attributes with the comment `zsazsa:fp` and value format `category|value|notes`. This keeps add and delete operations simple and lets scope values be regenerated safely without losing other attribute data.

## Configuration

Main runtime settings are in `config/__init__.py`.

You can configure:

- scraper and webapp MISP connections
- optional extra MISP sources for the collection browser
- manual collection sources (structured registry with name, owner, location, description, enable/disable, and Admiralty scale reliability rating - each backed by a MISP event)
- product type catalogue
- recommended immediate and near-term actions shown as presets in Flash Intel and VEA wizards
- notification channels (multiple named Mattermost webhooks, each with a name and enable/disable toggle; Teams and Email placeholders for future use)
- analyser polling window and marker tag
- log settings and file paths

The configuration page organises settings across tabs (Connections, Products, System, Prompts, Context elements, Notifications). Collection sources - the MISP scraper connection, additional MISP servers, and manual sources - are managed at `/config/sources/`. MISP connections can be tested live. Each server entry can be saved individually. Manual sources have per-source enable/disable with an in-use guard against PIR/GIR references. The config file is backed up automatically before each save.

## Running the application

```bash
source venv/bin/activate
python run_webapp.py
```

The application listens on `http://0.0.0.0:5000` by default. Open it in a browser at the IP address or hostname of your server.

Run the analyser pipeline (typically via cron):

```bash
source venv/bin/activate
python run_analyser.py
```

The hostname zsazsa listens on, as well as the port, are configurable in `config.py`:

```python
HOSTNAME = 'zsazsa.example.com'   # or an IP address
PORT = 5000
```

These values can also be changed from the Settings page in the web app (System tab). After saving, restart the application for the port change to take effect (the HOSTNAME value is stored for reference; the listener address is always `0.0.0.0`).

## Why the name zsazsa

Officially, it is the cat.

![docs/zsazsa.png](docs/zsazsa.png)

Unofficially, if anyone asks in a meeting, you can pick one of these:

- Zonal Security Analysis for Zero-day Situation Awareness
- Zero-day Signal Analysis and Strategic Assessment
- Zenith Sentinel for Adversary Surveillance and Alerting
- Zettabyte Source Aggregation for Security Analytics
- Zero-latency Surveillance and Alerting for Security Analysts
- Zealous Search and Attribution for Strategic Analysis
- Zone-focused Scouting and Assessment for Security Assurance
- Zero-trust Scoring and Adversary Signal Assessment
