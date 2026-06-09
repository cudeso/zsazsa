import logging

import requests

logger = logging.getLogger(__name__)

_CIRCL_URL = "https://vulnerability.circl.lu/api/cve/{}"
_SSVC_EXPLOIT_MAP = {"active": "Weaponised", "poc": "PoC public", "none": "None known"}


def fetch_cve_info(cve_id: str) -> dict:
    """Fetch and parse CVE details from vulnerability.circl.lu.

    Returns a dict with title, description, products, versions, cwes, cvss_score,
    cvss_severity, cvss_vector, exploit_availability, cisa_kev, and references.
    Returns an empty dict on any failure so callers can treat it as optional enrichment.
    """
    try:
        r = requests.get(_CIRCL_URL.format(cve_id), timeout=10, headers={"Accept": "application/json"})
        if r.status_code != 200:
            return {}
        return _parse(r.json())
    except Exception as exc:
        logger.warning("CVE lookup for %s failed: %s", cve_id, exc)
        return {}


def _parse(data: dict) -> dict:
    containers = data.get("containers") or {}
    cna = containers.get("cna") or {}

    title = cna.get("title") or ""
    descriptions = cna.get("descriptions") or []
    desc = next((d["value"] for d in descriptions if d.get("lang", "").lower().startswith("en")), "")

    products, versions = [], []
    for a in cna.get("affected") or []:
        vendor = (a.get("vendor") or "").strip()
        product = (a.get("product") or "").strip()
        if product and product.lower() not in ("n/a", "na"):
            label = f"{vendor} {product}".strip() if vendor else product
            if label not in products:
                products.append(label)
        for v in a.get("versions") or []:
            ver = (v.get("version") or "").strip()
            less_than = (v.get("lessThan") or v.get("lessThanOrEqual") or "").strip()
            if ver and ver not in ("0", "n/a", "*"):
                entry = f"{ver} < {less_than}" if less_than else ver
                if entry not in versions:
                    versions.append(entry)

    cwes = []
    for pt in cna.get("problemTypes") or []:
        for d in pt.get("descriptions") or []:
            cwe = (d.get("cweId") or "").strip()
            if cwe and cwe not in cwes:
                cwes.append(cwe)

    refs = []
    for ref in cna.get("references") or []:
        url = (ref.get("url") or "").strip()
        if url and url not in refs:
            refs.append(url)

    cvss_score = cvss_severity = cvss_vector = exploit_availability = ""
    cisa_kev = "No"
    for source in [cna] + (containers.get("adp") or []):
        for m in source.get("metrics") or []:
            if not cvss_score:
                for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
                    if key in m:
                        cvss_score = str(m[key].get("baseScore") or "")
                        cvss_severity = str(m[key].get("baseSeverity") or "").upper()
                        cvss_vector = str(m[key].get("vectorString") or "")
                        break
            if "other" in m and isinstance(m["other"], dict) and m["other"].get("type") == "ssvc":
                for opt in (m["other"].get("content") or {}).get("options") or []:
                    if "Exploitation" in opt:
                        exploit_availability = _SSVC_EXPLOIT_MAP.get((opt["Exploitation"] or "").lower(), "")
        for entry in source.get("timeline") or []:
            if "kev" in (entry.get("value") or "").lower():
                cisa_kev = "Yes"

    return {
        "title": title,
        "description": desc[:600],
        "products": products,
        "versions": versions[:8],
        "cwes": cwes[:5],
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "exploit_availability": exploit_availability,
        "cisa_kev": cisa_kev,
        "references": refs[:20],
    }
