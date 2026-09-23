"""CVE / CVSS enrichment via NVD API 2.0 and CISA KEV catalog."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _nvd_headers() -> Dict[str, str]:
    headers = {"User-Agent": "CipherBrief/0.1 (security-reporting)"}
    key = os.environ.get("NVD_API_KEY", "").strip()
    if key:
        headers["apiKey"] = key
    return headers


def _nvd_delay() -> float:
    return 0.7 if os.environ.get("NVD_API_KEY") else 6.1


def fetch_nvd(cve_id: str, session: requests.Session, cache: Dict[str, Any]) -> Dict[str, Any]:
    if cve_id in cache:
        return cache[cve_id]
    try:
        resp = session.get(NVD_URL, params={"cveId": cve_id}, headers=_nvd_headers(), timeout=30)
        if resp.status_code == 429:
            time.sleep(10)
            resp = session.get(NVD_URL, params={"cveId": cve_id}, headers=_nvd_headers(), timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        cache[cve_id] = {"cve": cve_id, "error": str(exc)}
        return cache[cve_id]

    parsed = _parse_nvd_item(cve_id, data)
    cache[cve_id] = parsed
    time.sleep(_nvd_delay())
    return parsed


def _parse_nvd_item(cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return {"cve": cve_id, "error": "not found in NVD"}
    cve = vulns[0].get("cve") or {}
    desc = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = d.get("value") or ""
            break
    metrics = cve.get("metrics") or {}
    score, severity, vector, version = None, "", "", ""
    for key, ver in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        block = metrics.get(key)
        if block:
            cvss = (block[0] or {}).get("cvssData") or {}
            score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity") or (block[0] or {}).get("baseSeverity") or ""
            vector = cvss.get("vectorString") or ""
            version = ver
            break

    refs = []
    for ref in (cve.get("references") or [])[:8]:
        url = ref.get("url") or ""
        tags = ref.get("tags") or []
        refs.append({"url": url, "tags": tags})

    # Prefer vendor advisory / patch style links for "possible fixes"
    fix_links = [
        r["url"]
        for r in refs
        if any(t.lower() in {"vendor advisory", "patch", "mitigation"} for t in r.get("tags") or [])
    ]
    if not fix_links:
        fix_links = [r["url"] for r in refs[:3] if r.get("url")]

    weaknesses = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            if d.get("value"):
                weaknesses.append(d["value"])

    return {
        "cve": cve_id,
        "description": desc,
        "cvss": score,
        "severity": severity,
        "vector": vector,
        "cvss_version": version,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "references": [r["url"] for r in refs if r.get("url")],
        "fix_links": fix_links,
        "cwe": weaknesses[:5],
    }


def load_kev(session: Optional[requests.Session] = None, offline: bool = False) -> Dict[str, Dict[str, Any]]:
    if offline:
        return {}
    sess = session or requests.Session()
    try:
        resp = sess.get(KEV_URL, timeout=30)
        resp.raise_for_status()
        catalog = resp.json()
    except Exception:
        return {}
    out = {}
    for item in catalog.get("vulnerabilities") or []:
        cve = (item.get("cveID") or "").upper()
        if cve:
            out[cve] = {
                "vendor": item.get("vendorProject"),
                "product": item.get("product"),
                "vulnerability_name": item.get("vulnerabilityName"),
                "required_action": item.get("requiredAction"),
                "due_date": item.get("dueDate"),
                "known_ransomware": item.get("knownRansomwareCampaignUse"),
                "notes": item.get("notes"),
                "date_added": item.get("dateAdded"),
            }
    return out


def load_cache(path: Path) -> Dict[str, Any]:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_cache(path: Path, cache: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def enrich_findings(
    findings: List[Dict[str, Any]],
    *,
    offline: bool = False,
    cache_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    cache: Dict[str, Any] = load_cache(cache_path) if cache_path else {}
    session = requests.Session()
    # KEV catalog is one small JSON file — still useful in --offline NVD mode.
    kev = load_kev(session, offline=False)

    unique_cves = []
    seen = set()
    for f in findings:
        for cve in f.get("cves") or []:
            if cve not in seen:
                seen.add(cve)
                unique_cves.append(cve)

    nvd_map: Dict[str, Any] = {}
    if not offline:
        for cve in unique_cves:
            nvd_map[cve] = fetch_nvd(cve, session, cache)
        if cache_path:
            save_cache(cache_path, cache)
    else:
        for cve in unique_cves:
            nvd_map[cve] = cache.get(cve) or {"cve": cve, "offline": True}

    enriched = []
    for f in findings:
        nvd_hits = [nvd_map.get(cve, {}) for cve in (f.get("cves") or [])]
        primary = next((h for h in nvd_hits if h and not h.get("error")), {})

        kev_hits = [kev[cve] for cve in (f.get("cves") or []) if cve in kev]
        kev_fix = kev_hits[0]["required_action"] if kev_hits else ""

        cvss = _to_float(f.get("cvss"))
        if cvss is None:
            cvss = _to_float(primary.get("cvss"))

        severity = f.get("severity") or primary.get("severity") or _score_to_severity(cvss)

        fix = f.get("fix") or kev_fix or ""
        if not fix and primary.get("fix_links"):
            fix = "Apply vendor patch / advisory. See: " + "; ".join(primary["fix_links"][:3])

        description = f.get("description") or primary.get("description") or ""

        enriched.append(
            {
                **f,
                "cvss": cvss,
                "severity": _normalize_severity(severity, cvss),
                "vector": f.get("vector") or primary.get("vector") or "",
                "description": description,
                "fix": fix,
                "nvd": primary or None,
                "kev": kev_hits[0] if kev_hits else None,
                "in_kev": bool(kev_hits),
            }
        )
    return enriched


def _to_float(val: Any) -> Optional[float]:
    if val is None or val == "":
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _score_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def _normalize_severity(raw: str, score: Optional[float]) -> str:
    s = (raw or "").strip().upper()
    mapping = {
        "CRIT": "CRITICAL",
        "CRITICAL": "CRITICAL",
        "P1": "CRITICAL",
        "HIGH": "HIGH",
        "P2": "HIGH",
        "MED": "MEDIUM",
        "MEDIUM": "MEDIUM",
        "MODERATE": "MEDIUM",
        "P3": "MEDIUM",
        "LOW": "LOW",
        "P4": "LOW",
        "INFO": "INFO",
        "INFORMATIONAL": "INFO",
        "NONE": "INFO",
        "UNKNOWN": "UNKNOWN",
    }
    if s in mapping:
        return mapping[s]
    if s.startswith("P1"):
        return "CRITICAL"
    if s.startswith("P2"):
        return "HIGH"
    if s.startswith("P3"):
        return "MEDIUM"
    if s.startswith("P4"):
        return "LOW"
    return _score_to_severity(score)