"""Flexible parsers for CrowdStrike Spotlight, Nessus, and Blumira exports."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _read_text(path: Path) -> str:
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def _pick(row: Dict[str, Any], *candidates: str) -> str:
    lookup = {_norm(k): v for k, v in row.items()}
    for cand in candidates:
        val = lookup.get(_norm(cand))
        if val is not None and str(val).strip() not in ("", "None", "null", "-"):
            return str(val).strip()
    return ""


def extract_cves(text: str) -> List[str]:
    if not text:
        return []
    found = [m.group(0).upper() for m in CVE_RE.finditer(text)]
    # preserve order, unique
    seen = set()
    out = []
    for cve in found:
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


def _load_rows(path: Path) -> List[Dict[str, Any]]:
    suffix = path.suffix.lower()
    text = _read_text(path)
    if suffix == ".json":
        data = json.loads(text)
        if isinstance(data, list):
            return data
        for key in ("resources", "vulnerabilities", "findings", "data", "items", "rows"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    # CSV (default)
    reader = csv.DictReader(text.splitlines())
    return [dict(r) for r in reader]


def parse_crowdstrike(path: Path) -> List[Dict[str, Any]]:
    rows = _load_rows(path)
    findings = []
    for row in rows:
        # Nested Spotlight JSON
        if "cve" in row and isinstance(row.get("cve"), dict):
            cve_obj = row["cve"]
            host = row.get("host_info") or {}
            rem = row.get("remediation") or {}
            entities = rem.get("entities") if isinstance(rem, dict) else rem
            titles, actions, links = [], [], []
            if isinstance(entities, list):
                for e in entities:
                    if isinstance(e, dict):
                        titles.append(str(e.get("title") or ""))
                        actions.append(str(e.get("action") or ""))
                        links.append(str(e.get("link") or ""))
            cve_id = (cve_obj.get("id") or "").upper()
            findings.append(
                {
                    "source": "crowdstrike",
                    "cves": [cve_id] if cve_id else extract_cves(json.dumps(cve_obj)),
                    "title": cve_obj.get("id") or "CrowdStrike vulnerability",
                    "severity": str(cve_obj.get("severity") or row.get("severity") or ""),
                    "cvss": cve_obj.get("base_score") or "",
                    "vector": cve_obj.get("vector") or "",
                    "host": host.get("hostname") or "",
                    "asset": host.get("hostname") or host.get("local_ip") or "",
                    "product": (row.get("apps") or {}).get("product_name_version")
                    if isinstance(row.get("apps"), dict)
                    else "",
                    "description": cve_obj.get("description") or "",
                    "fix": " | ".join(x for x in actions if x) or " | ".join(x for x in titles if x),
                    "fix_links": " | ".join(x for x in links if x),
                    "status": row.get("status") or "",
                    "raw": row,
                }
            )
            continue

        cves = extract_cves(
            " ".join(
                [
                    _pick(row, "CVE ID", "CVE", "cve.id"),
                    _pick(row, "CVE Description", "Description"),
                    _pick(row, "Name", "Title"),
                ]
            )
        )
        findings.append(
            {
                "source": "crowdstrike",
                "cves": cves,
                "title": _pick(row, "CVE ID", "Product", "Name", "Title") or (cves[0] if cves else "Finding"),
                "severity": _pick(row, "Severity"),
                "cvss": _pick(row, "Base Score", "CVSS", "CVSS Score"),
                "vector": _pick(row, "Vector"),
                "host": _pick(row, "Hostname", "Host", "Device Name"),
                "asset": _pick(row, "Hostname", "Host", "LocalIP", "Host ID"),
                "product": _pick(row, "Product", "Software Name", "Application"),
                "description": _pick(row, "CVE Description", "Description"),
                "fix": _pick(
                    row,
                    "Recommended Remediations",
                    "Remediation Details",
                    "Remediation",
                    "AdditionalRemediationSteps",
                ),
                "fix_links": _pick(row, "Remediation Links", "Vendor Advisory", "References"),
                "status": _pick(row, "Status"),
                "raw": row,
            }
        )
    return findings


def parse_nessus(path: Path) -> List[Dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix in (".nessus", ".xml"):
        return _parse_nessus_xml(path)

    rows = _load_rows(path)
    findings = []
    for row in rows:
        risk = _pick(row, "Risk", "Severity", "Risk Factor")
        # Skip informational noise unless it has a CVE
        cves = extract_cves(_pick(row, "CVE", "CVEs") + " " + _pick(row, "Name", "Description"))
        if risk.lower() in ("none", "info", "informational") and not cves:
            continue
        findings.append(
            {
                "source": "nessus",
                "cves": cves,
                "title": _pick(row, "Name", "Plugin Name", "definition.name") or "Nessus finding",
                "severity": risk,
                "cvss": _pick(
                    row,
                    "CVSS v3.0 Base Score",
                    "CVSS v3.1 Base Score",
                    "CVSSv3 Base Score",
                    "CVSS3",
                    "CVSS",
                    "CVSS v2.0 Base Score",
                    "definition.cvss3.base_score",
                ),
                "vector": _pick(row, "CVSS v3.0 Vector", "CVSS Vector", "definition.cvss3.base_vector"),
                "host": _pick(row, "Host", "asset.host_name", "DNS Name", "asset.name"),
                "asset": _pick(row, "Host", "asset.display_ipv4_address", "IP Address"),
                "product": _pick(row, "Plugin Family", "Family"),
                "description": _pick(row, "Synopsis", "Description", "definition.description"),
                "fix": _pick(row, "Solution", "Remediation"),
                "fix_links": _pick(row, "See Also", "See Also Link"),
                "status": _pick(row, "State", "Status"),
                "plugin_id": _pick(row, "Plugin ID", "definition.id"),
                "port": _pick(row, "Port"),
                "raw": row,
            }
        )
    return findings


def _parse_nessus_xml(path: Path) -> List[Dict[str, Any]]:
    import xml.etree.ElementTree as ET

    tree = ET.parse(path)
    root = tree.getroot()
    findings = []
    for host in root.iter("ReportHost"):
        hostname = host.get("name") or ""
        for item in host.iter("ReportItem"):
            severity = item.get("severity", "0")
            risk_map = {"0": "None", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
            cve_text = " ".join(el.text or "" for el in item.findall("cve"))
            cves = extract_cves(cve_text)
            risk = risk_map.get(severity, item.findtext("risk_factor") or severity)
            if risk in ("None", "Info") and not cves:
                continue
            findings.append(
                {
                    "source": "nessus",
                    "cves": cves,
                    "title": item.get("pluginName") or "Nessus finding",
                    "severity": risk,
                    "cvss": item.findtext("cvss3_base_score") or item.findtext("cvss_base_score") or "",
                    "vector": item.findtext("cvss3_vector") or item.findtext("cvss_vector") or "",
                    "host": hostname,
                    "asset": hostname,
                    "product": item.get("pluginFamily") or "",
                    "description": item.findtext("synopsis") or item.findtext("description") or "",
                    "fix": item.findtext("solution") or "",
                    "fix_links": item.findtext("see_also") or "",
                    "status": "",
                    "plugin_id": item.get("pluginID") or "",
                    "port": item.get("port") or "",
                    "raw": {},
                }
            )
    return findings


def parse_blumira(path: Path) -> List[Dict[str, Any]]:
    """Blumira weekly findings / report-builder export.

    Findings already include analysis and workflow/remediation steps.
    CVE enrichment is applied when a CVE is present in the text.
    """
    rows = _load_rows(path)
    findings = []
    for row in rows:
        blob = " ".join(str(v) for v in row.values())
        cves = extract_cves(blob)
        title = _pick(
            row,
            "Finding",
            "Finding Name",
            "Detection",
            "Detection Rule",
            "Detection Rule Name",
            "Name",
            "Title",
            "Rule",
        )
        findings.append(
            {
                "source": "blumira",
                "cves": cves,
                "title": title or (cves[0] if cves else "Blumira finding"),
                "severity": _pick(row, "Priority", "Severity", "Finding Priority", "Type"),
                "cvss": _pick(row, "CVSS", "Score"),
                "vector": "",
                "host": _pick(row, "Hostname", "Host", "Device", "Computer", "Asset"),
                "asset": _pick(row, "Hostname", "Host", "User", "Account", "Source"),
                "product": _pick(row, "Finding Type", "Type", "Category", "Detection Type"),
                "description": _pick(row, "Analysis", "Summary", "Description", "Details"),
                "fix": _pick(
                    row,
                    "Workflow",
                    "Remediation",
                    "Recommended Action",
                    "Recommended Actions",
                    "Fix",
                    "Resolution Steps",
                    "Response",
                    "Guidance",
                ),
                "fix_links": _pick(row, "Reference", "References", "Link"),
                "status": _pick(row, "Status", "Resolution", "Resolution Type"),
                "raw": row,
            }
        )
    return findings


PARSERS = {
    "crowdstrike": parse_crowdstrike,
    "nessus": parse_nessus,
    "blumira": parse_blumira,
}


def detect_source(path: Path) -> Optional[str]:
    name = path.name.lower()
    if "crowd" in name or "falcon" in name or "spotlight" in name:
        return "crowdstrike"
    if "nessus" in name or path.suffix.lower() == ".nessus":
        return "nessus"
    if "blumira" in name:
        return "blumira"
    return None