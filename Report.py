"""Executive summary PDF + supporting JSON/CSV exports."""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


NAVY = colors.HexColor("#0B1F3A")
TEAL = colors.HexColor("#1F6F8B")
GOLD = colors.HexColor("#C9A227")
CRIT = colors.HexColor("#B42318")
HIGH = colors.HexColor("#C4320A")
MED = colors.HexColor("#B54708")
LOW = colors.HexColor("#175CD3")
INFO = colors.HexColor("#475467")
LIGHT = colors.HexColor("#F8FAFC")
ROW_ALT = colors.HexColor("#EEF2F6")


SOURCE_LABELS = {
    "crowdstrike": "Crowdstrike EDR Vulnerabilities",
    "nessus": "Nessus Network Vulnerability Scan",
    "blumira": "Blumira Weekly Report of Events",
}

LETTERHEAD_CANDIDATES = [
    Path("/home/workdir/artifacts/TMS_Scan/tms_letterhead.png"),
    Path(__file__).resolve().parent / "tms_letterhead.png",
]


NOW_KEYWORDS = (
    "rce",
    "remote code",
    "code execution",
    "zerologon",
    "log4shell",
    "log4j",
    "eternalblue",
    "proxylogon",
    "ransomware",
    "mfa fatigue",
    "impossible travel",
    "password spray",
    "domain controller",
    "netlogon",
    "privilege",
    "elevation of privilege",
    "authentication bypass",
    "vpn",
    "rdp",
    "exchange",
    "brute force",
)

NOW_HOST_HINTS = ("dc", "domain", "vpn", "exchange", "adfs", "firewall", "fw-", "id-")


def classify_lane(finding: Dict[str, Any]) -> str:
    """now = keep the business running; wait = can ride the next change window."""
    status = (finding.get("status") or "").lower()
    if status in {"resolved", "closed", "false positive", "no action needed", "risk accepted"}:
        return "wait"

    sev = _sev(finding)
    score = _score(finding)
    blob = " ".join(
        str(finding.get(k) or "")
        for k in ("title", "description", "product", "host", "asset", "fix")
    ).lower()
    host = (finding.get("host") or finding.get("asset") or "").lower()

    if finding.get("in_kev"):
        return "now"
    if sev == "CRITICAL":
        return "now"
    if sev == "HIGH" and (score is None or score >= 7.0):
        return "now"
    if any(k in blob for k in NOW_KEYWORDS):
        return "now"
    if any(h in host for h in NOW_HOST_HINTS) and sev in {"HIGH", "CRITICAL", "MEDIUM"}:
        return "now"
    return "wait"


def verified_fix(finding: Dict[str, Any]) -> str:
    """Prefer scanner/Blumira/CISA text; otherwise a concrete best-practice fix."""
    if finding.get("in_kev") and finding.get("kev"):
        action = (finding["kev"].get("required_action") or "").strip()
        if action:
            due = finding["kev"].get("due_date") or ""
            return f"CISA KEV required action: {action}" + (f" Federal due date {due}." if due else "")

    src_fix = (finding.get("fix") or "").strip()
    if src_fix and src_fix.lower() not in {"n/a", "none", "unknown"}:
        return src_fix

    links = finding.get("nvd") or {}
    if links.get("fix_links"):
        return "Apply the vendor patch in the NVD advisory: " + "; ".join(links["fix_links"][:2])

    title = (finding.get("title") or "").lower()
    source = finding.get("source") or ""
    if source == "blumira":
        return (
            "Run the Blumira finding workflow to the end: confirm whether the activity is expected, "
            "contain the account or host if it is not, then set the resolution type (Valid / False positive / "
            "No action needed / Risk accepted)."
        )
    if "ssl" in title or "tls" in title or "poodle" in title or "beast" in title:
        return "Disable SSLv3 and TLS 1.0/1.1. Require TLS 1.2+ with AEAD ciphers. Recheck after the change window."
    if "smb" in title or "445" in title:
        return "Install the current Microsoft SMB/Netlogon updates, require SMB signing, and restrict TCP 445 to trusted subnets."
    if finding.get("cves"):
        cve = finding["cves"][0]
        return (
            f"Patch or upgrade the affected product for {cve}. If a patch is not available, isolate the host, "
            "apply the vendor workaround, and schedule a verified re-scan."
        )
    return (
        "Investigate with the asset owner. Apply the vendor fix or configuration change, then re-scan or "
        "re-check logs to verify the finding is closed."
    )


def assign_priority(finding: Dict[str, Any]) -> Dict[str, str]:
    """Realistic team schedule. Dates are calendar days from report generation."""
    today = datetime.now()
    status = (finding.get("status") or "").lower()
    sev = _sev(finding)
    lane = finding.get("lane") or "wait"
    source = finding.get("source") or ""
    blob = " ".join(str(finding.get(k) or "") for k in ("title", "description", "product")).lower()

    if status in {"resolved", "closed", "false positive", "no action needed", "risk accepted"}:
        due = today + timedelta(days=7)
        return {
            "priority": "P4",
            "priority_label": "P4 Verify only",
            "sla": "7 days",
            "due": due.strftime("%Y-%m-%d"),
            "work": "Confirm the closure in the source tool. No new change required unless it reopens.",
        }

    if finding.get("in_kev") or sev == "CRITICAL" or (
        source == "blumira" and any(k in blob for k in ("mfa fatigue", "impossible travel", "ransomware"))
    ):
        due = today + timedelta(days=2 if source == "blumira" else 7)
        sla = "48 hours" if source == "blumira" else "7 days"
        return {
            "priority": "P1",
            "priority_label": "P1 Immediate",
            "sla": sla,
            "due": due.strftime("%Y-%m-%d"),
            "work": "Investigate and contain first. Patch or revoke access before the due date.",
        }

    if lane == "now" or sev == "HIGH":
        due = today + timedelta(days=14)
        return {
            "priority": "P2",
            "priority_label": "P2 This sprint",
            "sla": "14 days",
            "due": due.strftime("%Y-%m-%d"),
            "work": "Owner assigned this week. Complete the fix in the next change window.",
        }

    if sev == "MEDIUM":
        due = today + timedelta(days=30)
        return {
            "priority": "P3",
            "priority_label": "P3 Planned",
            "sla": "30 days",
            "due": due.strftime("%Y-%m-%d"),
            "work": "Schedule with the asset owner. Do not block production work.",
        }

    due = today + timedelta(days=90)
    return {
        "priority": "P4",
        "priority_label": "P4 Backlog",
        "sla": "90 days",
        "due": due.strftime("%Y-%m-%d"),
        "work": "Track in the quarterly hygiene window and verify on the next scan.",
    }


def _action_item(finding: Dict[str, Any]) -> Dict[str, Any]:
    label = finding.get("title") or (finding.get("cves") or ["Finding"])[0]
    schedule = finding.get("schedule") or assign_priority(finding)
    return {
        "title": label,
        "severity": _sev(finding),
        "action": finding.get("verified_fix") or verified_fix(finding),
        "cves": finding.get("cves") or [],
        "kev": bool(finding.get("in_kev")),
        "host": finding.get("host") or finding.get("asset") or "",
        "lane": finding.get("lane") or "wait",
        "priority": schedule.get("priority"),
        "priority_label": schedule.get("priority_label"),
        "sla": schedule.get("sla"),
        "due": schedule.get("due"),
        "work": schedule.get("work"),
    }


def summarize(findings: List[Dict[str, Any]], source: str, input_name: str) -> Dict[str, Any]:
    for f in findings:
        f["lane"] = classify_lane(f)
        f["verified_fix"] = verified_fix(f)
        f["schedule"] = assign_priority(f)
        f["priority"] = f["schedule"]["priority"]
        f["due"] = f["schedule"]["due"]

    sev = Counter(_sev(f) for f in findings)
    hosts = Counter((f.get("host") or f.get("asset") or "Unknown") for f in findings)
    cves = []
    for f in findings:
        cves.extend(f.get("cves") or [])
    unique_cves = sorted(set(cves))
    kev = [f for f in findings if f.get("in_kev")]

    ranked = sorted(
        findings,
        key=lambda f: (
            0 if f.get("lane") == "now" else 1,
            0 if f.get("in_kev") else 1,
            -(_score(f) or 0),
            _sev_rank(_sev(f)),
        ),
    )

    now_findings = [f for f in ranked if f.get("lane") == "now"]
    wait_findings = [f for f in ranked if f.get("lane") != "now"]

    def _dedupe(items: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
        out, seen = [], set()
        for f in items:
            key = (f.get("title"), tuple(f.get("cves") or []), f.get("host"))
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
            if len(out) >= limit:
                break
        return out

    now_actions, wait_actions, seen_fix = [], [], set()
    for f in ranked:
        item = _action_item(f)
        key = (item["title"], item["action"][:80], item["host"])
        if key in seen_fix:
            continue
        seen_fix.add(key)
        if item["lane"] == "now":
            now_actions.append(item)
        else:
            wait_actions.append(item)

    return {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "source": source,
        "source_label": SOURCE_LABELS.get(source, source),
        "input_name": input_name,
        "total": len(findings),
        "now_count": len(now_findings),
        "wait_count": len(wait_findings),
        "severity": dict(sev),
        "unique_cves": unique_cves,
        "unique_hosts": len([h for h in hosts if h and h != "Unknown"]),
        "host_counts": hosts.most_common(8),
        "kev_count": len(kev),
        "top_now": _dedupe(now_findings, 50),
        "top_wait": _dedupe(wait_findings, 50),
        "now_actions": now_actions,
        "wait_actions": wait_actions,
        "work_plan": now_actions + wait_actions,
        "findings": findings,
    }


def write_json(summary: Dict[str, Any], path: Path) -> None:
    payload = {k: v for k, v in summary.items() if k != "findings"}
    slim = []
    for f in summary["findings"]:
        slim.append(
            {
                "source": f.get("source"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "cvss": f.get("cvss"),
                "cves": f.get("cves"),
                "host": f.get("host"),
                "product": f.get("product"),
                "description": (f.get("description") or "")[:500],
                "fix": f.get("fix"),
                "lane": f.get("lane"),
                "priority": f.get("priority"),
                "due": f.get("due"),
                "verified_fix": f.get("verified_fix"),
                "in_kev": f.get("in_kev"),
                "kev": f.get("kev"),
            }
        )
    payload["findings"] = slim
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def write_csv(findings: List[Dict[str, Any]], path: Path) -> None:
    fields = [
        "source",
        "title",
        "severity",
        "cvss",
        "cves",
        "host",
        "product",
        "lane",
        "priority",
        "due",
        "sla",
        "in_kev",
        "verified_fix",
        "fix",
        "description",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for f in findings:
            w.writerow(
                {
                    "source": f.get("source"),
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "cvss": f.get("cvss") if f.get("cvss") is not None else "",
                    "cves": ";".join(f.get("cves") or []),
                    "host": f.get("host"),
                    "product": f.get("product"),
                    "lane": "NOW" if f.get("lane") == "now" else "WAIT",
                    "priority": (f.get("schedule") or {}).get("priority") or f.get("priority") or "",
                    "due": (f.get("schedule") or {}).get("due") or f.get("due") or "",
                    "sla": (f.get("schedule") or {}).get("sla") or "",
                    "in_kev": "YES" if f.get("in_kev") else "",
                    "verified_fix": (f.get("verified_fix") or "").replace("\n", " "),
                    "fix": (f.get("fix") or "").replace("\n", " "),
                    "description": (f.get("description") or "").replace("\n", " ")[:400],
                }
            )


def write_pdf(summary: Dict[str, Any], path: Path) -> None:
    doc = SimpleDocTemplate(
        str(path),
        pagesize=letter,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.55 * inch,
        title=summary["source_label"],
        author="Devon Brown, Network Security Engineer",
    )
    styles = _styles()
    story = []

    logo_path = next((p for p in LETTERHEAD_CANDIDATES if p.exists()), None)
    if logo_path:
        from reportlab.platypus import Image, Table as _T
        logo = Image(str(logo_path), width=2.15 * inch, height=0.9 * inch)
        right = [
            Paragraph(summary["source_label"], styles["brand"]),
            Paragraph("Prepared by Devon Brown  |  Network Security Engineer", styles["meta"]),
            Paragraph(
                f"Times Microwave Systems  ·  {summary['generated']}  ·  {summary['input_name']}",
                styles["meta"],
            ),
        ]
        hdr = _T([[logo, right]], colWidths=[2.3 * inch, 4.9 * inch])
        hdr.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        story.append(hdr)
    else:
        story.append(Paragraph(summary["source_label"], styles["brand"]))
        story.append(Paragraph("Prepared by Devon Brown  |  Network Security Engineer", styles["subtitle"]))
        story.append(
            Paragraph(
                f"Times Microwave Systems  ·  {summary['generated']}  ·  {summary['input_name']}",
                styles["meta"],
            )
        )
    story.append(Spacer(1, 10))

    story.append(Paragraph("Situation snapshot", styles["h1"]))
    story.append(
        Paragraph(
            _narrative(summary),
            styles["body"],
        )
    )
    story.append(Spacer(1, 10))
    story.append(_kpi_table(summary))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Severity mix", styles["h1"]))
    story.append(_sev_table(summary))
    story.append(Spacer(1, 16))

    if summary["kev_count"]:
        story.append(Paragraph("Known exploited vulnerabilities (CISA KEV)", styles["h1"]))
        story.append(
            Paragraph(
                "These items appear on CISA’s Known Exploited Vulnerabilities catalog. "
                "Treat them as board-level risk until patched or formally accepted.",
                styles["body"],
            )
        )
        story.append(Spacer(1, 6))
        story.append(_kev_table(summary))
        story.append(Spacer(1, 16))

    story.append(Paragraph("Team work plan (priority and due date)", styles["h1"]))
    story.append(
        Paragraph(
            "Every finding has a verified fix when the scanner, Blumira workflow, or CISA KEV published one. "
            "If that text is missing, the plan uses the current best-practice remediation. "
            "Send this table to the team. P1 = investigate/contain immediately. "
            "P2 = this sprint. P3 = 30-day plan. P4 = quarterly backlog or verify a closure.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 6))
    story.append(_work_plan_table(summary["work_plan"], styles))
    story.append(Spacer(1, 16))

    story.append(Paragraph("1. Keep the business running — do these now", styles["h1"]))
    story.append(
        Paragraph(
            "Active exploitation risk, identity takeover, domain/VPN/email interruption, "
            "or Critical/High issues that can stop operations. Assign an owner this week.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 6))
    if summary["top_now"]:
        story.append(_finding_table(summary["top_now"]))
        story.append(Spacer(1, 8))
        story.append(_fix_list(summary["now_actions"], styles))
    else:
        story.append(Paragraph("No immediate run-the-business actions in this CSV.", styles["body"]))
    story.append(Spacer(1, 16))

    story.append(Paragraph("2. Can wait — next change window", styles["h1"]))
    story.append(
        Paragraph(
            "Hygiene, older protocol issues, operational alerts, and Medium/Low items that do not "
            "currently threaten uptime or identity. Schedule them; do not let them block production work.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 6))
    if summary["top_wait"]:
        story.append(_finding_table(summary["top_wait"]))
        story.append(Spacer(1, 8))
        story.append(_fix_list(summary["wait_actions"], styles))
    else:
        story.append(Paragraph("Nothing in the wait bucket for this export.", styles["body"]))
    story.append(Spacer(1, 16))

    if summary["host_counts"]:
        story.append(Paragraph("Assets with the most findings", styles["h1"]))
        story.append(_host_table(summary))
        story.append(Spacer(1, 16))

    story.append(Paragraph("How to read this brief", styles["h1"]))
    story.append(
        Paragraph(
            "Two lanes only. <b>Now</b> keeps payroll, email, VPN, identity, and file services alive. "
            "<b>Wait</b> is real work but it can follow the normal change calendar. "
            "CISA KEV items always land in Now. Blumira workflows and scanner Solution text are used as the action language.",
            styles["body"],
        )
    )

    def _header_footer(canvas, doc_):
        canvas.saveState()
        canvas.setFillColor(NAVY)
        canvas.rect(0, letter[1] - 18, letter[0], 18, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Times-Roman", 8)
        canvas.drawString(0.65 * inch, letter[1] - 13, "Times Microwave Systems  ·  Devon Brown, Network Security Engineer")
        canvas.setFillColor(NAVY)
        canvas.rect(0, 0, letter[0], 28, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.drawString(0.65 * inch, 12, "Confidential — internal security use")
        canvas.drawRightString(letter[0] - 0.65 * inch, 12, f"Page {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)


def _narrative(s: Dict[str, Any]) -> str:
    src = s["source_label"]
    bits = [
        f"This PDF is built from the <b>{src}</b> CSV <i>{s['input_name']}</i> "
        f"({s['total']} rows, {s['unique_hosts']} named assets, {len(s['unique_cves'])} unique CVEs)."
    ]
    bits.append(
        f"<b>{s['now_count']}</b> action(s) are required to keep the business running. "
        f"<b>{s['wait_count']}</b> can wait for the next planned window."
    )
    if s["kev_count"]:
        bits.append(
            f"<b>{s['kev_count']}</b> row(s) match CISA Known Exploited Vulnerabilities and are forced into the Now lane."
        )
    if s["source"] == "blumira":
        bits.append("Blumira already includes the fix steps; those fields are the action text.")
    return " ".join(bits)


def _kpi_table(s: Dict[str, Any]) -> Table:
    data = [
        ["CSV rows", "Do these now", "Can wait", "KEV / exploited", "Unique CVEs", "Named assets"],
        [
            str(s["total"]),
            str(s["now_count"]),
            str(s["wait_count"]),
            str(s["kev_count"]),
            str(len(s["unique_cves"])),
            str(s["unique_hosts"]),
        ],
    ]
    t = Table(data, colWidths=[1.15 * inch] * 6)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), TEAL),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BACKGROUND", (0, 1), (-1, 1), LIGHT),
                ("FONTNAME", (0, 0), (-1, 0), "Times-Bold"),
                ("FONTNAME", (0, 1), (-1, 1), "Times-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 8),
                ("FONTSIZE", (0, 1), (-1, 1), 14),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 0.4, TEAL),
            ]
        )
    )
    return t


def _sev_table(s: Dict[str, Any]) -> Table:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    header = [x.title() for x in order]
    row = [str(s["severity"].get(k, 0)) for k in order]
    t = Table([header, row], colWidths=[1.15 * inch] * 6)
    palette = [CRIT, HIGH, MED, LOW, INFO, colors.HexColor("#667085")]
    cmds = [
        ("FONTNAME", (0, 0), (-1, 0), "Times-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("BOX", (0, 0), (-1, -1), 0.3, colors.HexColor("#D0D5DD")),
    ]
    for i, c in enumerate(palette):
        cmds.append(("BACKGROUND", (i, 0), (i, 0), c))
        cmds.append(("TEXTCOLOR", (i, 0), (i, 0), colors.white))
    t.setStyle(TableStyle(cmds))
    return t


def _work_plan_table(actions: List[Dict[str, Any]], styles) -> Table:
    header = ["Pri", "Due", "SLA", "Finding / asset", "Verified fix"]
    rows = [header]
    for a in actions:
        finding = Paragraph(
            f"<b>{_clip(a.get('title') or '', 70)}</b><br/>"
            f"{_clip(a.get('host') or '—', 28)}"
            + (f"  {_clip(', '.join(a.get('cves') or [])[:24], 24)}" if a.get("cves") else ""),
            styles["fix"],
        )
        fix = Paragraph(_clip(a.get("action") or "", 320), styles["fix"])
        rows.append(
            [
                a.get("priority") or "",
                a.get("due") or "",
                a.get("sla") or "",
                finding,
                fix,
            ]
        )
    t = Table(rows, colWidths=[0.45 * inch, 0.85 * inch, 0.7 * inch, 2.1 * inch, 3.1 * inch])
    cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Times-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D0D5DD")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
    ]
    for i in range(1, len(rows)):
        if i % 2 == 0:
            cmds.append(("BACKGROUND", (0, i), (-1, i), ROW_ALT))
    t.setStyle(TableStyle(cmds))
    return t


def _finding_table(items: List[Dict[str, Any]]) -> Table:
    header = ["Sev", "CVSS", "Finding", "CVE", "Asset", "KEV"]
    rows = [header]
    for f in items:
        title = _clip(f.get("title") or "", 42)
        cve = ", ".join((f.get("cves") or [])[:2]) or "—"
        rows.append(
            [
                _sev(f)[:4],
                _fmt_score(f.get("cvss")),
                title,
                cve,
                _clip(f.get("host") or f.get("asset") or "—", 18),
                "YES" if f.get("in_kev") else "",
            ]
        )
    t = Table(rows, colWidths=[0.6 * inch, 0.5 * inch, 2.7 * inch, 1.5 * inch, 1.3 * inch, 0.5 * inch])
    cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Times-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D0D5DD")),
    ]
    for i in range(1, len(rows)):
        if i % 2 == 0:
            cmds.append(("BACKGROUND", (0, i), (-1, i), ROW_ALT))
    t.setStyle(TableStyle(cmds))
    return t


def _kev_table(s: Dict[str, Any]) -> Table:
    header = ["CVE", "Name", "Required action", "Due"]
    rows = [header]
    seen = set()
    for f in s["findings"]:
        if not f.get("in_kev") or not f.get("kev"):
            continue
        cves = f.get("cves") or ["—"]
        key = cves[0]
        if key in seen:
            continue
        seen.add(key)
        k = f["kev"]
        rows.append(
            [
                key,
                _clip(k.get("vulnerability_name") or f.get("title") or "", 28),
                _clip(k.get("required_action") or "", 48),
                k.get("due_date") or "—",
            ]
        )
        if len(rows) > 8:
            break
    t = Table(rows, colWidths=[1.2 * inch, 1.8 * inch, 3.3 * inch, 0.8 * inch])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), CRIT),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Times-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D0D5DD")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return t


def _fix_list(actions: List[Dict[str, Any]], styles) -> ListFlowable:
    items = []
    for i, fx in enumerate(actions, 1):
        kev = " [KEV]" if fx.get("kev") else ""
        cve = f" ({', '.join(fx['cves'][:2])})" if fx.get("cves") else ""
        host = f" — {fx['host']}" if fx.get("host") else ""
        text = f"<b>{i}. [{fx['severity']}]{kev}</b> {fx['title']}{cve}{host}<br/>{_clip(fx['action'], 280)}"
        items.append(ListItem(Paragraph(text, styles["fix"]), leftIndent=8, bulletColor=TEAL))
    if not items:
        items.append(ListItem(Paragraph("No prioritized remediations in this export.", styles["body"])))
    return ListFlowable(items, bulletType="bullet", start="•", leftIndent=12)


def _host_table(s: Dict[str, Any]) -> Table:
    header = ["Asset", "Finding count"]
    rows = [header] + [[h, str(c)] for h, c in s["host_counts"]]
    t = Table(rows, colWidths=[5.5 * inch, 1.6 * inch])
    cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), TEAL),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Times-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D0D5DD")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ]
    for i in range(1, len(rows)):
        if i % 2 == 0:
            cmds.append(("BACKGROUND", (0, i), (-1, i), ROW_ALT))
    t.setStyle(TableStyle(cmds))
    return t


def _styles():
    base = getSampleStyleSheet()
    return {
        "brand": ParagraphStyle(
            "brand",
            parent=base["Title"],
            fontName="Times-Bold",
            fontSize=22,
            textColor=NAVY,
            alignment=TA_LEFT,
            spaceAfter=0,
            leading=24,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            parent=base["Normal"],
            fontName="Times-Italic",
            fontSize=12,
            textColor=TEAL,
            spaceAfter=2,
        ),
        "meta": ParagraphStyle(
            "meta",
            parent=base["Normal"],
            fontName="Times-Roman",
            fontSize=8,
            textColor=INFO,
        ),
        "h1": ParagraphStyle(
            "h1",
            parent=base["Heading2"],
            fontName="Times-Bold",
            fontSize=12,
            textColor=NAVY,
            spaceBefore=4,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["Normal"],
            fontName="Times-Roman",
            fontSize=9.5,
            leading=13,
            alignment=TA_JUSTIFY,
            textColor=colors.HexColor("#1D2939"),
        ),
        "fix": ParagraphStyle(
            "fix",
            parent=base["Normal"],
            fontName="Times-Roman",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#1D2939"),
        ),
    }


def _sev(f: Dict[str, Any]) -> str:
    return (f.get("severity") or "UNKNOWN").upper()


def _score(f: Dict[str, Any]):
    try:
        return float(f.get("cvss"))
    except (TypeError, ValueError):
        return 0.0


def _sev_rank(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(sev, 5)


def _fmt_score(val) -> str:
    try:
        return f"{float(val):.1f}"
    except (TypeError, ValueError):
        return "—"


def _clip(text: str, n: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1] + "…"