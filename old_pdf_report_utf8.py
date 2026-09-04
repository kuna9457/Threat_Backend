"""
PDF Report Generator
Builds a professional threat-intelligence PDF report using reportlab.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from io import BytesIO
from datetime import datetime


# ΓöÇΓöÇ Colour palette ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
DARK_BG       = colors.HexColor("#0d1117")
CARD_BG       = colors.HexColor("#161b22")
BORDER        = colors.HexColor("#30363d")
GREEN         = colors.HexColor("#3fb950")
YELLOW        = colors.HexColor("#d29922")
RED           = colors.HexColor("#f85149")
TEXT_PRIMARY   = colors.HexColor("#c9d1d9")
TEXT_SECONDARY = colors.HexColor("#8b949e")
ACCENT         = colors.HexColor("#58a6ff")


def _verdict_color(verdict: str) -> colors.Color:
    mapping = {"ALLOW": GREEN, "REVIEW": YELLOW, "BLOCK": RED}
    return mapping.get(verdict, TEXT_SECONDARY)


def _grade_color(grade: str) -> colors.Color:
    if not grade:
        return TEXT_SECONDARY
    g = grade.upper()
    if g.startswith("A"):
        return GREEN
    if g.startswith("B"):
        return colors.HexColor("#3fb990")
    if g.startswith("C"):
        return YELLOW
    if g.startswith("D"):
        return colors.HexColor("#e08f30")
    return RED


def generate_pdf_report(results: list[dict]) -> bytes:
    """
    Generate a multi-page PDF report for a list of scan results.
    Returns raw PDF bytes.
    """
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
    )

    styles = getSampleStyleSheet()

    # ΓöÇΓöÇ Custom styles ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=colors.HexColor("#1f6feb"),
        spaceAfter=6,
        alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.gray,
        spaceAfter=20,
        alignment=TA_CENTER,
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.HexColor("#1f6feb"),
        spaceBefore=14,
        spaceAfter=6,
    )
    subheading_style = ParagraphStyle(
        "SubHeading",
        parent=styles["Heading3"],
        fontSize=11,
        textColor=colors.HexColor("#58a6ff"),
        spaceBefore=10,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#333333"),
        spaceAfter=4,
    )
    small_style = ParagraphStyle(
        "Small",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.gray,
    )

    story = []

    # ΓöÇΓöÇ Cover / Header ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
    story.append(Spacer(1, 30))
    story.append(Paragraph("≡ƒ¢í∩╕Å URL Threat Intelligence Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} "
        f"&nbsp;|&nbsp; URLs scanned: {len(results)}",
        subtitle_style,
    ))
    story.append(HRFlowable(
        width="100%", thickness=1, color=colors.HexColor("#d0d7de"),
        spaceAfter=10,
    ))

    # ΓöÇΓöÇ Executive summary table ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
    story.append(Paragraph("Executive Summary", heading_style))
    summary_data = [["#", "URL", "Score", "Verdict", "SSL Grade"]]
    for idx, res in enumerate(results, 1):
        ssl = res.get("data", {}).get("ssl_labs", {})
        summary_data.append([
            str(idx),
            _trunc(res.get("url", ""), 45),
            str(res.get("score", "ΓÇö")),
            res.get("verdict", "ΓÇö"),
            ssl.get("grade", "N/A"),
        ])

    summary_table = Table(summary_data, colWidths=[25, 220, 50, 60, 60])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f6feb")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f6f8fa")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
        ("ALIGN", (2, 0), (4, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 10))

    # ΓöÇΓöÇ Detailed results per URL ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
    for idx, res in enumerate(results, 1):
        story.append(PageBreak())
        data_block = res.get("data", {})
        vt = data_block.get("virustotal", {})
        urlscan = data_block.get("urlscan", {})
        abuseipdb = data_block.get("abuseipdb", {})
        ssl = data_block.get("ssl_labs", {})
        mx = data_block.get("mx_tools", {})

        # URL Header
        story.append(Paragraph(
            f"#{idx} ΓÇö {_esc(res.get('url', ''))}", heading_style
        ))
        story.append(Paragraph(
            f"Scanned: {res.get('timestamp', 'ΓÇö')}", small_style
        ))
        story.append(HRFlowable(
            width="100%", thickness=0.5,
            color=colors.HexColor("#d0d7de"), spaceAfter=8,
        ))

        # Risk overview
        story.append(Paragraph("Risk Overview", subheading_style))
        risk_data = [
            ["Risk Score", "Verdict", "VT Malicious", "VT Suspicious",
             "Domain Age (days)"],
            [
                str(res.get("score", 0)),
                res.get("verdict", "ΓÇö"),
                str(vt.get("malicious", 0)),
                str(vt.get("suspicious", 0)),
                str(data_block.get("domain_age", "ΓÇö")),
            ],
        ]
        story.append(_make_table(risk_data))

        # ΓöÇΓöÇ VirusTotal ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        story.append(Paragraph("VirusTotal Analysis", subheading_style))
        vt_rows = [
            ["Metric", "Value"],
            ["Malicious Engines", str(vt.get("malicious", 0))],
            ["Suspicious Engines", str(vt.get("suspicious", 0))],
            ["Harmless Engines", str(vt.get("harmless", 0))],
            ["Undetected", str(vt.get("undetected", 0))],
            ["Page Title", _trunc(str(vt.get("title", "ΓÇö")), 60)],
            ["Final URL", _trunc(str(vt.get("final_url", "ΓÇö")), 60)],
            ["HTTP Status", str(vt.get("last_http_response_code", "ΓÇö"))],
            ["Reputation", str(vt.get("reputation", "ΓÇö"))],
        ]
        if vt.get("threat_names"):
            vt_rows.append(["Flagging Engines", ", ".join(vt["threat_names"][:10])])
        story.append(_make_kv_table(vt_rows))

        # ΓöÇΓöÇ URLScan.io ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        if urlscan and "error" not in urlscan:
            story.append(Paragraph("URLScan.io", subheading_style))
            us_rows = [
                ["Metric", "Value"],
                ["Malicious", "YES" if urlscan.get("malicious") else "NO"],
                ["Score", str(urlscan.get("score", 0))],
                ["Total Scans", str(urlscan.get("total_scans", 0))],
                ["Country", str(urlscan.get("country", "ΓÇö"))],
                ["Server", str(urlscan.get("server", "ΓÇö"))],
            ]
            story.append(_make_kv_table(us_rows))

        # ΓöÇΓöÇ AbuseIPDB ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        if abuseipdb and "error" not in abuseipdb:
            story.append(Paragraph("AbuseIPDB", subheading_style))
            ab_rows = [
                ["Metric", "Value"],
                ["Resolved IP", str(abuseipdb.get("ip", "ΓÇö"))],
                ["Abuse Confidence", f"{abuseipdb.get('abuseConfidenceScore', 0)}%"],
                ["Total Reports", str(abuseipdb.get("totalReports", 0))],
                ["ISP", str(abuseipdb.get("isp", "ΓÇö"))],
                ["Country", str(abuseipdb.get("countryCode", "ΓÇö"))],
            ]
            story.append(_make_kv_table(ab_rows))

        # ΓöÇΓöÇ SSL Labs ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        if ssl and "error" not in ssl:
            story.append(Paragraph("SSL / TLS Analysis (SSL Labs)", subheading_style))

            cert = ssl.get("certificate", {})
            vulns = ssl.get("vulnerabilities", {})
            hsts = ssl.get("hsts", {})

            ssl_rows = [
                ["Metric", "Value"],
                ["Grade", ssl.get("grade", "N/A")],
                ["IP Address", ssl.get("ip_address", "ΓÇö")],
                ["Server Name", ssl.get("server_name", "ΓÇö")],
            ]
            if cert:
                ssl_rows += [
                    ["Cert Subject", _trunc(cert.get("subject", "ΓÇö"), 55)],
                    ["Cert Issuer", _trunc(cert.get("issuer", "ΓÇö"), 55)],
                    ["Key Algorithm", f"{cert.get('key_alg', 'ΓÇö')} ({cert.get('key_size', 'ΓÇö')} bit)"],
                    ["Signature Algorithm", str(cert.get("sig_alg", "ΓÇö"))],
                ]
                # Validity dates
                nb = cert.get("not_before")
                na = cert.get("not_after")
                if nb:
                    ssl_rows.append(["Valid From", _epoch_to_str(nb)])
                if na:
                    ssl_rows.append(["Valid Until", _epoch_to_str(na)])

            ssl_rows.append(["HSTS", hsts.get("status", "unknown")])
            ssl_rows.append(["OCSP Stapling", "Yes" if ssl.get("ocsp_stapling") else "No"])
            ssl_rows.append(["Forward Secrecy", "Yes" if ssl.get("forward_secrecy", 0) else "No"])
            story.append(_make_kv_table(ssl_rows))

            # Protocols
            protos = ssl.get("protocols", [])
            if protos:
                story.append(Paragraph("Supported Protocols", small_style))
                proto_data = [["Protocol", "Version"]]
                for p in protos:
                    proto_data.append([p.get("name", ""), p.get("version", "")])
                story.append(_make_table(proto_data))

            # Vulnerabilities
            if vulns:
                story.append(Paragraph("Vulnerability Checks", small_style))
                vuln_data = [["Check", "Status"]]
                for k, v in vulns.items():
                    label = k.replace("_", " ").title()
                    if isinstance(v, bool):
                        status = "VULNERABLE" if v else "Safe"
                    elif isinstance(v, int):
                        status = "Safe" if v <= 1 else "VULNERABLE"
                    else:
                        status = str(v)
                    vuln_data.append([label, status])
                story.append(_make_table(vuln_data))
        elif ssl and "error" in ssl:
            story.append(Paragraph("SSL / TLS Analysis", subheading_style))
            story.append(Paragraph(f"ΓÜá {ssl['error']}", body_style))

        # ΓöÇΓöÇ MX Tools ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        if mx and "error" not in mx:
            story.append(Paragraph("MX / DNS Analysis", subheading_style))

            # MX records
            mx_recs = mx.get("mx_records", [])
            if mx_recs:
                mx_data = [["Priority", "Mail Server"]]
                for m in mx_recs:
                    mx_data.append([str(m.get("preference", "")), m.get("exchange", "")])
                story.append(Paragraph("MX Records", small_style))
                story.append(_make_table(mx_data))

            # Mail security
            ms = mx.get("mail_security", {})
            if ms:
                story.append(Paragraph(
                    f"Mail Security Score: {ms.get('score', 0)} / 100", body_style
                ))
                checks = ms.get("checks", {})
                for check_name, check_info in checks.items():
                    status_icon = "Γ£à" if check_info.get("status") == "PASS" else (
                        "ΓÜá∩╕Å" if check_info.get("status") == "WARN" else "Γ¥î"
                    )
                    story.append(Paragraph(
                        f"{status_icon} <b>{check_name.upper()}</b>: {check_info.get('detail', '')}",
                        body_style,
                    ))

            # SPF / DMARC records
            spf = mx.get("spf", {})
            dmarc = mx.get("dmarc", {})
            if spf.get("record"):
                story.append(Paragraph(
                    f"<b>SPF:</b> {_trunc(spf['record'], 80)}", body_style
                ))
            if dmarc.get("record"):
                story.append(Paragraph(
                    f"<b>DMARC:</b> {_trunc(dmarc['record'], 80)}", body_style
                ))

            # NS records
            ns = mx.get("ns_records", [])
            if ns:
                story.append(Paragraph(
                    f"<b>Nameservers:</b> {', '.join(ns)}", body_style
                ))

            # A records
            a_recs = mx.get("a_records", [])
            if a_recs:
                story.append(Paragraph(
                    f"<b>A Records:</b> {', '.join(a_recs)}", body_style
                ))

        elif mx and "error" in mx:
            story.append(Paragraph("MX / DNS Analysis", subheading_style))
            story.append(Paragraph(f"ΓÜá {mx['error']}", body_style))

    # ΓöÇΓöÇ Footer ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
    story.append(Spacer(1, 30))
    story.append(HRFlowable(
        width="100%", thickness=0.5, color=colors.HexColor("#d0d7de"),
    ))
    footer_style = ParagraphStyle(
        "Footer", parent=styles["Normal"], fontSize=7,
        textColor=colors.gray, alignment=TA_CENTER,
    )
    story.append(Paragraph(
        "URL Threat Intelligence Platform ┬╖ Confidential Report ┬╖ "
        f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        footer_style,
    ))

    doc.build(story)
    return buf.getvalue()


# ΓöÇΓöÇ Helper utilities ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

def _trunc(text: str, max_len: int = 50) -> str:
    if len(text) > max_len:
        return text[:max_len - 1] + "ΓÇª"
    return text


def _esc(text: str) -> str:
    """Escape XML entities for ReportLab Paragraph."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _epoch_to_str(epoch_ms) -> str:
    """Convert epoch milliseconds to human-readable date."""
    try:
        if isinstance(epoch_ms, (int, float)):
            return datetime.utcfromtimestamp(epoch_ms / 1000).strftime("%Y-%m-%d")
    except Exception:
        pass
    return str(epoch_ms)


def _make_table(data: list[list[str]]) -> Table:
    """Build a styled table with header row."""
    t = Table(data, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f6feb")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTSIZE", (0, 1), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d7de")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t


def _make_kv_table(data: list[list[str]]) -> Table:
    """Build a key-value style table (first col bold header)."""
    t = Table(data, colWidths=[150, 310], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f6feb")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, -1), 7.5),
        ("TEXTCOLOR", (0, 1), (0, -1), colors.HexColor("#333333")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d7de")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t
