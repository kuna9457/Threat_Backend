
import io
import os
from io import BytesIO
from datetime import datetime
import urllib.request
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image as RLImage, KeepTogether
)
from reportlab.platypus.flowables import HRFlowable
from PIL import Image as PILImage
from app.services.evidence_screenshots import generate_evidence_screenshots

def _make_rl_image(img_buffer, target_width_mm):
    img_buffer.seek(0)
    with PILImage.open(img_buffer) as pil_img:
        native_w, native_h = pil_img.size
    target_w_pts = target_width_mm * mm
    target_h_pts = native_h * target_w_pts / native_w
    img_buffer.seek(0)
    return RLImage(img_buffer, width=target_w_pts, height=target_h_pts)

def _trunc(text, max_len=60):
    text = str(text)
    return text if len(text) <= max_len else text[:max_len-3] + "..."

def _esc(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def _epoch_to_str(epoch_ms) -> str:
    try:
        if isinstance(epoch_ms, (int, float)):
            return datetime.utcfromtimestamp(epoch_ms / 1000).strftime("%Y-%m-%d")
    except Exception:
        pass
    return str(epoch_ms)

_RISK_COLORS = {
    "High": colors.HexColor("#DC2626"),
    "Medium": colors.HexColor("#D97706"),
    "Low": colors.HexColor("#059669"),
}

def _make_summary_table(data: list[list[str]]) -> Table:
    """Light-themed summary table: SR. No. / URL / Risk level, with the risk
    level colored by severity. Row 0 is the header; data[i][-1] is the risk
    level text for row i."""
    t = Table(data, colWidths=[20*mm, 110*mm, 40*mm], hAlign="LEFT", repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C3E73")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#1F2937")),
        ("TEXTCOLOR", (1, 1), (1, -1), colors.HexColor("#1D4ED8")),  # URL in blue
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTNAME", (-1, 1), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]
    for row_idx, row in enumerate(data[1:], start=1):
        risk_color = _RISK_COLORS.get(row[-1])
        if risk_color:
            style.append(("TEXTCOLOR", (-1, row_idx), (-1, row_idx), risk_color))
    t.setStyle(TableStyle(style))
    return t

def _make_table(data: list[list[str]]) -> Table:
    t = Table(data, hAlign="LEFT", repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C3E73")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d7de")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t

def _make_kv_table(data: list[list[str]]) -> Table:
    t = Table(data, colWidths=[150, 310], hAlign="LEFT", repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C3E73")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("TEXTCOLOR", (0, 1), (0, -1), colors.HexColor("#333333")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d7de")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t

def _make_wrapped_table(header: list[str], rows: list[list], col_widths: list) -> Table:
    """Table whose cells wrap long text (engine names/results, categories, etc.)."""
    from reportlab.platypus import Paragraph as _P
    styles = getSampleStyleSheet()
    head_style = ParagraphStyle("WH", parent=styles["Normal"], fontSize=7, leading=9,
                                 fontName="Helvetica-Bold", textColor=colors.white)
    cell_style = ParagraphStyle("WC", parent=styles["Normal"], fontSize=7, leading=9)
    data = [[_P(_esc(h), head_style) for h in header]]
    for row in rows:
        data.append([_P(_esc(v), cell_style) for v in row])
    t = Table(data, colWidths=col_widths, hAlign="LEFT", repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C3E73")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d7de")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t

def generate_pdf_report(results: list, final_comment: str = "") -> bytes:
    pdf_buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )
    styles = getSampleStyleSheet()

    # Custom Styles
    cover_bank = ParagraphStyle(
        "CoverBank", parent=styles["Title"],
        fontSize=30, fontName="Helvetica-Bold", alignment=1, spaceAfter=10, textColor=colors.HexColor("#1C3E73")
    )
    cover_title = ParagraphStyle(
        "CoverTitle", parent=styles["Title"],
        fontSize=24, fontName="Helvetica-Bold", alignment=1, spaceAfter=20, textColor=colors.black
    )
    heading_style = ParagraphStyle(
        "Heading", parent=styles["Heading2"],
        fontSize=13, fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=8, textColor=colors.HexColor("#1C3E73")
    )
    subheading_style = ParagraphStyle(
        "SubHeading", parent=styles["Heading3"],
        fontSize=11, fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=6, textColor=colors.HexColor("#F37224")
    )
    from reportlab.lib.enums import TA_JUSTIFY
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=11, fontName="Helvetica", spaceAfter=6, leading=15, alignment=TA_JUSTIFY
    )
    small_style = ParagraphStyle(
        "Small", parent=styles["Normal"],
        fontSize=9, fontName="Helvetica", spaceAfter=3, leading=12
    )
    note_style = ParagraphStyle(
        "Note", parent=styles["Normal"],
        fontSize=9, fontName="Helvetica-Oblique", spaceAfter=6, leading=12, textColor=colors.HexColor("#6B7280")
    )

    story = []

    # ── PAGE 1: COVER ──────────────────────────────────────────────────────
    story.append(Spacer(1, 40 * mm))
    
    # Load transparent ICICI Logo
    try:
        logo_path = os.path.join(os.path.dirname(__file__), 'icici_logo_transparent.png')
        with open(logo_path, 'rb') as f:
            logo_data = f.read()
        story.append(_make_rl_image(BytesIO(logo_data), target_width_mm=60))
    except Exception:
        story.append(Paragraph("[ICICI BANK LOGO]", cover_bank))
    
    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph("ICICI BANK LIMITED", cover_bank))
    story.append(Paragraph("URL Risk Assessment", cover_title))
    story.append(PageBreak())

    # ── PAGE 2: SUMMARY ────────────────────────────────────────────────────
    date_str = datetime.utcnow().strftime("%b %d, %Y")
    story.append(Paragraph(f"<b>Drafted date:</b> {date_str}", body_style))
    story.append(Paragraph("<b>Type of assessment:</b> URL Risk Assessment", body_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Risk performed of what all URL:", heading_style))
    summary_data = [["SR. No.", "URL", "Risk level identified"]]
    for idx, res in enumerate(results, 1):
        score = res.get("score", 0)
        if score >= 60: risk_level = "High"
        elif score >= 30: risk_level = "Medium"
        else: risk_level = "Low"

        summary_data.append([
            str(idx),
            _trunc(res.get("url", ""), 55),
            risk_level
        ])
    story.append(_make_summary_table(summary_data))
    
    # ── DETAILED RESULTS ───────────────────────────────────────────────────
    for idx, res in enumerate(results, 1):
        story.append(PageBreak())

        url = res.get("url", "")
        data_block = res.get("data", {})
        vt = data_block.get("virustotal", {})
        urlscan_data = data_block.get("urlscan", {})
        abuseipdb = data_block.get("abuseipdb", {})
        ssl = data_block.get("ssl_labs", {})
        phishing = data_block.get("phishing", False)

        # URL Header
        story.append(Paragraph(f"<b>{idx} — {_esc(_trunc(url, 65))}</b>", heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#F37224"), spaceAfter=10))

        # Generate Evidence
        try:
            evidence = generate_evidence_screenshots(url, res)
        except Exception:
            evidence = {}

        # Risk Overview
        risk_data = [
            ["Risk Score", "Verdict", "VT Malicious", "VT Suspicious", "Domain Age (days)", "Google Phishing"],
            [
                str(res.get("score", 0)),
                res.get("verdict", "—"),
                str(vt.get("malicious", 0)),
                str(vt.get("suspicious", 0)),
                str(data_block.get("domain_age", "—")),
                "YES" if phishing else "No",
            ],
        ]
        story.append(KeepTogether([
            Paragraph("Risk Overview", subheading_style),
            _make_table(risk_data),
        ]))

        # ── Google Safe Browsing ─────────────────────────────────────────
        gsb_block = [Paragraph("Google Safe Browsing", subheading_style)]
        if "google_safe_browsing" in evidence:
            gsb_block.append(_make_rl_image(BytesIO(evidence["google_safe_browsing"]), target_width_mm=160))
            gsb_block.append(Spacer(1, 10))
        gsb_block.append(_make_kv_table([
            ["Metric", "Value"],
            ["Phishing Status", "⚠ Flagged as phishing" if phishing else "Not flagged"],
        ]))
        story.append(KeepTogether(gsb_block))

        # ── VirusTotal ────────────────────────────────────────────────────
        vt_block = [Paragraph("VirusTotal Multi-Engine Analysis", subheading_style)]
        if "virustotal" in evidence:
            vt_block.append(_make_rl_image(BytesIO(evidence["virustotal"]), target_width_mm=160))
            vt_block.append(Spacer(1, 10))

        vt_rows = [
            ["Metric", "Value"],
            ["Malicious Engines", str(vt.get("malicious", 0))],
            ["Suspicious Engines", str(vt.get("suspicious", 0))],
            ["Harmless Engines", str(vt.get("harmless", 0))],
            ["Undetected", str(vt.get("undetected", 0))],
            ["Page Title", _trunc(str(vt.get("title", "—")), 60)],
            ["Final URL", _trunc(str(vt.get("final_url", "—")), 60)],
            ["HTTP Status", str(vt.get("last_http_response_code", "—"))],
            ["Times Submitted", str(vt.get("times_submitted", 0))],
            ["Tags", _trunc(", ".join(vt.get("tags", [])) or "None", 60)],
            ["Reputation", str(vt.get("reputation", "N/A"))],
            ["Data Source", "Live VirusTotal API" if not vt.get("mock") else "Mock (no API key configured)"],
        ]
        vt_block.append(_make_kv_table(vt_rows))
        if vt.get("error"):
            vt_block.append(Paragraph(f"⚠ {_esc(vt['error'])} — the counts above reflect a failed/unchecked lookup, not a confirmed-clean result.", note_style))
        story.append(KeepTogether(vt_block))

        categories = vt.get("categories", {})
        if categories:
            cat_rows = [[str(k), str(v)] for k, v in categories.items()]
            story.append(KeepTogether([
                Spacer(1, 6),
                Paragraph("Vendor Categories", small_style),
                _make_wrapped_table(["Vendor", "Category"], cat_rows, [140, 300]),
            ]))

        chain = vt.get("redirection_chain", [])
        if chain:
            story.append(KeepTogether([
                Spacer(1, 6),
                Paragraph("Redirection Chain", small_style),
                Paragraph("<br/>".join(f"{i}. {_esc(_trunc(h, 90))}" for i, h in enumerate(chain, 1)), small_style),
            ]))

        analysis_results = vt.get("last_analysis_results", {})
        if analysis_results:
            order = {"malicious": 0, "suspicious": 1, "harmless": 2, "undetected": 3}
            eng_rows = sorted(
                (
                    [e, d.get("category", ""), d.get("result", "") or "—", d.get("method", "")]
                    for e, d in analysis_results.items()
                ),
                key=lambda r: (order.get(r[1], 4), r[0]),
            )
            story.append(KeepTogether([
                Spacer(1, 6),
                Paragraph(f"Per-Engine Results ({len(analysis_results)})", small_style),
                _make_wrapped_table(["Engine", "Category", "Result", "Method"], eng_rows, [110, 65, 220, 70]),
            ]))
        elif not vt.get("mock"):
            story.append(Paragraph("No per-engine results returned by VirusTotal for this URL.", note_style))
        else:
            story.append(Paragraph("Per-engine results unavailable — VirusTotal is running in mock mode (no API key configured).", note_style))

        # ── URLScan.io ────────────────────────────────────────────────────
        if not urlscan_data or "error" in urlscan_data:
            story.append(KeepTogether([
                Paragraph("URLScan.io Analysis", subheading_style),
                Paragraph(f"Not available — {urlscan_data.get('error', 'no data returned')}.", note_style),
            ]))
        else:
            us_rows = [
                ["Metric", "Value"],
                ["Malicious", "YES" if urlscan_data.get("malicious") else "No"],
                ["Score", str(urlscan_data.get("score", 0))],
                ["Total Scans", str(urlscan_data.get("total_scans", 0))],
                ["Country", str(urlscan_data.get("country", "Unknown"))],
                ["Server", str(urlscan_data.get("server", "Unknown"))],
                ["Report URL", _trunc(str(urlscan_data.get("report_url", "—")), 65)],
            ]
            story.append(KeepTogether([
                Paragraph("URLScan.io Analysis", subheading_style),
                _make_kv_table(us_rows),
            ]))

        # ── AbuseIPDB ─────────────────────────────────────────────────────
        if not abuseipdb or "error" in abuseipdb:
            story.append(KeepTogether([
                Paragraph("AbuseIPDB Reputation Check", subheading_style),
                Paragraph(f"Not available — {abuseipdb.get('error', 'no data returned') if abuseipdb else 'no data returned'}.", note_style),
            ]))
        else:
            ab_block = [Paragraph("AbuseIPDB Reputation Check", subheading_style)]
            if "abuseipdb" in evidence:
                ab_block.append(_make_rl_image(BytesIO(evidence["abuseipdb"]), target_width_mm=160))
                ab_block.append(Spacer(1, 10))
            ab_rows = [
                ["Metric", "Value"],
                ["Abuse Confidence", f"{abuseipdb.get('abuseConfidenceScore', 0)}%"],
                ["Total Reports", str(abuseipdb.get("totalReports", 0))],
                ["Usage Type", str(abuseipdb.get("usageType", "Unknown"))],
                ["ISP", str(abuseipdb.get("isp", "—"))],
                ["Country", str(abuseipdb.get("countryCode", "—"))],
            ]
            ab_block.append(_make_kv_table(ab_rows))
            story.append(KeepTogether(ab_block))

        # ── SSL Labs ──────────────────────────────────────────────────────
        if not ssl or "error" in ssl:
            story.append(KeepTogether([
                Paragraph("SSL / TLS Analysis (Qualys SSL Labs)", subheading_style),
                Paragraph(f"Not available — {ssl.get('error', 'no data returned') if ssl else 'no data returned'}.", note_style),
            ]))
        else:
            ssl_block = [Paragraph("SSL / TLS Analysis (Qualys SSL Labs)", subheading_style)]
            if "ssllabs" in evidence:
                ssl_block.append(_make_rl_image(BytesIO(evidence["ssllabs"]), target_width_mm=160))
                ssl_block.append(Spacer(1, 10))
            hsts = ssl.get("hsts", {})
            ssl_rows = [
                ["Metric", "Value"],
                ["Grade", ssl.get("grade", "N/A")],
                ["Server Name", ssl.get("server_name", "—") or "—"],
                ["HSTS", str(hsts.get("status", "unknown")).title()],
                ["OCSP Stapling", "Yes" if ssl.get("ocsp_stapling") else "No"],
            ]
            cert = ssl.get("certificate", {})
            if cert:
                ssl_rows += [
                    ["Cert Subject", _trunc(cert.get("subject", "—"), 55)],
                    ["Cert Issuer", _trunc(cert.get("issuer", "—"), 55)],
                    ["Key Algorithm", f"{cert.get('key_alg','—')} ({cert.get('key_size','—')} bit)"],
                    ["Valid Until", _epoch_to_str(cert.get("not_after"))],
                ]
            ssl_block.append(_make_kv_table(ssl_rows))
            story.append(KeepTogether(ssl_block))

            protocols = ssl.get("protocols", [])
            if protocols:
                proto_rows = [[p.get("name", ""), p.get("version", "")] for p in protocols]
                story.append(KeepTogether([
                    Spacer(1, 6),
                    Paragraph(f"Supported Protocols ({len(protocols)})", small_style),
                    _make_wrapped_table(["Protocol", "Version"], proto_rows, [220, 220]),
                ]))

            vulns = ssl.get("vulnerabilities", {})
            if vulns:
                vuln_rows = []
                for k, v in vulns.items():
                    label = k.replace("_", " ").title()
                    if isinstance(v, bool):
                        status = "VULNERABLE" if v else "Safe"
                    elif isinstance(v, int):
                        status = "Safe" if v <= 1 else "VULNERABLE"
                    else:
                        status = str(v)
                    vuln_rows.append([label, status])
                story.append(KeepTogether([
                    Spacer(1, 6),
                    Paragraph("Vulnerability Checks", small_style),
                    _make_wrapped_table(["Check", "Status"], vuln_rows, [220, 220]),
                ]))

            ciphers = ssl.get("cipher_suites", [])
            if ciphers:
                cipher_rows = [[c.get("name", ""), str(c.get("cipher_strength", "")), c.get("kx_type", "")] for c in ciphers]
                story.append(KeepTogether([
                    Spacer(1, 6),
                    Paragraph(f"Cipher Suites ({ssl.get('total_cipher_suites', len(ciphers))})", small_style),
                    _make_wrapped_table(["Cipher Suite", "Strength (bits)", "Key Exchange"], cipher_rows, [280, 90, 90]),
                ]))

    # ── LAST PAGE: COMMENTS ────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Assessment Comments", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#F37224"), spaceAfter=15))

    story.append(Paragraph("Final Assessment Comment:", subheading_style))
    if final_comment.strip():
        story.append(Paragraph(_esc(final_comment), body_style))
    else:
        story.append(Paragraph("<i>No final comment provided.</i>", body_style))

    doc.build(story)
    return pdf_buffer.getvalue()
