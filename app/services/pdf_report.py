
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

# ── WelthWest Brand ──────────────────────────────────────────────────────────
WW_NAVY = colors.HexColor("#0A1930")
WW_TEAL = colors.HexColor("#0FA593")  # slightly deepened for print contrast
WW_LOGO_PATH = os.path.join(os.path.dirname(__file__), "welthwest_logo.png")


def _header_footer(canvas, doc):
    """Draws the WelthWest brand strip (logo + name) and footer on every page."""
    canvas.saveState()
    width, height = A4

    # Header logo + wordmark
    try:
        canvas.drawImage(
            WW_LOGO_PATH, 20 * mm, height - 18 * mm,
            width=9 * mm, height=9 * mm, mask="auto", preserveAspectRatio=True,
        )
    except Exception:
        pass
    canvas.setFont("Helvetica-Bold", 10)
    canvas.setFillColor(WW_NAVY)
    canvas.drawString(31 * mm, height - 13 * mm, "WelthWest")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.drawString(31 * mm, height - 17 * mm, "Cyber Threat Intelligence Platform")

    canvas.setFont("Helvetica-Bold", 7)
    canvas.setFillColor(colors.HexColor("#94A3B8"))
    canvas.drawRightString(width - 20 * mm, height - 13 * mm, "CONFIDENTIAL")

    canvas.setStrokeColor(WW_TEAL)
    canvas.setLineWidth(0.8)
    canvas.line(20 * mm, height - 20 * mm, width - 20 * mm, height - 20 * mm)

    # Footer
    canvas.setStrokeColor(colors.HexColor("#E2E8F0"))
    canvas.setLineWidth(0.5)
    canvas.line(20 * mm, 16 * mm, width - 20 * mm, 16 * mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#94A3B8"))
    canvas.drawString(20 * mm, 11 * mm, "WelthWest — Confidential, For Internal Use Only")
    canvas.drawCentredString(width / 2, 11 * mm, f"Page {doc.page}")
    canvas.drawRightString(width - 20 * mm, 11 * mm, datetime.utcnow().strftime("%Y-%m-%d"))

    canvas.restoreState()

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

def _risk_assessment_summary(results: list) -> str:
    """
    Auto-generated summary sentence.
    - "As per Risk Assessment, 1 low found among total 5 URL."
    - "As per Risk Assessment, 2 low and 4 medium found among total 6 URL."
    - "As per Risk Assessment, no risk found among total 5 URL." (nothing found)
    Only counts Low/Medium/High — "No Risk" URLs aren't a finding worth
    calling out here, and are only implied by omission.
    """
    order = ["Low", "Medium", "High"]
    counts = {lvl: 0 for lvl in order}
    for res in results:
        lvl = res.get("final_risk_level")
        if lvl in counts:
            counts[lvl] += 1

    parts = [f"{counts[lvl]} {lvl.lower()}" for lvl in order if counts[lvl] > 0]
    total = len(results)

    if not parts:
        return f"As per Risk Assessment, no risk found among total {total} URL."

    joined = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]
    return f"As per Risk Assessment, {joined} found among total {total} URL."


_RISK_COLORS = {
    "High": colors.HexColor("#DC2626"),
    "Medium": colors.HexColor("#D97706"),
    "Low": colors.HexColor("#2563EB"),
    "No Risk": colors.HexColor("#059669"),
    "Unknown": colors.HexColor("#6B7280"),
}

def _make_summary_table(data: list[list[str]]) -> Table:
    """Light-themed summary table: SR. No. / URL / Risk level, with the risk
    level colored by severity. Row 0 is the header; data[i][-1] is the risk
    level text for row i."""
    t = Table(data, colWidths=[20*mm, 110*mm, 40*mm], hAlign="LEFT", repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), WW_NAVY),
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
        ("BACKGROUND", (0, 0), (-1, 0), WW_NAVY),
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
        ("BACKGROUND", (0, 0), (-1, 0), WW_NAVY),
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
        ("BACKGROUND", (0, 0), (-1, 0), WW_NAVY),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d7de")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t

def generate_pdf_report(
    results: list,
    final_comment: str = "",
    app_name: str | None = None,
    can_id: str | None = None,
    server_ip: str | None = None,
    request_id: str | None = None
) -> bytes:
    pdf_buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=28 * mm,
        bottomMargin=20 * mm,
    )
    styles = getSampleStyleSheet()

    # Custom Styles
    cover_bank = ParagraphStyle(
        "CoverBank", parent=styles["Title"],
        fontSize=30, fontName="Helvetica-Bold", alignment=1, spaceAfter=4, textColor=WW_NAVY
    )
    cover_subtitle = ParagraphStyle(
        "CoverSubtitle", parent=styles["Normal"],
        fontSize=11, fontName="Helvetica", alignment=1, spaceAfter=20, textColor=colors.HexColor("#64748B")
    )
    cover_title = ParagraphStyle(
        "CoverTitle", parent=styles["Title"],
        fontSize=24, fontName="Helvetica-Bold", alignment=1, spaceAfter=20, textColor=colors.black
    )
    heading_style = ParagraphStyle(
        "Heading", parent=styles["Heading2"],
        fontSize=13, fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=8, textColor=WW_NAVY
    )
    subheading_style = ParagraphStyle(
        "SubHeading", parent=styles["Heading3"],
        fontSize=11, fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=6, textColor=WW_TEAL
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
    story.append(Spacer(1, 30 * mm))

    # WelthWest company logo
    try:
        with open(WW_LOGO_PATH, 'rb') as f:
            logo_data = f.read()
        logo_img = _make_rl_image(BytesIO(logo_data), target_width_mm=42)
        logo_img.hAlign = "CENTER"
        story.append(logo_img)
    except Exception:
        story.append(Paragraph("[WELTHWEST LOGO]", cover_bank))

    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("WELTHWEST", cover_bank))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph("Cyber Threat Intelligence Platform", cover_subtitle))
    story.append(Paragraph("URL Risk Assessment", cover_title))
    story.append(PageBreak())

    # ── PAGE 2: SUMMARY ────────────────────────────────────────────────────
    date_str = datetime.utcnow().strftime("%b %d, %Y")
    story.append(Paragraph(f"<b>Drafted date:</b> {date_str}", body_style))
    story.append(Paragraph("<b>Type of assessment:</b> URL Risk Assessment", body_style))
    story.append(Spacer(1, 10))

    if app_name or can_id or server_ip or request_id:
        story.append(Paragraph("Application Details:", heading_style))
        app_rows = [["Detail", "Value"]]
        if app_name: app_rows.append(["App Name", app_name])
        if can_id: app_rows.append(["Can ID", can_id])
        if server_ip: app_rows.append(["Server IP", server_ip])
        if request_id: app_rows.append(["Request Id", request_id])
        story.append(_make_kv_table(app_rows))
        story.append(Spacer(1, 15))

    story.append(Paragraph("Risk performed of what all URL:", heading_style))
    summary_header_style = ParagraphStyle(
        "SumHead", parent=styles["Normal"], fontSize=10, leading=12,
        fontName="Helvetica-Bold", textColor=colors.white
    )
    summary_cell_style = ParagraphStyle(
        "SumCell", parent=styles["Normal"], fontSize=10, leading=12,
        textColor=colors.HexColor("#1D4ED8"), wordWrap="CJK"
    )
    summary_data = [[Paragraph(h, summary_header_style) for h in ["SR. No.", "URL", "Final Risk Level"]]]
    for idx, res in enumerate(results, 1):
        risk_level = res.get("final_risk_level", "Unknown")

        summary_data.append([
            str(idx),
            Paragraph(_esc(res.get("url", "")), summary_cell_style),
            risk_level
        ])
    story.append(_make_summary_table(summary_data))

    # ── DETAILED RESULTS ───────────────────────────────────────────────────
    for idx, res in enumerate(results, 1):
        story.append(PageBreak())

        url = res.get("url", "")
        data_block = res.get("data", {})
        vt = data_block.get("virustotal", {})
        abuseipdb = data_block.get("abuseipdb", {})
        sslyze = data_block.get("sslyze", {})

        # URL Header
        story.append(Paragraph(f"<b>{idx} — {_esc(_trunc(url, 65))}</b>", heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=WW_TEAL, spaceAfter=10))

        # Generate Evidence
        try:
            evidence = generate_evidence_screenshots(url, res)
        except Exception:
            evidence = {}

        risk_sources = res.get("risk_sources", {})
        final_level = res.get("final_risk_level", "Unknown")
        remarks = res.get("risk_remarks", "")

        def _src_level(name):
            s = risk_sources.get(name, {})
            level = s.get("level")
            detail = _trunc(s.get("detail", ""), 150)
            if level:
                return f"{level} ({detail})" if detail else level
            return f"Not usable — {detail}" if detail else "Not usable"

        story.append(_make_kv_table([
            ["Metric", "Value"],
            ["Final Risk Level", final_level],
            ["Basis", _trunc(remarks, 300) if remarks else "—"],
        ]))
        story.append(Spacer(1, 8))

        # ── VirusTotal ────────────────────────────────────────────────────
        vt_block = [Paragraph("VirusTotal Multi-Engine Analysis", subheading_style)]
        if "virustotal" in evidence:
            vt_block.append(_make_rl_image(BytesIO(evidence["virustotal"]), target_width_mm=160))
            vt_block.append(Spacer(1, 10))

        vt_rows = [
            ["Metric", "Value"],
            ["Risk Level", _src_level("VirusTotal")],
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

        # ── AbuseIPDB ─────────────────────────────────────────────────────
        if abuseipdb and "error" not in abuseipdb:
            ab_block = [Paragraph("AbuseIPDB Reputation Check", subheading_style)]
            if "abuseipdb" in evidence:
                ab_block.append(_make_rl_image(BytesIO(evidence["abuseipdb"]), target_width_mm=160))
                ab_block.append(Spacer(1, 10))
            ab_rows = [
                ["Metric", "Value"],
                ["Risk Level", _src_level("AbuseIPDB")],
                ["Abuse Confidence", f"{abuseipdb.get('abuseConfidenceScore', 0)}%"],
                ["Total Reports", str(abuseipdb.get("totalReports", 0))],
                ["Usage Type", str(abuseipdb.get("usageType", "Unknown"))],
                ["ISP", str(abuseipdb.get("isp", "—"))],
                ["Country", str(abuseipdb.get("countryCode", "—"))],
            ]
            ab_block.append(_make_kv_table(ab_rows))
            story.append(KeepTogether(ab_block))

        # ── SSLyze ────────────────────────────────────────────────────────
        if sslyze:
            ssl_block = [Paragraph("SSLyze — TLS/SSL Protocol Analysis", subheading_style)]
            if sslyze.get("error"):
                ssl_block.append(_make_kv_table([
                    ["Metric", "Value"],
                    ["Risk Level", _src_level("SSLyze")],
                    ["Error", sslyze["error"]],
                ]))
            else:
                protocols = sslyze.get("protocols", [])
                ssl_block.append(_make_kv_table([
                    ["Metric", "Value"],
                    ["Risk Level", _src_level("SSLyze")],
                    ["Host", sslyze.get("host", "—")],
                    ["Port", str(sslyze.get("port", 443))],
                    ["Accepted Protocols", ", ".join(f"{p.get('name')} {p.get('version')}" for p in protocols) or "None detected"],
                ]))
            story.append(KeepTogether(ssl_block))

        # ── WHOIS ─────────────────────────────────────────────────────────
        # Only shown when WHOIS actually returned a usable domain age —
        # failed/unknown lookups (and bare-IP skips) are left out of the
        # report entirely rather than shown as an error row.
        whois_info = data_block.get("whois", {})
        if risk_sources.get("WHOIS", {}).get("usable"):
            whois_block = [
                Paragraph("WHOIS — Domain Age", subheading_style),
                _make_kv_table([
                    ["Metric", "Value"],
                    ["Risk Level", _src_level("WHOIS")],
                    ["Domain Age", f"{whois_info.get('age_days')} days"],
                ]),
            ]
            story.append(KeepTogether(whois_block))

    # ── LAST PAGE: COMMENTS ────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Assessment Comments", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=WW_TEAL, spaceAfter=15))

    story.append(Paragraph("Consolidated Risk Overview", subheading_style))
    cons_head_style = ParagraphStyle("ConsHead", parent=styles["Normal"], fontSize=7, leading=9,
                                      fontName="Helvetica-Bold", textColor=colors.white)
    cons_url_style = ParagraphStyle("ConsUrl", parent=styles["Normal"], fontSize=7, leading=9, wordWrap="CJK")
    cons_cell_style = ParagraphStyle("ConsCell", parent=styles["Normal"], fontSize=7, leading=9)

    consolidated_data = [[Paragraph(h, cons_head_style) for h in ["URL", "Final Risk Level", "Per-Source Risk Level"]]]
    for res in results:
        url = res.get("url", "")
        final_level = res.get("final_risk_level", "Unknown")
        rs = res.get("risk_sources", {})
        per_source = ", ".join(
            f"{name}: {s.get('level') or 'N/A'}" for name, s in rs.items()
        ) if rs else "None"

        consolidated_data.append([
            Paragraph(_esc(url), cons_url_style),
            Paragraph(_esc(final_level), cons_cell_style),
            Paragraph(_esc(per_source), cons_cell_style),
        ])

    if len(consolidated_data) > 1:
        cons_table = Table(consolidated_data, colWidths=[130, 80, 260], hAlign="LEFT", repeatRows=1)
        cons_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C3E73")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d7de")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(cons_table)
        story.append(Spacer(1, 15))

    story.append(Paragraph("Final Assessment Comment:", subheading_style))
    story.append(Paragraph(_esc(_risk_assessment_summary(results)), body_style))
    if final_comment.strip():
        story.append(Paragraph(_esc(final_comment), body_style))

    # ── LAST PAGE: RISK SCORING METHODOLOGY ─────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Risk Scoring Methodology", heading_style))
    story.append(Paragraph(
        "Each source below is independently classified as No Risk, Low, Medium or High. "
        "The Final Risk Level for a URL is the single worst (highest-severity) result among "
        "every source that returned a usable value for it. \"Unknown\" is shown only when none "
        "of the four sources returned a usable result (e.g. every lookup errored or the target "
        "could not be reached). Google Safe Browsing and URLScan.io results are still collected "
        "as supporting evidence but are not part of this risk calculation.",
        body_style
    ))

    scoring_data = [
        ["VirusTotal", "0 malicious engines", "No Risk"],
        ["", "1-2 malicious engines", "Low"],
        ["", "3-5 malicious engines", "Medium"],
        ["", "6+ malicious engines", "High"],
        ["AbuseIPDB", "Abuse Confidence Score = 0", "No Risk"],
        ["", "Abuse Confidence Score 1-24", "Low"],
        ["", "Abuse Confidence Score 25-74", "Medium"],
        ["", "Abuse Confidence Score 75-100", "High"],
        ["SSLyze (weakest TLS/SSL\naccepted on port 443)", "Weakest = TLS 1.2 or TLS 1.3", "No Risk"],
        ["", "Weakest = SSL 2.0 / SSL 3.0 / TLS 1.0 / TLS 1.1", "Medium"],
        ["WHOIS (domain age)", "Age >= 30 days", "No Risk"],
        ["", "Age < 30 days", "Low"],
        ["", "Bare-IP input", "Skipped (not scored)"],
    ]

    story.append(_make_wrapped_table(["Source", "Condition", "Risk Level"], scoring_data, [140, 220, 80]))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return pdf_buffer.getvalue()
