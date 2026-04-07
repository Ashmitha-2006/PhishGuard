from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import os

def generate_pdf_report(url, result):
    """Generate a professional PDF security report."""

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url = url.replace("://", "_").replace("/", "_").replace(".", "_")[:30]
    filename = f"PhishGuard_Report_{safe_url}_{timestamp}.pdf"
    filepath = os.path.join("reports", filename)
    os.makedirs("reports", exist_ok=True)

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )

    elements = []

    # Colors
    cyan        = colors.HexColor('#00d4ff')
    dark_bg     = colors.HexColor('#1a1d2e')
    danger_red  = colors.HexColor('#cc0000')
    warning_org = colors.HexColor('#e67e00')
    safe_green  = colors.HexColor('#007a29')
    dark_gray   = colors.HexColor('#2c2c2c')
    mid_gray    = colors.HexColor('#666666')
    light_gray  = colors.HexColor('#f5f5f5')
    white       = colors.white
    border_gray = colors.HexColor('#dddddd')

    verdict_color_map = {
        "green":  safe_green,
        "orange": warning_org,
        "red":    danger_red
    }
    verdict_col = verdict_color_map.get(result["verdict_color"], safe_green)

    def score_color(score):
        if score <= 30: return safe_green
        elif score <= 60: return warning_org
        return danger_red

    # ── HEADER ──────────────────────────────────────────────
    header_data = [[
        Paragraph(
            '<font size="22" color="#00d4ff"><b>PHISHGUARD</b></font><br/>'
            '<font size="10" color="#888888">Phishing Detection Security Report</font>',
            ParagraphStyle('h', fontName='Helvetica')
        ),
        Paragraph(
            f'<font size="9" color="#888888">Report Date<br/>'
            f'{datetime.now().strftime("%B %d, %Y")}<br/>'
            f'{datetime.now().strftime("%H:%M:%S UTC")}</font>',
            ParagraphStyle('hr', fontName='Helvetica', alignment=TA_RIGHT)
        )
    ]]

    header_table = Table(header_data, colWidths=[10*cm, 7*cm])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
    ]))
    elements.append(header_table)
    elements.append(HRFlowable(width="100%", thickness=2, color=cyan, spaceAfter=16))

    # ── EXECUTIVE SUMMARY BOX ───────────────────────────────
    summary_label = ParagraphStyle(
        'sl', fontName='Helvetica-Bold', fontSize=9,
        textColor=colors.HexColor('#888888'), spaceAfter=4
    )
    elements.append(Paragraph("EXECUTIVE SUMMARY", summary_label))

    verdict_bg = {
        "green":  colors.HexColor('#e6f9ed'),
        "orange": colors.HexColor('#fff4e0'),
        "red":    colors.HexColor('#fce8e8')
    }.get(result["verdict_color"], colors.HexColor('#e6f9ed'))

    summary_data = [[
        Paragraph(
            f'<font size="28" color="{verdict_col.hexval()}"><b>{result["verdict"]}</b></font>',
            ParagraphStyle('vs', fontName='Helvetica', alignment=TA_CENTER)
        ),
        Paragraph(
            f'<font size="28" color="{verdict_col.hexval()}"><b>{result["final_score"]}</b></font>'
            f'<font size="14" color="#888888">/100</font><br/>'
            f'<font size="9" color="#888888">RISK SCORE</font>',
            ParagraphStyle('rs', fontName='Helvetica', alignment=TA_CENTER)
        ),
        Paragraph(
            f'<font size="28" color="#2c2c2c"><b>{result["total_flags"]}</b></font><br/>'
            f'<font size="9" color="#888888">TOTAL FLAGS</font>',
            ParagraphStyle('tf', fontName='Helvetica', alignment=TA_CENTER)
        ),
    ]]

    summary_table = Table(summary_data, colWidths=[6*cm, 5*cm, 6*cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), verdict_bg),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 16),
        ('BOTTOMPADDING', (0,0), (-1,-1), 16),
        ('ROUNDEDCORNERS', [8,8,8,8]),
        ('BOX', (0,0), (-1,-1), 1, border_gray),
        ('LINEAFTER', (0,0), (1,-1), 0.5, border_gray),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 8))

    # Summary text
    sum_style = ParagraphStyle(
        'sum', fontName='Helvetica', fontSize=10,
        textColor=dark_gray, leading=15, spaceAfter=4
    )
    rec_style = ParagraphStyle(
        'rec', fontName='Helvetica-Bold', fontSize=10,
        textColor=verdict_col, leading=15, spaceAfter=16
    )
    elements.append(Paragraph(result["summary"], sum_style))
    elements.append(Paragraph(f"Recommendation: {result['recommendation']}", rec_style))

    # ── SCANNED URL ─────────────────────────────────────────
    elements.append(Paragraph("SCANNED URL", summary_label))
    url_data = [[Paragraph(
        f'<font size="10" color="#2c2c2c">{url}</font>',
        ParagraphStyle('url', fontName='Helvetica-Oblique')
    )]]
    url_table = Table(url_data, colWidths=[17*cm])
    url_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), light_gray),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('BOX', (0,0), (-1,-1), 0.5, border_gray),
        ('LINEBEFORE', (0,0), (0,-1), 3, cyan),
    ]))
    elements.append(url_table)
    elements.append(Spacer(1, 16))

    # ── ENGINE BREAKDOWN ────────────────────────────────────
    elements.append(HRFlowable(width="100%", thickness=0.5, color=border_gray, spaceAfter=8))
    elements.append(Paragraph("ENGINE BREAKDOWN", summary_label))

    engine_header = [
        Paragraph('<font size="9" color="#ffffff"><b>Engine</b></font>',
                  ParagraphStyle('eh', fontName='Helvetica-Bold', alignment=TA_LEFT)),
        Paragraph('<font size="9" color="#ffffff"><b>Score</b></font>',
                  ParagraphStyle('eh2', fontName='Helvetica-Bold', alignment=TA_CENTER)),
        Paragraph('<font size="9" color="#ffffff"><b>Risk Level</b></font>',
                  ParagraphStyle('eh3', fontName='Helvetica-Bold', alignment=TA_CENTER)),
        Paragraph('<font size="9" color="#ffffff"><b>Weight</b></font>',
                  ParagraphStyle('eh4', fontName='Helvetica-Bold', alignment=TA_CENTER)),
    ]

    engines = [
        ("URL Analyser",   result['engine_scores']['url_score'],   "35%"),
        ("Brand Checker",  result['engine_scores']['brand_score'], "25%"),
        ("Page Analyser",  result['engine_scores']['page_score'],  "20%"),
        ("ML Scorer",      result['engine_scores']['ml_score'],    "20%"),
    ]

    def risk_label(score):
        if score <= 30: return "LOW RISK"
        elif score <= 60: return "MEDIUM RISK"
        return "HIGH RISK"

    engine_rows = [engine_header]
    for name, score, weight in engines:
        sc = score_color(score)
        engine_rows.append([
            Paragraph(f'<font size="10" color="#2c2c2c"><b>{name}</b></font>',
                      ParagraphStyle('en', fontName='Helvetica-Bold')),
            Paragraph(f'<font size="12" color="{sc.hexval()}"><b>{score}/100</b></font>',
                      ParagraphStyle('es', fontName='Helvetica-Bold', alignment=TA_CENTER)),
            Paragraph(f'<font size="9" color="{sc.hexval()}">{risk_label(score)}</font>',
                      ParagraphStyle('el', fontName='Helvetica', alignment=TA_CENTER)),
            Paragraph(f'<font size="9" color="#888888">{weight}</font>',
                      ParagraphStyle('ew', fontName='Helvetica', alignment=TA_CENTER)),
        ])

    engine_table = Table(engine_rows, colWidths=[6*cm, 4*cm, 4.5*cm, 2.5*cm])
    engine_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), dark_bg),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [white, light_gray]),
        ('ALIGN', (1,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('BOX', (0,0), (-1,-1), 0.5, border_gray),
        ('INNERGRID', (0,0), (-1,-1), 0.3, border_gray),
    ]))
    elements.append(engine_table)
    elements.append(Spacer(1, 16))

    # ── DETAILED FINDINGS ───────────────────────────────────
    elements.append(HRFlowable(width="100%", thickness=0.5, color=border_gray, spaceAfter=8))
    elements.append(Paragraph("DETAILED FINDINGS", summary_label))

    # Stats row
    stats_data = [[
        Paragraph(f'<font size="20" color="#cc0000"><b>{result["high_count"]}</b></font><br/>'
                  f'<font size="8" color="#888888">HIGH RISK</font>',
                  ParagraphStyle('st', fontName='Helvetica', alignment=TA_CENTER)),
        Paragraph(f'<font size="20" color="#e67e00"><b>{result["medium_count"]}</b></font><br/>'
                  f'<font size="8" color="#888888">MEDIUM RISK</font>',
                  ParagraphStyle('st2', fontName='Helvetica', alignment=TA_CENTER)),
        Paragraph(f'<font size="20" color="#007a29"><b>{result["low_count"]}</b></font><br/>'
                  f'<font size="8" color="#888888">LOW RISK</font>',
                  ParagraphStyle('st3', fontName='Helvetica', alignment=TA_CENTER)),
        Paragraph(f'<font size="20" color="#00d4ff"><b>{result["total_flags"]}</b></font><br/>'
                  f'<font size="8" color="#888888">TOTAL FLAGS</font>',
                  ParagraphStyle('st4', fontName='Helvetica', alignment=TA_CENTER)),
    ]]

    stats_table = Table(stats_data, colWidths=[4.25*cm, 4.25*cm, 4.25*cm, 4.25*cm])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), light_gray),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('BOX', (0,0), (-1,-1), 0.5, border_gray),
        ('LINEAFTER', (0,0), (2,-1), 0.3, border_gray),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 12))

    # Individual findings
    sev_colors = {
        "High":   danger_red,
        "Medium": warning_org,
        "Low":    colors.HexColor('#cc9900'),
        "Info":   colors.HexColor('#3366cc')
    }
    sev_bg = {
        "High":   colors.HexColor('#fff0f0'),
        "Medium": colors.HexColor('#fff8ee'),
        "Low":    colors.HexColor('#fffff0'),
        "Info":   colors.HexColor('#f0f4ff')
    }

    real_findings = [f for f in result["all_findings"] if f["severity"] != "Info"]

    if real_findings:
        for i, finding in enumerate(real_findings):
            sc = sev_colors.get(finding["severity"], mid_gray)
            bg = sev_bg.get(finding["severity"], light_gray)

            finding_data = [[
                Paragraph(
                    f'<font size="10" color="#2c2c2c"><b>{finding["check"]}</b></font>',
                    ParagraphStyle('fc', fontName='Helvetica-Bold')
                ),
                Paragraph(
                    f'<font size="9" color="{sc.hexval()}"><b>{finding["severity"].upper()}</b></font>',
                    ParagraphStyle('fb', fontName='Helvetica-Bold', alignment=TA_CENTER)
                ),
            ],[
                Paragraph(
                    f'<font size="9" color="#555555">{finding["explanation"]}</font>',
                    ParagraphStyle('fe', fontName='Helvetica', leading=13)
                ),
                Paragraph(
                    f'<font size="8" color="#888888">{finding["engine"]}</font>',
                    ParagraphStyle('fen', fontName='Helvetica-Oblique', alignment=TA_CENTER)
                ),
            ]]

            ft = Table(finding_data, colWidths=[13*cm, 4*cm])
            ft.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), bg),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TOPPADDING', (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ('LEFTPADDING', (0,0), (-1,-1), 10),
                ('RIGHTPADDING', (0,0), (-1,-1), 10),
                ('BOX', (0,0), (-1,-1), 0.5, border_gray),
                ('LINEBEFORE', (0,0), (0,-1), 3, sc),
                ('LINEBELOW', (0,0), (-1,0), 0.3, border_gray),
            ]))
            elements.append(ft)
            elements.append(Spacer(1, 6))
    else:
        elements.append(Paragraph(
            "No significant security findings detected.",
            ParagraphStyle('nf', fontName='Helvetica', fontSize=10, textColor=mid_gray)
        ))

    # ── FOOTER ──────────────────────────────────────────────
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=border_gray, spaceAfter=8))

    footer_data = [[
        Paragraph(
            '<font size="8" color="#888888">Generated by PhishGuard Security Tool</font>',
            ParagraphStyle('fl', fontName='Helvetica')
        ),
        Paragraph(
            '<font size="8" color="#888888">CONFIDENTIAL — For authorized use only</font>',
            ParagraphStyle('fr', fontName='Helvetica', alignment=TA_RIGHT)
        ),
    ]]
    footer_table = Table(footer_data, colWidths=[8.5*cm, 8.5*cm])
    footer_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    elements.append(footer_table)
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        '<font size="7" color="#aaaaaa">This report was automatically generated and should be reviewed by a qualified security professional. '
        'PhishGuard is for educational and security research purposes only.</font>',
        ParagraphStyle('disc', fontName='Helvetica', alignment=TA_CENTER)
    ))

    doc.build(elements)
    return filename, filepath