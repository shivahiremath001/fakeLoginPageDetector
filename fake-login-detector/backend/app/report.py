"""
report.py — JSON and PDF report generation.

Generates a formatted forensic PDF report containing:
  - Header with verdict, risk score, scan id, and timestamp
  - Executive summary and brand identification
  - Detected evidence reasons table with severity levels
  - Signal contributions breakdown table
  - Form action comparison
  - Screenshot evidence (suspect, genuine, and diff heatmap)
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    Image as RLImage,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models import ScanResult

logger = logging.getLogger(__name__)


def _format_time(iso_str: Optional[str]) -> str:
    if not iso_str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(iso_str)


def _safe_image(path_str: Optional[str], width: float = 240, height: float = 140) -> Optional[RLImage]:
    if not path_str:
        return None
    try:
        p = Path(path_str)
        if p.is_file():
            return RLImage(str(p), width=width, height=height)
    except Exception:
        pass
    return None


async def generate_pdf(result: ScanResult, output_path: str) -> bool:
    """
    Generate a forensic PDF report from a ScanResult.

    Inputs:  result — completed ScanResult model
             output_path — absolute file path to write PDF
    Outputs: True if successfully generated, False on error
    """
    try:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            str(out_file),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
        )

        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748b"),
        )

        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#1e293b"),
            fontName="Helvetica-Bold",
            spaceBefore=10,
            spaceAfter=4,
        )

        body_style = ParagraphStyle(
            "ReportBody",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
        )

        verdict_val = result.verdict.value.upper().replace("_", " ")
        is_clone = result.verdict.value in ("likely_clone", "suspicious")
        verdict_color = colors.HexColor("#ef4444") if is_clone else colors.HexColor("#22c55e")

        elements = []

        # Header Title
        elements.append(Paragraph("Fake Login Page Detector — Forensic Report", title_style))
        elements.append(
            Paragraph(
                f"Scan ID: {result.scan_id} &nbsp;|&nbsp; Generated: {_format_time(result.created_at)}",
                subtitle_style,
            )
        )
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=12))

        # Key Metrics Matrix Table
        meta_data = [
            [
                Paragraph("<b>Target URL:</b>", body_style),
                Paragraph(f"<code>{result.suspect_url}</code>", body_style),
                Paragraph("<b>Verdict:</b>", body_style),
                Paragraph(f"<b><font color='{verdict_color.hexval()}'>{verdict_val}</font></b>", body_style),
            ],
            [
                Paragraph("<b>Targeted Brand:</b>", body_style),
                Paragraph(result.brand or "Unknown / Unrelated", body_style),
                Paragraph("<b>Risk Score:</b>", body_style),
                Paragraph(f"<b>{result.score} / 100</b>", body_style),
            ],
            [
                Paragraph("<b>Duration:</b>", body_style),
                Paragraph(f"{result.duration_ms} ms", body_style),
                Paragraph("<b>Genuine Reference:</b>", body_style),
                Paragraph(result.genuine_url or "None provided", body_style),
            ],
        ]
        meta_table = Table(meta_data, colWidths=[90, 220, 90, 140])
        meta_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ])
        )
        elements.append(meta_table)
        elements.append(Spacer(1, 12))

        # Executive Summary
        if result.summary:
            elements.append(Paragraph("Executive Summary", h2_style))
            elements.append(Paragraph(result.summary, body_style))
            elements.append(Spacer(1, 10))

        # Detected Evidence Reasons Table
        elements.append(Paragraph("Detected Evidence &amp; Reasons", h2_style))
        if result.reasons:
            reasons_data = [
                [
                    Paragraph("<b>Severity</b>", body_style),
                    Paragraph("<b>Reason Title</b>", body_style),
                    Paragraph("<b>Technical Detail</b>", body_style),
                ]
            ]
            for r in result.reasons[:8]:
                sev = getattr(r.severity, "value", str(r.severity)).upper()
                sev_color = colors.HexColor("#ef4444") if sev in ("CRITICAL", "HIGH") else colors.HexColor("#64748b")
                reasons_data.append([
                    Paragraph(f"<b><font color='{sev_color.hexval()}'>{sev}</font></b>", body_style),
                    Paragraph(r.title, body_style),
                    Paragraph(r.detail, body_style),
                ])

            r_table = Table(reasons_data, colWidths=[70, 170, 300])
            r_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ])
            )
            elements.append(r_table)
        else:
            elements.append(Paragraph("No anomalous signals or phishing indicators detected.", body_style))
        elements.append(Spacer(1, 12))

        # Form Comparison
        if result.form_comparison:
            elements.append(Paragraph("Form Action Comparison", h2_style))
            fc = result.form_comparison
            fc_data = [
                [
                    Paragraph("<b>Property</b>", body_style),
                    Paragraph("<b>Genuine Form</b>", body_style),
                    Paragraph("<b>Suspect Form</b>", body_style),
                ],
                [
                    Paragraph("Submission Action", body_style),
                    Paragraph(fc.genuine_action or "None", body_style),
                    Paragraph(fc.suspect_action or "None", body_style),
                ],
                [
                    Paragraph("Target Host", body_style),
                    Paragraph("Original Origin", body_style),
                    Paragraph(fc.action_host or "Same Host", body_style),
                ],
                [
                    Paragraph("Cross-Origin Post", body_style),
                    Paragraph("No", body_style),
                    Paragraph("<b>YES (External)</b>" if fc.is_cross_origin else "No", body_style),
                ],
            ]
            fc_table = Table(fc_data, colWidths=[120, 210, 210])
            fc_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ])
            )
            elements.append(fc_table)
            elements.append(Spacer(1, 12))

        # Visual Evidence Screenshots (if files exist on disk)
        imgs = result.images or {}
        img_cells = []

        if "suspect" in imgs:
            img_obj = _safe_image(imgs["suspect"], width=240, height=135)
            if img_obj:
                img_cells.append([Paragraph("<b>Suspect Page Screenshot</b>", body_style), img_obj])

        if "diff" in imgs:
            diff_obj = _safe_image(imgs["diff"], width=240, height=135)
            if diff_obj:
                img_cells.append([Paragraph("<b>Visual Difference Heatmap</b>", body_style), diff_obj])

        if img_cells:
            elements.append(Paragraph("Visual Evidence", h2_style))
            v_table = Table(
                [[cell[0] for cell in img_cells], [cell[1] for cell in img_cells]],
                colWidths=[270] * len(img_cells),
            )
            v_table.setStyle(
                TableStyle([
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ])
            )
            elements.append(KeepTogether([v_table]))

        doc.build(elements)
        logger.info("Generated PDF report at %s", output_path)
        return True

    except Exception as exc:
        logger.error("Failed to generate PDF report: %s", exc, exc_info=True)
        return False
