"""Render a F0undM3 Markdown writeup as a compact A4 two-column PDF."""
from __future__ import annotations

import argparse
import html
import re
import textwrap
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    FrameBreak,
    Image,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
    XPreformatted,
)

# A standalone `![caption](path.png)` line becomes a numbered figure.  Screenshots
# are required evidence in the F0undM3 standard, so a missing file is reported in
# the rendered page rather than silently dropped or allowed to abort the render.
IMAGE_LINE = re.compile(r"^!\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)\s*$")

# Two-column A4: a figure may not exceed the column width, and is capped in height
# so one tall screenshot cannot orphan a whole column.
FIGURE_MAX_WIDTH = 74 * mm
FIGURE_MAX_HEIGHT = 95 * mm


def figure_from_markdown(alt: str, source: str, base_dir: Path, number: int,
                         caption_style: ParagraphStyle) -> list:
    """Build a scaled, captioned figure flowable from a Markdown image line."""
    path = Path(source)
    if not path.is_absolute():
        path = (base_dir / source).resolve()
    caption = f"Figure {number}. {alt}" if alt else f"Figure {number}."
    if not path.is_file():
        return [Paragraph(inline(f"[missing figure: `{source}`]"), caption_style)]
    try:
        width, height = ImageReader(str(path)).getSize()
    except Exception as error:  # unreadable or unsupported image
        return [Paragraph(inline(f"[unreadable figure `{source}`: {error}]"), caption_style)]
    if width <= 0 or height <= 0:
        return [Paragraph(inline(f"[empty figure: `{source}`]"), caption_style)]
    scale = min(FIGURE_MAX_WIDTH / width, FIGURE_MAX_HEIGHT / height)
    figure = Image(str(path), width=width * scale, height=height * scale)
    figure.hAlign = "CENTER"
    return [
        figure,
        Spacer(1, 1.5 * mm),
        Paragraph(inline(caption), caption_style),
        Spacer(1, 3 * mm),
    ]


def inline(markdown: str) -> str:
    # The core PDF fonts used here deliberately favour portability.  Normalize
    # a few common Unicode symbols that those fonts do not consistently cover.
    markdown = (markdown.replace("—", "-").replace("–", "-")
                         .replace("→", "->").replace("≤", "<=")
                         .replace("≥", ">=").replace("∅", "empty"))
    text = html.escape(markdown.strip())
    text = re.sub(r"`([^`]+)`", r'<font name="Courier">\1</font>', text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    return text


def parse_metadata(lines: list[str]) -> tuple[dict[str, str], int]:
    metadata: dict[str, str] = {}
    index = 0
    while index < len(lines):
        line = lines[index].strip()
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) == 2 and not all(set(cell) <= {"-", ":"} for cell in cells):
            metadata[cells[0]] = cells[1]
        index += 1
    return metadata, index


def table_from_lines(lines: list[str], width: float) -> Table:
    rows: list[list[str]] = []
    cell_style = ParagraphStyle("table-cell", fontName="Times-Roman", fontSize=7.1, leading=8.5, alignment=TA_LEFT)
    header_style = ParagraphStyle("table-header", fontName="Times-Bold", fontSize=7.1, leading=8.5, alignment=TA_LEFT)
    for line in lines:
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if all(set(cell) <= {"-", ":"} for cell in cells):
            continue
        style = header_style if not rows else cell_style
        rows.append([Paragraph(inline(cell), style) for cell in cells])
    table = Table(rows, colWidths=[width / max(1, len(rows[0]))] * len(rows[0]), repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, 0), "Times-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Times-Roman"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.4),
                ("LEADING", (0, 0), (-1, -1), 9.2),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDEDED")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#AFAFAF")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table


def wrapped_code_lines(text: str, width: int = 56) -> list[str]:
    """Wrap display-only code lines to the narrow academic columns."""
    rendered: list[str] = []
    for line in text.splitlines() or [""]:
        rendered.extend(
            textwrap.wrap(
                line,
                width=width,
                subsequent_indent="  ",
                replace_whitespace=False,
                drop_whitespace=False,
                break_long_words=True,
                break_on_hyphens=False,
            )
            or [""]
        )
    return rendered


CODE_KEYWORDS = {
    "and", "as", "assert", "break", "case", "class", "const", "continue", "def", "elif",
    "else", "false", "finally", "for", "from", "func", "function", "if", "import", "in",
    "let", "match", "new", "nil", "none", "not", "null", "or", "package", "pass", "public",
    "return", "static", "struct", "switch", "then", "true", "try", "type", "var", "while",
}


def highlight_code_line(line: str, language: str) -> str:
    """Apply a restrained, portable syntax palette to an escaped code line."""
    values: list[str] = []

    def hold(value: str, colour: str) -> str:
        marker = f"\x00T{chr(65 + len(values))}\x01"
        values.append(f'<font color="{colour}">{html.escape(value)}</font>')
        return marker

    # Store quoted values first, then comments, so a comment character inside a
    # string cannot turn the rest of the line green.
    escaped = re.sub(r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')', lambda match: hold(match.group(0), "#7B3F98"), line)
    escaped = re.sub(r'(^\s*(?:#|//).*$|\s+#.*$)', lambda match: hold(match.group(0), "#5C7A4D"), escaped)
    escaped = html.escape(escaped)
    escaped = re.sub(r'\b(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?)\b', r'<font color="#A33A3A">\g<0></font>', escaped)
    escaped = re.sub(
        r'\b[A-Za-z_][A-Za-z0-9_]*\b',
        lambda match: f'<font color="#1B5E8A">{match.group(0)}</font>' if match.group(0).lower() in CODE_KEYWORDS else match.group(0),
        escaped,
    )
    for index, value in enumerate(values):
        escaped = escaped.replace(f"\x00T{chr(65 + index)}\x01", value)
    return escaped


def highlighted_code(text: str, language: str) -> str:
    return "\n".join(highlight_code_line(line, language) for line in wrapped_code_lines(text))


class AcademicDoc(BaseDocTemplate):
    def __init__(self, filename: str):
        width, height = A4
        margin = 18 * mm
        gap = 7 * mm
        header_height = 76 * mm
        body_top = height - margin - header_height - 5 * mm
        column_width = (width - 2 * margin - gap) / 2
        first = [
            Frame(margin, body_top, width - 2 * margin, header_height, id="front", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0),
            Frame(margin, margin, column_width, body_top - margin - 4 * mm, id="left", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0),
            Frame(margin + column_width + gap, margin, column_width, body_top - margin - 4 * mm, id="right", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0),
        ]
        later = [
            Frame(margin, margin, column_width, height - 2 * margin, id="later-left", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0),
            Frame(margin + column_width + gap, margin, column_width, height - 2 * margin, id="later-right", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0),
        ]
        super().__init__(filename, pagesize=A4, leftMargin=margin, rightMargin=margin, topMargin=margin, bottomMargin=margin)
        self.addPageTemplates(
            [
                PageTemplate(id="first", frames=first, onPage=self.draw_page, autoNextPageTemplate="later"),
                PageTemplate(id="later", frames=later, onPage=self.draw_page),
            ]
        )

    @staticmethod
    def draw_page(canvas, doc):
        if doc.page == 1:
            canvas.setStrokeColor(colors.HexColor("#333333"))
            canvas.setLineWidth(0.55)
            canvas.line(18 * mm, A4[1] - 99 * mm, A4[0] - 18 * mm, A4[1] - 99 * mm)
        if doc.page > 1:
            canvas.setStrokeColor(colors.HexColor("#A0A0A0"))
            canvas.setLineWidth(0.3)
            canvas.line(18 * mm, A4[1] - 13 * mm, A4[0] - 18 * mm, A4[1] - 13 * mm)
        canvas.setFont("Times-Roman", 8)
        canvas.drawCentredString(A4[0] / 2, 10 * mm, str(doc.page))


def build(input_path: Path, output_path: Path) -> None:
    lines = input_path.read_text(encoding="utf-8").splitlines()
    title = next((line[2:].strip() for line in lines if line.startswith("# ")), input_path.stem)
    title_index = next(i for i, line in enumerate(lines) if line.startswith("# "))
    metadata_start = title_index + 1
    while metadata_start < len(lines) and not lines[metadata_start].strip():
        metadata_start += 1
    metadata, offset = parse_metadata(lines[metadata_start:])
    body = lines[metadata_start + offset :]

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("paper-title", parent=styles["Title"], fontName="Times-Bold", fontSize=22, leading=25, alignment=TA_LEFT, spaceAfter=5)
    author_style = ParagraphStyle("paper-author", parent=styles["Normal"], fontName="Times-Roman", fontSize=10.5, leading=13)
    abstract_style = ParagraphStyle("paper-abstract", parent=styles["Normal"], fontName="Times-Roman", fontSize=9.5, leading=12.4, alignment=TA_JUSTIFY, spaceAfter=5)
    body_style = ParagraphStyle("paper-body", parent=styles["Normal"], fontName="Times-Roman", fontSize=9.6, leading=12.7, alignment=TA_JUSTIFY, spaceAfter=5)
    h1 = ParagraphStyle("paper-h1", parent=styles["Heading1"], fontName="Times-Bold", fontSize=14.5, leading=17, spaceBefore=8, spaceAfter=4)
    h2 = ParagraphStyle("paper-h2", parent=styles["Heading2"], fontName="Times-Bold", fontSize=11.2, leading=13.5, spaceBefore=6, spaceAfter=3)
    code_style = ParagraphStyle("paper-code", fontName="Courier", fontSize=6.6, leading=8.2, leftIndent=4, rightIndent=4, borderColor=colors.HexColor("#BFBFBF"), borderWidth=0.35, borderPadding=5, backColor=colors.HexColor("#F3F3F3"))

    doc = AcademicDoc(str(output_path))
    story = [Paragraph(inline(title), title_style)]
    author = metadata.get("Author", "numpav")
    team = metadata.get("Team", "F0undM3")
    category = metadata.get("Category", "CTF")
    event = metadata.get("Event", "")
    date = metadata.get("Date", "")
    story.append(Paragraph(f"{inline(author)} - {inline(team)}", author_style))
    # `Event` is optional; joining unconditionally would emit a leading comma.
    venue = ", ".join(part for part in (event, category) if part)
    story.append(Paragraph(f"{inline(venue)}<br/>{inline(date)}", author_style))
    story.append(Spacer(1, 4))

    index = 0
    abstract_lines: list[str] = []
    while index < len(body):
        if body[index].strip() == "## Abstract":
            index += 1
            while index < len(body) and not body[index].startswith("## "):
                if body[index].strip():
                    abstract_lines.append(body[index].strip())
                index += 1
            break
        index += 1
    story.append(Paragraph(f"<b>Abstract:</b> {inline(' '.join(abstract_lines))}", abstract_style))
    keywords = ", ".join(filter(None, [event, category, "F0undM3", "CTF"]))
    story.append(Paragraph(f"<b>Keywords:</b> {inline(keywords)}", abstract_style))
    story.append(Spacer(1, 4))
    story.append(FrameBreak())

    index = 0
    paragraph: list[str] = []
    code: list[str] = []
    code_language = ""
    table: list[str] = []
    in_code = False
    figure_number = 0
    caption_style = ParagraphStyle(
        "figure-caption", parent=styles["BodyText"], fontName="Times-Italic",
        fontSize=6.8, leading=8.2, alignment=TA_CENTER, textColor=colors.HexColor("#444444"),
    )

    def flush_paragraph() -> None:
        if paragraph:
            story.append(Paragraph(inline(" ".join(part.strip() for part in paragraph)), body_style))
            paragraph.clear()

    while index < len(body):
        line = body[index]
        stripped = line.strip()
        if stripped == "## Abstract":
            index += 1
            while index < len(body) and not body[index].startswith("## "):
                index += 1
            continue
        if stripped.startswith("```"):
            flush_paragraph()
            if in_code:
                text = "\n".join(code)
                # A diagram block is rendered as its source rather than dropped.
                # Silently discarding it loses content the author wrote, and the
                # arrow notation still reads as a chain on the page.
                is_diagram = code_language in {"mermaid", "flowchart"} or (
                    code and code[0].startswith(("flowchart", "graph ", "sequenceDiagram"))
                )
                # Solver appendices can span hundreds of lines.  Compact,
                # independently flowable chunks prevent a two-column
                # layout failure while retaining the complete source.
                code_lines = highlighted_code(text, "" if is_diagram else code_language).splitlines()
                for offset in range(0, len(code_lines), 38):
                    story.append(XPreformatted("\n".join(code_lines[offset:offset + 38]), code_style))
                    story.append(Spacer(1, 2 * mm))
                code.clear()
                code_language = ""
            else:
                code_language = stripped[3:].strip().lower()
            in_code = not in_code
            index += 1
            continue
        if in_code:
            code.append(line)
            index += 1
            continue
        image_match = IMAGE_LINE.match(stripped)
        if image_match:
            flush_paragraph()
            figure_number += 1
            story.append(
                KeepTogether(
                    figure_from_markdown(
                        image_match.group(1), image_match.group(2),
                        input_path.parent, figure_number, caption_style,
                    )
                )
            )
            index += 1
            continue
        if stripped.startswith("|"):
            flush_paragraph()
            table = []
            while index < len(body) and body[index].strip().startswith("|"):
                table.append(body[index])
                index += 1
            story.append(KeepTogether([table_from_lines(table, 74 * mm), Spacer(1, 4)]))
            continue
        if stripped.startswith("## "):
            flush_paragraph()
            story.append(Paragraph(inline(stripped[3:]), h1))
        elif stripped.startswith("### "):
            flush_paragraph()
            story.append(Paragraph(inline(stripped[4:]), h2))
        elif stripped.startswith("#### "):
            # Deeper headings previously fell through to body text, printing the
            # literal hashes.  A detailed writeup nests, so render them.
            flush_paragraph()
            story.append(Paragraph(f"<b>{inline(stripped[5:])}</b>", body_style))
        elif not stripped:
            flush_paragraph()
        elif stripped.startswith("-"):
            flush_paragraph()
            story.append(Paragraph("- " + inline(stripped[1:].strip()), body_style))
        elif re.match(r"\d+\. ", stripped):
            flush_paragraph()
            story.append(Paragraph(inline(stripped), body_style))
        else:
            paragraph.append(stripped)
        index += 1
    flush_paragraph()
    doc.build(story)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    build(args.input, args.output)
