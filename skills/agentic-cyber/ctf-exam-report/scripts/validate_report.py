#!/usr/bin/env python3
"""Perform deterministic preflight checks on a Markdown CTF/exam report."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote


@dataclass(frozen=True)
class Finding:
    level: str
    message: str


REQUIRED_SECTION_GROUPS = {
    "executive summary": ("executive summary",),
    "scope": ("scope",),
    "rules/compliance": ("rules", "compliance"),
    "detailed walkthrough": ("walkthrough", "reproduction"),
    "evidence index": ("evidence index", "evidence register"),
    "command index": ("command index", "command register"),
}

PLACEHOLDER_PATTERNS = (
    (re.compile(r"\{\{[^}\n]+\}\}"), "unresolved double-brace placeholder"),
    (re.compile(r"(?im)\bTODO\b"), "TODO marker"),
    (re.compile(r"(?im)\bTBD\b"), "TBD marker"),
)

IMAGE_RE = re.compile(r"!\[(?P<alt>[^\]]*)\]\((?P<target>[^)]+)\)")
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\((?P<target>[^)]+)\)")
HEADING_RE = re.compile(r"(?m)^#{1,6}\s+(?P<title>.+?)\s*$")
FENCE_RE = re.compile(r"(?m)^\s*```(?P<lang>[^\s`]*)[^\n]*$")
HTML_COMMENT_RE = re.compile(r"<!--[\s\S]*?-->")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check a Markdown CTF/exam report for common submission defects."
    )
    parser.add_argument("report", type=Path, help="Path to the Markdown report")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return a non-zero status for warnings as well as errors",
    )
    parser.add_argument(
        "--require-images",
        action="store_true",
        help="Warn when the report has no screenshot/image references",
    )
    return parser.parse_args()


def normalize_link_target(raw_target: str) -> str:
    target = raw_target.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    if " " in target and not target.startswith(("http://", "https://")):
        # Markdown permits an optional title after a path. This deliberately handles
        # the common quoted-title form without pretending to be a full parser.
        target = re.split(r"\s+[\"']", target, maxsplit=1)[0]
    return unquote(target)


def is_external_or_anchor(target: str) -> bool:
    lowered = target.lower()
    return lowered.startswith(("http://", "https://", "mailto:", "data:")) or target.startswith("#")


def check_local_target(report_path: Path, raw_target: str) -> bool:
    target = normalize_link_target(raw_target)
    if is_external_or_anchor(target):
        return True
    target = target.split("#", 1)[0]
    if not target:
        return True
    linked = Path(target)
    if not linked.is_absolute():
        linked = report_path.parent / linked
    return linked.exists()


def fenced_blocks(text: str) -> tuple[list[tuple[str, str, int]], bool]:
    blocks: list[tuple[str, str, int]] = []
    current_lang: str | None = None
    current_start = 0
    current_lines: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = re.match(r"^\s*```([^\s`]*)[^\n]*$", line)
        if not match:
            if current_lang is not None:
                current_lines.append(line)
            continue
        if current_lang is None:
            current_lang = match.group(1).lower()
            current_start = line_number
            current_lines = []
        else:
            blocks.append((current_lang, "\n".join(current_lines), current_start))
            current_lang = None
            current_lines = []
    return blocks, current_lang is None


def section_body(text: str, required_terms: tuple[str, ...]) -> str:
    lines = text.splitlines()
    start: int | None = None
    level = 0
    for index, line in enumerate(lines):
        match = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if not match:
            continue
        title = match.group(2).lower()
        if start is None and any(term in title for term in required_terms):
            start = index + 1
            level = len(match.group(1))
            continue
        if start is not None and len(match.group(1)) <= level:
            return "\n".join(lines[start:index])
    if start is not None:
        return "\n".join(lines[start:])
    return ""


def first_column_id_counts(section: str, pattern: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    compiled = re.compile(pattern)
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if not cells:
            continue
        match = compiled.search(cells[0])
        if match:
            item_id = match.group(0)
            counts[item_id] = counts.get(item_id, 0) + 1
    return counts


def validate(report_path: Path, require_images: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = report_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [Finding("ERROR", f"report does not exist: {report_path}")]
    except UnicodeDecodeError:
        return [Finding("ERROR", "report is not valid UTF-8")]
    except OSError as exc:
        return [Finding("ERROR", f"could not read report: {exc}")]

    if not text.strip():
        return [Finding("ERROR", "report is empty")]

    headings = [m.group("title").strip().lower() for m in HEADING_RE.finditer(text)]
    if not headings:
        findings.append(Finding("ERROR", "no Markdown headings found"))

    for label, terms in REQUIRED_SECTION_GROUPS.items():
        if not any(any(term in heading for term in terms) for heading in headings):
            findings.append(Finding("WARNING", f"no recognizable {label} section"))

    for pattern, label in PLACEHOLDER_PATTERNS:
        matches = list(pattern.finditer(text))
        if matches:
            line = text.count("\n", 0, matches[0].start()) + 1
            findings.append(
                Finding("ERROR", f"{label}: {len(matches)} occurrence(s), first at line {line}")
            )

    comments = list(HTML_COMMENT_RE.finditer(text))
    if comments:
        findings.append(
            Finding("WARNING", f"HTML instructional/comment block(s) remain: {len(comments)}")
        )

    unchecked = re.findall(r"(?m)^\s*[-*]\s+\[ \]\s+", text)
    if unchecked:
        findings.append(Finding("WARNING", f"unchecked checklist item(s) remain: {len(unchecked)}"))

    gaps = set(re.findall(r"\bGAP-[A-Za-z0-9][A-Za-z0-9._-]*-\d{3}\b", text))
    if gaps:
        findings.append(Finding("WARNING", f"evidence gap ID(s) remain: {len(gaps)}"))

    blocks, fences_balanced = fenced_blocks(text)
    if not fences_balanced:
        findings.append(Finding("ERROR", "unbalanced triple-backtick code fence"))

    command_languages = {
        "bash",
        "sh",
        "shell",
        "zsh",
        "fish",
        "powershell",
        "pwsh",
        "cmd",
        "batch",
        "console",
    }
    prompt_patterns = (
        re.compile(r"(?m)^\s*\$\s+\S"),
        re.compile(r"(?mi)^\s*PS\s+[A-Z]:\\[^>]*>\s+\S"),
        re.compile(r"(?m)^\s*C:\\[^>]*>\s+\S", re.IGNORECASE),
    )
    for lang, body, start_line in blocks:
        if lang in command_languages and not body.strip():
            findings.append(Finding("ERROR", f"empty command block beginning at line {start_line}"))
        if lang in command_languages and any(pattern.search(body) for pattern in prompt_patterns):
            findings.append(
                Finding("WARNING", f"possible copied shell prompt in command block at line {start_line}")
            )

    images = list(IMAGE_RE.finditer(text))
    if require_images and not images:
        findings.append(Finding("WARNING", "no Markdown screenshot/image references found"))
    for match in images:
        alt = match.group("alt").strip()
        target = match.group("target")
        line = text.count("\n", 0, match.start()) + 1
        if not alt:
            findings.append(Finding("WARNING", f"image has empty alt text at line {line}"))
        if not check_local_target(report_path, target):
            findings.append(Finding("ERROR", f"broken local image link at line {line}: {target}"))

    for match in LINK_RE.finditer(text):
        target = match.group("target")
        line = text.count("\n", 0, match.start()) + 1
        if not check_local_target(report_path, target):
            findings.append(Finding("ERROR", f"broken local link at line {line}: {target}"))

    evidence_ids = set(re.findall(r"\bE-[A-Za-z0-9][A-Za-z0-9._-]*-\d{3}\b", text))
    command_ids = set(re.findall(r"\bCMD-[A-Za-z0-9][A-Za-z0-9._-]*-\d{3}\b", text))
    source_ids = set(re.findall(r"\bSRC-\d{3}\b", text))
    if not evidence_ids:
        findings.append(Finding("WARNING", "no canonical evidence IDs such as E-web01-001 found"))
    if not command_ids:
        findings.append(Finding("WARNING", "no canonical command IDs such as CMD-web01-001 found"))

    evidence_index = section_body(text, ("evidence index", "evidence register"))
    command_index = section_body(text, ("command index", "command register"))
    source_ledger = section_body(text, ("source ledger", "source index"))
    evidence_row_counts = first_column_id_counts(
        evidence_index, r"\bE-[A-Za-z0-9][A-Za-z0-9._-]*-\d{3}\b"
    )
    command_row_counts = first_column_id_counts(
        command_index, r"\bCMD-[A-Za-z0-9][A-Za-z0-9._-]*-\d{3}\b"
    )
    source_row_counts = first_column_id_counts(source_ledger, r"\bSRC-\d{3}\b")
    indexed_evidence_ids = set(evidence_row_counts)
    indexed_command_ids = set(command_row_counts)
    indexed_source_ids = set(source_row_counts)
    missing_evidence_rows = evidence_ids - indexed_evidence_ids
    missing_command_rows = command_ids - indexed_command_ids
    missing_source_rows = source_ids - indexed_source_ids
    if missing_evidence_rows:
        sample = ", ".join(sorted(missing_evidence_rows)[:5])
        findings.append(
            Finding("ERROR", f"evidence ID(s) missing from evidence index: {sample}")
        )
    if missing_command_rows:
        sample = ", ".join(sorted(missing_command_rows)[:5])
        findings.append(
            Finding("ERROR", f"command ID(s) missing from command index: {sample}")
        )
    if missing_source_rows:
        sample = ", ".join(sorted(missing_source_rows)[:5])
        findings.append(
            Finding("ERROR", f"source ID(s) missing from source ledger: {sample}")
        )

    duplicate_evidence_rows = sorted(
        item_id for item_id, count in evidence_row_counts.items() if count != 1
    )
    duplicate_command_rows = sorted(
        item_id for item_id, count in command_row_counts.items() if count != 1
    )
    duplicate_source_rows = sorted(
        item_id for item_id, count in source_row_counts.items() if count != 1
    )
    if duplicate_evidence_rows:
        findings.append(
            Finding(
                "ERROR",
                "evidence ID(s) have multiple canonical index rows: "
                + ", ".join(duplicate_evidence_rows[:5]),
            )
        )
    if duplicate_command_rows:
        findings.append(
            Finding(
                "ERROR",
                "command ID(s) have multiple canonical index rows: "
                + ", ".join(duplicate_command_rows[:5]),
            )
        )
    if duplicate_source_rows:
        findings.append(
            Finding(
                "ERROR",
                "source ID(s) have multiple canonical ledger rows: "
                + ", ".join(duplicate_source_rows[:5]),
            )
        )

    if re.search(r"(?im)^\s*(observation|observed result)\s*[:.]?\s*$", text):
        findings.append(Finding("WARNING", "an observation/result label appears to have no content"))

    return findings


def main() -> int:
    args = parse_args()
    report_path = args.report.expanduser().resolve()
    findings = validate(report_path, require_images=args.require_images)

    errors = [finding for finding in findings if finding.level == "ERROR"]
    warnings = [finding for finding in findings if finding.level == "WARNING"]

    print(f"Report: {report_path}")
    for finding in findings:
        print(f"{finding.level}: {finding.message}")
    print(f"Summary: {len(errors)} error(s), {len(warnings)} warning(s)")

    if errors or (args.strict and warnings):
        return 1
    print("PASS: deterministic preflight checks completed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
