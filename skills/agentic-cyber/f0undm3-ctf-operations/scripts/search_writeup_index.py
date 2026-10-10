"""Search the local public-writeup index by keyword, platform, or source.

The index holds metadata and URLs only.  Use this to find where a technique has
been written up publicly, then read the source yourself and write an original,
source-credited note into the owning skill.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def _candidate_indexes() -> list[Path]:
    """Locations to try, in order.

    The repository checkout keeps the index outside the skill directory, but an
    uploaded skill package has no repository above it — so also look beside the
    skill itself, where a bundled index would live.
    """
    here = Path(__file__).resolve()
    return [
        here.parents[3] / "sources" / "writeup-index.jsonl",  # repository checkout
        here.parents[1] / "writeup-index.jsonl",              # bundled in the skill
        here.parent / "writeup-index.jsonl",
    ]


def default_index() -> Path:
    for candidate in _candidate_indexes():
        if candidate.is_file():
            return candidate
    return _candidate_indexes()[0]


DEFAULT_INDEX = default_index()

UNAVAILABLE = """No writeup index found. Looked in:
{searched}

The index is a large data file that is not bundled with the uploaded skill package.

  - Running from the repository checkout? Build it once with:
        python scripts/collect_writeup_index.py
    It harvests many public sites over the network and takes a long time, so do
    not start it in the middle of an exam or an engagement.

  - Using an uploaded skill package? The index is not available here. Search the
    web for prior writeups instead, and consult references/practice-labs.md for
    named practice targets."""


def load(index: Path):
    if not index.is_file():
        searched = "\n".join(f"  {path}" for path in _candidate_indexes())
        raise SystemExit(UNAVAILABLE.format(searched=searched))
    for line in index.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def haystack(record: dict) -> str:
    parts = (
        record.get("title", ""),
        record.get("event", ""),
        record.get("challenge", ""),
        record.get("tags", ""),
        record.get("platform", ""),
        record.get("url", ""),
    )
    return " ".join(str(part) for part in parts).casefold()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("terms", nargs="*", help="Words that must all appear in the entry.")
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--source", help="Restrict to one harvested source, e.g. 0xdf.")
    parser.add_argument("--platform", help="Substring match on the platform label.")
    parser.add_argument("--regex", help="Regular expression applied to the whole entry.")
    parser.add_argument("--limit", type=int, default=40, help="Maximum results to print (0 = all).")
    parser.add_argument("--stats", action="store_true", help="Show index composition and exit.")
    args = parser.parse_args()

    records = list(load(args.index))

    if args.stats:
        by_source: dict[str, int] = {}
        for record in records:
            by_source[str(record.get("source", "?"))] = by_source.get(str(record.get("source", "?")), 0) + 1
        width = max(len(name) for name in by_source) if by_source else 10
        for name, count in sorted(by_source.items(), key=lambda item: -item[1]):
            print(f"{name:<{width}}  {count:>7,}")
        print(f"{'TOTAL':<{width}}  {len(records):>7,}")
        return

    needles = [term.casefold() for term in args.terms]
    pattern = re.compile(args.regex, re.IGNORECASE) if args.regex else None

    matches = []
    for record in records:
        if args.source and str(record.get("source", "")) != args.source:
            continue
        if args.platform and args.platform.casefold() not in str(record.get("platform", "")).casefold():
            continue
        text = haystack(record)
        if needles and not all(needle in text for needle in needles):
            continue
        if pattern and not pattern.search(text):
            continue
        matches.append(record)

    shown = matches if args.limit == 0 else matches[: args.limit]
    for record in shown:
        title = str(record.get("title", "")).strip() or "(untitled)"
        print(f"{title}\n    {record.get('url')}\n    [{record.get('source')}] {record.get('platform', '')}")
    print(f"\n{len(matches):,} match(es); showing {len(shown):,}.")


if __name__ == "__main__":
    main()
