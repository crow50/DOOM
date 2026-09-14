#!/usr/bin/env python3
"""Fail the build when the documentation drifts away from the code.

An external audit found four different published test counts in four files, an
ASVS requirement claimed in one section and admitted as a gap in another, and a
control credited to a library that was never imported.  None of that was
dishonesty; it was ten commits landing after the last documentation commit.  A
grep is what stops it happening again.

Three checks, in order of how quietly the thing they catch would otherwise rot:

1. Exactly one file publishes a test count.  Four files publishing four numbers
   is the failure that started this.
2. COMPLIANCE.md's exception table names exactly the ledger rows that are not
   Met and not N/A.  This is what makes the "§1 says met, §4 says gap"
   contradiction impossible rather than merely unlikely.
3. Every ASVS id cited anywhere in docs/ is a real 4.0.3 requirement, and every
   cited L1/L2 one has a ledger row.  A requirement discussed in prose but absent
   from the mapping is how 2.1.8 went missing, and citing 12.4.1 when you mean
   12.4.2 is how the malware gap ended up filed under the wrong control.

Run via ``make lint``.  Check 1 has a numeric half that needs pytest; when it is
unavailable (the CI lint job installs no application dependencies) it is skipped
here and covered by ``make verify-test-count`` in the containerised test job
instead.  Everything else is plain text and always runs.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "docs" / "COMPLIANCE.md"
REQUIREMENTS = Path(__file__).resolve().parent / "asvs-4.0.3-requirements.tsv"

#: The one file allowed to state how many tests there are.
COUNT_HOME = Path("docs/COMPLIANCE.md")

#: "228 tests", "74 passing", "130 tests, all passing".
COUNT_RE = re.compile(r"\b(\d{2,5})\s+(?:tests?|passing)\b", re.IGNORECASE)

LEDGER_BLOCK = re.compile(
    r"<!-- ledger:begin -->(.*?)<!-- ledger:end -->", re.DOTALL
)
EXCEPTIONS_BLOCK = re.compile(
    r"<!-- exceptions:begin -->(.*?)<!-- exceptions:end -->", re.DOTALL
)
ROW_RE = re.compile(r"^\|\s*(\d+\.\d+\.\d+)\s*\|", re.MULTILINE)
ASVS_ID_RE = re.compile(r"\b(?:V|ASVS\s+)?(\d{1,2}\.\d{1,2}\.\d{1,2})\b")

failures: list[str] = []
notes: list[str] = []


def asvs_universe() -> dict[str, int]:
    """Every real 4.0.3 requirement id, mapped to its lowest level.

    Without this, "ASVS 4.0.3" and "python:3.12.7-slim" both look exactly like
    requirement ids to a regex, and a genuine typo looks like neither.
    """
    universe: dict[str, int] = {}
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        rid, level, _, *_ = (line.split("\t") + ["", ""])[:3] + [""]
        universe[rid] = int(level)
    return universe


def ledger_rows() -> dict[str, str]:
    """Map every ledger row id to its status cell."""
    text = LEDGER.read_text(encoding="utf-8")
    block = LEDGER_BLOCK.search(text)
    if not block:
        failures.append(
            "docs/COMPLIANCE.md: no <!-- ledger:begin --> / <!-- ledger:end --> "
            "markers - the ledger cannot be checked"
        )
        return {}

    rows: dict[str, str] = {}
    for line in block.group(1).splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 5 or not re.fullmatch(r"\d+\.\d+\.\d+", cells[0]):
            continue
        rows[cells[0]] = cells[3].replace("*", "")
    return rows


def check_one_published_count() -> None:
    docs = sorted(ROOT.glob("*.md")) + sorted((ROOT / "docs").glob("*.md"))
    offenders: dict[str, list[str]] = {}
    home_counts: list[str] = []

    for path in docs:
        rel = path.relative_to(ROOT)
        for line in path.read_text(encoding="utf-8").splitlines():
            # "12 tests" in a sentence about something else is still a number
            # someone has to remember to update.
            for match in COUNT_RE.finditer(line):
                if rel == COUNT_HOME:
                    home_counts.append(match.group(1))
                else:
                    offenders.setdefault(str(rel), []).append(line.strip())

    for name, lines in offenders.items():
        failures.append(
            f"{name}: publishes a test count, but {COUNT_HOME} is the only file "
            f"that may. Refer to `make test` without a number.\n"
            + "\n".join(f"      {line}" for line in lines)
        )

    if not home_counts:
        failures.append(f"{COUNT_HOME}: no test count found - it is the one place that should carry one")
        return
    if len(set(home_counts)) > 1:
        failures.append(f"{COUNT_HOME}: disagrees with itself: {sorted(set(home_counts))}")
        return

    claimed = int(home_counts[0])
    actual = collected_test_count()
    if actual is None:
        notes.append(
            f"test count {claimed} not verified here - pytest is unavailable; "
            "`make verify-test-count` checks it in the container"
        )
    elif actual != claimed:
        failures.append(
            f"{COUNT_HOME}: claims {claimed} tests, pytest collects {actual}"
        )


def collected_test_count() -> int | None:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q",
             "-p", "no:cacheprovider"],
            cwd=ROOT / "app", capture_output=True, text=True, timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"^(\d+) tests? collected", result.stdout, re.MULTILINE)
    if match:
        return int(match.group(1))
    match = re.search(r"^(\d+)/(\d+) tests collected", result.stdout, re.MULTILINE)
    return int(match.group(1)) if match else None


def check_exceptions_match_ledger(rows: dict[str, str]) -> None:
    if not rows:
        return
    text = LEDGER.read_text(encoding="utf-8")
    block = EXCEPTIONS_BLOCK.search(text)
    if not block:
        failures.append(
            "docs/COMPLIANCE.md: no <!-- exceptions:begin --> / "
            "<!-- exceptions:end --> markers"
        )
        return

    listed = set(ROW_RE.findall(block.group(1)))
    expected = {rid for rid, status in rows.items() if status not in ("Met", "N/A")}

    for rid in sorted(expected - listed, key=_key):
        failures.append(
            f"docs/COMPLIANCE.md: {rid} is '{rows[rid]}' in the ledger but is "
            "missing from the exception table"
        )
    for rid in sorted(listed - expected, key=_key):
        status = rows.get(rid, "absent from the ledger")
        failures.append(
            f"docs/COMPLIANCE.md: the exception table lists {rid}, which the "
            f"ledger records as '{status}'"
        )


def check_cited_ids_exist(rows: dict[str, str]) -> None:
    if not rows:
        return
    universe = asvs_universe()
    ledger_text = LEDGER.read_text(encoding="utf-8")
    ledger_body = LEDGER_BLOCK.search(ledger_text)
    ledger_span = ledger_body.span() if ledger_body else (0, 0)

    for path in sorted((ROOT / "docs").glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for match in ASVS_ID_RE.finditer(text):
            # The ledger's own rows are the definition, not a citation of it.
            if path == LEDGER and ledger_span[0] <= match.start() < ledger_span[1]:
                continue
            rid = match.group(1)
            level = universe.get(rid)
            if level is None:
                # Not a 4.0.3 requirement at all: a version string, a Python
                # version, a section number. Only worth flagging when it is
                # written as a requirement, i.e. with an explicit V prefix.
                if match.group(0).startswith("V"):
                    line = text[: match.start()].count("\n") + 1
                    failures.append(
                        f"{path.relative_to(ROOT)}:{line}: cites V{rid}, which is "
                        "not a requirement in ASVS 4.0.3"
                    )
                continue
            if level == 3:
                continue          # L3 is not claimed, so it has no ledger row
            if rid not in rows:
                line = text[: match.start()].count("\n") + 1
                failures.append(
                    f"{path.relative_to(ROOT)}:{line}: cites ASVS {rid} (L{level}), "
                    "which has no row in the ledger"
                )


def _key(rid: str) -> list[int]:
    return [int(part) for part in rid.split(".")]


def main() -> int:
    rows = ledger_rows()
    check_one_published_count()
    check_exceptions_match_ledger(rows)
    check_cited_ids_exist(rows)

    print(f"checking documentation against the code ({len(rows)} ledger rows)...")
    for note in notes:
        print(f"  note: {note}")

    if failures:
        print()
        for failure in failures:
            print(f"FAIL: {failure}")
        print(f"\n{len(failures)} documentation check(s) failed.")
        return 1

    print("  clean: one test count, exceptions match the ledger, no orphan ids")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
