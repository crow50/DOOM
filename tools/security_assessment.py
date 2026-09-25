#!/usr/bin/env python3
"""Validate the ASVS ledger and the finding register; render the status summary.

This checks that the bookkeeping is internally consistent and that everything
it points at exists. It cannot check whether a conclusion is true - that
remains a review obligation, and the thing that makes a conclusion checkable is
the test each row cites, not this script.

What this deliberately does not do any more. It used to verify a SHA-256 of
every source file recorded in a manifest, reconcile a committed snapshot of
GitHub's alert API against a committed register derived from it, and require
that every file in an evidence directory be cited by something. All three were
circular: they checked that self-attested records agreed with each other. The
commit SHA is the source manifest, GitHub is the authority on GitHub's alerts,
and archived scanner output is worth less than the instruction to re-run the
scanner - which is in docs/security/README.md.
"""
import argparse
from collections import Counter
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
BASE = Path("docs/security")
VERSION = "5.0.0"

STATUSES = ("Met", "Partial", "Compensating", "Not met", "N/A", "Not assessed")
FINDING_STATUSES = ("open", "closed")
RISKS = ("critical", "high", "medium", "low", "none", "unknown")
FINDING_FIELDS = ("rationale", "exploitability", "remediation", "verification")


def read(path, root=ROOT):
    return json.loads((root / path).read_text())


def universe(root=ROOT):
    """Every official L1/L2/L3 requirement, from the vendored release."""
    result = {}
    with (root / "tools/asvs" / f"{VERSION}.csv").open(newline="") as handle:
        for row in csv.DictReader(handle):
            rid = f"v{VERSION}-{row['req_id'].removeprefix('V')}"
            if rid in result:
                raise ValueError(f"duplicate official requirement: {rid}")
            result[rid] = {"level": int(row["L"]), "requirement": row["req_description"]}
    return result


def validate(root=ROOT, release=False, deployment="local", publish=False):
    release = release or publish
    errors = []

    def require(condition, message):
        if not condition:
            errors.append(message)

    def evidence(refs, label):
        require(bool(refs), f"{label}: cites no evidence")
        for ref in refs:
            path, _, line = ref.partition(":")
            resolved = (root / path).resolve()
            require(resolved.is_relative_to(root.resolve()) and resolved.is_file(),
                    f"{label}: evidence does not exist: {ref}")
            if line and resolved.is_file():
                require(line.isdigit() and 0 < int(line) <= len(resolved.read_text().splitlines()),
                        f"{label}: evidence line out of range: {ref}")

    # --- the standard itself is what we say it is ---------------------------
    provenance = read(BASE / "standards.json", root)
    listed = {entry["path"] for entry in provenance}
    require({f"tools/asvs/{VERSION}.csv", "tools/asvs/LICENSE.md"} <= listed,
            "standards.json must record the vendored requirement list and its licence")
    for entry in provenance:
        path = root / entry["path"]
        require(path.is_file()
                and hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"],
                f"vendored standard has changed since it was recorded: {entry['path']}")

    official = universe(root)
    ledger = read(BASE / f"asvs-{VERSION}.json", root)
    rows = ledger["requirements"]
    counts = Counter(row["id"] for row in rows)

    mandatory = {rid for rid, row in official.items() if row["level"] <= 2}
    require(mandatory <= counts.keys(),
            f"ledger is missing mandatory requirements: {sorted(mandatory - counts.keys())}")

    findings = read(BASE / "findings.json", root)
    finding_ids = [f["id"] for f in findings]
    require(len(finding_ids) == len(set(finding_ids)), "duplicate finding id")
    by_id = {f["id"]: f for f in findings}

    for row in rows:
        rid = row["id"]
        require(counts[rid] == 1, f"{rid}: appears more than once")
        require(rid in official, f"{rid}: not a requirement in ASVS {VERSION}")
        require(row["status"] in STATUSES, f"{rid}: invalid status {row['status']!r}")
        require(bool(row.get("rationale")) and bool(row.get("verification")),
                f"{rid}: a status without a rationale and a way to verify it is an assertion")
        if rid in official:
            require(row["level"] == official[rid]["level"], f"{rid}: wrong level")
            require(row["requirement"] == official[rid]["requirement"],
                    f"{rid}: requirement text does not match the standard verbatim")
        if row["level"] == 3:
            require(bool(row.get("selection_reason")),
                    f"{rid}: a Level 3 row needs the threat that justifies selecting it")
        evidence(row.get("evidence", []), rid)

        if row["status"] in ("Partial", "Compensating", "Not met"):
            require(bool(row.get("finding_ids")),
                    f"{rid}: a gap with no finding is a gap nobody owns")
        for fid in row.get("finding_ids", []):
            require(fid in by_id, f"{rid}: references a finding that does not exist: {fid}")
            if fid in by_id:
                require(by_id[fid]["status"] == "open" or row["status"] in ("Met", "N/A"),
                        f"{rid}: is a gap but {fid} is closed")
        require(row.get("exception") is None,
                f"{rid}: risk acceptance belongs in the finding register, not in a status")
        if release:
            require(row["status"] != "Not assessed", f"{rid}: never assessed")

    require(ledger["totals"] == dict(Counter(row["status"] for row in rows)),
            "the ledger's totals do not match its rows")

    # --- findings ----------------------------------------------------------
    exception_rows = read(BASE / "exceptions.json", root)
    exceptions = {e["id"]: e for e in exception_rows}
    require(len(exceptions) == len(exception_rows), "duplicate exception id")

    for finding in findings:
        fid = finding["id"]
        require(finding["status"] in FINDING_STATUSES, f"{fid}: invalid status")
        require(finding["residual_risk"] in RISKS, f"{fid}: invalid residual risk")
        for field in FINDING_FIELDS:
            require(bool(finding.get(field)), f"{fid}: missing {field}")
        evidence(finding.get("evidence", []), fid)
        if finding.get("requirement"):
            require(finding["requirement"] in official,
                    f"{fid}: maps to an unknown requirement {finding['requirement']}")
        if finding["status"] == "closed":
            require(finding["residual_risk"] == "none",
                    f"{fid}: closed but still carries residual risk")
        if release and finding["status"] == "open":
            require(finding["residual_risk"] not in ("critical", "high", "unknown"),
                    f"{fid}: open with {finding['residual_risk']} residual risk")
            require(finding.get("exception") in exceptions,
                    f"{fid}: open risk that nobody has accepted")

    for eid, exception in exceptions.items():
        require(bool(exception.get("owner")) and bool(exception.get("reassessment_trigger")),
                f"{eid}: an accepted risk needs an owner and a trigger to revisit it")
        require(bool(exception.get("approved_by")) and bool(exception.get("approval_evidence")),
                f"{eid}: acceptance without an approver is not acceptance")
        evidence(exception.get("approval_evidence", []), eid)
        try:
            require(dt.date.fromisoformat(exception["expires"])
                    > dt.datetime.now(dt.timezone.utc).date(), f"{eid}: expired")
        except (ValueError, KeyError):
            require(False, f"{eid}: invalid or missing expiry")
        for fid in exception.get("finding_ids", []):
            require(fid in by_id and by_id[fid].get("exception") == eid,
                    f"{eid}: inconsistent with finding {fid}")

    # --- every ASVS id cited in prose is real ------------------------------
    for path in (root / "docs").rglob("*.md"):
        for rid in re.findall(rf"\bv{re.escape(VERSION)}-(\d+\.\d+\.\d+)\b", path.read_text()):
            require(f"v{VERSION}-{rid}" in official,
                    f"{path.relative_to(root)}: cites v{VERSION}-{rid}, which is not a requirement")

    if publish:
        candidate = read(BASE / "release-candidate.json", root)
        require(bool(re.fullmatch(r"ghcr\.io/crow50/doom-organizer@sha256:[a-f0-9]{64}",
                                 candidate.get("registry_ref") or "")),
                "publishing requires an immutable, reviewed registry reference")
        require(bool(re.fullmatch(r"sha256:[a-f0-9]{64}", candidate.get("image_id") or "")),
                "publishing requires the reviewed image id")
    return errors


def render(root=ROOT):
    ledger = read(BASE / f"asvs-{VERSION}.json", root)
    findings = read(BASE / "findings.json", root)

    lines = [
        "# Security assessment summary",
        "",
        "Generated by `python3 tools/security_assessment.py --write`. A status is not a",
        "risk decision: see [findings](findings.json) for what is open and",
        "[the assessment](RELEASE-ASSESSMENT.md) for the release decision.",
        "",
        f"## ASVS {VERSION}",
        "",
        "| Scope | " + " | ".join(STATUSES) + " |",
        "|---|" + "---:|" * len(STATUSES),
    ]
    for level in (1, 2, 3):
        counts = Counter(r["status"] for r in ledger["requirements"] if r["level"] == level)
        label = f"L{level}" if level < 3 else "selected L3"
        lines.append(f"| {label} | " + " | ".join(str(counts[s]) for s in STATUSES) + " |")

    open_findings = [f for f in findings if f["status"] == "open"]
    lines += [
        "",
        "## Findings",
        "",
        f"{len(open_findings)} open, {len(findings) - len(open_findings)} closed.",
        "",
        "| Residual risk | Open |",
        "|---|---:|",
    ]
    risks = Counter(f["residual_risk"] for f in open_findings)
    for risk in RISKS:
        if risks[risk]:
            lines.append(f"| {risk} | {risks[risk]} |")
    lines += ["", "No ASVS level is claimed.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate SUMMARY.md")
    parser.add_argument("--release", action="store_true",
                        help="also require that nothing is unassessed or unaccepted")
    parser.add_argument("--deployment", choices=("local", "non-local"), default="local")
    parser.add_argument("--publish", action="store_true",
                        help="also require a reviewed, immutable registry artifact")
    args = parser.parse_args()

    errors = validate(release=args.release, deployment=args.deployment, publish=args.publish)
    summary = render()
    path = ROOT / BASE / "SUMMARY.md"
    if args.write and not errors:
        path.write_text(summary)
    elif not path.exists() or path.read_text() != summary:
        errors.append("SUMMARY.md is stale; run --write")

    for error in errors:
        print(f"FAIL: {error}")
    if not errors:
        print("Ledger and findings are consistent"
              + ("; release gate passed" if args.release else "; release readiness not implied"))
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
