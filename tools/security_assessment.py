#!/usr/bin/env python3
"""Validate and render evidence ledgers; release mode fails closed on review gaps.

This checks evidence structure, not the truth of an auditor's conclusions.
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
STATUSES = ("Met", "Partial", "Compensating", "Not met", "N/A", "Not assessed")
DISPOSITIONS = {"confirmed", "false positive", "duplicate", "resolved/stale", "unresolved"}
#: Evidence files that nothing cites because a *tool* reads them rather than a
#: human argument. Everything else under docs/security/evidence must be cited
#: by a ledger row, a finding, an exception or a verification check - see
#: `unreferenced_evidence`.
RAW_EXPORTS = {
    "evidence/code-scanning-pages.json",
    "evidence/dependabot-pages.json",
    "evidence/secret-scanning-pages.json",
    "evidence/source-availability.json",
    "evidence/candidate-image.json",
    "evidence/updated-main/code-scanning-pages.json",
    "evidence/updated-main/dependabot-pages.json",
    "evidence/updated-main/secret-scanning-pages.json",
    "evidence/updated-main/source-availability.json",
    "evidence/updated-main/analyses-pages.json",
    "evidence/updated-main/latest-main-analyses.json",
    "evidence/README.md",
}

REQUIRED_CHECKS = {
    "container-suite", "documentation", "dependency-scan", "bandit", "semgrep",
    "codeql-candidate", "secret-scan", "release-image-scan", "candidate-image-scan",
    "published-release-execution", "deployment", "operator-controls",
}


def read(path, root=ROOT):
    return json.loads((root / path).read_text())


def universe(version, root=ROOT):
    result = {}
    with (root / "tools/asvs" / f"{version}.csv").open(newline="") as handle:
        for row in csv.DictReader(handle):
            if version == "5.0.0":
                level = int(row["L"])
            else:
                # 'o' is optional. Text such as 'OS assisted' or '30 days'
                # defines a real obligation and must not be silently omitted.
                levels = [i for i in (1, 2, 3) if row[f"level{i}"] not in ("", "-", "✗", "o")]
                if not levels:  # officially deleted requirements
                    continue
                level = min(levels)
            rid = f"v{version}-{row['req_id'].removeprefix('V')}"
            if rid in result:
                raise ValueError(f"Duplicate official requirement: {rid}")
            result[rid] = {"level": level, "requirement": row["req_description"]}
    return result


def source_hashes(root=ROOT):
    """All candidate code/configuration inputs, not an arbitrary subset."""
    paths = [root / 'Makefile', root / 'docker-compose.yml']
    for folder in ('app', 'tools', '.github', 'caddy', 'db'):
        paths.extend(p for p in (root / folder).rglob('*') if p.is_file()
                     and '__pycache__' not in p.parts and '.pytest_cache' not in p.parts)
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def unreferenced_evidence(cited, root=ROOT):
    """Evidence files that support nothing.

    An orphan is not harmless. A reviewer who finds a log in this directory
    reasonably assumes some claim rests on it, and a directory that accumulates
    outputs nobody cites makes the set that *is* load-bearing harder to see -
    which is the opposite of what an evidence directory is for. Anything kept
    here has to be pointed at by a ledger row, a finding, an exception or a
    verification check, or be one of the raw exports above that a tool reads.

    Deleting an orphan is the usual fix; citing it from the claim it supports
    is the other one, and is right more often than it looks.
    """
    directory = root / BASE / 'evidence'
    if not directory.is_dir():
        return []
    present = {
        str(path.relative_to(root / BASE)) for path in directory.rglob('*')
        if path.is_file()
    }
    return sorted(present - RAW_EXPORTS - {
        ref.removeprefix(f'{BASE}/') for ref in cited
    })


def validate(root=ROOT, release=False, deployment='local', publish=False):
    release = release or publish
    errors = []

    def require(condition, message):
        if not condition:
            errors.append(message)

    def evidence(refs, label):
        require(bool(refs), f"{label}: missing evidence")
        for ref in refs:
            path, _, line = ref.partition(":")
            resolved = (root / path).resolve()
            require(resolved.is_relative_to(root.resolve()) and resolved.is_file(),
                    f"{label}: missing/unsafe evidence {ref}")
            if line and resolved.is_file():
                require(line.isdigit() and 0 < int(line) <= len(resolved.read_text().splitlines()),
                        f"{label}: invalid evidence line {ref}")

    provenance = read(BASE / "standards.json", root)
    require({f"tools/asvs/{name}" for name in ('4.0.3.csv', '5.0.0.csv',
            '4.0.3-to-5.0.0.yml', '5.0.0-to-4.0.3.yml')} <= {e['path'] for e in provenance},
            "incomplete standards provenance")
    for entry in provenance:
        path = root / entry["path"]
        require(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"],
                f"standard changed: {entry['path']}")
    all_ids = set()
    control_findings = []
    #: Every evidence path anything points at, so orphans can be spotted below.
    cited = set()
    for version in ("4.0.3", "5.0.0"):
        official = universe(version, root)
        ledger = read(BASE / f"asvs-{version}.json", root)
        rows = ledger["requirements"]
        counts = Counter(row["id"] for row in rows)
        required = {rid for rid, row in official.items() if row["level"] <= 2}
        require(required <= counts.keys(), f"ASVS {version}: missing {sorted(required - counts.keys())}")
        for row in rows:
            rid = row["id"]
            all_ids.add(rid)
            require(counts[rid] == 1, f"{rid}: duplicate row")
            require(rid in official, f"{rid}: unknown/version-mismatched requirement")
            require(row["status"] in STATUSES, f"{rid}: invalid status")
            require(bool(row.get("rationale")) and bool(row.get("verification")), f"{rid}: missing rationale/verification")
            if rid in official:
                require(row["level"] == official[rid]["level"], f"{rid}: wrong level")
                require(row["requirement"] == official[rid]["requirement"], f"{rid}: modified requirement text")
            if row["level"] == 3:
                require(bool(row.get("selection_reason")), f"{rid}: L3 needs threat justification")
            cited.update(ref.partition(":")[0] for ref in row.get("evidence", []))
            evidence(row.get("evidence", []), rid)
            if row["status"] in ("Partial", "Compensating", "Not met"):
                require(bool(row.get('finding_ids')), f"{rid}: gap has no risk-review finding")
            control_findings.extend((rid, fid) for fid in row.get('finding_ids', []))
            require(row.get('exception') is None, f"{rid}: risk acceptance belongs in finding register, not compliance status")
            if release and row["status"] == "Not assessed":
                require(False, f"{rid}: release assessment incomplete")
        totals = dict(Counter(row["status"] for row in rows))
        require(ledger["totals"] == totals, f"ASVS {version}: stale status totals")
    for path in (root / "docs").rglob("*.md"):
        for version, rid in re.findall(r"\bv(4\.0\.3|5\.0\.0)-(\d+\.\d+\.\d+)\b", path.read_text()):
            require(f"v{version}-{rid}" in universe(version, root), f"{path.name}: unknown v{version}-{rid}")

    register = read(BASE / "alerts.json", root)
    raw = sum(read(BASE / "evidence/code-scanning-pages.json", root), [])
    expected = {f"code-scanning:{a['number']}" for a in raw}
    dependencies = sum(read(BASE / "evidence/dependabot-pages.json", root), [])
    expected |= {f"dependabot:{a['number']}" for a in dependencies}
    secrets = sum(read(BASE / "evidence/secret-scanning-pages.json", root), [])
    expected |= {f"secret-scanning:{a['number']}" for a in secrets}
    alerts = register["alerts"] + register["new_findings"]
    ids = [a["id"] for a in alerts]
    for rid, fid in control_findings:
        require(fid in ids, f"{rid}: nonexistent finding {fid}")
    require(len(ids) == len(set(ids)), "duplicate finding ID")
    require({a['id'] for a in register['alerts']} == expected, "alert export/register mismatch")
    # Later captures must not silently introduce alerts outside the register.
    # Preserve the original baseline while requiring separate reconciliation.
    refreshed = root / BASE / 'evidence/updated-main'
    if refreshed.exists():
        for source in ('code-scanning', 'dependabot', 'secret-scanning'):
            capture = refreshed / f'{source}-pages.json'
            if capture.is_file():
                current = sum(read(capture, root), [])
                require({f"{source}:{a['number']}" for a in current} <= set(ids),
                        f'{source}: refreshed alerts missing from register')
    require(register["baseline_open"] == sorted(a["number"] for a in raw if a["state"] == "open"),
            "baseline open IDs changed")
    exception_rows = read(BASE / "exceptions.json", root)
    exceptions = {e["id"]: e for e in exception_rows}
    require(len(exceptions) == len(exception_rows), 'duplicate exception ID')
    for eid, exception in exceptions.items():
        require(bool(exception.get("owner")) and bool(exception.get("reassessment_trigger")), f"{eid}: missing owner/trigger")
        require(bool(exception.get("approved_by")) and bool(exception.get("approval_evidence")), f"{eid}: acceptance not approved")
        cited.update(ref.partition(":")[0] for ref in exception.get("approval_evidence", []))
        evidence(exception.get("approval_evidence", []), eid)
        try:
            require(dt.date.fromisoformat(exception["expires"]) > dt.datetime.now(dt.timezone.utc).date(), f"{eid}: expired exception")
        except (ValueError, KeyError):
            require(False, f"{eid}: invalid expiry")
        require(bool(exception.get("finding_ids")), f"{eid}: no findings")
        for fid in exception.get("finding_ids", []):
            require(any(a['id'] == fid and a.get('exception') == eid for a in alerts), f"{eid}: inconsistent finding {fid}")
    for a in alerts:
        aid = a['id']
        require(a['disposition'] in DISPOSITIONS, f"{aid}: invalid disposition")
        for key in ('affected_versions', 'impact', 'rationale', 'remediation', 'verification', 'group', 'exploitability', 'residual_risk'):
            require(bool(a.get(key)), f"{aid}: missing {key}")
        require(a['residual_risk'] in ('critical', 'high', 'medium', 'low', 'none', 'unknown'), f"{aid}: invalid residual risk")
        cited.update(ref.partition(":")[0] for ref in a.get('evidence', []))
        evidence(a.get('evidence', []), aid)
        if a['disposition'] == 'duplicate':
            require(a.get('duplicate_of') in ids and a.get('duplicate_of') != aid, f"{aid}: invalid duplicate reference")
        if a.get('exception'):
            require(a['exception'] in exceptions and aid in exceptions[a['exception']]['finding_ids'], f"{aid}: invalid exception")
        if release:
            require(a['disposition'] != 'unresolved', f"{aid}: unresolved")
            require(a['residual_risk'] not in ('critical', 'high', 'unknown'), f"{aid}: blocking residual risk")
            if a['residual_risk'] in ('medium', 'low'):
                require(a.get('exception') in exceptions, f"{aid}: residual risk not accepted")
            if a.get('blocking_exposure') and a['residual_risk'] != 'none':
                require(False, f"{aid}: demonstrated blocking exposure")
    for check in read(BASE / 'verification.json', root)['checks']:
        cited.update(ref.partition(":")[0] for ref in check.get('evidence', []))

    # A file a document argues from is cited as surely as one a ledger row
    # points at, so prose counts. Matching on the path as written means a link
    # in RELEASE-ASSESSMENT.md and a row in the ledger reach the same file.
    for path in (root / "docs").rglob("*.md"):
        text = path.read_text(encoding="utf-8")
        for match in re.findall(r"(?:docs/security/)?evidence/[A-Za-z0-9_./-]+", text):
            cited.add(str(BASE / match[match.index("evidence/"):]).rstrip(".,)"))

    for orphan in unreferenced_evidence(cited, root):
        require(False, f'{orphan}: evidence file that nothing cites')

    availability = read(BASE / 'evidence/source-availability.json', root)
    if release:
        for name, source in availability.items():
            if isinstance(source, dict):
                require(source.get('available'), f"{name}: unavailable source")
        if refreshed.exists():
            refreshed_availability = read(refreshed / 'source-availability.json', root)
            for name, source in refreshed_availability.items():
                if isinstance(source, dict):
                    require(source.get('available'), f"{name}: refreshed source unavailable")
        verification = read(BASE / 'verification.json', root)
        require(REQUIRED_CHECKS <= {c['name'] for c in verification['checks']}, 'missing required verification checks')
        check_names = [c['name'] for c in verification['checks']]
        require(len(check_names) == len(set(check_names)), 'duplicate verification check')
        for check in verification['checks']:
            require(check.get('scope') != 'non-local' or check['name'] == 'operator-controls',
                    f"{check['name']}: mandatory check cannot be deferred to non-local hosting")
            if check.get('scope') == 'non-local' and check['name'] == 'operator-controls' and deployment == 'local':
                continue
            require(check['status'] == 'passed', f"{check['name']}: {check['status']}")
            evidence(check.get('evidence', []), check['name'])
        require(verification.get('candidate_digest'), 'candidate image digest absent')
        candidate = read(BASE / 'evidence/candidate-image.json', root)
        require(verification.get('candidate_digest') == candidate.get('Id'), 'candidate image/verification digest mismatch')
        if publish:
            require(bool(re.fullmatch(r'ghcr\.io/crow50/doom-organizer@sha256:[a-f0-9]{64}',
                                      verification.get('candidate_registry_ref', ''))),
                    'publication requires an immutable reviewed registry reference')
            require(bool(re.fullmatch(r'sha256:[a-f0-9]{64}', verification.get('candidate_digest', ''))),
                    'publication requires a valid reviewed image/config digest')
        require(bool(verification.get('source_hashes')), 'candidate source hashes absent')
        require(set(verification.get('source_hashes', {})) == set(source_hashes(root)),
                'candidate source inventory incomplete or changed')
        for path, digest in verification.get('source_hashes', {}).items():
            source = root / path
            require(isinstance(digest, list) and len(digest) == 32
                    and all(type(byte) is int and 0 <= byte <= 255 for byte in digest),
                    f'candidate source hash has invalid byte-array format: {path}')
            normalized_digest = bytes(digest).hex() if isinstance(digest, list) \
                and all(type(byte) is int and 0 <= byte <= 255 for byte in digest) else ''
            require(source.is_file() and hashlib.sha256(source.read_bytes()).hexdigest() == normalized_digest,
                    f'candidate source changed: {path}')
    return errors


def render(root=ROOT):
    lines = ['# Security assessment summary', '',
             'Generated by `python3 tools/security_assessment.py --write`. Status is separate from risk acceptance.', '',
             '| Version / scope | Met | Partial | Compensating | Not met | N/A | Not assessed |',
             '|---|---:|---:|---:|---:|---:|---:|']
    for version in ('4.0.3', '5.0.0'):
        ledger = read(BASE / f'asvs-{version}.json', root)
        for scope in (1, 2, 3):
            counts = Counter(r['status'] for r in ledger['requirements'] if r['level'] == scope)
            label = f'L{scope}' if scope < 3 else 'selected L3'
            lines.append(f'| {version} {label} | ' + ' | '.join(str(counts[s]) for s in STATUSES) + ' |')
    register = read(BASE / 'alerts.json', root)
    lines += ['', '| Finding disposition | Exported alerts | New findings |', '|---|---:|---:|']
    for disposition in sorted(DISPOSITIONS):
        lines.append(f"| {disposition} | {sum(a['disposition'] == disposition for a in register['alerts'])} | {sum(a['disposition'] == disposition for a in register['new_findings'])} |")
    lines += ['', 'No ASVS level is claimed. See [release assessment](RELEASE-ASSESSMENT.md) for the decision and operating conditions.', '']
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='regenerate summary')
    parser.add_argument('--release', action='store_true', help='enforce release readiness, not just ledger integrity')
    parser.add_argument('--deployment', choices=('local', 'non-local'), default='local',
                        help='non-local additionally requires future host-specific verification')
    parser.add_argument('--publish', action='store_true',
                        help='also require an immutable registry artifact for promotion')
    args = parser.parse_args()
    errors = validate(release=args.release, deployment=args.deployment, publish=args.publish)
    summary = render()
    path = ROOT / BASE / 'SUMMARY.md'
    if args.write and not errors:
        path.write_text(summary)
    elif not path.exists() or path.read_text() != summary:
        errors.append('security summary is stale; run --write')
    for error in errors:
        print(f'FAIL: {error}')
    if not errors:
        print('Security evidence structure verified' + ('; release gate passed' if args.release else '; release readiness not implied'))
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
