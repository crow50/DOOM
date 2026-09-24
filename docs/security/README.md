# Reproducing the security review

Start with the [assessment](RELEASE-ASSESSMENT.md), [generated status summary](SUMMARY.md),
[alert register](alerts.json), [v4 ledger](asvs-4.0.3.json) and
[v5 ledger](asvs-5.0.0.json). Current execution scope is local self-hosting;
non-local hosting is future state. The ledgers account for requirements without
claiming that unassessed requirements have passed.

Run these from the repository root:

```sh
python3 tools/check_docs.py
python3 -m unittest discover -s tools/tests -v
python3 tools/security_assessment.py --write
python3 tools/security_assessment.py --release
```

The release command is expected to fail while findings and control reviews are
unresolved. For future non-local hosting, additionally run
`python3 tools/security_assessment.py --release --deployment non-local`.
Structural checks passing does not imply a release recommendation or ASVS level.

To rerun the full container suite and deployment probes:

```sh
python3 tools/run_security_review.py --output /tmp/doom-review-new-run
```

Use a new output directory. This requires Docker/Compose with `!override`
support, make, and network access for image/dependency downloads. The runner
copies source to a temporary directory, creates fresh secrets and a unique
project, binds test ports to loopback, runs migrations/seed/tests and restricted
role/secret checks, verifies TLS and production cookies through Caddy, then
removes that project's containers and volumes. Generated logs redact the test
secrets. Images remain available for scanning. Read `results.json` and use its
project name to identify `<project>-web`; never substitute an operator stack.

Capture image metadata and archive the runtime image before scanning. Use the
scanner image digests in `evidence/scanners.json`, mount only the archive/input
needed, and scan both the separately pulled release and rebuilt candidate.
Trivy JSON records all severities; Grype JSON preserves matching details and
database build metadata. Generate a CycloneDX SBOM with Syft. Do not use
`--ignore-unfixed`/`--only-fixed` when collecting evidence. Record scanner errors
and skipped/partially parsed files as coverage gaps. Capture new database
timestamps: current scans cannot reproduce an old advisory database by date
alone. Historic scan files are retained as the exact observed results.

Export fresh GitHub evidence without dismissing or modifying any alert:

```sh
python3 tools/export_security_evidence.py --repo crow50/DOOM --output /tmp/doom-alerts-new-run
```

The authenticated `gh` account needs read access to the respective security
APIs. All pages are exported; failures are recorded in source availability.
Secret-scanning exports contain metadata only, never secret values. Preserve
the original baseline IDs when reconciling later snapshots. New scan observations
and compliance gaps have distinct IDs; `related_alerts` correlates advisory and
package matches without erasing artifact differences.

Before updating an assessment, inspect the complete official requirement text
and migration mapping. Evidence must support every clause to justify **Met**.
Conditional features can be **N/A** only with an explicit applicability reason.
Risk acceptance belongs in the finding register and `exceptions.json`, with
approval evidence, a named owner, expiry and reassessment trigger. It never
changes a compliance status to Met.

`verification.json` records the source revision plus hashes of every code and
configuration input because this review's candidate includes uncommitted branch
changes. It distinguishes Docker image/config IDs from registry manifest
digests. Refresh it only after rerunning relevant verification against the
new candidate; copying a passing status from an older build is not verification.

Tag publication additionally requires `--release --publish` and a reviewed
`candidate_registry_ref` in the form `ghcr.io/crow50/doom-organizer@sha256:…`.
The workflow pulls that immutable reference, verifies its image/config ID, and
promotes its existing manifest to release tags. It never rebuilds a release
after verification. Current local evidence has no published candidate reference
and therefore cannot authorize publication. Development branch builds continue
to publish development images for subsequent testing and review.
