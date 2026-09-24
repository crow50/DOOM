# Release security assessment — 2026-09-24

**Release recommendation: blocked. No ASVS level is claimed.** This review fixes
reproduced defects and accounts for the exported alerts and required controls;
it does not certify the remaining unassessed controls or accept residual risks.
No risk exceptions have been approved. The remaining work is substantive, not a
requirement to make scanner counts smaller.

**Update, 2026-09-24 — ASVS 5.0 Level 1 and Level 2 are now fully assessed.**
No row at either level is `Not assessed`; see the section
[Closing Level 1 and Level 2](#closing-level-1-and-level-2) below for what was
implemented, what was assessed as already met, and the eleven rows that remain
open with a finding against each. The release recommendation is unchanged: a
complete assessment is not a release, the candidate artifact must be rebuilt
and rescanned against the current source, and the published release's own
findings are untouched by any of this.

## Scope and artifacts

The user confirmed that **no public host is defined** and all non-local hosting
is future state. Current execution evidence covers isolated **local self-hosting**.
Public self-hosting and hosted service controls are readiness targets, not claims
about an existing deployment. The absence of a public host is not a present
deployment defect. See the separate [readiness assessment](HOSTED-READINESS.md).

- Release `v0.1.0` commit: `7076c6b24b4aa9f0395d2db1b1bb33f95c4ee152`.
  Annotated tag object: `1d9240df907b9fd9820fd5cd476515f6338beec3`.
- Initial development: `7076c6b24b4aa9f0395d2db1b1bb33f95c4ee152`.
- Updated development after Renovate: `aff50f28e3c979fe543f2d5882e691fa928aeaac`. The scanner actions
  and Renovate configuration changed; dependency versions did not. Candidate
  builds, tests and scans were refreshed after integrating these commits.
- Security candidate code with the Alpine/zlib and Hadolint fixes:
  `7f187a8c5524fd96f018d749067e28f6879c2755`. Final CI evidence is recorded
  on `a8dadfcfe1ff6d64dde59fe5c5f38fe78c915bf5`; its local ARM64 and native
  AMD64 image identities are recorded separately from the published release.
- The release tag resolves to the initial development commit (`git rev-parse 'v0.1.0^{commit}'`).
  The candidate adds the changes in this branch; it is not the published release.
- Published release: `ghcr.io/crow50/doom-organizer:0.1.0`, manifest-list digest
  `sha256:99a4b7bde30e88a728bedab57e9e6d1735c1ef5ad65bfef5ad75f60e72474a2c`.
  [Image metadata](evidence/release-image.json) pins its local image/config ID.
- Published image is AMD64. The review host and local candidate are ARM64; GitHub
  Actions built and scanned the candidate natively on AMD64. Release image
  inspection/scans are static; executable validation of the published release
  on AMD64 remains required. Candidate execution is not release execution evidence.
- [Candidate metadata](evidence/candidate-image.json), [verification manifest](verification.json)
  and [scanner inventory](evidence/scanners.json) record exact image IDs, source
  hashes, scanner versions and vulnerability database metadata. Local Docker
  image IDs are config digests, not registry manifest digests.

The original checkout and its deployment data were not used for tests. Local
Compose project `doomreview-20260923` used fresh secrets and named volumes with
only loopback ports 18480/18443. The reusable runner makes a disposable source
copy and unique images, project names and volumes, and cleans its own project.

## CI failure and candidate recheck — 2026-09-24

The failed checks on `5cb52c9` had two independent causes. The Lint, Compile,
and Test run [36001808021](https://github.com/crow50/DOOM/actions/runs/36001808021)
failed `test_grouped_candidate_hashes_still_verify`: the recorded source digest
for `app/tests/test_security_review.py` did not match the updated file. Commit
`2af8b5a` refreshed the manifest, and run
[36002613739](https://github.com/crow50/DOOM/actions/runs/36002613739) passed.
The Trivy and Grype failures were image findings, not test failures. The old
Debian 13.7 candidate produced 44 Trivy HIGH findings and 49 Grype HIGH matches
across 12 distinct high-severity CVEs. Grype's report retained 156 total
matches. Debian's stable package metadata had no available fixes for several
reported packages; the per-alert register keeps these separate from false
positives and deployment mitigations.

The current local candidate replaces the Debian slim base with the supported
Python 3.14.7 Alpine 3.23 image, pinned to multi-architecture manifest digest
`sha256:218761489de417a6eb0808e264cbdd7043ec6659fe5a61898815e9848536541d`.
It builds zlib from immutable upstream commit
[`df84af25`](https://github.com/madler/zlib/commit/df84af25dc1942490e1d1c899a07619152a46148).
The source archive SHA-256 is pinned in [app/Dockerfile](../../app/Dockerfile).
The builder runs the upstream zlib tests; the runtime asserts that Python maps
the uniquely versioned patched library. Candidate evidence records the exact
ARM64 image ID, SBOM, scanner/database versions and timestamps, VEX statement,
and local Compose results. The review Docker host has no AMD64 binfmt emulator,
so its local cross-architecture build stops with `/bin/sh: exec format error`
before running Dockerfile steps. Native AMD64 verification was completed by
GitHub Actions on the final branch revision; its immutable image identity is
preserved in [candidate-image-amd64-ci.json](evidence/candidate-image-amd64-ci.json).

Against the exact candidate SBOM, Grype 0.118.0 without VEX still exits 2 at the
HIGH threshold and reports ten matches. With VEX, it exits 0: the one HIGH
`CVE-2026-85091` match is retained in `ignoredMatches` as `fixed` for only the
exact Alpine zlib package PURL; eight MEDIUM and one LOW matches remain active
and are separately unresolved in the alert register. This is a verified
backport, not a broad ignore-unfixed or CVE suppression. Trivy 0.70.0 reports
no vulnerability matches for this ARM64 candidate with the current database;
that result does not supersede Grype's findings. The isolated Compose security
runner passed all 305 application tests, database-role, secret, proxy,
container-hardening and loopback-port checks, then removed its disposable
project. The published release remains a separate Debian image with its own
open findings.

The image-fix push `716ae80` exposed one additional CI failure: Hadolint
reported unpinned Alpine packages (DL3018), a `cd` inside `RUN` (DL3003), and a
pipeline without explicit `pipefail` (DL4006). Commit `7f187a8` pins the build
and runtime package versions, uses `WORKDIR` for the zlib source tree, and sets
Alpine `ash` with `pipefail`. Hadolint 2.12.0 passed locally, and the revised
Dockerfile rebuilt successfully on ARM64 with the upstream zlib test suite and
runtime loader assertion passing.

All seven workflows passed on final CI revision `a8dadfc`: [Lint, Compile,
and Test](https://github.com/crow50/DOOM/actions/runs/36013720296),
[Hadolint](https://github.com/crow50/DOOM/actions/runs/36013720063),
[Trivy](https://github.com/crow50/DOOM/actions/runs/36013720073),
[Grype](https://github.com/crow50/DOOM/actions/runs/36013720084),
[Semgrep](https://github.com/crow50/DOOM/actions/runs/36013720025),
[Bandit](https://github.com/crow50/DOOM/actions/runs/36013719986), and
[Gitleaks](https://github.com/crow50/DOOM/actions/runs/36013720099). The
container workflow passed all 305 tests, test-count verification, restricted
database-role checks, and secret checks. Trivy 0.70.0's CRITICAL/HIGH gate
reported zero vulnerabilities for the Alpine and Python package targets.
Grype 0.118.0's HIGH gate passed after finding 10 matches across 75 packages;
one exact-PURL zlib finding is ignored as fixed by the verified runtime
backport, leaving nine findings visible for review. Its vulnerability database
was built at `2026-09-24T06:31:52Z` (schema v6.1.9). Passing these gates does
not remove the lower-severity candidate findings, the published release's
separate findings, or the unassessed ASVS controls; the release recommendation
remains blocked and no ASVS level is claimed.

## Findings and evidence

[Alert register](alerts.json) retains all baseline IDs, source locations,
affected versions, grouping keys, evidence, disposition, exploitability,
residual risk, remediation and verification instructions. Grouping does not
remove an alert. Distinct packages and artifacts are not treated as duplicates
merely because they share a CVE. New scan observations are separate from the
baseline and linked to their source reports.

The live export verified **170 open code-scanning alerts**: 156 Trivy, six
Bandit, four CodeQL and four Grype. Three previously dismissed CodeQL findings
were also reviewed. Dependabot was accessible with 27 fixed alerts and no open
alerts. Secret scanning was accessible with no alerts; non-provider patterns
and validity checking are disabled, so an empty list is not comprehensive
secret coverage. [Availability](evidence/source-availability.json), raw paginated
exports and [analyses](evidence/analyses-pages.json) preserve this snapshot.
The [post-Renovate export](evidence/updated-main/source-availability.json)
found no new code-scanning IDs or state changes; the
[comparison](evidence/alert-refresh-delta.json) preserves that reconciliation.
The validator also checks every refreshed dependency and secret alert ID against
the register without replacing the original baseline.
The refreshed analyses include Python CodeQL at the updated main commit with
seven results (four open and three previously dismissed). Its zero-result
JavaScript and Actions categories do not establish Python coverage. These
upstream findings are current, not obsolete alerts that can be dismissed as
stale. They still do not cover the uncommitted candidate fixes.

The six Bandit findings are reviewed false positives: four event-description
strings are not credentials; dummy-password mismatch handling always denies
access; audit rollback failure follows an already-logged failure and grants no
access. No broad Bandit suppression was added. The three dismissed CodeQL
password-corpus findings concern public breach-list data, not user credentials.
The published `tools/build_password_corpus.py` is a corpus maintenance tool.
The final staged source snapshot passed Gitleaks 8.30.0 in directory and
one-commit history modes with no suppressions; its empty report and logs are
retained in the evidence directory.

CodeQL redirect findings flow through the validation helpers. The helper
accepted control-character/backslash combinations; the HTTP response encodes
the backslash as `%5C`, so an off-origin browser redirect was **not demonstrated**.
The exact-value validation defect is fixed and covered without claiming a proven
phishing exploit. Lookup errors are now generic; previously generated error
strings disclosed provider failure details, but no real credential or traceback
was demonstrated in the response. A synthetic secret sentinel tests the new
boundary. Fresh CodeQL analysis on the candidate remains required.

Reproduced application defects and their acceptance tests:

| Finding | Before | Candidate acceptance evidence |
|---|---|---|
| REV-001: PIN approval survives credential change | A signed session stored a boolean by object ID; old approval still opened a share after PIN/token rotation | `test_share_approval_revoked_when_credentials_change`; server-keyed approval binds object, token and current PIN hash, without exposing the hash in the readable cookie |
| REV-002: redirect validator normalization | Validator accepted control characters and backslashes behind them | Exact input rejects whitespace/control characters/backslashes; login falls back to local location index |
| REV-003: lookup error disclosure boundary | Caller serialized `str(exc)` | Response carries a fixed message; synthetic sentinel remains absent |
| REV-004: encoded share URL in referrer logs | `/%74/<token>` was not recognized by URL redaction | URL path is decoded for redaction; malformed referrers are redacted rather than throwing |
| REV-005: forwarded port trust | ProxyFix trusted a port field Caddy does not overwrite | Application ignores that field; Caddy-supplied host retains its actual port |
| REV-006: image pixel ceiling | Pillow only warns above configured maximum, raising at twice the limit | Explicit dimension check rejects above the configured limit before pixel decoding |

The before logs and `app/tests/test_security_review.py` provide reproducible
negative-path evidence. [Candidate suite](evidence/tests-candidate.txt) also
exercises cross-account access, session revocation, share revocation, uploads,
SSRF filtering and redaction. Tests use a privileged disposable test database;
[deployment verification](evidence/deployment.txt) separately exercises the
restricted application role and migrated database.

## Dependency risk and scan behavior

The published release and the initial Debian candidate each had 156 Trivy
package findings, including 44 high, 53 medium, 57 low and two unknown. Those
historical reports are preserved as distinct artifacts; the original
candidate's Debian image evidence is under `evidence/candidate-debian-pre-alpine-*`.
They are not the current Alpine candidate scan. Several binary packages inherit
the same source-package advisory, so these are not 156 independent exploits.
Reported severity and residual exploitability are separate fields.

The published release and historical Debian candidate have high util-linux
findings requiring local privileged mount/cgroup operations;
[Debian's tracker](https://security-tracker.debian.org/tracker/CVE-2026-76642)
identifies the affected source package and currently unpatched stable version.
Those Debian images run as UID 10001 with no capabilities,
no-new-privileges, and no configured fstab mounts. Those are real mitigations,
not false-positive evidence or approved risk acceptance. The current Alpine
candidate's SBOM does not include util-linux; that does not change the published
release's finding or disposition.

Other high findings in those Debian artifacts include
[infocmp processing](https://security-tracker.debian.org/tracker/CVE-2025-69720),
[systemd-homed](https://security-tracker.debian.org/tracker/CVE-2026-16742), and
[Perl Archive::Tar](https://security-tracker.debian.org/tracker/CVE-2026-9538).
The latter two components were absent at the inspected Debian runtime paths,
while infocmp was present. The application does not invoke these utilities.
These observations narrow reachability but do not resolve the entire
source-package advisory set. [Reachability evidence](evidence/runtime-reachability.txt)
is scoped to the pre-Alpine Debian candidate and must not be applied to the
published release or the current Alpine candidate without fresh evidence.

Trivy and Grype gates include unfixed vulnerabilities. Trivy's report includes
unknown severity. Scanner failure/skipping appears in the CI summary; Semgrep
strict mode makes scan errors fail. The high zlib match is addressed in the
current candidate by an upstream-patched runtime library and an exact-PURL VEX
statement. The statement must be removed when Alpine ships the package fix or
reassessed if its build, PURL or runtime changes. The published release's
zlib finding remains open. Tag publication runs the release assessment
preflight. Lower residual risks require an approved owner, expiry, evidence and
reassessment trigger in `exceptions.json`; none is accepted here.

## ASVS interpretation

Official stable releases and both migration directions are vendored with source
URLs, hashes and license in `tools/asvs/` and `standards.json`.
[OWASP's release notes](https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release)
identify the migration mappings; they do not certify equivalence between the
requirements. The qualified ledgers retain full requirement text and record the
mapping as context only. Version 5 has 253 L1/L2 requirements. Correctly parsing
textual level cells in version 4 yields 258 mandatory L1/L2 requirements; optional
`o` markers are not treated as mandatory. The old 253-row v4 ledger remains in
`docs/COMPLIANCE.md` for historical comparison, with its 12 unmet, 17 partial and
six compensating rows verified as the original claims.

The new assessment deliberately downgrades unsupported historical passes and
exclusions to **Not assessed** until the full requirement is revalidated.
**N/A** means the specific conditional technology/feature is absent, with scope
and source evidence. Missing MFA, recovery, TLS or secret infrastructure is not
an N/A rationale. Production cookie prefixes and per-device session management were revalidated.
Version 5 stronger authentication, backend
credentials, file-extension validation and logging obligations are independently
assessed and expose additional gaps. See the generated [summary](SUMMARY.md).
Selected L3 requirements address takeover, credential revocation, uploads and
backup protection. They carry individual threat reasons and confer no L3 claim.

`tools/check_docs.py` checks both current ledgers, complete mandatory coverage,
duplicates, qualified IDs, verbatim requirements, evidence references, totals,
alert accounting and exception consistency. Structural validation cannot prove
that an evidence file establishes every clause; that remains a review obligation.
`python3 tools/security_assessment.py --release` additionally fails for missing
assessment, unresolved findings, blocking or unaccepted residual risk, missing
verification and changed candidate source hashes.

## Remaining release blockers and operating conditions

- Final exploitability/residual-risk review of every dependency finding,
  including new full Grype findings and ambiguous/stale Python matches.
- Candidate CodeQL analysis and execution of the published AMD64 release suite.
- The earlier Semgrep Jinja parser failure was addressed by limiting strict
  Semgrep to supported source formats and adding template compilation and
  autoescape regression checks. The latest recorded Semgrep run on `2af8b5a`
  passed; the current source changes still require the branch's post-push run.
- Every `Not assessed` control needs full requirement evidence before any ASVS
  level claim. Known gaps prevent L1/L2 claims even if scanner findings close.
- DNS rebinding remains possible in opt-in lookup because address validation and
  connection use separate DNS lookups. Keep `BARCODE_LOOKUP_PROVIDER` unset until
  transport pins validated addresses with correct TLS hostname verification and
  regression tests cover DNS changes, IPv6 and redirect/proxy behavior.
- Antivirus scanning is absent. PDF/text/Markdown are stored unchanged and
  downloads remain owner-authorized attachments. No cross-account malicious
  download was demonstrated, but this is an unmet ASVS control and unaccepted
  residual risk. Do not equate image re-encoding with antivirus scanning.
- For future non-local hosting, operator evidence will be required for public certificate chain/renewal,
  encryption of disks and backups, restore drills, host time synchronization,
  log access/retention/off-host monitoring, secret custody/rotation and host
  patching. Local test certificates and Docker network isolation do not prove
  those deployment controls. These future host checks are deferred, and are not
  treated as failures of a nonexistent public deployment. Use the additional
  `--release --deployment non-local` gate before enabling non-local service.

A release recommendation requires blockers closed and retested on the exact
candidate artifact, fresh scans accounted for, and explicit time-limited
acceptance of any lower residual risks. No such acceptance is invented here.

## Closing Level 1 and Level 2

A second pass on 2026-09-24 took every ASVS 5.0 Level 1 and Level 2 row from
`Not assessed` to a status backed by evidence. Where a control was missing it
was built; where it existed it was verified against the full requirement text
rather than its summary; where it cannot be satisfied from this repository the
row says so and carries a finding.

| Scope | Met | Compensating | Not met | N/A | Not assessed |
|---|---:|---:|---:|---:|---:|
| 5.0.0 L1 | 58 | 1 | 0 | 11 | 0 |
| 5.0.0 L2 | 108 | 7 | 4 | 64 | 0 |

### Controls built to close a row

- **14.2.1 — a capability out of the URL.** A share label now encodes
  `https://host/t/#<code>`. A fragment is never transmitted, so scanning one
  sends the server `GET /t/` and nothing else; the unlock page moves the code
  into a POST body and the server redirects to a per-session handle that is
  worthless without the cookie holding it. Typed entry works without
  JavaScript.
- **11.4.1, 9.1.2 — signing raised off SHA-1.** Flask signs the session cookie
  with HMAC-SHA1 by default and Flask-WTF inherits the same default for the
  CSRF serializer it builds internally. Both are now SHA-256, with a changed
  salt so a pre-upgrade cookie cannot be evaluated against the new key at all.
- **3.4.1, 3.4.4, 3.4.6 — the edge's own header set.** A Caddy-generated 502
  during a container replacement carried no security headers and still
  identified the server. `handle_errors` now covers the responses the
  application never produces. The `?` defaults are written one directive per
  field because the Caddyfile adapter merges a block into a single `require`
  matcher, which silently never matches once any one of those headers is
  present — a block that reads correctly and does nothing.
- **6.3.3 — a second factor.** TOTP with ten single-use recovery codes,
  implemented against the RFC 4226 and RFC 6238 published vectors rather than
  imported. A consumed time step cannot be replayed, a failed code counts
  toward the password step's lockout, a pending sign-in is not a session, and
  removing the factor requires both the password and a current code.
- **7.3.1, 7.1.2 — session limits that exist.** A 60-minute idle timeout that
  revokes the row rather than refusing the request, and a 10-session cap that
  evicts the least recently used rather than refusing the new sign-in.
- **13.2.4, 13.2.5 — the application has no egress.** Caddy now bridges the
  edge and an internal-only proxy network, so `web` can reach the database and
  the cache and nothing else. A deny-all where the requirement asks for an
  allowlist, and it holds even when the SSRF validation in the lookup path is
  wrong — which matters, because that path's DNS-rebinding defect is not
  closed.
- **5.2.2, 5.2.4 — the other halves of two file controls.** The submitted
  extension must now agree with the sniffed content type, and a file-count
  quota sits alongside the byte quota, because five thousand one-kilobyte
  files fit inside the byte ceiling and still cost an inode each.
- **6.3.2 — no default account.** `flask seed` generated a demo login with a
  published password. It now generates one, prints it once and refuses to run
  against a database that already holds other accounts.
- **14.3.1, 7.4.5, 7.5.1, 6.1.2, 16.2.5** — `Clear-Site-Data` on sign-out; an
  operator command that terminates sessions for one account or all; the
  password required before an email change; a documented context-specific word
  list screened alongside the breach corpus; and log scrubbing extended to
  free-text messages and exception tracebacks, which the key-based redaction
  never reached.

`docs/security/POLICIES.md` is new and carries the sixteen documented policies
the standard asks for by name — validation rules, anti-automation, the
authorization model, session limits, key lifecycle, remediation deadlines, the
communication inventory, upload rules, data classification, the logging
inventory, business-logic limits, resource-demanding functionality, the single
authentication pathway and the cryptographic inventory.

### What remains open, and why

Eleven rows are not Met. None is an oversight; each carries a finding with an
exploitability assessment and a residual risk, and none has an approved
exception.

| Row | Status | Why it cannot close here |
|---|---|---|
| 12.2.2 | Compensating | `DOOM_DOMAIN=localhost` — no public CA can issue for it. The ACME path is present and automatic the moment a public name is configured. |
| 12.3.1, 12.3.3 | Compensating | Caddy→app, app→Postgres and app→Redis are plaintext on internal-only networks. Containment, not encryption. |
| 12.3.4 | Not met | Recorded separately so that adding internal TLS cannot silently leave consumers trusting any certificate presented. |
| 13.2.1 | Not met | Backend authentication is static passwords. Certificate or short-lived credentials need 12.3.1 closed first. |
| 13.3.1 | Compensating | Secrets are file-mounted and access-controlled; managed creation, rotation and destruction are not. |
| 5.4.3 | Not met | No antivirus. Image re-encoding is not a substitute and is not offered as one. |
| 6.4.3 | Compensating | No self-service reset by design (D-12); operator-mediated recovery is coarse but does not bypass the second factor. |
| 1.3.6 | Compensating | DNS rebinding in the opt-in lookup remains open. The network now has no egress, which is why this is Compensating rather than Not met. |
| 16.2.2 | Compensating | Timestamps are UTC and internally consistent; host time synchronisation is an operator obligation with no evidence. |
| 16.4.2 | Compensating | `audit_log` is append-only for the application's role and hash-chained; host log-store protection is the operator's. |
| 16.4.3 | Not met | No off-host log shipping, no alerting, no escalation. |

Six of the eleven are deployment or operator obligations rather than code —
the certificate, internal TLS and its trust decisions, the secrets manager,
host time and off-host logging — and they are exactly the set the hosted
readiness assessment already lists. The other five are work with a shape:
antivirus in the upload path, certificate-based backend authentication, and
pinning validated addresses in the lookup transport.

### What this does *not* establish

- **No ASVS level is claimed.** Level 2 has four Not met rows and seven
  Compensating ones; an L2 claim requires them closed or formally accepted,
  and no exception has been approved.
- **The candidate artifact is stale.** This source has not been built,
  scanned or run in a container since these changes. `verification.json`
  records every check whose result depends on the source as "rerun required"
  rather than carrying a passing status forward, because copying one from an
  older build is not verification. The application suite (453 tests) does pass
  on the review host against real PostgreSQL, and the migration applies,
  reverses and reapplies cleanly with no drift from the models.
- **The ASVS 4.0.3 ledger is unchanged.** It is retained for historical
  comparison, as recorded above; the migration mappings are context, not
  equivalences, so a v5 conclusion has not been propagated to a v4 row.
- **The published release is untouched.** Its Debian image and its open
  findings are a separate artifact from the candidate this review assessed.
