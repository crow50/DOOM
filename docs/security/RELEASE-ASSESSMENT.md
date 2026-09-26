# Release security assessment

**Last reviewed 2026-09-25. Release recommendation: blocked. No ASVS level is
claimed.**

Every ASVS 5.0 Level 1 and Level 2 requirement is now assessed — no row is left
`Not assessed` — and that is not the same as a release. Four Level 2 rows are
Not met, eight more are Compensating, none of the sixteen open findings has an
approved risk acceptance, and the candidate artifact has not been rebuilt or
rescanned since the changes that closed the ledger. `SUMMARY.md` is the
scoreboard; `findings.json` is what somebody has to decide about.

## Scope

Current execution is isolated **local self-hosting**. Non-local hosting is a
readiness target, not a claim about anything running — the absence of a public
host is not a present defect, and [HOSTED-READINESS.md](HOSTED-READINESS.md)
records what one would additionally have to prove. Deployment-dependent rows say
so in their rationale rather than borrowing credit from a deployment that does
not exist.

- **Published release:** `ghcr.io/crow50/doom-organizer:0.1.0`, manifest-list
  digest `sha256:99a4b7bde30e88a728bedab57e9e6d1735c1ef5ad65bfef5ad75f60e72474a2c`,
  built from commit `7076c6b24b4aa9f0395d2db1b1bb33f95c4ee152`. Debian-based,
  AMD64, with its own open dependency findings.
- **Candidate:** this branch. Alpine-based, with zlib built from an immutable
  upstream commit to carry a fix Alpine had not yet shipped. Its identity is
  whatever `git rev-parse HEAD` says — that is the source manifest, and a
  hand-maintained list of file hashes was deleted for trying to be one.
- The candidate is **not** the published release, and the published release's
  findings are not the candidate's.

Tests ran against a disposable Compose project with generated secrets and
loopback-only ports. Neither an operator's stack nor its data was used.

## What this review changed

Six defects were found by reproducing them rather than by reading a scanner, and
each now has a regression test (`REV-001` to `REV-006` in `findings.json`):
a PIN approval that survived credential rotation, a redirect validator that
accepted control characters behind a backslash, a lookup error that serialised
its exception, an encoded share path that escaped log redaction, a forwarded
port that ProxyFix trusted and Caddy does not set, and an image pixel ceiling
that Pillow only warned about.

Closing Level 1 and Level 2 then required building controls rather than
documenting them. Share capabilities moved out of the URL into a fragment; the
session cookie and the CSRF serializer moved off HMAC-SHA1; the edge gained its
own security header set so a proxy-generated 502 is not a hole in it; a second
factor was added with recovery codes; an idle timeout and a concurrent-session
cap were added; the application container lost its egress route entirely; and
`flask seed` stopped shipping a published demo password. Each is named in the
ledger row it closes, with the test that fails if it regresses.

## What is open

Twelve findings, none accepted. The two Not met rows are the ones to look at
first: backend authentication on static passwords rather than certificates or
short-lived credentials (`CONTROL-13.2.1`), and no off-host log shipping or
alerting (`CONTROL-16.4.3`). Antivirus scanning of uploads and all three
internal TLS hops (`CONTROL-12.3.1`, `12.3.3`, `12.3.4`), previously also Not
met, closed as `Met` - see `docs/security/POLICIES.md` §§9-10 and
`make verify-internal-tls`.

Of the twelve, five are deployment or operator obligations that no code in
this repository can discharge — the publicly trusted certificate, a secrets
manager, host time synchronisation, host log protection, and off-host
shipping. The rest have a shape: certificate-based backend authentication
(now that internal TLS exists to present a certificate on - `CONTROL-13.2.1`
names this dependency directly), and pinning validated addresses in the
barcode lookup transport, where DNS rebinding remains open because validation
and connection resolve the name separately. Keep `BARCODE_LOOKUP_PROVIDER`
unset until that is closed; the container having no egress route is what
currently makes it unreachable rather than merely unexploited.

## How the ledger counts

The official stable release is vendored in `tools/asvs/5.0.0.csv` with its
source URL, hash and licence, and `standards.json` fails the build if it
changes. Every row quotes the requirement verbatim — the validator compares it
against the CSV, so a row cannot be a paraphrase that happens to be easier to
satisfy.

ASVS 5.0 has **258 Level 1 and Level 2 requirements**. Rows are assessed against
the full text of each one, and a status that cannot cite something executable is
treated with suspicion:

- **Met** requires evidence for every clause. Sixty-six of them cite a test that
  fails if the control is removed.
- **N/A** requires the specific technology or feature to be genuinely absent,
  with the reason stated. Missing MFA, missing recovery, missing TLS and missing
  secret infrastructure are **not** N/A rationales — a control that was never
  built is Not met.
- **Compensating** states what the mitigation is *and* that it is not the
  control. Internal plaintext on an internal-only network with no egress is
  containment, and the rows say so.

The previous revision kept a parallel ledger against ASVS 4.0.3, 81% of it never
assessed, plus seven megabytes of archived scanner output. Both are deleted;
D-40 records why, and the short version is that self-attested evidence persuades
nobody who was not already persuaded.

## What this does not establish

- **No ASVS level.** Four Not met rows and sixteen unaccepted risks. An L2 claim
  needs them closed or formally accepted with an owner and an expiry.
- **The candidate is not verified as an artifact.** The 453-test suite passes on
  the review host against real PostgreSQL 16, and the migration applies,
  reverses and reapplies with no drift from the models. The containerised run,
  the image scans and the deployment probes all predate these changes and need
  repeating — `README.md` says how. CI is the authority for whether a gate
  passed on a given commit; this document does not restate it.
- **The published release is untouched.** Scan it yourself for its current
  state; a report frozen against an old advisory database is worse than no
  report, because it looks like an answer.
- **Nothing here is an audit.** It is the maintainer's own assessment, which is
  why it points at code, tests and commands rather than at conclusions.
