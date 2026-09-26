# Checking this yourself

Nothing in this directory asks to be believed. Every claim below is one you can
re-run, and the reason there is no archive of past runs is that an archive is
exactly the thing a sceptical reader cannot use — see D-40.

Read in this order:

| File | What it is |
|---|---|
| [SUMMARY.md](SUMMARY.md) | The scoreboard. Generated; twenty lines. |
| [asvs-5.0.0.json](asvs-5.0.0.json) | One row per ASVS 5.0 requirement: status, the reasoning, how to verify it, and the code or test that demonstrates it. |
| [findings.json](findings.json) | What is open. Sixteen rows, each with a residual risk somebody has to accept or close. |
| [RELEASE-ASSESSMENT.md](RELEASE-ASSESSMENT.md) | The release decision and the conditions attached to it. |
| [POLICIES.md](POLICIES.md) | The policies several requirements ask for by name — validation rules, anti-automation, session limits, key lifecycle, remediation deadlines. |
| [REMEDIATION.md](REMEDIATION.md) | The work queue, with acceptance criteria per batch. |
| [HOSTED-READINESS.md](HOSTED-READINESS.md) | What a non-local deployment would additionally have to prove. |

## The checks, and what each one actually establishes

```sh
make test          # the suite. Every control the ledger claims is pinned here.
make lint          # no autoescape bypass; the ledger against the code it cites
python3 -m unittest discover -s tools/tests -v    # the validator's own tests
```

`make lint` runs `tools/security_assessment.py`, which checks that every
mandatory Level 1 and Level 2 requirement has a row, that each row quotes the
standard verbatim, that no status is asserted without a rationale and a way to
verify it, that every file a row cites exists, and that no gap is left without
a finding. **It cannot check whether a conclusion is true.** That is a review
obligation, and the thing that makes a conclusion checkable is the test the row
names — which is why `evidence` points at code and tests and not at logs.

```sh
python3 tools/security_assessment.py --release
```

Expected to fail, and the failures are the point: it refuses while any risk is
open and unaccepted. A passing release gate would mean somebody had signed for
each one in `exceptions.json`, with an owner and an expiry.

## Reproducing the deployment checks

These need Docker, Compose with `!override` support, make, and network access.

```sh
python3 tools/run_security_review.py --output /tmp/doom-review-$(date +%s)
```

Use a fresh output directory. The runner copies the source to a temporary
directory, generates its own secrets, picks a unique project name, binds test
ports to loopback only, runs the migrations, the seed and the suite inside the
image, checks the restricted database role and the secret hygiene, verifies TLS
and the production cookie attributes through Caddy, then removes its own
containers and volumes. Read `results.json` and use its project name to
identify the containers. **Never point it at an operator's stack.**

Against a running stack:

```sh
make verify-db-roles     # the app role cannot ALTER, DROP, or rewrite audit_log
make verify-secrets      # no secret value in any process environment or docker inspect
make verify-cert         # the certificate being served is the one you think it is
make verify-internal-tls # db, cache and caddy->web require TLS and reject a foreign CA
make audit-verify        # walk the audit hash chain and print its head
```

## Scanning the images

There is no stored scan to read, deliberately. Both images are public, so scan
them yourself and get an answer against today's advisory database rather than
one frozen against last week's:

```sh
trivy image ghcr.io/crow50/doom-organizer:0.1.0        # the published release
docker build -f app/Dockerfile --target runtime -t doom-candidate ./app
trivy image doom-candidate
grype doom-candidate --fail-on high
syft doom-candidate -o cyclonedx-json
```

Do not pass `--ignore-unfixed` or `--only-fixed`: an unavailable patch is still
a risk. CI runs the same gates on every push and uploads SARIF to the
repository's Security tab and the SBOM as a build artifact, which is where the
authoritative copies live.

The published `0.1.0` image is Debian-based and has open findings; the candidate
that supersedes it is Alpine-based and does not contain the affected packages.
That is recorded once, as `DEP-release-0.1.0`, rather than as one row per CVE.

## Current GitHub alerts

```sh
python3 tools/export_security_evidence.py --repo crow50/DOOM --output /tmp/doom-alerts
```

Exports code-scanning, Dependabot and secret-scanning alerts for whoever wants
to work with them offline. The output is deliberately not committed: GitHub is
the authority on its own alerts, and a snapshot in git is stale the moment a
scan runs. Secret-scanning exports carry metadata only, never a secret value.

## Writing a status

Read the full official requirement text, not a summary of it. Evidence must
support every clause for **Met**. **N/A** needs the specific technology or
feature to be genuinely absent, with the reason stated — a control that was
never built is Not met, not N/A. A gap needs a finding, and risk acceptance
goes in `exceptions.json` with an approver, an owner, an expiry and a
reassessment trigger; it never changes a status to Met.
