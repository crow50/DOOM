# DevSecOps pipeline

This file used to open "Out of scope for this build — to be wired up separately on
GitHub" and then describe, as a roadmap, tooling that had already been wired up.
Seven workflows, Renovate and hash-pinned installs landed in commits that did not
touch the documentation. An audit read the roadmap and reasonably concluded the
scanning did not exist.

So this is now a record of what runs, and a much shorter list of what does not.

---

## Shipped

| Tool | What it catches | Where | Runs on |
|---|---|---|---|
| **gitleaks** | Secrets entering history | [`gitleaks-secret-scanning.yml`](../.github/workflows/gitleaks-secret-scanning.yml) + [`.pre-commit-config.yaml`](../.pre-commit-config.yaml) | push, PR, and pre-commit |
| **bandit** | Weak hashing, `shell=True`, `eval`, hardcoded credentials | [`bandit-python-scanning.yml`](../.github/workflows/bandit-python-scanning.yml) | push and PR touching `app/`; **gates** on medium+ severity/confidence over `app/doom`, uploads full SARIF |
| **pip-audit** | Known CVEs in pinned dependencies | [`pip-audit.yml`](../.github/workflows/pip-audit.yml) | push and PR touching the lockfile; **gates** |
| **semgrep** | `p/flask` + `p/owasp-top-ten` over our own code | [`semgrep.yml`](../.github/workflows/semgrep.yml) | every push and PR; **gates** (`--error`) |
| **hadolint** | Dockerfile smells — root users, unpinned tags | [`hadolint-docker-linting.yml`](../.github/workflows/hadolint-docker-linting.yml) | push and PR touching `app/Dockerfile` |
| **trivy** | Image and OS-package CVEs; fails on HIGH/CRITICAL, uploads SARIF | [`trivy-image-scanning.yaml`](../.github/workflows/trivy-image-scanning.yaml) | push, PR |
| **syft** + **grype** | Third-party library inventory (CycloneDX SBOM), then known CVEs against it | [`sbom-scanning.yml`](../.github/workflows/sbom-scanning.yml) | push and PR touching `app/**` etc.; **gates** on HIGH+ unfixed, uploads the SBOM as a build artifact and SARIF to the Security tab |
| **Renovate** | Dependency currency — pinning as a maintained position, not a snapshot | [`renovate.json`](../.github/renovate.json) | scheduled |
| **Lockfile drift** | A hand-edited `requirements.txt` | [`diff-and-make-test.yml`](../.github/workflows/diff-and-make-test.yml) | every push and PR |
| **Hash-pinned installs** | A substituted artifact, not merely a wrong version | `app/requirements.txt` — every pin carries `--hash=sha256:` | every build |
| **`make lint`** | `\|safe` / `Markup(` in templates, and documentation drift | [`Makefile`](../Makefile), [`tools/check_docs.py`](../tools/check_docs.py) | every push and PR |
| **`make test`** | Every control in the ASVS ledger | `diff-and-make-test.yml` | every push and PR |

The strongest control in that list is the least obvious one: the lockfile check
recompiles `app/requirements.in` and diffs the result against the committed
`app/requirements.txt`, so a dependency cannot be added, removed or bumped without
the lockfile being regenerated properly.

### Why the lockfile check seeds its output file

`pip-compile` honours the pins already present in its output file unless
`--upgrade` is passed. The check originally compiled into an empty `/tmp` file,
which gave it nothing to honour, so it resolved every dependency to the latest
release on PyPI and compared that against the committed lockfile. That is not a
drift check — it fails whenever *upstream* moves, with nothing changed here, and
it did: `wrapt` 2.4.1 shipped between two runs and turned the build red.

Copying `app/requirements.txt` over `/tmp/requirements-hashed.txt` first makes it
ask the intended question — does the committed lockfile still satisfy
`requirements.in`? Keeping dependencies current is Renovate's job, and pip-audit
and Trivy are what fail the build on a pin that has become dangerous. pip-tools
itself is pinned for the same reason: an unpinned tool makes the check fail on
its own upgrade.

### A trigger bug worth remembering

`pip-audit` and `bandit` were originally filtered on `paths: ['**/app']`. That glob
matches a path *component* named exactly `app`, not the `app/` subtree — so
neither scan reliably fired, on `main` or anywhere else, and both were still being
cited as evidence that dependencies were scanned. Both now use `app/**` (and
`app/requirements*` for pip-audit) and both run on pull requests.

The lesson is not about globs. A control cited as evidence has to run where the
claim is checked, and nothing in the pipeline was verifying that.

The same class of bug outlived that fix in a quieter form. `trivy` and the SBOM
scan filtered on a repository-root `Dockerfile` and `.dockerignore` long after
the build context moved under `app/` and took both files with it. Nothing broke,
because `app/**` was also listed and covered them — but two of the five paths
guarding each scan could never match anything. A path filter naming a file that
does not exist is indistinguishable, from the outside, from one that works.

### Every workflow now declares a timeout and its token scope

Two bits of hygiene that were applied to one workflow each and never to the rest:

- **`timeout-minutes` on every job.** The default is six hours. `diff-and-make-test.yml`
  had been given a bound after a hung step burned an afternoon of runner time;
  the other seven workflows had not, and a hung `docker build` in the Trivy or
  SBOM job would have done exactly the same thing.
- **A least-privilege `permissions:` block on every workflow.** The scans that
  upload SARIF declared what they needed; the five that did not declare anything
  inherited the repository default token, which is broader than a checkout and a
  `pip install` require. Each workflow now names its scopes — `contents: read`
  for most, plus `security-events: write` where a SARIF file is uploaded,
  `pull-requests: write` for gitleaks' PR summary, and `packages: write` for the
  publish.

A `pull_request: branches: [main]` filter was also removed from `trivy`,
`hadolint` and `gitleaks`, finishing a change made to `sbom-scanning.yml`
alone: a pull request targeting any branch but `main` skipped those scans, and
the secret scan is the last check that should depend on where a branch is headed.

---

## Not shipped

One item, real, and recorded as a gap in
[COMPLIANCE.md](COMPLIANCE.md) rather than described here as future work.

### Antivirus scanning of uploads — ASVS 12.4.2, **Not met**

ClamAV as a sidecar, called from `security/uploads.py` before the store step.
Worth being precise about why the current position is not enough: images are fully
decoded and re-encoded, which destroys an embedded payload more reliably than a
signature scanner finds it — but PDF, text and Markdown uploads are stored byte
for byte, and 12.4.2 is a **Level 1** requirement that says "antivirus scanners".

---

## Deliberately not added

- **Coverage gates.** A percentage target rewards testing what is easy to reach.
  The suite exists to pin named controls, and the ledger names which test pins
  which requirement.
- **Severity thresholds below HIGH.** Fail on HIGH and CRITICAL. Anything lower
  becomes noise that gets ignored, which is worse than not scanning.
- **A dependency-review action.** Renovate plus pip-audit plus the lockfile diff
  already cover the same ground; a fourth opinion on the same change is friction
  without information.

---

## Notes for anyone extending this

**Which scanners can actually fail a build.** All of them, now — but two could
not until an external audit checked. `semgrep` exits 0 on findings unless
`--error` is passed, and a run on this branch reported "Findings: 1 (1 blocking)"
followed by a green check. `PyCQA/bandit-action` ends its command with `|| true`
and only uploads SARIF. Both are now invoked so that a finding is a red build:
`semgrep --error`, and `bandit -r app/doom -ll -ii` run directly. Bandit's
remaining Low-severity notes (`B105` on audit-label strings such as
`"Password changed"`, `B110` on the deliberate `except: pass` in the
timing-equalisation path) are below the gate and appear only in the SARIF report;
if one ever needs silencing, annotate the line with `# nosec` and a reason rather
than lowering the gate.

**Suppressions name the rule.** The one `# nosemgrep` in the codebase
(`cli.py`, the `REVOKE` in `db-grants`) carries the full rule id and a comment
saying why the interpolated identifier is safe. A bare `# nosemgrep` silences
every rule on that line and should not appear.

**Why the SBOM scan is one step, not two.** Trivy needs two invocations
because its `severity:` input filters what is *found*, not just the exit code
— the gate step only looks at HIGH/CRITICAL and a second, always-run step at
every severity feeds the SARIF upload. `anchore/scan-action`'s `severity-cutoff`
only decides `fail-build`; the SARIF it writes carries every severity grype
found regardless. One `grype` step, gated on HIGH-and-above with unfixed
findings ignored (parity with Trivy's `ignore-unfixed`, and for the same
reason — see I-9 in the 2026-09-12 audit), covers both the gate and the report.

**The runtime image ships no tests either.** `make test` builds and runs the
`test` stage of `app/Dockerfile` - the runtime image plus `tests/`, `pytest.ini`
and a venv with `requirements-dev.txt` installed. The runtime stage copies an
explicit allowlist and fails its own build if `import pytest` succeeds. Because
`test` is the Dockerfile's final stage, anything that builds without naming a
target gets it: compose, Trivy and the publish workflow all say `runtime`.

**The runtime image ships no pip.** It is removed in the runtime stage, along with
setuptools, `pkg_resources` and `ensurepip`. Nothing in the container installs
anything, and pip's *vendored* dependency tree was the source of every **Python**
CVE Trivy reported against this image — it vendors setuptools and msgpack, neither
of which this application imports. If you need to add a package, it goes in
`requirements.in` and the image is rebuilt. The `RUN` that strips them ends with an
import check, so the build fails immediately if something still wanted
`pkg_resources`. The **OS** packages are a separate surface — see the next note.

**The runtime image runs `apt-get upgrade`.** hadolint DL3005 says not to, and
the ignore is deliberate — see D-39. A pinned base tag freezes the OS packages at
whatever shipped the day that tag was last rebuilt, and Debian keeps publishing
security updates in between: a scan found twelve fixed CVEs (three CRITICAL) in
`perl-base`, `libsqlite3-0`, `libpcre2-8-0` and `gzip` on a commit that touched
only migrations and documentation. Pinning the fixed versions instead does not
work, because Debian's archive holds only the current version of each package and
an exact pin stops resolving the day it is superseded. So expect Trivy to go red
occasionally with nothing in the diff to explain it; the usual cause is a CVE
Debian has published but not yet fixed, and the usual fix is to wait or to remove
the package.

**Base images are version-pinned but not digest-pinned.** `python:3.14.7-slim`,
`postgres:18.6-alpine`, `redis:8.10.1-alpine` and `caddy:2.11.4-alpine` are
reproducible to a tag, not to a digest, so a re-pushed tag would go unnoticed.
Renovate keeps the versions current; digest pinning is the next increment.

**`make lint` runs `tools/check_docs.py`.** If you add an ASVS requirement to a
document, add its ledger row too — the check fails otherwise. That is deliberate:
this file being wrong for ten commits is what prompted it.
