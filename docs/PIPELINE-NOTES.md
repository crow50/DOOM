# DevSecOps pipeline

Current release decisions are governed by the
[security assessment](security/RELEASE-ASSESSMENT.md), not a green scanner count.
Unfixed findings are now included in both image gates. No blanket OS risk
acceptance applies. Tag publication runs the evidence release preflight.
Semgrep strict mode preserves parse errors/skipped paths in an artifact; a
partial parse is a coverage gap, not a clean source review.

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
| **gitleaks** | Secrets entering history | [`gitleaks-secret-scanning.yml`](../.github/workflows/gitleaks-secret-scanning.yml) + [`.pre-commit-config.yaml`](../.pre-commit-config.yaml) | push, PR, and pre-commit; uploads SARIF |
| **bandit** | Weak hashing, `shell=True`, `eval`, hardcoded credentials | [`bandit-python-scanning.yml`](../.github/workflows/bandit-python-scanning.yml) | push and PR touching `app/`; **gates** on medium+ severity/confidence over `app/doom`, uploads full SARIF |
| **pip-audit** | Known CVEs in pinned dependencies | [`pip-audit.yml`](../.github/workflows/pip-audit.yml) | push and PR touching the lockfile; **gates** |
| **semgrep** | `p/flask` + `p/owasp-top-ten` over our own code | [`semgrep.yml`](../.github/workflows/semgrep.yml) | every push and PR; **gates** (`--error`) |
| **hadolint** | Dockerfile smells — root users, unpinned tags | [`hadolint-docker-linting.yml`](../.github/workflows/hadolint-docker-linting.yml) | push and PR touching `app/Dockerfile` |
| **trivy** | Image and OS-package CVEs; fails on HIGH/CRITICAL, uploads SARIF | [`trivy-image-scanning.yaml`](../.github/workflows/trivy-image-scanning.yaml) | push, PR, and **weekly** |
| **syft** + **grype** | Third-party library inventory (CycloneDX SBOM), then known CVEs against it | [`sbom-scanning.yml`](../.github/workflows/sbom-scanning.yml) | push and PR touching `app/**` etc., and **weekly**; **gates** on HIGH+, including unfixed, uploads the SBOM as a build artifact and SARIF to the Security tab |
| **Renovate** | Dependency currency — pinning as a maintained position, not a snapshot | [`renovate.json`](../.github/renovate.json) | scheduled |
| **Lockfile drift** | A hand-edited `requirements.txt` | [`diff-and-make-test.yml`](../.github/workflows/diff-and-make-test.yml) | every push and PR |
| **Hash-pinned installs** | A substituted artifact, not merely a wrong version | `app/requirements.txt` — every pin carries `--hash=sha256:` | every build |
| **`make lint`** | `\|safe` / `Markup(` in templates, and the ASVS ledger against the code it cites | [`Makefile`](../Makefile), [`tools/security_assessment.py`](../tools/security_assessment.py) | every push and PR |
| **`make test`** | Executable application regressions; operator and unassessed controls require separate evidence | `diff-and-make-test.yml` | every push and PR |

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

## Releasing

Images publish to `ghcr.io/crow50/doom-organizer` from
[`build-and-push-container.yml`](../.github/workflows/build-and-push-container.yml).

Development branches build images. Release tags promote a previously reviewed
immutable registry reference after verifying its image/config ID; they do not
rebuild after approval. The current assessment has no approved registry
candidate. See [the review procedure](security/README.md) for evidence fields
and the publication gate.

| Tag | What it is |
|---|---|
| `:0.1.0` | An exact release, from a `v0.1.0` git tag |
| `:0.1` | The newest patch of that minor line |
| `:latest` | The newest **release** - not the newest commit |
| `:main` | The current default branch |
| `:main-<sha>` | One specific commit on main |

After the evidence release gate passes, to cut a release: bump `__version__` in `app/doom/__init__.py`, commit, then tag
`v<that version>` and push the tag.

### The tag and `__version__` must agree

`make verify-version` compares the two and the publish workflow runs it, before
the build, on every tag push. A container tagged `v0.2.0` that logs `0.1.0` at
startup is lying about itself in the one field an operator would use to work out
what they are running, and nothing else in this pipeline would notice - it is not
a vulnerability, so no scanner looks for it, and both files are individually
valid. This is the same reasoning as the ledger validator: two places state the
same fact, so something has to fail when they disagree.

The check is also the reason the version bump is a *commit* and not part of the
tagging step. The tag points at a commit; `__version__` has to already be right
in that commit.

### Why `:latest` follows releases rather than main

It used to follow the default branch, which meant `docker pull ...:latest` gave
you whatever merged most recently. For something people self-host, `:latest`
should mean the newest deliberate release. Main has not gone away - it is `:main`.

### Why there is no `:0` tag

`type=semver,pattern={{major}}` is deliberately absent while the version is
`0.x`. Under SemVer, major version zero carries no compatibility promise
whatsoever, so a `:0` tag spanning `0.1.0` through `0.9.0` would advertise a
stability that the versioning scheme explicitly disclaims. Add it at `1.0.0`,
where it starts to mean something.

### Why the publish trigger has no `paths` filter

A `paths` filter on a `push` trigger applies to tag pushes too. With one in
place, tagging a release on a commit that touched only `docs/` would match
nothing and publish no image - a release that silently does not exist. Rebuilding
main on a docs-only commit is the cheaper mistake, and the `type=gha` cache makes
it nearly free.

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

**The runtime image runs `apk upgrade`, and no Alpine package in `app/Dockerfile` is
version-pinned.** A pinned base tag freezes the OS packages at whatever shipped the
day that tag was last rebuilt, and the distro keeps publishing security fixes in
between, so the runtime stage takes the branch's current packages at build time (D-39
records the same decision from when this image was Debian-based). Pinning the fixed
versions instead does not work: Debian's archive and Alpine's repositories both hold
only the current build of each package, so an exact pin stops resolving the day it is
superseded. That is not hypothetical - `curl=8.22.0-r0` did it on 2026-10-25 and every
build of the image failed at once. hadolint DL3018 ("pin versions in `apk add`") is
therefore ignored, with the reason beside it in the Dockerfile. What stays pinned is
what can be verified: the base image digest, the hash-pinned requirements, and the
zlib source (a commit and its SHA-256). So expect Trivy to go red occasionally with
nothing in the diff to explain it; the usual cause is a CVE the distro has published
but not yet fixed, and the usual fix is to wait or to remove the package.

**Every action is pinned to a commit SHA.** `uses: actions/checkout@v6` trusts
whatever `v6` points at *today*: a tag is a mutable pointer the publisher can
move, and moving it is the shape of a real supply-chain attack rather than a
hypothetical one. Every `uses:` in this directory therefore names a 40-character
SHA with the release it corresponds to in a trailing comment - the SHA is what
runs, the comment is for humans. The worst offender before this was
`anchore/sbom-action@v0`, a floating *major* tag: every release of that action
for the life of v0 would have been picked up silently, inside the job that
generates the dependency inventory.

Renovate maintains these: `helpers:pinGitHubActionDigests` bumps the SHA and
rewrites the comment together, so the two cannot drift apart. Do not "tidy" a
pin back to a tag.

**Renovate batches its pull requests.** It opens them on Monday mornings (New
York time), and an individual update waits until the release is three days old,
so a yanked or compromised release has time to be pulled first. Non-major action
bumps arrive as one pull request. `anchore/sbom-action` and `anchore/scan-action`
always arrive together, majors included: syft writes the SBOM that grype reads,
and a newer syft can emit a CycloneDX version an older grype rejects as "sbom
format not recognized". Bumping the first alone turned the SBOM scan red once.

Python pins move through one weekly lock-file-maintenance pull request, which
deletes each lockfile and recompiles it from its `.in` file; it takes whatever is
current, so the three-day wait does not apply to it. That depends on Renovate's
`pip-compile` manager reading the command out of each lockfile's header and
accepting every option in it. It does not accept `--no-index`, and skips any file
whose header carries it. The plain `pip_requirements` manager is switched off so
that the two do not update the same file twice, which means a skipped lockfile
gets no Python updates at all. Regenerate a lockfile with exactly the command its
header shows.

**Base images are version-pinned but not digest-pinned.** `python:3.14.7-slim`,
`postgres:18.6-alpine`, `redis:8.10.1-alpine` and `caddy:2.11.4-alpine` are
reproducible to a tag, not to a digest, so a re-pushed tag would go unnoticed.
This is the same hole the action pins above just closed, still open one layer
down; Renovate keeps the versions current, and digest pinning is the next
increment.

**The weekly scans exist because the repository is not the only thing that
changes.** Trivy and the SBOM scan run on a cron as well as on push and pull
request. Both gate on CVEs in code that a commit here need not have touched -
a Debian advisory, or a new CVE against a pinned library - so without a schedule
they are only consulted when somebody happens to edit `app/**`, which for a
finished image can be never. A scheduled failure opens an issue
(`update-existing: true`, so one issue rather than a weekly pile) because a red
check at 06:00 Monday with no pull request attached notifies nobody. Those two
jobs are the only ones holding `issues: write`.

The issue templates live in `.github/workflows/ISSUE_TEMPLATE/`, which looks
misplaced and is not: `JasonEtco/create-an-issue` resolves `filename` from the
workflow directory, and templates moved one level up to `.github/ISSUE_TEMPLATE/`
are not found. GitHub only discovers workflows from `.yml`/`.yaml` files sitting
directly in `.github/workflows/`, so a subdirectory of Markdown is inert there.

**Several checks going red together is one cause, not several.** Every workflow that
builds `app/Dockerfile` (the `test` job, Trivy, the SBOM scan) runs the same build,
and the ledger validator runs in both the unit tests and `make lint`. So one change
outside the repository fails all of them at once - on `main`, on the weekly schedule
and on every open branch. It happened four times in October, each with nothing in the
diff to explain it:

| When | What moved | What broke | Failed jobs |
|---|---|---|---:|
| Oct 11-25 | Alpine zlib `1.3.2-r0` -> `-r1`, via `apk upgrade` | `generate_runtime_vex.py` required `-r0` exactly | 74 |
| Oct 12-25 | lockfiles regenerated by bots on `renovate/` and `dependabot/` branches | the lockfile drift diff: comment-only on Renovate's (checked on Oct 25), real hash drift on Dependabot's | 10 |
| Oct 25 on | Alpine `curl-8.22.0-r0` -> `8.23.0-r0` | `apk add curl=8.22.0-r0` | 30 |
| Oct 27 on | the calendar | `EXC-DEP-release-0.1.0` expired and the validator errored | 2, then every run |

The curl failure also hid the VEX one: the image stopped building before it reached
that step, so fixing the pin alone would have turned everything red again.

What is in place, and the rule each one stands for:

- **Do not pin what the upstream retires.** Pin what can be verified (a digest, a
  hash, a commit and its SHA-256), not a package build the repository will outlive.
- **A fail-closed check keys on the property that was reviewed**, not on a packaging
  detail that moves by itself. The zlib VEX is bound to the upstream release and the
  distro; an Alpine `-rN` revision is accepted, a new upstream release still fails.
- **A check that depends on the clock never gates unrelated work.** A lapsed
  exception fails `--release` and `--publish`; elsewhere it is a warning, and the
  weekly `exception-expiry` workflow opens an issue 30 days ahead.
- **A scheduled failure says whether the scanner found something or never ran.** A
  skipped gate step means an earlier step broke, and that opens the "could not scan"
  issue, not the "new CVE" one. Issues #161 and #162 blamed a CVE for a broken
  `apk add`.

Still exposed, so the next one is not a surprise:

- `clamav/Dockerfile` pins `clamav=1.4.6-r0` on purpose: `clamav/clamav-vex.json` is
  bound to those exact package URLs. When Alpine 3.24 ships its next build, that
  `apk add` fails in all three workflows. The fix is to bump the pin *and* re-review
  the VEX, which is why it is not simply unpinned.
- The eleven remaining exceptions all expire on 2026-12-26. Stagger the dates when
  they are renewed, so one day does not carry all of them.
- Dependabot and Renovate both manage `app/requirements.txt`. Dependabot edits it
  directly while `requirements.in` is unchanged, so its pull requests fail the drift
  check, correctly. That is a repository setting rather than a file here.
- The three image workflows each build the image separately. A reusable workflow
  that builds once would make a build failure one red check instead of three.

**`make lint` runs `tools/security_assessment.py`.** If you cite an ASVS
requirement in a document it has to be a real one, and every row's evidence has
to exist — the check fails otherwise. That is deliberate: this file being wrong
for ten commits is what prompted it.
