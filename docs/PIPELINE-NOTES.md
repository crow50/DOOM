# DevSecOps roadmap

Out of scope for this build - to be wired up separately on GitHub. Listed in
order of value for a project like this, with what each would actually catch.

The codebase is laid out so adding these is configuration only; none of them
require restructuring.

---

## Tier 1 - the three worth doing first

### `gitleaks` as a pre-commit hook

Catches secrets before they enter history. A committed `.env` is the single
most common breach in a student or homelab project, and `git rm` does not
undo it - the value stays in the object store and has to be treated as
compromised.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks: [{ id: gitleaks }]
```

DOOM already helps here: `.gitignore` and `.dockerignore` exclude `.env`,
`*.pem` and `uploads/`, `make init` generates secrets rather than shipping
defaults, and `.env.example` holds placeholders that make the app refuse to
start. `gitleaks` is the backstop for the case none of that covers.

### `bandit` - Python SAST

Flags weak hashing, `shell=True`, `eval`, hardcoded credentials, disabled
certificate verification. Fast, no configuration needed.

```bash
bandit -r app/doom -ll
```

Expect one finding to need review rather than fixing: `security/passwords.py`
contains a module-level constant that looks like a hardcoded password. It is
the dummy Argon2 hash used to equalise login timing for unknown users - a
deliberate control, not a credential. Annotate it with `# nosec` and a comment
rather than silencing the rule globally.

### `pip-audit` - dependency CVEs

Every pinned version in `requirements.txt` is a snapshot that ages. This is
the cheapest control that catches a class of problem the code review cannot.

```bash
pip-audit -r app/requirements.txt
```

---

## Tier 2

### `semgrep`

Pattern SAST over your own code rather than dependencies.

```bash
semgrep --config p/flask --config p/owasp-top-ten app/
```

Worth running specifically for the rules covering string-formatted SQL,
`send_file` with request-derived paths, and missing CSRF - the three places
this application deliberately does the safe thing, so a regression should be
loud.

### `hadolint` - Dockerfile linting

Catches root users, unpinned base tags, and layer-cache mistakes that leave
secrets in an image.

### `trivy` - image and filesystem CVE scanning

```bash
trivy image doom-web --severity HIGH,CRITICAL
```

The base image is most of the attack surface and none of it is code you wrote.
`python:3.12.7-slim` is pinned, which makes results reproducible - and means
you must deliberately bump it to pick up fixes.

---

## Tier 3

### SBOM

```bash
syft doom-web -o cyclonedx-json > sbom.json
```

One command, and it answers "are we affected by X" in seconds rather than an
afternoon.

### Renovate

Automated dependency PRs. Converts pinning from a snapshot into a maintained
position, which is the difference between a project that was secure once and
one that stays secure.

### Hash-pinned installs

```bash
pip-compile --generate-hashes app/requirements.in -o app/requirements.txt
```

Upgrades version pinning into tamper-evidence: the exact artifact is verified,
not just its version number.

---

## A CI shape that works

```yaml
name: ci
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install bandit pip-audit
      - run: bandit -r app/doom -ll
      - run: pip-audit -r app/requirements.txt
      - run: make lint          # the |safe template grep
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16.4-alpine
        env: { POSTGRES_PASSWORD: ci, POSTGRES_USER: doom_admin, POSTGRES_DB: doom_test }
        options: >-
          --health-cmd pg_isready --health-interval 5s
          --health-timeout 5s --health-retries 10
    steps:
      - uses: actions/checkout@v4
      - run: make test
```

Fail the build on HIGH and CRITICAL. Anything lower becomes noise that gets
ignored, which is worse than not scanning.

---

## Already in the build

These are properties of the application rather than external tooling, so they
did not wait for a pipeline:

- **Threat model written before the code** - [THREAT-MODEL.md](THREAT-MODEL.md)
- **`make lint`** - greps templates for `|safe` and `Markup(`, failing the
  build if user data could bypass autoescaping
- **`make test`** - 74 tests pinning the security controls
- **Secrets generated, never shipped** - `make init` with `openssl rand`
- **Placeholders that fail closed** - the app refuses to start on `CHANGE_ME`
- **Pinned dependencies and base images**
- **`make backup` / `make restore`** - covering the database *and* the uploads
  volume, tested rather than assumed
