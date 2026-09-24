# Evidence

Every file here is retained because something points at it. The rule is
enforced rather than intended: `tools/security_assessment.py` collects every
evidence path cited by a ledger row, a finding, an exception, a verification
check or a document, and fails if a file in this directory is not among them.
The exceptions are the raw exports a tool reads directly, which are listed in
`RAW_EXPORTS` in that module.

That rule exists because this directory had accumulated thirty-seven files
nothing referenced, including seven that were zero bytes long. An orphan is not
harmless: a reviewer who finds a log in an evidence directory reasonably
assumes some claim rests on it, and a pile of outputs nobody cites makes the
set that *is* load-bearing harder to find. Deleting an orphan is the usual fix;
citing it from the claim it supports is the other one, and is right more often
than it looks.

**Three files were removed rather than cited**, because nothing rested on them:
`migrations.txt` and `tests-candidate-pre-alpine.txt` were earlier runs of the
same checks that `migrations-final.txt` and `tests-candidate.txt` record, and
`candidate-debian-pre-alpine-sbom.json` was the 1.1 MB input to scans of a
Debian base image this project no longer builds. The scan *reports* for that
image are kept — they record findings — but the inventory they were generated
from supports nothing that can still be re-run.

Historic files are the exact results observed at the time and are not
regenerated. A scan re-run today produces different results against a newer
vulnerability database; that is a new observation with its own ID, not a
correction of an old one. See [README.md](../README.md) for how to reproduce
each class of evidence.

75 files, 6.8 MB.

| File | Size | Cited by |
|---|---:|---|
| `alert-refresh-delta.json` | 137 B | docs/security/RELEASE-ASSESSMENT.md |
| `analyses-pages.json` | 59.3 KB | docs/security/RELEASE-ASSESSMENT.md |
| `bandit-baseline.json` | 20.6 KB | finding code-scanning:445, finding code-scanning:446, finding code-scanning:762 (+3 more) |
| `bandit-candidate.json` | 20.6 KB | check `bandit` |
| `bandit-final.log` | 641 B | check `bandit` |
| `bandit-gate.log` | 1,001 B | check `bandit` |
| `candidate-amd64-preflight.txt` | 535 B | check `candidate-amd64-preflight` |
| `candidate-debian-pre-alpine-grype.json` | 709.0 KB | finding SCAN-candidate-006251c7ca7d4aec, finding SCAN-candidate-03970ba0bcc47088, finding SCAN-candidate-04714ea6f7c9d68d (+153 more) |
| `candidate-debian-pre-alpine-image.json` | 3.5 KB | finding SCAN-candidate-006251c7ca7d4aec, finding SCAN-candidate-03970ba0bcc47088, finding SCAN-candidate-04714ea6f7c9d68d (+153 more) |
| `candidate-debian-pre-alpine-trivy.json` | 801.4 KB | finding code-scanning:1, finding code-scanning:10, finding code-scanning:12 (+153 more) |
| `candidate-grype-db-status.json` | 326 B | check `candidate-image-scan` |
| `candidate-grype-unfiltered.json` | 35.6 KB | check `candidate-image-scan`, finding SCAN-candidate-alpine-29b74010ece718a2 |
| `candidate-grype.json` | 36.2 KB | ASVS 5.0.0 1.4.1, ASVS 5.0.0 15.2.1, check `candidate-image-scan` (+10 more) |
| `candidate-image-amd64-ci.json` | 4.6 KB | check `candidate-amd64-ci`, check `candidate-image-scan`, docs/security/RELEASE-ASSESSMENT.md |
| `candidate-image.json` | 3.6 KB | raw export — read by `tools/security_assessment.py` |
| `candidate-runtime-zlib.vex.json` | 1.3 KB | check `runtime-zlib-backport`, finding SCAN-candidate-alpine-29b74010ece718a2 |
| `candidate-sbom.json` | 474.7 KB | ASVS 5.0.0 1.4.1, ASVS 5.0.0 15.1.2, ASVS 5.0.0 15.2.1 (+10 more) |
| `candidate-trivy-db-metadata.json` | 153 B | check `candidate-image-scan` |
| `candidate-trivy-high-gate.json` | 113.3 KB | check `candidate-image-scan` |
| `candidate-trivy.json` | 113.3 KB | ASVS 5.0.0 15.2.1, check `candidate-image-scan` |
| `candidate-zlib-runtime-verify.txt` | 170 B | check `runtime-zlib-backport`, finding SCAN-candidate-alpine-29b74010ece718a2 |
| `candidate-zlib-scan-metadata.json` | 4.3 KB | check `candidate-image-scan`, check `runtime-zlib-backport` |
| `code-scanning-pages.json` | 519.2 KB | raw export — read by `tools/security_assessment.py` |
| `codeql.sarif` | 253.0 KB | check `codeql-candidate`, finding code-scanning:781, finding code-scanning:782 (+1 more) |
| `dependabot-pages.json` | 170.1 KB | raw export — read by `tools/security_assessment.py` |
| `deployment-final.json` | 1.5 KB | ASVS 5.0.0 12.3.1, check `deployment`, finding CONTROL-v5.0.0-12.3.1 |
| `deployment-inspect.json` | 3.3 KB | check `deployment` |
| `deployment.txt` | 1.5 KB | ASVS 4.0.3 2.10.2, docs/security/RELEASE-ASSESSMENT.md |
| `docs-check.log` | 247 B | check `documentation` |
| `final-container-review.log` | 187 B | check `container-suite` |
| `gitleaks-candidate.json` | 3 B | check `secret-scan` |
| `gitleaks-candidate.log` | 180 B | ASVS 5.0.0 13.2.3 |
| `gitleaks-history.json` | 3 B | check `secret-scan` |
| `gitleaks-history.log` | 256 B | check `secret-scan` |
| `make-lint.log` | 325 B | check `documentation` |
| `migrations-final.txt` | 2.0 KB | check `container-suite` |
| `pip-audit-final.log` | 265 B | check `dependency-scan` |
| `pip-audit.json` | 2.3 KB | check `dependency-scan`, finding dependabot:1, finding dependabot:10 (+25 more) |
| `pixels-before.txt` | 2.0 KB | finding REV-006 |
| `proxy-before.txt` | 2.2 KB | finding REV-005 |
| `proxy-client-ip.txt` | 1.8 KB | ASVS 5.0.0 15.3.4, ASVS 5.0.0 4.1.3, docs/security/POLICIES.md |
| `proxy-edge-headers.txt` | 2.7 KB | ASVS 5.0.0 11.2.3, ASVS 5.0.0 11.3.1, ASVS 5.0.0 11.3.2 (+9 more) |
| `proxy-final.json` | 2.1 KB | check `deployment` |
| `proxy-headers.txt` | 908 B | ASVS 4.0.3 3.4.4, ASVS 5.0.0 3.3.1, ASVS 5.0.0 3.3.2 (+2 more) |
| `proxy-restart-502.txt` | 179 B | finding REV-010 |
| `referrer-before.txt` | 1.5 KB | finding REV-004 |
| `regressions-before.txt` | 9.1 KB | finding code-scanning:758, finding code-scanning:759, finding code-scanning:760 |
| `release-gate.log` | 63.2 KB | check `release-image-scan` |
| `release-grype.json` | 709.6 KB | check `release-image-scan`, finding SCAN-release-02217e62bc382d00, finding SCAN-release-04d2a8fb4fd223fd (+158 more) |
| `release-image.json` | 3.9 KB | check `published-release-execution`, docs/security/RELEASE-ASSESSMENT.md, finding SCAN-release-02217e62bc382d00 (+155 more) |
| `release-sbom.json` | 1.1 MB | check `release-image-scan` |
| `release-trivy.json` | 800.8 KB | check `release-image-scan`, finding code-scanning:1, finding code-scanning:10 (+154 more) |
| `repository-security-settings.json` | 341 B | docs/security/RELEASE-ASSESSMENT.md |
| `revisions.json` | 314 B | docs/security/RELEASE-ASSESSMENT.md |
| `roles-final.txt` | 296 B | ASVS 5.0.0 13.2.2, ASVS 5.0.0 16.4.2, finding CONTROL-v5.0.0-16.4.2 |
| `runner-final.json` | 778 B | check `deployment` |
| `runtime-reachability.txt` | 365 B | docs/security/RELEASE-ASSESSMENT.md, finding code-scanning:169, finding code-scanning:170 (+34 more) |
| `scanners.json` | 5.4 KB | docs/security/README.md, docs/security/RELEASE-ASSESSMENT.md |
| `secret-scanning-pages.json` | 9 B | raw export — read by `tools/security_assessment.py` |
| `secrets-final.txt` | 293 B | ASVS 5.0.0 11.1.1, ASVS 5.0.0 13.3.1, ASVS 5.0.0 13.3.2 (+2 more) |
| `semgrep-final.log` | 1.9 KB | check `semgrep` |
| `semgrep.json` | 22.1 KB | check `semgrep` |
| `source-availability.json` | 310 B | raw export — read by `tools/security_assessment.py` |
| `test-count-final.txt` | 147 B | check `container-suite` |
| `tests-candidate.txt` | 1.6 KB | ASVS 4.0.3 12.3.1, ASVS 4.0.3 2.1.1, ASVS 4.0.3 2.1.3 (+39 more) |
| `tests-l2-candidate.txt` | 1.6 KB | check `container-suite` |
| `tool-tests.log` | 1.9 KB | check `documentation` |
| `trivy-db.json` | 152 B | check `release-image-scan` |
| `updated-main/analyses-pages.json` | 149.6 KB | raw export — read by `tools/security_assessment.py` |
| `updated-main/code-scanning-pages.json` | 520.1 KB | raw export — read by `tools/security_assessment.py` |
| `updated-main/dependabot-pages.json` | 170.1 KB | raw export — read by `tools/security_assessment.py` |
| `updated-main/latest-main-analyses.json` | 4.8 KB | raw export — read by `tools/security_assessment.py` |
| `updated-main/secret-scanning-pages.json` | 9 B | raw export — read by `tools/security_assessment.py` |
| `updated-main/source-availability.json` | 311 B | raw export — read by `tools/security_assessment.py` |
| `workflow-syntax.log` | 19 B | check `documentation` |
