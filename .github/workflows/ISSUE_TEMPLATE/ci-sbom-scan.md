---
title: "grype: HIGH or CRITICAL vulnerability in the SBOM"
labels: security, dependencies, ci
assignees: crow50
---

The weekly SBOM scan failed on `{{ env.GITHUB_REF_NAME }}`.

- Run: {{ env.GITHUB_SERVER_URL }}/{{ env.GITHUB_REPOSITORY }}/actions/runs/{{ env.GITHUB_RUN_ID }}
- Commit: `{{ env.GITHUB_SHA }}`
- Findings: the Security tab, category `grype-sbom-scan`
- Inventory: the `doom-organizer-sbom.cyclonedx.json` artifact on the run above

This is a scheduled run, so **nothing in the repository changed to cause it**.
A new CVE has been published against a third-party library already pinned in
`app/requirements.txt`. The gate gates on fixed findings only (`only-fixed`), so
a fix exists: bump the pin in `app/requirements.in`, then recompile the lockfile
**from the repository root** so the drift check in `diff-and-make-test.yml`
agrees with it:

```
pip install 'pip-tools==7.6.1'
pip-compile --generate-hashes app/requirements.in -o app/requirements.txt
```

Do not silence the gate to close this issue.
