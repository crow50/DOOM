---
title: "Trivy: HIGH or CRITICAL vulnerability in the runtime image"
labels: security, dependencies, ci
assignees: crow50
---

The weekly Trivy scan of the runtime image failed on `{{ env.GITHUB_REF_NAME }}`.

- Run: {{ env.GITHUB_SERVER_URL }}/{{ env.GITHUB_REPOSITORY }}/actions/runs/{{ env.GITHUB_RUN_ID }}
- Commit: `{{ env.GITHUB_SHA }}`
- Findings: the Security tab, category `trivy-container-scan`

This is a scheduled run, so **nothing in the repository changed to cause it**.
A new CVE has been published against a package already in the image. Per
`docs/PIPELINE-NOTES.md`, the usual cause is a Debian advisory that has been
published but not yet fixed upstream, and the usual resolutions are to wait for
the fix, or to remove the package.

Do not silence the gate to close this issue.
