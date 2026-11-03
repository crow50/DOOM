---
title: "{{ env.GITHUB_WORKFLOW }}: scheduled run could not scan the image"
labels: ci
assignees: crow50
---

The weekly **{{ env.GITHUB_WORKFLOW }}** run on `{{ env.GITHUB_REF_NAME }}` failed
**before its scanner gave a verdict**. This is a pipeline failure, not a
vulnerability finding: the scan did not run, so nothing here says the image is
vulnerable *or* clean.

- Run: {{ env.GITHUB_SERVER_URL }}/{{ env.GITHUB_REPOSITORY }}/actions/runs/{{ env.GITHUB_RUN_ID }}
- Commit: `{{ env.GITHUB_SHA }}`

This is a scheduled run, so **nothing in the repository changed to cause it** -
something outside it did. Open the run and read the **first** red step; it names
the cause. The ones that have happened here:

- **A pinned upstream package stopped resolving.** Alpine keeps only the current
  build of each package, so `apk add curl=8.22.0-r0` fails the day the branch
  ships `curl-8.23.0-r0` (2026-10-25: every build of `app/Dockerfile` failed at
  once). Fix: stop pinning a build tool that Alpine will retire.
- **A fail-closed step rejected something that moved with no change here.**
  `tools/generate_runtime_vex.py` refused zlib `1.3.2-r1` because it had been
  written for `-r0`. Fix: bind the check to the property that was reviewed, not
  to a packaging revision.
- **A registry or network blip** while pulling or building. Re-run the job first.

The same build runs in `diff-and-make-test.yml`, the Trivy scan and the SBOM scan,
so if this is a build failure expect all three to be red for the one reason.

Do not silence a scanner gate to close this issue; fix the step that failed.
