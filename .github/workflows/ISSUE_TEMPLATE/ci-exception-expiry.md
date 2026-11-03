---
title: "Security exception expiring or expired"
labels: security, ci
assignees: crow50
---

The weekly exception check found at least one accepted risk that has lapsed or
lapses within 30 days.

- Run: {{ env.GITHUB_SERVER_URL }}/{{ env.GITHUB_REPOSITORY }}/actions/runs/{{ env.GITHUB_RUN_ID }}
- The run log lists each one with the date and the days left. To see it locally:
  `python3 tools/security_assessment.py --expiring-within 30`

This is a clock check, so **nothing in the repository changed to cause it**.

What happens if nothing is done: a lapsed exception fails the release and publish
gates (`--release`, `--publish`), so no tagged release goes out. It does not fail
ordinary pull requests - it used to, on every branch at once, which is why this
check exists.

For each exception listed, decide one of two things:

1. **Close the finding** if what it was waiting for has shipped. Mark the finding
   `closed` with `residual_risk` `none`, remove its row from
   `docs/security/exceptions.json`, and record why in `docs/DECISIONS.md`. Check
   the exception's own `reassessment_trigger` first - it says what closes it.
2. **Renew it deliberately**: a new `expires` date with an approver and approval
   evidence for the *new* date (`docs/security/README.md`, "Writing a status").
   Renewing is a risk decision, not housekeeping, and an exception is not a
   status change.

Do not move the date without one of those.
