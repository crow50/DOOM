# Remediation batches and acceptance specifications

No exceptions are approved. Suggested responsibility below identifies the work
queue, not acceptance on behalf of an owner.

| Priority | Batch | Responsible role | Acceptance criteria |
|---|---|---|---|
| P0 | Share credential revocation and log leakage | Application maintainer | Before tests reproduce; candidate denies old PIN approval after PIN/token changes and never logs encoded capability referrers; inspect cookie to ensure no PIN verifier is disclosed |
| P0 | Complete advisory/release review | Release maintainer | Account for all exported and new scan IDs against exact release/candidate digests; document each impact/path; unresolved potentially blocking matches remain blockers |
| P1 | Redirect, lookup error and proxy trust | Application maintainer | No accepted redirect contains control/backslash ambiguity; errors expose no internal sentinel; attacker forwarded port cannot override proxy host |
| P1 | Upload processing | Application maintainer/operator | Enforce pixel ceiling before decode; retain authorization and byte caps; specify antivirus quarantine/failure behavior, scan all served untrusted documents, test scanner unavailable/timeout/malicious/clean cases before enabling that feature |
| P1 | Lookup transport | Application maintainer | Pin actual socket destination to validated public addresses, preserve hostname verification/SNI, refuse redirect/private/IPv6 special addresses and environment proxy bypass; test DNS rebinding and streaming resource limits |
| P1 | Build/scan/release evidence | CI maintainer | Unfixed/unknown findings remain visible, scan failures/skips never imply clean, fresh candidate source analysis and image scans are retained; publishing promotes the exact verified image |
| P2 | Account/session gaps | Product and security owners | Specify MFA and recovery, context password screening and session inactivity/concurrency policy from applicable v4/v5 requirements; define misuse tests before choosing APIs/schema |
| P2 | Deployment gaps | Operator | Produce certificate, storage/backup encryption, restore, clock, centralized log, key rotation and internal TLS evidence; test with restricted DB role and through proxy |
| P2 | ASVS full reassessment | Security reviewer | Complete each Not assessed row independently against full text; recheck historical N/A and mapped/split v5 requirements; met evidence must address every clause |

Lower residual risks need an explicit named owner, approval evidence, expiry and
reassessment trigger in `exceptions.json`. Triggers include new exploit evidence,
package/base image changes, network/privilege changes and enabling lookup or new
sharing/upload behavior. Expiry never changes compliance status to Met.
