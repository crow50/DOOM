# Hosted-service readiness

**Future scope: no public host is defined.** The user confirmed that current
operation is local and non-local hosting is future state. This assessment covers
future public self-hosting and hosted service requirements; it adds no hosted
architecture or application APIs. No hosted-service readiness claim is made.

| Area | Self-hosting assumption that stops holding | Evidence required before hosting |
|---|---|---|
| Tenant isolation | A trusted household/operator controls one database and runtime | Full route and background-task tenant matrix; negative tests through the real proxy and restricted role; isolation for exports, blobs, dedup, queues and caches; concurrency tests |
| Operator access | Host administrator is trusted with all inventory, location and credentials | Named operator identities, least privilege, MFA, approvals for data access, tamper-resistant audit and break-glass drill |
| Account takeover and recovery | Local operator can assist; no recovery delivery service | Verified recovery channel, identity proofing, anti-enumeration and abuse controls, factor enrollment/recovery, token expiry and session revocation tests |
| Abuse and availability | Trusted registration and a small population | Registration abuse controls, per-tenant and global quotas, race-safe quota enforcement, upload isolation/scanning, sustained load and rate-limit tests, incident response |
| Sharing | Physical labels and owner-managed tokens | Demonstrated immediate revocation, PIN/token change invalidation, time limits and intentional sharing scope; credential redaction through every proxy/log processor |
| Privacy and deletion | Operator determines retention and stores their own data | Data inventory, purposes/retention policy, user notices, authenticated export/deletion workflow, backup aging and surviving audit-data rationale; independent legal review where needed |
| Backups and restoration | Operator owns backups and host storage | Encrypted off-site backup, managed keys, tested restoration with tenant boundaries preserved, RPO/RTO, retained immutable copy and restoration access audit |
| Monitoring and response | Operator reads container output | Centralized protected logs, synchronized UTC clocks, tested alerts for account takeover/abuse/secret exposure, on-call ownership and incident drills |
| Managed secrets | Compose files under a trusted host directory suffice | Workload identities, scoped secret store, rotation/revocation drills, key lifecycle inventory, separation of deployment and data-access roles |
| Network and cryptography | Internal Docker network is treated as a trust boundary | Authenticated encrypted internal connections, controlled egress, certificate lifecycle, proxy topology tests and independent host hardening review |
| Release assurance | Maintainer rebuilds and manually checks a stack | One immutable artifact tested/scanned/promoted, provenance and SBOM, fresh vulnerability review, signed risk acceptance, rollback/restore exercise |

The ledgers' conditional N/A decisions must be revisited when federation, email,
OTP, external storage, queueing or other hosted features are introduced. Lack of
those systems does not waive required MFA, account recovery or log monitoring.
