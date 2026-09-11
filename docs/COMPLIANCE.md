# Standards mapping

An exhaustive control ledger against **[OWASP ASVS 4.0.3][asvs]** — every Level 1
and Level 2 requirement in all fourteen chapters, each with a status, evidence you
can open, and its ASVS-assigned CWE. 253 rows, because that is how many L1/L2
requirements 4.0.3 contains.

[asvs]: https://github.com/OWASP/ASVS/tree/v4.0.3/4.0/en

## Why it is shaped like this

An earlier revision of this document was a curated table of controls that were
working. An external audit pointed out what that shape cannot do, and it was
right on every count:

- A mapping that lists only wins **cannot support a level claim.** Nothing in it
  enumerated what "Level 1 in full" would require, so nothing could show the
  claim was met. V2.1.8 (password strength meter, L1) was simply absent — neither
  claimed, nor marked inapplicable, nor listed as a gap.
- The same requirement appeared **as met in §1 and as a gap in §4** (14.2.1),
  which is a contradiction, not a nuance.
- Some rows credited controls to things that were not there. 5.2.1 cited an `nh3`
  allowlist "for Markdown"; `nh3` was a pinned dependency that no module ever
  imported, and there is no Markdown rendering to sanitise.
- Requirements were paraphrased into weaker forms than the standard uses. 14.2.1
  became "no known-vulnerable components"; 12.4.2, which says *antivirus
  scanners*, became "content scanned **or neutralised**" — and a re-encode was
  offered against it.
- "No IDOR" is a universal negative. A helper existing does not prove that every
  route calls it.

So the ledger is now generated from the requirement list rather than assembled
from the implementation, exhaustive by construction, and the gap table below is
**derived from it** rather than maintained beside it. `make lint` fails if the two
disagree, if any document cites a requirement absent from the ledger, or if more
than one file publishes a test count.

## How to read a status

The distinction that matters is the last one: an argument that the *risk* is
handled is not the same as meeting the requirement, and is never counted as
meeting it.

| Status | Meaning |
|---|---|
| **Met** | Implemented. The evidence column names a file, a line, or a test |
| **Partial** | Implemented in part. The row says what is missing |
| **Compensating** | The literal requirement is **not** implemented. Something else addresses the risk it describes, named in the row. A verifier is free to disagree — that is why these are counted separately rather than folded into Met |
| **Not met** | A gap |
| **N/A** | Out of scope for this application, with the reason. A mapping in which everything applies is not a mapping |

## Where that leaves the claim

| Level | Requirements | Met | Partial | Compensating | Not met | N/A |
|---|---:|---:|---:|---:|---:|---:|
| **L1** | 127 | 100 | 2 | 1 | 3 | 21 |
| **L2** | 126 | 65 | 15 | 5 | 10 | 31 |
| **L1 + L2** | 253 | 165 | 17 | 6 | 13 | 52 |

Stated as plainly as the numbers allow:

- **Level 1 is not met in full.** 100 of 127 met, 21 not applicable, and **six
  exceptions**: 2.2.3 and 2.5.5 (no notification channel exists at all), 12.4.2
  (no antivirus scanning of uploads), 5.2.6 (a DNS-rebinding window in the
  optional lookup), 13.1.3 (a share token is a secret that travels in a URL) and
  8.3.3 (no privacy notice in the interface). Each is argued in §1.
- **Level 2 is not met in full.** 65 of 126 met, 31 not applicable, and 30
  exceptions — most consequentially 1.9.1, 1.9.2 and 9.2.2 (no TLS between
  containers), 1.7.2 (logs are not shipped off-host), 14.2.5 (no SBOM) and 2.3.2
  (no second-factor enrollment path).
- **Level 3 is not claimed,** and no L3 row appears below. L3 expects segregation
  of duties, phishing-resistant multi-factor authentication, HSM-backed key
  management and independent verification, none of which this deployment has.

The previous revision claimed "L1 met in full" and "L2 met, with two requirements
answered by compensating controls". Both were overstated: L1 had three unmet
requirements, and the L2 exceptions numbered thirty rather than two.

> **A correction, and a correction to the correction.** An earlier revision said
> missing MFA was "the largest gap against L2", then corrected itself to say MFA
> is purely an L3 concern because V2.2.4 (phishing resistance) is L3. That
> correction was itself wrong. **V2.3.2 is Level 2** and asks that "enrollment and
> use of user-provided authentication devices are supported, such as a U2F or FIDO
> token". It does not require MFA to be mandatory, but it does require the
> capability, and DOOM has no enrollment path at all. Being single-factor is
> therefore an L2 gap *and* an L3 one. It is recorded as **Not met** at 2.3.2.

---

## 1. Exceptions — every row that is not Met and not N/A

Derived from the ledger in §2. If a requirement is listed here it is because its
ledger row says so, and `tools/check_docs.py` fails the build if this table and
those rows ever disagree.

<!-- exceptions:begin -->

| ASVS | L | Status | Requirement | Why not, and what stands in its place |
|---|:--:|---|---|---|
| 1.1.2 | 2 | Partial | Verify the use of threat modeling for every design change or sprint planning to identify ... | `THREAT-MODEL.md` (47 threats) written once before the code, not revisited per design change |
| 1.1.3 | 2 | Partial | Verify that all user stories and features contain functional security constraints, such as "As ... | Security constraints recorded per decision in `DECISIONS.md`; no user-story artifact exists to carry them |
| 1.1.7 | 2 | Partial | Verify availability of a secure coding checklist, security requirements, guideline, or policy ... | `docs/SECURITY.md` + `DECISIONS.md` serve the purpose; no separate secure-coding checklist |
| 1.2.2 | 2 | Partial | Verify that communications between application components, including APIs, middleware and data ... | `db` and `cache` require passwords (`app/entrypoint.sh:21,27`) but the channel itself is unauthenticated - see 1.9.2 |
| 1.6.1 | 2 | Partial | Verify that there is an explicit policy for management of cryptographic keys and that a ... | Secrets are file-mounted and regenerable via `make init`; no formal key lifecycle or management standard |
| 1.6.2 | 2 | Compensating | Verify that consumers of cryptographic services protect key material and other secrets by ... | Docker secrets as mounted files, never the environment (`config.py`); no key vault. Argued, not implemented |
| 1.7.2 | 2 | Compensating | Verify that logs are securely transmitted to a preferably remote system for analysis, ... | stdout JSON is what a collector consumes, and the audit trail is hash-chained in Postgres - but nothing ships off-host. Not implemented |
| 1.8.2 | 2 | Partial | Verify that all protection levels have an associated set of protection requirements, such as ... | Assets classified, but no per-level retention or encryption requirement is written down |
| 1.9.1 | 2 | **Not met** | Verify the application encrypts communications between components, particularly when these ... | All three internal hops are plaintext: `caddy->web` (`caddy/Caddyfile:34`), `web->db` and `web->cache` (`app/entrypoint.sh:21,27`) |
| 1.9.2 | 2 | **Not met** | Verify that application components verify the authenticity of each side in a communication ... | No component authenticates the other side of a link; passwords authenticate the client only |
| 1.10.1 | 2 | Partial | Verify that a source code control system is in use, with procedures to ensure that check-ins ... | Git with a documented history; check-ins are not tied to issues or change tickets |
| 2.2.3 | 1 | **Not met** | Verify that secure notifications are sent to users after updates to authentication details, ... | Nothing notifies the user of a credential change. Other sessions are invalidated (T-06), which is containment, not notification |
| 2.3.2 | 2 | **Not met** | Verify that enrollment and use of user-provided authentication devices are supported, such as ... | No enrollment path for user-provided authenticators (U2F/FIDO). Single-factor by design - and this is an L2 requirement, not only the L3 2.2.4 |
| 2.4.5 | 2 | **Not met** | Verify that an additional iteration of a key derivation function is performed, using a salt ... | No secret-salt (pepper) iteration is performed. Would require a key store the deployment does not have |
| 2.5.5 | 1 | **Not met** | Verify that if an authentication factor is changed or replaced, that the user is notified of ... | Same gap as 2.2.3 - no notification channel exists |
| 4.3.3 | 2 | Partial | Verify the application has additional authorization (such as step up or adaptive ... | Session revocation re-asks for the password (`blueprints/account.py:176`); other destructive actions have no step-up |
| 5.2.6 | 1 | Partial | Verify that the application protects against SSRF attacks, by validating or sanitizing ... | User URLs are never fetched (D-13); the optional lookup is pinned to a code-level provider list and refuses redirects (D-32). A resolve-then-connect rebinding window remains |
| 6.1.1 | 2 | Compensating | Verify that regulated private data is stored encrypted while at rest, such as Personally ... | Not encrypted at rest by the application. Disk encryption is the operator's job and a declared non-goal (`SECURITY.md` Scope); the sensitive asset is the inventory map, and every path to it is authenticated |
| 6.4.1 | 2 | Compensating | Verify that a secrets management solution such as a key vault is used to securely create, ... | Secrets are Docker-mounted files, absent from `docker inspect`, child processes and `/proc/<pid>/environ`. That is secrets management, but it is not a key vault |
| 6.4.2 | 2 | **Not met** | Verify that key material is not exposed to the application but instead uses an isolated ... | Key material is readable by the application process; no HSM or isolated security module exists |
| 7.3.3 | 2 | Partial | Verify that security logs are protected from unauthorized access and modification | Hash chain plus `UPDATE`/`DELETE` revoked on `audit_log` (D-33). Tamper-evident, not tamper-proof, and the revoke lives in a migration that `downgrade()` reverses |
| 7.3.4 | 2 | Partial | Verify that time sources are synchronized to the correct time and time zone | Timestamps are UTC from the database clock; host time synchronisation is assumed, not verified or documented |
| 8.1.4 | 2 | Partial | Verify the application can detect and alert on abnormal numbers of requests, such as by IP, ... | Rate limits detect and block abnormal volumes and denials are audited - but nothing alerts anyone |
| 8.3.3 | 1 | Partial | Verify that users are provided clear language regarding collection and use of supplied ... | Collection and use are documented in `COMPLIANCE.md` §3, but the application shows no privacy notice in the interface |
| 8.3.6 | 2 | **Not met** | Verify that sensitive information contained in memory is overwritten as soon as it is no ... | CPython strings cannot be reliably zeroed; password material stays in memory until garbage collected |
| 8.3.7 | 2 | Compensating | Verify that sensitive or private information that is required to be encrypted, is encrypted ... | See 6.1.1 - the deployment relies on operator disk encryption rather than application-level encryption |
| 8.3.8 | 2 | Partial | Verify that sensitive personal information is subject to data retention classification, such ... | Self-hosted, so the operator controls retention entirely; no classification or retention schedule is published |
| 9.2.1 | 2 | Partial | Verify that connections to and from the server use trusted TLS certificates | A real domain gets Let's Encrypt certificates; the default `DOOM_DOMAIN=localhost` uses Caddy's internal CA, which no client trusts without `make trust-cert` |
| 9.2.2 | 2 | **Not met** | Verify that encrypted communications such as TLS is used for all inbound and outbound ... | `web->db` and `web->cache` are plaintext (`app/entrypoint.sh:21,27`), as is `caddy->web`. The Postgres image is started without TLS enabled at all |
| 9.2.3 | 2 | Partial | Verify that all encrypted connections to external systems that involve sensitive information ... | The only outbound connection is the optional barcode lookup, which is HTTPS to a pinned provider list but is not client-authenticated |
| 11.1.7 | 2 | Partial | Verify that the application monitors for unusual events or activity from a business logic ... | Denials, lockouts and rate-limit hits are all recorded in `audit_log`; nothing monitors the record |
| 11.1.8 | 2 | **Not met** | Verify that the application has configurable alerting when automated attacks or unusual ... | No alerting exists, configurable or otherwise |
| 12.4.2 | 1 | **Not met** | Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent ... | No antivirus scanner is present. Images are fully re-encoded, which destroys embedded payloads - but PDFs and text/markdown are stored byte for byte (`security/uploads.py:238-240`) |
| 13.1.3 | 1 | Compensating | Verify API URLs do not expose sensitive information, such as the API key, session tokens etc | A share token is a capability URL, so it is deliberately in the path. It is 256-bit, revocable, rate limited and every open is audited - but it is a secret in a URL and reaches the access log |
| 14.2.5 | 2 | **Not met** | Verify that a Software Bill of Materials (SBOM) is maintained of all third party libraries in ... | No SBOM is generated. Tracked separately and expected before this work reaches `main` |
| 14.2.6 | 2 | **Not met** | Verify that the attack surface is reduced by sandboxing or encapsulating third party libraries ... | Third-party libraries run in-process with the application's full privileges; no per-library sandboxing exists |
<!-- exceptions:end -->

---

## 2. The ledger

Every L1 and L2 requirement of ASVS 4.0.3, in requirement order. Requirement text
is the standard's own, trimmed where a row would otherwise be unreadable; CWE
numbers are the ones 4.0.3 assigns, not ones chosen here.

<!-- ledger:begin -->

### V1 - Architecture, design and threat modelling

*38 requirements at L1/L2 - 26 met, 7 partial, 2 compensating, 2 not met, 1 n/a.*

| ASVS | L | Requirement | Status | Evidence | CWE |
|---|:--:|---|---|---|:--:|
| 1.1.1 | 2 | Verify the use of a secure software development lifecycle that addresses security in all stages of development | Met | Threat model written before the code, 36 ADRs in `DECISIONS.md`, controls pinned by tests, 7 CI workflows | - |
| 1.1.2 | 2 | Verify the use of threat modeling for every design change or sprint planning to identify threats, plan for countermeasures, facilitate appropriate risk responses, and guide ... | Partial | `THREAT-MODEL.md` (47 threats) written once before the code, not revisited per design change | 1053 |
| 1.1.3 | 2 | Verify that all user stories and features contain functional security constraints, such as "As a user, I should be able to view and edit my profile. I should not be able to ... | Partial | Security constraints recorded per decision in `DECISIONS.md`; no user-story artifact exists to carry them | 1110 |
| 1.1.4 | 2 | Verify documentation and justification of all the application's trust boundaries, components, and significant data flows | Met | `THREAT-MODEL.md` §4 - 8 trust boundaries | 1059 |
| 1.1.5 | 2 | Verify definition and security analysis of the application's high-level architecture and all connected remote services | Met | `THREAT-MODEL.md` §3-§4; `README.md` Architecture | 1059 |
| 1.1.6 | 2 | Verify implementation of centralized, simple (economy of design), vetted, secure, and reusable security controls to avoid duplicate, missing, ineffective, or insecure controls | Met | `app/doom/security/` - 9 modules; one access-control mechanism at `security/authz.py:58` | 637 |
| 1.1.7 | 2 | Verify availability of a secure coding checklist, security requirements, guideline, or policy to all developers and testers | Partial | `docs/SECURITY.md` + `DECISIONS.md` serve the purpose; no separate secure-coding checklist | 637 |
| 1.2.1 | 2 | Verify the use of unique or special low-privilege operating system accounts for all application components, services, and servers | Met | `app/Dockerfile:37-58` uid 10001, `nologin`; `db/init/01-roles.sh` two-role split, asserted by `make verify-db-roles` | 250 |
| 1.2.2 | 2 | Verify that communications between application components, including APIs, middleware and data layers, are authenticated. Components should have the least necessary ... | Partial | `db` and `cache` require passwords (`app/entrypoint.sh:21,27`) but the channel itself is unauthenticated - see 1.9.2 | 306 |
| 1.2.3 | 2 | Verify that the application uses a single vetted authentication mechanism that is known to be secure, can be extended to include strong authentication, and has sufficient ... | Met | Single Flask-Login + Argon2id path; `app/doom/extensions.py:22-30` | 306 |
| 1.2.4 | 2 | Verify that all authentication pathways and identity management APIs implement consistent authentication security control strength, such that there are no weaker alternatives ... | Met | One login path, no alternate identity API; `app/doom/blueprints/auth.py:156` | 306 |
| 1.4.1 | 2 | Verify that trusted enforcement points, such as access control gateways, servers, and serverless functions, enforce access controls. Never enforce access controls on the ... | Met | `security/authz.py:58` server-side; no client-side enforcement anywhere | 602 |
| 1.4.4 | 2 | Verify the application uses a single and well-vetted access control mechanism for accessing protected data and resources. All requests must pass through this single mechanism ... | Met | `get_owned_or_404()` / `owned_query()`; every object-scoped endpoint proven by `tests/test_authz_coverage.py` | 284 |
| 1.4.5 | 2 | Verify that attribute or feature-based access control is used whereby the code checks the user's authorization for a feature/data item rather than just their role. ... | Met | Authorisation is per-object ownership, not a role bit; `security/authz.py:58` | 275 |
| 1.5.1 | 2 | Verify that input and output requirements clearly define how to handle and process data based on type, content, and applicable laws, regulations, and other policy compliance | Met | `app/doom/validation.py:1-24` defines every bound and type | 1029 |
| 1.5.2 | 2 | Verify that serialization is not used when communicating with untrusted clients. If this is not possible, ensure that adequate integrity controls (and possibly encryption if ... | Met | No serialization to untrusted clients; signed cookies only | 502 |
| 1.5.3 | 2 | Verify that input validation is enforced on a trusted service layer | Met | WTForms validators + `validation.py` allowlists, all server-side | 602 |
| 1.5.4 | 2 | Verify that output encoding occurs close to or by the interpreter for which it is intended | Met | Jinja2 autoescaping at render; `make lint` fails on any bypass | 116 |
| 1.6.1 | 2 | Verify that there is an explicit policy for management of cryptographic keys and that a cryptographic key lifecycle follows a key management standard such as NIST SP 800-57 | Partial | Secrets are file-mounted and regenerable via `make init`; no formal key lifecycle or management standard | 320 |
| 1.6.2 | 2 | Verify that consumers of cryptographic services protect key material and other secrets by using key vaults or API based alternatives | Compensating | Docker secrets as mounted files, never the environment (`config.py`); no key vault. Argued, not implemented | 320 |
| 1.6.3 | 2 | Verify that all keys and passwords are replaceable and are part of a well-defined process to re-encrypt sensitive data | Met | `make init` regenerates; `session_version` invalidates every issued session | 320 |
| 1.6.4 | 2 | Verify that the architecture treats client-side secrets--such as symmetric keys, passwords, or API tokens--as insecure and never uses them to protect or access sensitive data | Met | No client-side secrets; share tokens are server-issued capabilities, revocable | 320 |
| 1.7.1 | 2 | Verify that a common logging format and approach is used across the system | Met | Structured JSON from both the application (`security/logging.py:55-84`) and gunicorn (`security/gunicorn_logging.py`) | 1009 |
| 1.7.2 | 2 | Verify that logs are securely transmitted to a preferably remote system for analysis, detection, alerting, and escalation | Compensating | stdout JSON is what a collector consumes, and the audit trail is hash-chained in Postgres - but nothing ships off-host. Not implemented | - |
| 1.8.1 | 2 | Verify that all sensitive data is identified and classified into protection levels | Met | `THREAT-MODEL.md` §2 asset table A1-A9 | - |
| 1.8.2 | 2 | Verify that all protection levels have an associated set of protection requirements, such as encryption requirements, integrity requirements, retention, privacy and other ... | Partial | Assets classified, but no per-level retention or encryption requirement is written down | - |
| 1.9.1 | 2 | Verify the application encrypts communications between components, particularly when these components are in different containers, systems, sites, or cloud providers | **Not met** | All three internal hops are plaintext: `caddy->web` (`caddy/Caddyfile:34`), `web->db` and `web->cache` (`app/entrypoint.sh:21,27`) | 319 |
| 1.9.2 | 2 | Verify that application components verify the authenticity of each side in a communication link to prevent person-in-the-middle attacks | **Not met** | No component authenticates the other side of a link; passwords authenticate the client only | 295 |
| 1.10.1 | 2 | Verify that a source code control system is in use, with procedures to ensure that check-ins are accompanied by issues or change tickets. The source code control system ... | Partial | Git with a documented history; check-ins are not tied to issues or change tickets | 284 |
| 1.11.1 | 2 | Verify the definition and documentation of all application components in terms of the business or security functions they provide | Met | `README.md` Architecture; `docs/SECURITY.md` §1 per-component control matrix | 1059 |
| 1.11.2 | 2 | Verify that all high-value business logic flows, including authentication, session management and access control, do not share unsynchronized state | Met | `pg_advisory_xact_lock` (`security/audit.py:91-95`); `SELECT ... FOR UPDATE` (`blueprints/items.py:616-620`) | 362 |
| 1.12.2 | 2 | Verify that user-uploaded files - if required to be displayed or downloaded from the application - are served by either octet stream downloads, or from an unrelated domain, ... | Met | Uploads served as attachments through an authorised handler; `blueprints/files.py:115` | 646 |
| 1.14.1 | 2 | Verify the segregation of components of differing trust levels through well-defined security controls, firewall rules, API gateways, reverse proxies, cloud-based security ... | Met | `docker-compose.yml:163-169` - `internal: true` network; Caddy is the only published port | 923 |
| 1.14.2 | 2 | Verify that binary signatures, trusted connections, and verified endpoints are used to deploy binaries to remote devices | N/A | No binaries are deployed to remote devices | 494 |
| 1.14.3 | 2 | Verify that the build pipeline warns of out-of-date or insecure components and takes appropriate actions | Met | `pip-audit.yml`, `trivy-image-scanning.yaml` (`exit-code: 1` on HIGH/CRITICAL), Renovate, and a lockfile-drift diff | 1104 |
| 1.14.4 | 2 | Verify that the build pipeline contains a build step to automatically build and verify the secure deployment of the application, particularly if the application ... | Met | `build-and-push-container.yml`; `diff-and-make-test.yml` builds and tests the real compose stack | - |
| 1.14.5 | 2 | Verify that application deployments adequately sandbox, containerize and/or isolate at the network level to delay and deter attackers from attacking other applications, ... | Met | `docker-compose.yml:77-83,146-154` - `read_only`, `cap_drop: ALL`, `no-new-privileges`, internal network | 265 |
| 1.14.6 | 2 | Verify the application does not use unsupported, insecure, or deprecated client-side technologies such as NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or ... | Met | No Flash/ActiveX/applets; two hand-written vanilla JS files, no build step | 477 |

### V2 - Authentication

*48 requirements at L1/L2 - 18 met, 4 not met, 26 n/a.*

| ASVS | L | Requirement | Status | Evidence | CWE |
|---|:--:|---|---|---|:--:|
| 2.1.1 | 1 | Verify that user set passwords are at least 12 characters in length (after multiple spaces are combined) | Met | `PASSWORD_MIN = 12` (`validation.py:50`), enforced at `security/passwords.py:96` | 521 |
| 2.1.2 | 1 | Verify that passwords of at least 64 characters are permitted, and that passwords of more than 128 characters are denied | Met | `PASSWORD_MAX = 128` (`validation.py:55`); 64+ accepted, >128 rejected | 521 |
| 2.1.3 | 1 | Verify that password truncation is not performed. However, consecutive multiple spaces may be replaced by a single space | Met | Argon2id hashes the full submitted value; no truncation anywhere | 521 |
| 2.1.4 | 1 | Verify that any printable Unicode character, including language neutral characters such as spaces and Emojis are permitted in passwords | Met | No `Regexp` on either password field (`forms.py:104,180`); any printable Unicode is accepted | 521 |
| 2.1.5 | 1 | Verify users can change their password | Met | `blueprints/auth.py:287` - change-password route | 620 |
| 2.1.6 | 1 | Verify that password change functionality requires the user's current and new password | Met | `ChangePasswordForm.current_password` is required (`forms.py:179`) and verified before the change | 620 |
| 2.1.7 | 1 | Verify that passwords submitted during account registration, login, and password change are checked against a set of breached passwords either locally (such as the top 1,000 ... | Met | 10,000-entry breach corpus filtered to the 12-character policy (`security/data/common_passwords.txt`), checked at `security/passwords.py` | 521 |
| 2.1.8 | 1 | Verify that a password strength meter is provided to help users set a stronger password | Met | `static/js/password-meter.js`, wired into `auth/register.html` and `auth/change_password.html` | 521 |
| 2.1.9 | 1 | Verify that there are no password composition rules limiting the type of characters permitted. There should be no requirement for upper or lower case or numbers or special ... | Met | No composition rules exist; deliberate, reasoned in D-03 | 521 |
| 2.1.10 | 1 | Verify that there are no periodic credential rotation or password history requirements | Met | No expiry, no password history; nothing rotates credentials on a schedule | 263 |
| 2.1.11 | 1 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted | Met | No `autocomplete=off`, no paste handler; `templates/_macros.html:12` renders fields plainly | 521 |
| 2.1.12 | 1 | Verify that the user can choose to either temporarily view the entire masked password, or temporarily view the last typed character of the password on platforms that do not ... | Met | Reveal toggle in `static/js/password-meter.js`, on both password forms | 521 |
| 2.2.1 | 1 | Verify that anti-automation controls are effective at mitigating breached credential testing, brute force, and account lockout attacks. Such controls include blocking the ... | Met | Per-IP rate limit plus per-account lockout (D-04); `extensions.py:45` | 307 |
| 2.2.2 | 1 | Verify that the use of weak authenticators (such as SMS and email) is limited to secondary verification and transaction approval and not as a replacement for more secure ... | N/A | No SMS, email or other weak authenticator is offered - email is never used for delivery (D-25) | 304 |
| 2.2.3 | 1 | Verify that secure notifications are sent to users after updates to authentication details, such as credential resets, email or address changes, logging in from unknown or ... | **Not met** | Nothing notifies the user of a credential change. Other sessions are invalidated (T-06), which is containment, not notification | 620 |
| 2.3.1 | 1 | Verify system generated initial passwords or activation codes SHOULD be securely randomly generated, SHOULD be at least 6 characters long, and MAY contain letters and ... | N/A | No system-generated initial passwords or activation codes exist; `flask seed` is an explicit demo opt-in | 330 |
| 2.3.2 | 2 | Verify that enrollment and use of user-provided authentication devices are supported, such as a U2F or FIDO tokens | **Not met** | No enrollment path for user-provided authenticators (U2F/FIDO). Single-factor by design - and this is an L2 requirement, not only the L3 2.2.4 | 308 |
| 2.3.3 | 2 | Verify that renewal instructions are sent with sufficient time to renew time bound authenticators | N/A | No time-bound authenticators are issued | 287 |
| 2.4.1 | 2 | Verify that passwords are stored in a form that is resistant to offline attacks | Met | Argon2id `t=3, m=64 MiB, p=4` (`security/passwords.py:32-38`, D-02) | 916 |
| 2.4.2 | 2 | Verify that the salt is at least 32 bits in length and be chosen arbitrarily to minimize salt value collisions among stored hashes. For each credential, a unique salt value ... | Met | `argon2-cffi` 16-byte (128-bit) salt per credential | 916 |
| 2.4.3 | 2 | Verify that if PBKDF2 is used, the iteration count SHOULD be as large as verification server performance will allow, typically at least 100,000 iterations | N/A | PBKDF2 is not used | 916 |
| 2.4.4 | 2 | Verify that if bcrypt is used, the work factor SHOULD be as large as verification server performance will allow, with a minimum of 10 | N/A | bcrypt is not used | 916 |
| 2.4.5 | 2 | Verify that an additional iteration of a key derivation function is performed, using a salt value that is secret and known only to the verifier | **Not met** | No secret-salt (pepper) iteration is performed. Would require a key store the deployment does not have | 916 |
| 2.5.1 | 1 | Verify that a system generated initial activation or recovery secret is not sent in clear text to the user | N/A | No activation or recovery secret is ever generated - there is no recovery flow (D-12) | 640 |
| 2.5.2 | 1 | Verify password hints or knowledge-based authentication (so-called "secret questions") are not present | Met | No password hints and no knowledge-based questions exist | 640 |
| 2.5.3 | 1 | Verify password credential recovery does not reveal the current password in any way | N/A | No credential recovery path exists to reveal anything | 640 |
| 2.5.4 | 1 | Verify shared or default accounts are not present (e.g. "root", "admin", or "sa") | Met | No account exists until an operator creates one; `flask seed` is an explicit, documented demo opt-in | 16 |
| 2.5.5 | 1 | Verify that if an authentication factor is changed or replaced, that the user is notified of this event | **Not met** | Same gap as 2.2.3 - no notification channel exists | 304 |
| 2.5.6 | 1 | Verify forgotten password, and other recovery paths use a secure recovery mechanism, such as time-based OTP (TOTP) or other soft token, mobile push, or another offline ... | N/A | No forgotten-password path exists. A lost password means a lost account, reasoned in D-12 | 640 |
| 2.5.7 | 2 | Verify that if OTP or multi-factor authentication factors are lost, that evidence of identity proofing is performed at the same level as during enrollment | N/A | No OTP or MFA factors exist to lose | 308 |
| 2.6.1 | 2 | Verify that lookup secrets can be used only once | N/A | Lookup secrets are not used | 308 |
| 2.6.2 | 2 | Verify that lookup secrets have sufficient randomness (112 bits of entropy), or if less than 112 bits of entropy, salted with a unique and random 32-bit salt and hashed with ... | N/A | Lookup secrets are not used | 330 |
| 2.6.3 | 2 | Verify that lookup secrets are resistant to offline attacks, such as predictable values | N/A | Lookup secrets are not used | 310 |
| 2.7.1 | 1 | Verify that clear text out of band (NIST "restricted") authenticators, such as SMS or PSTN, are not offered by default, and stronger alternatives such as push notifications ... | Met | No out-of-band authenticator is offered at all, so none is offered by default | 287 |
| 2.7.2 | 1 | Verify that the out of band verifier expires out of band authentication requests, codes, or tokens after 10 minutes | N/A | No out-of-band authenticator exists | 287 |
| 2.7.3 | 1 | Verify that the out of band verifier authentication requests, codes, or tokens are only usable once, and only for the original authentication request | N/A | No out-of-band authenticator exists | 287 |
| 2.7.4 | 1 | Verify that the out of band authenticator and verifier communicates over a secure independent channel | N/A | No out-of-band authenticator exists | 523 |
| 2.7.5 | 2 | Verify that the out of band verifier retains only a hashed version of the authentication code | N/A | No out-of-band authenticator exists | 256 |
| 2.7.6 | 2 | Verify that the initial authentication code is generated by a secure random number generator, containing at least 20 bits of entropy (typically a six digital random number is ... | N/A | No out-of-band authenticator exists | 310 |
| 2.8.1 | 1 | Verify that time-based OTPs have a defined lifetime before expiring | N/A | No OTP authenticator exists | 613 |
| 2.8.2 | 2 | Verify that symmetric keys used to verify submitted OTPs are highly protected, such as by using a hardware security module or secure operating system based key storage | N/A | No OTP authenticator exists | 320 |
| 2.8.3 | 2 | Verify that approved cryptographic algorithms are used in the generation, seeding, and verification of OTPs | N/A | No OTP authenticator exists | 326 |
| 2.8.4 | 2 | Verify that time-based OTP can be used only once within the validity period | N/A | No OTP authenticator exists | 287 |
| 2.8.5 | 2 | Verify that if a time-based multi-factor OTP token is re-used during the validity period, it is logged and rejected with secure notifications being sent to the holder of the ... | N/A | No OTP authenticator exists | 287 |
| 2.8.6 | 2 | Verify physical single-factor OTP generator can be revoked in case of theft or other loss | N/A | No physical OTP generator exists | 613 |
| 2.9.1 | 2 | Verify that cryptographic keys used in verification are stored securely and protected against disclosure, such as using a Trusted Platform Module (TPM) or Hardware Security ... | N/A | No cryptographic authenticator exists | 320 |
| 2.9.2 | 2 | Verify that the challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of the cryptographic device | N/A | No cryptographic authenticator exists | 330 |
| 2.9.3 | 2 | Verify that approved cryptographic algorithms are used in the generation, seeding, and verification | N/A | No cryptographic authenticator exists | 327 |

### V3 - Session management

*17 requirements at L1/L2 - 15 met, 2 n/a.*

| ASVS | L | Requirement | Status | Evidence | CWE |
|---|:--:|---|---|---|:--:|
| 3.1.1 | 1 | Verify the application never reveals session tokens in URL parameters | Met | Session lives in a cookie only; the `/t/<token>` capability URL is not a session token | 598 |
| 3.2.1 | 1 | Verify the application generates a new session token on user authentication | Met | `session.clear()` then re-issue on login (T-04); `blueprints/auth.py` | 384 |
| 3.2.2 | 1 | Verify that session tokens possess at least 64 bits of entropy | Met | Session row id is a UUID4 (122 bits); share tokens are `secrets.token_urlsafe` 256-bit | 331 |
| 3.2.3 | 1 | Verify the application only stores session tokens in the browser using secure methods such as appropriately secured cookies (see section 3.4) or HTML 5 session storage | Met | `HttpOnly`, `Secure`, `SameSite=Lax` (`config.py:124-126`); no browser storage is used | 539 |
| 3.2.4 | 2 | Verify that session tokens are generated using approved cryptographic algorithms | Met | `itsdangerous` HMAC signing with `SECRET_KEY`; ids from `os.urandom` via `uuid4` | 331 |
| 3.3.1 | 1 | Verify that logout and expiration invalidate the session token, such that the back button or a downstream relying party does not resume an authenticated session, including ... | Met | `session.clear()` plus a `session_version` bump; `blueprints/auth.py:260` | 613 |
| 3.3.3 | 2 | Verify that the application gives the option to terminate all other active sessions after a successful password change (including change via password reset/recovery), and ... | Met | A password change invalidates every other session (T-06) | 613 |
| 3.3.4 | 2 | Verify that users are able to view and (having re-entered login credentials) log out of any or all currently active sessions and devices | Met | `user_sessions` listed on the account page; revocation re-asks for the password (`blueprints/account.py:162-189`) | 613 |
| 3.4.1 | 1 | Verify that cookie-based session tokens have the 'Secure' attribute set | Met | `SESSION_COOKIE_SECURE = True` (`config.py:125`) | 614 |
| 3.4.2 | 1 | Verify that cookie-based session tokens have the 'HttpOnly' attribute set | Met | `SESSION_COOKIE_HTTPONLY = True` (`config.py:124`) | 1004 |
| 3.4.3 | 1 | Verify that cookie-based session tokens utilize the 'SameSite' attribute to limit exposure to cross-site request forgery attacks | Met | `SESSION_COOKIE_SAMESITE = 'Lax'` (`config.py:126`) | 16 |
| 3.4.4 | 1 | Verify that cookie-based session tokens use the "__Host-" prefix so cookies are only sent to the host that initially set the cookie | Met | `SESSION_COOKIE_NAME = '__Host-doom_session'` (`config.py:123`) - Secure, `Path=/`, no `Domain` | 16 |
| 3.4.5 | 1 | Verify that if the application is published under a domain name with other applications that set or use session cookies that might disclose the session cookies, set the path ... | N/A | The application is the only thing served on its host; no sibling app sets cookies on the domain | 16 |
| 3.5.1 | 2 | Verify the application allows users to revoke OAuth tokens that form trust relationships with linked applications | N/A | No OAuth or linked-application trust relationships exist | 290 |
| 3.5.2 | 2 | Verify the application uses session tokens rather than static API secrets and keys, except with legacy implementations | Met | Share tokens are 256-bit and revocable; no static API key exists | 798 |
| 3.5.3 | 2 | Verify that stateless session tokens use digital signatures, encryption, and other countermeasures to protect against tampering, enveloping, replay, null cipher, and key ... | Met | The session cookie is signed, and every request re-checks a server-side `user_sessions` row | 345 |
| 3.7.1 | 1 | Verify the application ensures a full, valid login session or requires re-authentication or secondary verification before allowing any sensitive transactions or account ... | Met | `login_required` on every authenticated route; `login_manager.session_protection = 'strong'` | 306 |

### V4 - Access control

*9 requirements at L1/L2 - 7 met, 1 partial, 1 n/a.*

| ASVS | L | Requirement | Status | Evidence | CWE |
|---|:--:|---|---|---|:--:|
| 4.1.1 | 1 | Verify that the application enforces access control rules on a trusted service layer, especially if client-side access control is present and could be bypassed | Met | `security/authz.py:58` - enforcement is a `WHERE` clause on the server | 602 |
| 4.1.2 | 1 | Verify that all user and data attributes and policy information used by access controls cannot be manipulated by end users unless specifically authorized | Met | Field-by-field form binding; never `**request.form` (D-07) | 639 |
| 4.1.3 | 1 | Verify that the principle of least privilege exists - users should only be able to access functions, data files, URLs, controllers, services, and other resources, for which ... | Met | App DB role holds DML only (`db/init/01-roles.sh`, D-08), asserted by `make verify-db-roles`; objects scoped by owner | 285 |
| 4.1.5 | 1 | Verify that access controls fail securely including when an exception occurs | Met | A miss is 404, not 403 (D-06); a non-UUID id takes the same path (`security/authz.py:43-55`) | 285 |
| 4.2.1 | 1 | Verify that sensitive data and APIs are protected against Insecure Direct Object Reference (IDOR) attacks targeting creation, reading, updating and deletion of records, such ... | Met | Ownership filtered inside the query; `tests/test_authz_coverage.py` fails if any object-scoped endpoint escapes the invariant | 639 |
| 4.2.2 | 1 | Verify that the application or framework enforces a strong anti-CSRF mechanism to protect authenticated functionality, and effective anti-automation or anti-CSRF protects ... | Met | `CSRFProtect` global (`extensions.py:20`); no state change on GET | 352 |
| 4.3.1 | 1 | Verify administrative interfaces use appropriate multi-factor authentication to prevent unauthorized use | N/A | There is no administrative interface, role or console - every account is an ordinary single-tenant user | 419 |
| 4.3.2 | 1 | Verify that directory browsing is disabled unless deliberately desired | Met | No directory browsing; uploads are served only through an authorised handler | 548 |
| 4.3.3 | 2 | Verify the application has additional authorization (such as step up or adaptive authentication) for lower value systems, and / or segregation of duties for high value ... | Partial | Session revocation re-asks for the password (`blueprints/account.py:176`); other destructive actions have no step-up | 732 |

### V5 - Validation, sanitisation and encoding

*30 requirements at L1/L2 - 23 met, 1 partial, 6 n/a.*

| ASVS | L | Requirement | Status | Evidence | CWE |
|---|:--:|---|---|---|:--:|
| 5.1.1 | 1 | Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request ... | Met | WTForms reads a single named field; Werkzeug does not merge duplicate parameters into one value | 235 |
| 5.1.2 | 1 | Verify that frameworks protect against mass parameter assignment attacks, or that the application has countermeasures to protect against unsafe parameter assignment, such as ... | Met | Explicit form fields only, never `**request.form` (T-10, D-07) | 915 |
| 5.1.3 | 1 | Verify that all input (HTML form fields, REST requests, URL parameters, HTTP headers, cookies, batch files, RSS feeds, etc) is validated using positive validation (allow ... | Met | Allowlists throughout `validation.py`, enforced server-side | 20 |
| 5.1.4 | 1 | Verify that structured data is strongly typed and validated against a defined schema including allowed characters, length and pattern (e.g. credit card numbers, e-mail ... | Met | Every bound is a named constant in `validation.py` (D-01), enforced by validator, ORM column and Postgres CHECK | 20 |
| 5.1.5 | 1 | Verify that URL redirects and forwards only allow destinations which appear on an allow list, or show a warning when redirecting to potentially untrusted content | Met | `security/redirects.py:24` - allowlist of shapes, not a denylist of strings | 601 |
| 5.2.1 | 1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is properly sanitized with an HTML sanitizer library or framework feature | N/A | No untrusted HTML is ever rendered - there is no WYSIWYG editor and no Markdown rendering. `make lint` proves zero autoescape bypasses | 116 |
| 5.2.2 | 1 | Verify that unstructured data is sanitized to enforce safety measures such as allowed characters and length | Met | Unstructured text is length-bounded and character-validated in `validation.py`, then autoescaped at render | 138 |
| 5.2.3 | 1 | Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection | N/A | The application sends no mail; email is collected but never used for delivery (D-25) | 147 |
| 5.2.4 | 1 | Verify that the application avoids the use of eval() or other dynamic code execution features | Met | No `eval`, `exec`, `pickle`, `yaml.load` or dynamic import anywhere in `app/doom` | 95 |
| 5.2.5 | 1 | Verify that the application protects against template injection attacks by ensuring that any user input being included is sanitized or sandboxed | Met | Jinja2 autoescaping; zero `|safe` and zero `Markup(`, enforced by `make lint` | 94 |
| 5.2.6 | 1 | Verify that the application protects against SSRF attacks, by validating or sanitizing untrusted data or HTTP file metadata, such as filenames and URL input fields, and uses ... | Partial | User URLs are never fetched (D-13); the optional lookup is pinned to a code-level provider list and refuses redirects (D-32). A resolve-then-connect rebinding window remains | 918 |
| 5.2.7 | 1 | Verify that the application sanitizes, disables, or sandboxes user-supplied Scalable Vector Graphics (SVG) scriptable content, especially as they relate to XSS resulting from ... | Met | SVG is rejected by the upload allowlist (`validation.py:249-255`) | 159 |
| 5.2.8 | 1 | Verify that the application sanitizes, disables, or sandboxes user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, ... | Met | No BBCode, Markdown or template rendering of user content exists | 94 |
| 5.3.1 | 1 | Verify that output encoding is relevant for the interpreter and context required | Met | Jinja2 autoescaping is the single output-encoding path | 116 |
| 5.3.2 | 1 | Verify that output encoding preserves the user's chosen character set and locale, such that any Unicode character point is valid and safely handled | Met | UTF-8 end to end; Jinja2 escapes without transcoding | 176 |
| 5.3.3 | 1 | Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against reflected, stored, and DOM based XSS | Met | Jinja2 context-aware autoescaping, build-enforced by `make lint` | 79 |
| 5.3.4 | 1 | Verify that data selection or database queries (e.g. SQL, HQL, ORM, NoSQL) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from database ... | Met | SQLAlchemy throughout; `websearch_to_tsquery` bound as a parameter | 89 |
| 5.3.5 | 1 | Verify that where parameterized or safer mechanisms are not present, context-specific output encoding is used to protect against injection attacks, such as the use of SQL ... | Met | No query is built by string concatenation anywhere | 89 |
| 5.3.6 | 1 | Verify that the application protects against JSON injection attacks, JSON eval attacks, and JavaScript expression evaluation | Met | `json.dumps` for log output; no `JSON.parse` of untrusted input and no JS eval in either static file | 830 |
| 5.3.7 | 1 | Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented | N/A | No LDAP is used | 90 |
| 5.3.8 | 1 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding | Met | No `subprocess`, `os.system` or shell invocation anywhere in `app/doom` | 78 |
| 5.3.9 | 1 | Verify that the application protects against Local File Inclusion (LFI) or Remote File Inclusion (RFI) attacks | Met | Stored names are generated UUIDs; `security/uploads.py:315-333` resolves and confines every path | 829 |
| 5.3.10 | 1 | Verify that the application protects against XPath injection or XML injection attacks | N/A | No XML or XPath parsing exists; SVG is rejected | 643 |
| 5.4.1 | 2 | Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows | N/A | CPython is memory-safe; no native extension is written by this project | 120 |
| 5.4.2 | 2 | Verify that format strings do not take potentially hostile input, and are constant | Met | Format strings are constants; the only two `.format()` calls take a fixed template (`errors.py:86`, `lookup.py:149` with `quote()`) | 134 |
| 5.4.3 | 2 | Verify that sign, range, and input validation techniques are used to prevent integer overflows | Met | Quantity and depth bounds are typed and range-checked in `validation.py` | 190 |
| 5.5.1 | 1 | Verify that serialized objects use integrity checks or are encrypted to prevent hostile object creation or data tampering | Met | The session cookie is signed by `itsdangerous`; nothing else is serialized to a client | 502 |
| 5.5.2 | 1 | Verify that the application correctly restricts XML parsers to only use the most restrictive configuration possible and to ensure that unsafe features such as resolving ... | N/A | No XML parser is used | 611 |
| 5.5.3 | 1 | Verify that deserialization of untrusted data is avoided or is protected in both custom code and third-party libraries (such as JSON, XML and YAML parsers) | Met | No untrusted deserialization - no `pickle`, no `yaml.load`, no custom decoder | 502 |
| 5.5.4 | 1 | Verify that when parsing JSON in browsers or JavaScript-based backends, JSON.parse is used to parse the JSON document. Do not use eval() to parse JSON | Met | Neither static JS file parses or evaluates untrusted JSON | 95 |

### V6 - Stored cryptography

*13 requirements at L1/L2 - 6 met, 2 compensating, 1 not met, 4 n/a.*

| ASVS | L | Requirement | Status | Evidence | CWE |
|---|:--:|---|---|---|:--:|
| 6.1.1 | 2 | Verify that regulated private data is stored encrypted while at rest, such as Personally Identifiable Information (PII), sensitive personal information, or data assessed ... | Compensating | Not encrypted at rest by the application. Disk encryption is the operator's job and a declared non-goal (`SECURITY.md` Scope); the sensitive asset is the inventory map, and every path to it is authenticated | 311 |
| 6.1.2 | 2 | Verify that regulated health data is stored encrypted while at rest, such as medical records, medical device details, or de-anonymized research records | N/A | No health data is collected | 311 |
| 6.1.3 | 2 | Verify that regulated financial data is stored encrypted while at rest, such as financial accounts, defaults or credit history, tax records, pay history, beneficiaries, or ... | N/A | No financial or payment data is collected | 311 |
| 6.2.1 | 1 | Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable Padding Oracle attacks | Met | Argon2 verification failure returns a generic credential error; `security/passwords.py:141-146` | 310 |
| 6.2.2 | 2 | Verify that industry proven or government approved cryptographic algorithms, modes, and libraries are used, instead of custom coded cryptography | Met | Argon2id via `argon2-cffi`, HMAC via `itsdangerous`, `secrets` for randomness - no hand-rolled cryptography | 327 |
| 6.2.3 | 2 | Verify that encryption initialization vector, cipher configuration, and block modes are configured securely using the latest advice | N/A | The application performs no symmetric encryption, so there is no IV or block mode to configure | 326 |
| 6.2.4 | 2 | Verify that random number, encryption or hashing algorithms, key lengths, rounds, ciphers or modes, can be reconfigured, upgraded, or swapped at any time, to protect against ... | Met | Argon2id parameters are named constants and rehash-on-login upgrades them (`security/passwords.py:158-168`) | 326 |
| 6.2.5 | 2 | Verify that known insecure block modes (i.e. ECB, etc.), padding modes (i.e. PKCS#1 v1.5, etc.), ciphers with small block sizes (i.e. Triple-DES, Blowfish, etc.), and weak ... | N/A | No block cipher or padding mode is used | 326 |
| 6.2.6 | 2 | Verify that nonces, initialization vectors, and other single use numbers must not be used more than once with a given encryption key. The method of generation must be ... | Met | Per-credential 16-byte salts and per-token `secrets.token_urlsafe`; nothing single-use is reused | 326 |
| 6.3.1 | 2 | Verify that all random numbers, random file names, random GUIDs, and random strings are generated using the cryptographic module's approved cryptographically secure random ... | Met | `secrets.token_urlsafe` and `secrets.choice` throughout; `make init` uses `openssl rand` | 338 |
| 6.3.2 | 2 | Verify that random GUIDs are created using the GUID v4 algorithm, and a Cryptographically-secure Pseudo-random Number Generator (CSPRNG). GUIDs created using other ... | Met | `uuid4()`, which draws from `os.urandom` | 338 |
| 6.4.1 | 2 | Verify that a secrets management solution such as a key vault is used to securely create, store, control access to and destroy secrets | Compensating | Secrets are Docker-mounted files, absent from `docker inspect`, child processes and `/proc/<pid>/environ`. That is secrets management, but it is not a key vault | 798 |
| 6.4.2 | 2 | Verify that key material is not exposed to the application but instead uses an isolated security module like a vault for cryptographic operations | **Not met** | Key material is readable by the application process; no HSM or isolated security module exists | 320 |

### V7 - Error handling and logging

*12 requirements at L1/L2 - 10 met, 2 partial.*

| ASVS | L | Requirement | Status | Evidence | CWE |
|---|:--:|---|---|---|:--:|
| 7.1.1 | 1 | Verify that the application does not log credentials or payment details. Session tokens should only be stored in logs in an irreversible, hashed form | Met | Credentials are never logged (`security/logging.py:28-52`), and the share token is scrubbed from both logs - the application's (`scrub_path`) and gunicorn's (`security/gunicorn_logging.py`) | 532 |
| 7.1.2 | 1 | Verify that the application does not log other sensitive data as defined under local privacy laws or relevant security policy | Met | `SENSITIVE_KEY_FRAGMENTS` redaction (`security/logging.py:28-31`) applied to every structured field | 532 |
| 7.1.3 | 2 | Verify that the application logs security relevant events including successful and failed authentication events, access control failures, deserialization failures and input ... | Met | `audit_log` records authentication, access-control denials, uploads, sharing and custody changes | 778 |
| 7.1.4 | 2 | Verify that each log event includes necessary information that would allow for a detailed investigation of the timeline when an event happens | Met | Each event carries actor, action, object, timestamp, IP and correlation id (`security/audit.py:97-116`) | 778 |
| 7.2.1 | 2 | Verify that all authentication decisions are logged, without storing sensitive session tokens or passwords | Met | Both success and failure are recorded; no token or password is stored with them | 778 |
| 7.2.2 | 2 | Verify that all access control decisions can be logged and all failed decisions are logged | Met | `security/authz.py:79-84` audits every denial, including the inline checkout query (`blueprints/items.py:616-620`) | 285 |
| 7.3.1 | 2 | Verify that all logging components appropriately encode data to prevent log injection | Met | Structured JSON; `json.dumps` escapes newlines and control characters | 117 |
| 7.3.3 | 2 | Verify that security logs are protected from unauthorized access and modification | Partial | Hash chain plus `UPDATE`/`DELETE` revoked on `audit_log` (D-33). Tamper-evident, not tamper-proof, and the revoke lives in a migration that `downgrade()` reverses | 200 |
| 7.3.4 | 2 | Verify that time sources are synchronized to the correct time and time zone | Partial | Timestamps are UTC from the database clock; host time synchronisation is assumed, not verified or documented | - |
| 7.4.1 | 1 | Verify that a generic message is shown when an unexpected or security sensitive error occurs, potentially with a unique ID which support personnel can use to investigate | Met | A correlation id and nothing else (D-17); `blueprints/errors.py` | 210 |
| 7.4.2 | 2 | Verify that exception handling (or a functional equivalent) is used across the codebase to account for expected and unexpected error conditions | Met | Handlers registered for 400/403/404/413/429/500; `record_audit` itself never raises (`security/audit.py:126-133`) | 544 |
| 7.4.3 | 2 | Verify that a "last resort" error handler is defined which will catch all unhandled exceptions | Met | A catch-all handler with an HTML fallback that cannot itself fail (`blueprints/errors.py:86`) | 431 |

### V8 - Data protection

*15 requirements at L1/L2 - 10 met, 3 partial, 1 compensating, 1 not met.*

| ASVS | L | Requirement | Status | Evidence | CWE |
|---|:--:|---|---|---|:--:|
| 8.1.1 | 2 | Verify the application protects sensitive data from being cached in server components such as load balancers and application caches | Met | `Cache-Control: no-store` plus `Vary: Cookie` on every authenticated response (`security/headers.py:110-112`) | 524 |
| 8.1.2 | 2 | Verify that all cached or temporary copies of sensitive data stored on the server are protected from unauthorized access or purged/invalidated after the authorized user ... | Met | Uploads are written `0600` (`security/uploads.py:297-312`); `/tmp` is a size-capped tmpfs | 524 |
| 8.1.3 | 2 | Verify the application minimizes the number of parameters in a request, such as hidden fields, Ajax variables, cookies and header values | Met | Forms carry only the fields they need plus a CSRF token; no hidden state is round-tripped | 233 |
| 8.1.4 | 2 | Verify the application can detect and alert on abnormal numbers of requests, such as by IP, user, total per hour or day, or whatever makes sense for the application | Partial | Rate limits detect and block abnormal volumes and denials are audited - but nothing alerts anyone | 770 |
| 8.2.1 | 1 | Verify the application sets sufficient anti-caching headers so that sensitive data is not cached in modern browsers | Met | `no-store`, `Pragma: no-cache` and `Vary: Cookie` (`security/headers.py:110-112`) | 525 |
| 8.2.2 | 1 | Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data | Met | No `localStorage`, `sessionStorage` or IndexedDB use anywhere in the two static JS files | 922 |
| 8.2.3 | 1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated | Met | Nothing authenticated is written to client storage, so logout leaves nothing to clear | 922 |
| 8.3.1 | 1 | Verify that sensitive data is sent to the server in the HTTP message body or headers, and that query string parameters from any HTTP verb do not contain sensitive data | Met | Credentials and state changes are POST bodies; `security/logging.py:69` deliberately drops the query string | 319 |
| 8.3.2 | 1 | Verify that users have a method to remove or export their data on demand | Met | `/account/activity.csv` exports the audit trail; account deletion cascades | 212 |
| 8.3.3 | 1 | Verify that users are provided clear language regarding collection and use of supplied personal information and that users have provided opt-in consent for the use of that ... | Partial | Collection and use are documented in `COMPLIANCE.md` §3, but the application shows no privacy notice in the interface | 285 |
| 8.3.4 | 1 | Verify that all sensitive data created and processed by the application has been identified, and ensure that a policy is in place on how to deal with sensitive data | Met | `THREAT-MODEL.md` §2 asset table A1-A9 | 200 |
| 8.3.5 | 2 | Verify accessing sensitive data is audited (without logging the sensitive data itself), if the data is collected under relevant data protection directives or where logging of ... | Met | Every read of a shared page and every export is written to `audit_log` | 532 |
| 8.3.6 | 2 | Verify that sensitive information contained in memory is overwritten as soon as it is no longer required to mitigate memory dumping attacks, using zeroes or random data | **Not met** | CPython strings cannot be reliably zeroed; password material stays in memory until garbage collected | 226 |
| 8.3.7 | 2 | Verify that sensitive or private information that is required to be encrypted, is encrypted using approved algorithms that provide both confidentiality and integrity | Compensating | See 6.1.1 - the deployment relies on operator disk encryption rather than application-level encryption | 327 |
| 8.3.8 | 2 | Verify that sensitive personal information is subject to data retention classification, such that old or out of date data is deleted automatically, on a schedule, or as the ... | Partial | Self-hosted, so the operator controls retention entirely; no classification or retention schedule is published | 285 |

### V9 - Communications

*7 requirements at L1/L2 - 3 met, 2 partial, 1 not met, 1 n/a.*

| ASVS | L | Requirement | Status | Evidence | CWE |
|---|:--:|---|---|---|:--:|
| 9.1.1 | 1 | Verify that TLS is used for all client connectivity, and does not fall back to insecure or unencrypted communications | Met | Caddy terminates TLS and redirects HTTP (`caddy/Caddyfile:14`); `SESSION_COOKIE_SECURE` prevents any plaintext fallback | 319 |
| 9.1.2 | 1 | Verify using up to date TLS testing tools that only strong cipher suites are enabled, with the strongest cipher suites set as preferred | Met | Caddy's defaults - modern suites only, no configuration weakening them | 326 |
| 9.1.3 | 1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3 | Met | Caddy negotiates TLS 1.2/1.3 only | 326 |
| 9.2.1 | 2 | Verify that connections to and from the server use trusted TLS certificates | Partial | A real domain gets Let's Encrypt certificates; the default `DOOM_DOMAIN=localhost` uses Caddy's internal CA, which no client trusts without `make trust-cert` | 295 |
| 9.2.2 | 2 | Verify that encrypted communications such as TLS is used for all inbound and outbound connections, including for management ports, monitoring, authentication, API, or web ... | **Not met** | `web->db` and `web->cache` are plaintext (`app/entrypoint.sh:21,27`), as is `caddy->web`. The Postgres image is started without TLS enabled at all | 319 |
| 9.2.3 | 2 | Verify that all encrypted connections to external systems that involve sensitive information or functions are authenticated | Partial | The only outbound connection is the optional barcode lookup, which is HTTPS to a pinned provider list but is not client-authenticated | 287 |
| 9.2.4 | 2 | Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured | N/A | No externally trusted certificate is served by default; revocation checking is Caddy's when a real domain is configured | 299 |

### V10 - Malicious code

*5 requirements at L1/L2 - 3 met, 2 n/a.*

| ASVS | L | Requirement | Status | Evidence | CWE |
|---|:--:|---|---|---|:--:|
| 10.2.1 | 2 | Verify that the application source code and third party libraries do not contain unauthorized phone home or data collection capabilities | Met | No telemetry, analytics or phone-home; the only outbound call is the off-by-default barcode lookup (D-13) | 359 |
| 10.2.2 | 2 | Verify that the application does not ask for unnecessary or excessive permissions to privacy related features or sensors, such as contacts, cameras, microphones, or location | Met | `security/headers.py` Permissions-Policy denies everything except `camera=(self)` for QR scanning | 272 |
| 10.3.1 | 1 | Verify that if the application has a client or server auto-update feature, updates should be obtained over secure channels and digitally signed. The update code must validate ... | N/A | There is no auto-update feature; the operator pulls images deliberately | 16 |
| 10.3.2 | 1 | Verify that the application employs integrity protections, such as code signing or subresource integrity. The application must not load or execute code from untrusted ... | Met | Hash-pinned dependencies (`app/requirements.txt`, 877 `--hash=sha256:` entries); no externally hosted asset to need SRI | 353 |
| 10.3.3 | 1 | Verify that the application has protection from subdomain takeovers if the application relies upon DNS entries or DNS subdomains, such as expired domain names, out of date ... | N/A | No wildcard DNS and no external subdomain is relied upon | 350 |

### V11 - Business logic

*8 requirements at L1/L2 - 6 met, 1 partial, 1 not met.*

| ASVS | L | Requirement | Status | Evidence | CWE |
|---|:--:|---|---|---|:--:|
| 11.1.1 | 1 | Verify that the application will only process business logic flows for the same user in sequential step order and without skipping steps | Met | Checkout, return and move each validate current state before acting; `blueprints/items.py` | 841 |
| 11.1.2 | 1 | Verify that the application will only process business logic flows with all steps being processed in realistic human time, i.e. transactions are not submitted too quickly | Met | State transitions are ordered and re-checked at each step, not inferred from the client | 799 |
| 11.1.3 | 1 | Verify the application has appropriate limits for specific business actions or transactions which are correctly enforced on a per user basis | Met | Rate limits on login, register, share, lookup and every write path (`validation.py`) | 770 |
| 11.1.4 | 1 | Verify that the application has anti-automation controls to protect against excessive calls such as mass data exfiltration, business logic requests, file uploads or denial of ... | Met | Write and upload limits on capture, create, adjust, checkout, upload and search - not authentication alone | 770 |
| 11.1.5 | 1 | Verify the application has business logic limits or validation to protect against likely business risks or threats, identified using threat modeling or similar methodologies | Met | Quantity bounds, per-account storage quota and location tree depth, all from `validation.py` | 841 |
| 11.1.6 | 2 | Verify that the application does not suffer from "Time Of Check to Time Of Use" (TOCTOU) issues or other race conditions for sensitive operations | Met | Atomic quantity arithmetic; `SELECT ... FOR UPDATE` on checkout (`blueprints/items.py:616-620`) | 367 |
| 11.1.7 | 2 | Verify that the application monitors for unusual events or activity from a business logic perspective | Partial | Denials, lockouts and rate-limit hits are all recorded in `audit_log`; nothing monitors the record | 754 |
| 11.1.8 | 2 | Verify that the application has configurable alerting when automated attacks or unusual activity is detected | **Not met** | No alerting exists, configurable or otherwise | 390 |

### V12 - Files and resources

*15 requirements at L1/L2 - 13 met, 1 not met, 1 n/a.*

| ASVS | L | Requirement | Status | Evidence | CWE |
|---|:--:|---|---|---|:--:|
| 12.1.1 | 1 | Verify that the application will not accept large files that could fill up storage or cause a denial of service | Met | Caddy 12 MB (`caddy/Caddyfile:21-23`) -> Flask 10 MB (`validation.py:231`) -> per-file check | 400 |
| 12.1.2 | 2 | Verify that the application checks compressed files (e.g. zip, gz, docx, odt) against maximum allowed uncompressed size and against maximum number of files before ... | N/A | Archives and compressed documents are rejected by the upload allowlist (`validation.py:249-255`), so none is ever decompressed | 409 |
| 12.1.3 | 2 | Verify that a file size quota and maximum number of files per user is enforced to ensure that a single user cannot fill up the storage with too many files, or excessively ... | Met | Per-account storage ceiling checked before write (T-46); batch counts capped per request | 770 |
| 12.2.1 | 2 | Verify that files obtained from untrusted sources are validated to be of expected type based on the file's content | Met | libmagic sniff of the first 4096 bytes; filename and Content-Type are ignored (`security/uploads.py:82-88`) | 434 |
| 12.3.1 | 1 | Verify that user-submitted filename metadata is not used directly by system or framework filesystems and that a URL API is used to protect against path traversal | Met | Stored names are generated UUIDs (D-10); the submitted name is display-only (`security/uploads.py:69-79`) | 22 |
| 12.3.2 | 1 | Verify that user-submitted filename metadata is validated or ignored to prevent the disclosure, creation, updating or removal of local files (LFI) | Met | Submitted filename never reaches the filesystem; `resolve_stored_path` confines every read (`security/uploads.py:315-333`) | 73 |
| 12.3.3 | 1 | Verify that user-submitted filename metadata is validated or ignored to prevent the disclosure or execution of remote files via Remote File Inclusion (RFI) or Server-side ... | Met | No filename or metadata is ever used to fetch a remote resource; no upload path performs a fetch | 98 |
| 12.3.4 | 1 | Verify that the application protects against Reflective File Download (RFD) by validating or ignoring user-submitted filenames in a JSON, JSONP, or URL parameter, the ... | Met | Downloads are served with a fixed generated filename and an explicit `Content-Disposition: attachment` | 641 |
| 12.3.5 | 1 | Verify that untrusted file metadata is not used directly with system API or libraries, to protect against OS command injection | Met | No system or shell API receives file metadata - there is no shell invocation anywhere | 78 |
| 12.3.6 | 2 | Verify that the application does not include and execute functionality from untrusted sources, such as unverified content distribution networks, JavaScript libraries, node ... | Met | No CDN, no external JavaScript, no runtime plugin loading; every asset is served from `static/` | 829 |
| 12.4.1 | 1 | Verify that files obtained from untrusted sources are stored outside the web root, with limited permissions | Met | Uploads live on a dedicated volume outside the web root, written `0600` and owned by uid 10001 | 552 |
| 12.4.2 | 1 | Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent upload and serving of known malicious content | **Not met** | No antivirus scanner is present. Images are fully re-encoded, which destroys embedded payloads - but PDFs and text/markdown are stored byte for byte (`security/uploads.py:238-240`) | 509 |
| 12.5.1 | 1 | Verify that the web tier is configured to serve only files with specific file extensions to prevent unintentional information and source code leakage | Met | Uploads are served only through an authorised handler with a fixed Content-Type; no extension-based static serving of user files | 552 |
| 12.5.2 | 1 | Verify that direct requests to uploaded files will never be executed as HTML/JavaScript content | Met | Every upload is served `Content-Disposition: attachment` with `nosniff`, so nothing executes as HTML or JavaScript | 434 |
| 12.6.1 | 1 | Verify that the web or application server is configured with an allow list of resources or systems to which the server can send requests or load data/files from | Met | The optional lookup is pinned to a code-level provider allowlist and refuses redirects (D-32) | 918 |

### V13 - API and web service

*13 requirements at L1/L2 - 6 met, 1 compensating, 6 n/a.*

| ASVS | L | Requirement | Status | Evidence | CWE |
|---|:--:|---|---|---|:--:|
| 13.1.1 | 1 | Verify that all application components use the same encodings and parsers to avoid parsing attacks that exploit different URI or file parsing behavior that could be used in ... | Met | UTF-8 end to end; one parser (Werkzeug) for every request | 116 |
| 13.1.3 | 1 | Verify API URLs do not expose sensitive information, such as the API key, session tokens etc | Compensating | A share token is a capability URL, so it is deliberately in the path. It is 256-bit, revocable, rate limited and every open is audited - but it is a secret in a URL and reaches the access log | 598 |
| 13.1.4 | 2 | Verify that authorization decisions are made at both the URI, enforced by programmatic or declarative security at the controller or router, and at the resource level, ... | Met | Authorisation is enforced per object inside the query, not by URI pattern alone | 285 |
| 13.1.5 | 2 | Verify that requests containing unexpected or missing content types are rejected with appropriate headers (HTTP response status 406 Unacceptable or 415 Unsupported Media Type) | Met | WTForms rejects a request whose body does not parse as the expected form encoding | 434 |
| 13.2.1 | 1 | Verify that enabled RESTful HTTP methods are a valid choice for the user or action, such as preventing normal users using DELETE or PUT on protected API or resources | Met | State changes are POST with a CSRF token; GET is side-effect free | 650 |
| 13.2.2 | 1 | Verify that JSON schema validation is in place and verified before accepting input | N/A | No JSON request body is accepted anywhere - every input is an HTML form | 20 |
| 13.2.3 | 1 | Verify that RESTful web services that utilize cookies are protected from Cross-Site Request Forgery via the use of at least one or more of the following: double submit cookie ... | Met | `CSRFProtect` covers every cookie-authenticated state change | 352 |
| 13.2.5 | 2 | Verify that REST services explicitly check the incoming Content-Type to be the expected one, such as application/xml or application/json | N/A | No REST service accepting JSON exists | 436 |
| 13.2.6 | 2 | Verify that the message headers and payload are trustworthy and not modified in transit. Requiring strong encryption for transport (TLS only) may be sufficient in many cases ... | Met | TLS to the client; the session cookie is signed and integrity-checked on every request | 345 |
| 13.3.1 | 1 | Verify that XSD schema validation takes place to ensure a properly formed XML document, followed by validation of each input field before any processing of that data takes ... | N/A | No XML or SOAP surface exists | 20 |
| 13.3.2 | 2 | Verify that the message payload is signed using WS-Security to ensure reliable transport between client and service | N/A | No SOAP or WS-Security surface exists | 345 |
| 13.4.1 | 2 | Verify that a query allow list or a combination of depth limiting and amount limiting is used to prevent GraphQL or data layer expression Denial of Service (DoS) as a result ... | N/A | No GraphQL surface exists | 770 |
| 13.4.2 | 2 | Verify that GraphQL or other data layer authorization logic should be implemented at the business logic layer instead of the GraphQL layer | N/A | No GraphQL surface exists | 285 |

### V14 - Configuration

*23 requirements at L1/L2 - 19 met, 2 not met, 2 n/a.*

| ASVS | L | Requirement | Status | Evidence | CWE |
|---|:--:|---|---|---|:--:|
| 14.1.1 | 2 | Verify that the application build and deployment processes are performed in a secure and repeatable way, such as CI / CD automation, automated configuration management, and ... | Met | `make build` from a pinned base image and a hash-pinned lockfile; CI rebuilds the whole compose stack | - |
| 14.1.2 | 2 | Verify that compiler flags are configured to enable all available buffer overflow protections and warnings, including stack randomization, data execution prevention, and to ... | N/A | No compiled code is produced - CPython only, no native extension written here | 120 |
| 14.1.3 | 2 | Verify that server configuration is hardened as per the recommendations of the application server and frameworks in use | Met | `read_only`, `cap_drop: ALL`, `no-new-privileges`, non-root uid, tmpfs `/tmp` (`docker-compose.yml:77-83`) | 16 |
| 14.1.4 | 2 | Verify that the application, configuration, and all dependencies can be re-deployed using automated deployment scripts, built from a documented and tested runbook in a ... | Met | `docker compose up` plus `make upgrade` re-deploys the whole stack from source | - |
| 14.2.1 | 1 | Verify that all components are up to date, preferably using a dependency checker during build or compile time | Met | `pip-audit.yml` on every push and pull request, Trivy failing on HIGH/CRITICAL, Renovate, and a lockfile-drift diff in `diff-and-make-test.yml:13-15` | 1026 |
| 14.2.2 | 1 | Verify that all unneeded features, documentation, sample applications and configurations are removed | Met | Multi-stage build; `.dockerignore` excludes docs, tests and `.env`; no sample application ships in the image | 1002 |
| 14.2.3 | 1 | Verify that if application assets, such as JavaScript libraries, CSS or web fonts, are hosted externally on a Content Delivery Network (CDN) or external provider, Subresource ... | N/A | No asset is hosted externally - CSP is `default-src 'self'` with no CDN, so there is nothing for SRI to cover | 829 |
| 14.2.4 | 2 | Verify that third party components come from pre-defined, trusted and continually maintained repositories | Met | PyPI only, every version pinned with a SHA-256 hash; Renovate keeps the set maintained | 829 |
| 14.2.5 | 2 | Verify that a Software Bill of Materials (SBOM) is maintained of all third party libraries in use | **Not met** | No SBOM is generated. Tracked separately and expected before this work reaches `main` | - |
| 14.2.6 | 2 | Verify that the attack surface is reduced by sandboxing or encapsulating third party libraries to expose only the required behaviour into the application | **Not met** | Third-party libraries run in-process with the application's full privileges; no per-library sandboxing exists | 265 |
| 14.3.2 | 1 | Verify that web or application server and application framework debug modes are disabled in production to eliminate debug features, developer consoles, and unintended ... | Met | `DEBUG = False` and `TESTING = False`, and `config.py:169` refuses to start if `FLASK_DEBUG` is set | 497 |
| 14.3.3 | 1 | Verify that the HTTP headers or any part of the HTTP response do not expose detailed version information of system components | Met | `Server` header stripped by both Caddy (`caddy/Caddyfile:26`) and the application (`security/headers.py:125`) | 200 |
| 14.4.1 | 1 | Verify that every HTTP response contains a Content-Type header. Also specify a safe character set (e.g., UTF-8, ISO-8859-1) if the content types are text/*, /+xml and ... | Met | Flask sets `Content-Type` with an explicit charset on every response; uploads get a sniffed, allowlisted type | 173 |
| 14.4.2 | 1 | Verify that all API responses contain a Content-Disposition: attachment; filename="api.json" header (or other appropriate filename for the content type) | Met | The CSV export is served `Content-Disposition: attachment`, as is every uploaded file | 116 |
| 14.4.3 | 1 | Verify that a Content Security Policy (CSP) response header is in place that helps mitigate impact for XSS attacks like HTML, DOM, JSON, and JavaScript injection ... | Met | `security/headers.py:22-35` - no `unsafe-inline`, `script-src 'self'`, `object-src 'none'` | 1021 |
| 14.4.4 | 1 | Verify that all responses contain a X-Content-Type-Options: nosniff header | Met | `X-Content-Type-Options: nosniff` globally (`security/headers.py:74`) and per file | 116 |
| 14.4.5 | 1 | Verify that a Strict-Transport-Security header is included on all responses and for all subdomains, such as Strict-Transport-Security: max-age=15724800; includeSubdomains | Met | `Strict-Transport-Security` from Caddy and the application both (`security/headers.py:122`) | 523 |
| 14.4.6 | 1 | Verify that a suitable Referrer-Policy header is included to avoid exposing sensitive information in the URL through the Referer header to untrusted parties | Met | `Referrer-Policy: same-origin` (`security/headers.py:93`) | 116 |
| 14.4.7 | 1 | Verify that the content of a web application cannot be embedded in a third-party site by default and that embedding of the exact resources is only allowed where necessary by ... | Met | `frame-ancestors 'none'` plus `X-Frame-Options: DENY` (`security/headers.py:114`) | 1021 |
| 14.5.1 | 1 | Verify that the application server only accepts the HTTP methods in use by the application/API, including pre-flight OPTIONS, and logs/alerts on any requests that are not ... | Met | Every route declares its methods; anything else gets 405. No TRACE or TRACK surface | 749 |
| 14.5.2 | 1 | Verify that the supplied Origin header is not used for authentication or access control decisions, as the Origin header can easily be changed by an attacker | Met | `Origin` is never consulted for authentication or authorisation; ownership is a database predicate | 346 |
| 14.5.3 | 1 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header uses a strict allow list of trusted domains and subdomains to match against and does ... | Met | No CORS headers are emitted at all, so no origin is granted cross-origin access | 346 |
| 14.5.4 | 2 | Verify that HTTP headers added by a trusted proxy or SSO devices, such as a bearer token, are authenticated by the application | Met | `ProxyFix` trusts exactly one hop, and Caddy overwrites `X-Forwarded-For` with the real peer (`caddy/Caddyfile:42`) | 306 |

<!-- ledger:end -->

---

## 3. The arguments worth making at length

Six rows above say "Compensating", and a few of the "Partial" ones rest on a
judgement rather than a missing line of code. Those deserve more than a table
cell.

### Internal traffic is unencrypted (1.9.1, 1.9.2, 9.2.2)

`db` and `cache` sit on a Docker network declared `internal: true`, with no route
off the host and no published ports, and both require passwords. TLS between them
would protect against an attacker already executing inside that network — at
which point the application's own credentials are readable anyway.

That is an argument, and it is a real one, but it is **not** the requirement.
9.2.2 names database connections explicitly, and 1.9.1 names containers
explicitly. The honest position is that three hops are plaintext — `caddy → web`,
`web → db`, `web → cache` — that the Postgres image is not even started with TLS
available, and that the Redis password therefore crosses the bridge in cleartext
on every connection. Recorded as **Not met**, not as a pass with an asterisk.

### Logs are not shipped off-host (1.7.2)

Logs go to stdout as structured JSON, which is exactly what a collector consumes;
the *audit* trail — the security-relevant half — is in Postgres, hash-chained and
append-only, which is a stronger integrity property than remote shipping alone
provides. But nothing ships anywhere, so an attacker with host root can still
edit `docker logs` output at rest. **Compensating**, not met.

### A share token is a secret in a URL (7.1.1, 13.1.3)

`/t/<token>` is a capability URL by design (T-36): the token identifies *and*
authorises, so it cannot not be in the request. It is 256-bit, revocable, rate
limited, and every open is audited.

What was wrong until this revision is that the token was also **written to the
logs**. `security/logging.py` dropped the query string with a comment explaining
that it "can carry a share token" — while the token actually travels as a path
segment, and `request.path` was recorded verbatim. Every visit to a shared page
put a live credential into the log stream. That is fixed: `scrub_path()` reduces
`/t/<token>` to `/t/[redacted]`, pinned by `tests/test_asvs_l1_gaps.py`.

Gunicorn's access log had the same hole and no redaction hook of its own, so it
is now produced by `security/gunicorn_logging.py` — a logger class that scrubs
the path and the `Referer` (which matters: `Referrer-Policy` is `same-origin`, so
following any link from a shared page hands the server the whole capability URL)
and drops the query string. It emits JSON while it is there, which is what finally
makes 1.7.1's "common logging format across the system" true of the system rather
than of the application alone.

What remains is the requirement itself: the token is still *in* a URL, which is
what a capability URL means. It can be shoulder-surfed, pasted into a chat, or
kept in browser history. Rotation is the answer, and 13.1.3 stays Compensating
for that reason — the logging half is fixed, the design half is a choice.

### The audit chain is evident, not proof (7.3.3)

Someone with database access *and* the source can recompute the chain. An
externally recorded head hash is the mitigation, and the account page shows one
(D-33). Two further limits are worth stating because the previous revision did
not: the `REVOKE UPDATE, DELETE` lives in migration `a1c4e7b90d21`, **not** in
`db/init/01-roles.sh` as `security/audit.py` used to claim — so a deployment that
initialises the database but never migrates leaves the application role holding
the broad four-verb grant from `01-roles.sh:38` — and that migration's
`downgrade()` re-grants both verbs.

### Uploads are neutralised, not scanned (12.4.2)

Images are fully decoded and re-encoded from a fresh `Image` object, so no
original byte survives and an embedded payload does not either. That is a genuine
control and in some respects a stronger one than signature matching.

It is still not what 12.4.2 asks for, and it does not cover the whole surface:
**PDF, plain text and Markdown uploads are stored byte for byte**
(`security/uploads.py:238-240`). The allowlist excludes SVG and archives, files
are never executed, and everything is served `Content-Disposition: attachment`
with `nosniff` — but there is no antivirus scanner, this is an **L1** requirement,
and ClamAV is the production answer.

### Secrets are managed, but not in a vault (1.6.2, 6.4.1)

Secrets are read from mounted files and never from the environment: absent from
`docker inspect`, from child processes, and from `/proc/<pid>/environ`. That is
real secrets management and the verification commands are in §6. It is not a key
vault with rotation and audit, which is what the requirement describes.

### Data at rest is the operator's job (6.1.1, 8.3.7)

An optional email address is the only regulated personal data collected, and it is
never used for delivery (D-25). Nothing is encrypted at rest by the application;
full-disk encryption is the operator's responsibility and a declared non-goal
(`SECURITY.md` § Scope). Named as a compensating position rather than left
unmentioned.

---

## 4. Other standards cited

| Standard | Where it applies |
|---|---|
| **NIST SP 800-63B-4** (final, 31 July 2025) | Password policy: length over composition, blocklist screening, no forced rotation (D-03). Rev. 4 supersedes Rev. 3, which ASVS 4.0.3 itself was written against; the 12-character minimum and absent composition rules satisfy both |
| **NIST SP 800-53 AU-9** — *Protection of Audit Information* | Hash-chained, append-only audit log (D-33) |
| **NIST SP 800-53 AC-3, AC-6** | Ownership filtering; least-privilege database role |
| **NIST SP 800-53 SC-8** | TLS in transit — at the edge only; see §3 |
| **NIST CSF 2.0** | PR.AA (access control), PR.DS (data security), DE.AE (event analysis) |
| **GS1 General Specifications** | GTIN-8/12/13/14 barcode format — and the reason a barcode can be validated to digits at all (T-43) |
| **OWASP Top 10 2021** | A01 broken access control, A03 injection, A05 misconfiguration, A07 auth failures, A10 SSRF |
| **CIS Docker Benchmark** | Non-root user, dropped capabilities, read-only rootfs, no new privileges |

**Deliberately not claimed:** PCI DSS (no cardholder data — stating this is itself
the correct answer), HIPAA (no health data), SOC 2 (an organisational audit, not a
property of software).

---

## 5. Privacy posture

Not a certification, but the design decisions line up with GDPR principles and are
worth stating plainly:

| Principle | How |
|---|---|
| **Data minimisation** (Art. 5(1)(c)) | Every profile field optional; email collected but never used for delivery (D-25) |
| **Storage limitation** | Self-hosted; the operator controls retention entirely |
| **Right of access** (Art. 15) | `/account/activity.csv` exports the full audit trail |
| **Right to erasure** (Art. 17) | Account deletion cascades — with the audit trail deliberately surviving as a legitimate-interest record (D-33) |
| **Data protection by design** (Art. 25) | Threat model written before the code |

The gap is presentation, not practice: none of this is shown to a user in the
interface, which is what 8.3.3 asks for and why that row reads Partial.

---

## 6. Verifying the claims

Most of this ledger is executable rather than asserted.

```bash
make test           # 281 tests pinning the controls above
make lint           # autoescape bypasses, and tools/check_docs.py against this file
make audit-verify   # walks the audit hash chain
make db-shell-app   # connect as the app role and try to exceed its privileges
make verify-db-roles # assert the two-role split exists and is restricted
```

`make verify-db-roles` is worth singling out. Until it existed, every claim resting
on the two-role split was an assertion about a shell script nobody checked the
output of - and that script had been failing since the first commit, leaving the
restricted role uncreated. The suite could not notice, because it connects to a
separate database as the admin role. A control with no executable evidence is the
thing this document was rebuilt to stop.

`make lint` is the guard on this document specifically. It fails if a requirement
in the ledger is not Met and not listed in §1, if any document cites a requirement
that has no ledger row, or if a second file starts publishing its own test count.

Secrets never reach the process environment (1.6.2, 6.4.1):

```bash
docker inspect doom-web-1 --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -i password
# only *_FILE paths appear, never a value

docker compose exec web sh -c 'tr "\0" "\n" < /proc/1/environ | grep -cE "^(SECRET_KEY|APP_DB_PASSWORD|REDIS_PASSWORD)="'
# 0
```

As the application's own database role, all of these must fail:

```sql
DROP TABLE items;                     -- must be owner of table items
SELECT * FROM pg_shadow;              -- permission denied
UPDATE audit_log SET detail = 'x';    -- permission denied
DELETE FROM audit_log;                -- permission denied
```

Note the scope of that last pair. `UPDATE` and `DELETE` are revoked on
`audit_log` **only**; the application role holds full DML on every other table
(`db/init/01-roles.sh:38`). A successful SQL injection through the application
could therefore still modify or delete items and locations. What it cannot do is
rewrite history.
