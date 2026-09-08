# Reporting a security issue

This is a self-hosted personal project, not a service with users to protect,
but reports are welcome and will be taken seriously.

**Please do not open a public issue for a security problem.** Open a GitHub
security advisory on the repository instead, or contact the maintainer
directly.

Useful things to include: what you did, what happened, what you expected, and
which version or commit you were on. A proof of concept helps but is not
required.

## Scope

In scope: anything in this repository - the application, the container
configuration, the reverse proxy configuration, the database role setup.

Out of scope, because they are documented non-goals rather than oversights
(see [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) §6):

- A malicious operator or host root
- Data at rest on a stolen disk - full-disk encryption is the operator's job
- Username disclosure on the registration form - accepted, reasoned in
  [docs/DECISIONS.md](docs/DECISIONS.md) D-05
- NFC tag cloning - physically unpreventable with cheap NDEF tags, handled by
  making the tag's URL a low-value capability
- Denial of service at network scale

## What already exists

Before reporting, it may be worth checking
[docs/SECURITY.md](docs/SECURITY.md), which maps each implemented control to
the threat it answers, and its §4 listing known accepted risks.
