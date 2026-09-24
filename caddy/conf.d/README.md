# Operator TLS settings

Anything in this directory named `*.caddy` is merged into the Caddyfile's
global options block. Nothing here is needed for the default
`DOOM_DOMAIN=localhost` deployment, which Caddy serves from its own internal
CA; this is where the settings for a **public** domain go.

The directory is empty by design, and the `import` that reads it is a glob, so
an empty directory is not an error.

## Moving to a public domain

Set `DOOM_DOMAIN` to a publicly resolvable name in `.env`, and
`PUBLIC_BASE_URL` to match — the second is what every printed QR code and NFC
tag is built from, so getting it wrong means reprinting labels. Caddy then
switches from its internal CA to ACME automatically, with Let's Encrypt as the
issuer and ZeroSSL as the fallback; there is no setting to turn that on.

Then create `acme.caddy` here:

```
# Contact address on the ACME account. Optional for Let's Encrypt, which no
# longer relies on it to warn you about expiry, and required by ZeroSSL if
# Caddy ever falls back to it.
email you@example.com

# While you are still getting the first certificate issued, point at staging.
# Let's Encrypt rate-limits *failed* validations, and a misconfigured first
# attempt spends that budget while you are working out why. Remove this line
# once a staging certificate is issued — the staging CA is not publicly
# trusted, so browsers will still warn until you do.
acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
```

## What has to be true before a certificate can be issued

The challenge has to reach this host **from the public internet**, on the
standard ports, whatever the container publishes locally:

| Challenge | Must be reachable on | Notes |
|---|---|---|
| TLS-ALPN-01 | port **443** | Caddy's first choice |
| HTTP-01 | port **80** | fallback |

`.env` defaults to `HTTP_PORT=8080` and `HTTPS_PORT=8443`, because rootless
Docker cannot bind below 1024. Those are the *host* ports; the CA still has to
arrive on 80 and 443, so a router forwarding `80 → 8080` and `443 → 8443` is
required, or the host ports have to be 80 and 443 on a rootful daemon.

## Before you do this at all

Issuing a public certificate means two things that are worth deciding on
purpose rather than discovering:

1. **The host is reachable from the internet.** Both challenge types need an
   inbound path, so this stops being a LAN-only deployment. That is a much
   larger change than a certificate, and every other control in this
   application was written for the smaller threat model.

2. **The hostname becomes public.** Every certificate Let's Encrypt issues is
   published to Certificate Transparency logs, which are searchable by anyone
   — `crt.sh` will show `doom.yourdomain.example` within minutes of issuance.
   For an application whose entire purpose is a map of where physical property
   is kept, and which goes to some trouble elsewhere to stay unindexed
   (`X-Robots-Tag`, `robots.txt`, no enumerable routes), publishing the
   hostname is a reconnaissance gift.

   A **wildcard** certificate avoids this: `*.yourdomain.example` appears in
   the CT log, the specific subdomain does not. Wildcards require the DNS-01
   challenge, which needs a DNS provider plugin compiled into Caddy — the
   stock image does not carry one. DNS-01 also removes obstacle 1 entirely,
   because validation happens through a DNS TXT record and needs no inbound
   connection at all, which makes it the right shape for a LAN deployment that
   wants a publicly trusted certificate. It is not wired up here; see the
   `CONTROL-v5.0.0-12.2.2` finding in `docs/security/alerts.json`.
