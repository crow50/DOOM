# TLS topology

Nothing here is needed for the default `DOOM_DOMAIN=localhost` deployment,
which Caddy serves from its own internal CA. This is where the settings go
when the certificate has to be publicly trusted.

Two directories, because Caddyfiles have no conditionals and a glob that
matches nothing is how you spell "optional":

| Path | Merged into | For |
|---|---|---|
| `conf.d/*.caddy` | the global options block | `email`, `acme_ca`, `trusted_proxies` |
| `conf.d/site/*.caddy` | the site block | `tls`, anything else site-scoped |

Both are mounted read-only at `/etc/caddy/conf.d`. Restart Caddy after
changing either: `docker compose restart caddy`.

---

## Pick a topology

### A. Something else already terminates TLS — *recommended for a homelab*

You run Traefik, Nginx Proxy Manager, or another Caddy as the thing that holds
certificates for the whole network. It terminates TLS for
`doom.yourdomain.example` and proxies to this stack.

**This is the least work and the least to go wrong.** Renewal stays entirely
your existing manager's problem, this stack never needs restarting when a
certificate rolls, and the wildcard never has to be copied anywhere.

Point your proxy at this stack's **HTTPS** port, not its HTTP port. The HTTP
listener here only answers `308` to the HTTPS one, and the reason to keep the
hop encrypted is not ceremony: the session cookie is `__Host-` prefixed and
`Secure`, and Flask-WTF's CSRF check is SSL-strict, so the application has to
see `X-Forwarded-Proto: https` to work at all — and it should only see that
when it is true. Your proxy will need to trust this stack's internal CA
(`make trust-cert` exports it), or you can give this stack the real
certificate as well, per topology B.

Then declare your proxy trusted, so client addresses survive the hop —
`conf.d/trusted-proxy.caddy`:

```
servers {
	# The address your proxy connects FROM, not the range your clients are on.
	# Narrow it to the proxy itself. Anything you list here is allowed to tell
	# this stack who the client is.
	trusted_proxies static 172.18.0.0/16
}
```

**Do not skip this.** Without it every visitor arriving through your proxy
collapses into one per-IP rate-limit bucket and every audit row records the
proxy's address instead of the client's. Nothing breaks visibly; the
rate limiting simply stops meaning anything.

Set `DOOM_DOMAIN` to the public name (so this stack's site block matches the
`Host` your proxy forwards) and `PUBLIC_BASE_URL` to the public URL. The
second is what every printed QR code and NFC tag is built from, so getting it
wrong means reprinting labels.

### B. Bring the certificate here

You have a wildcard — issued by your own Caddy, Traefik, `acme.sh`, `certbot`,
`lego`, `step-ca`, anything — and you want *this* Caddy to serve it.

Mount it (see `caddy/certs/README.md`) and add `conf.d/site/tls.caddy`:

```
tls /etc/caddy/certs/wildcard.pem /etc/caddy/certs/wildcard-key.pem
```

Caddy wants PEM. Two formats commonly need converting first:

- **Traefik** stores certificates base64-encoded inside `acme.json`. Extract
  them with `traefik-certs-dumper` or a `jq` one-liner; you cannot point Caddy
  at `acme.json`.
- **A PKCS#12 / `.pfx` bundle** needs `openssl pkcs12 -in bundle.pfx -nodes`
  split into certificate and key files.

If the file contains a chain, put the leaf first and the intermediates after
it in the same file. Caddy serves what it is given, in order.

> **The one that bites.** Caddy loads a certificate named this way **once, at
> config load**, and does not watch the file. When your manager renews the
> wildcard in place, this Caddy carries on serving the old one until it is
> restarted — and keeps doing so past expiry, which is a browser error on
> every device sixty days after everything worked. Hook the restart onto your
> renewal:
>
> ```
> acme.sh   --reloadcmd "docker compose -f /path/to/doom/docker-compose.yml restart caddy"
> certbot   --deploy-hook "docker compose -f /path/to/doom/docker-compose.yml restart caddy"
> ```
>
> `make verify-cert` compares the certificate on disk against the one actually
> being served and fails when they differ, so this is a check you can run
> rather than a thing you have to remember. Run it from cron if you would
> rather find out from a cron mail than from a phone.

### C. This stack gets its own certificate

Set `DOOM_DOMAIN` to a publicly resolvable name and `PUBLIC_BASE_URL` to
match. Caddy then switches from its internal CA to ACME on its own, with
Let's Encrypt as the issuer and ZeroSSL as the fallback — there is no setting
to turn that on. Optionally add `conf.d/acme.caddy`:

```
# Contact on the ACME account. Optional for Let's Encrypt; required by ZeroSSL
# if Caddy ever falls back to it.
email you@example.com

# Use this while you are still getting the first certificate issued. Let's
# Encrypt rate-limits *failed* validations, and a misconfigured first attempt
# spends that budget while you are working out why. Remove it once a staging
# certificate is issued — staging is not publicly trusted, so browsers keep
# warning until you do.
acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
```

Three things have to be true, and the first two are why this is topology C
rather than the default:

1. **The challenge must reach this host from the internet**, on port **443**
   (TLS-ALPN-01, Caddy's first choice) or port **80** (HTTP-01). `.env`
   defaults to `8080`/`8443` because rootless Docker cannot bind below 1024;
   those are *host* ports, and the CA still arrives on 80 and 443, so you need
   a router forwarding `80 → 8080` and `443 → 8443`, or host ports of 80 and
   443 on a rootful daemon.

2. **The host becomes internet-facing.** Both challenge types need an inbound
   path. That is a much larger change than a certificate, and every other
   control in this application was written for a smaller threat model.

3. **The hostname becomes public.** Every certificate Let's Encrypt issues is
   published to Certificate Transparency logs that anyone can search; `crt.sh`
   will show `doom.yourdomain.example` within minutes. For an application that
   is a map of where physical property is kept — and which goes to some
   trouble elsewhere to stay unindexed — that is a reconnaissance gift.

   A **wildcard** avoids it: `*.yourdomain.example` appears in the log, the
   specific subdomain does not. Wildcards require the DNS-01 challenge, which
   needs a DNS provider plugin compiled into Caddy; the stock image this stack
   pins does not carry one, and building a custom one is deliberately not done
   here. Issue the wildcard wherever you already issue certificates and use
   topology A or B — which is the same conclusion most homelabs reach anyway.
