# Certificates this deployment did not issue

Empty by design. Anything here is mounted read-only into the Caddy container
at `/etc/caddy/certs`, and `.gitignore` re-admits only this README — a private
key dropped in beside it stays ignored.

Point at a file here from `caddy/conf.d/site/tls.caddy`:

```
tls /etc/caddy/certs/wildcard.pem /etc/caddy/certs/wildcard-key.pem
```

See [../conf.d/README.md](../conf.d/README.md) for which topology this is,
what else has to be set, and — the part that bites people — why Caddy has to
be restarted when the certificate is renewed.
