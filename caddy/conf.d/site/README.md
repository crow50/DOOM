# Site-scoped Caddy settings

Files named `*.caddy` here are merged into this stack's **site block**, which
is where directives that apply to the site rather than the server go —
`tls` above all. Global options such as `email`, `acme_ca` and
`trusted_proxies` belong one directory up, in `conf.d/*.caddy`.

Typical contents, as `tls.caddy`:

```
tls /etc/caddy/certs/wildcard.pem /etc/caddy/certs/wildcard-key.pem
```

Read [../README.md](../README.md) first — particularly the note about Caddy
not reloading a certificate file that changes underneath it.
