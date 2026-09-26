#!/bin/bash
# ---------------------------------------------------------------------------
# Runs once, on first initialisation of an empty data directory - same
# lifecycle as 01-roles.sh, and it runs first only because "00" sorts before
# "01"; the two are otherwise independent.
#
# initdb generates a catch-all `host all all all scram-sha-256` rule, which
# authenticates that row over EITHER plaintext or TLS - a client that does
# not ask for TLS gets plaintext, silently. Rewritten to `hostssl` so that
# row refuses a connection outright rather than merely permitting an
# encrypted one (ASVS 5.0.0-12.3.1: "does not fall back to insecure or
# unencrypted communications").
#
# Every other rule initdb wrote is left exactly as generated: the `local`
# (unix socket) and 127.0.0.1/::1 loopback trust rules are used only by
# tooling running inside this same container - make test's admin bootstrap,
# `make verify-db-roles` - where there is no network hop to encrypt, and the
# unused replication rows were never reachable to begin with.
# ---------------------------------------------------------------------------
set -euo pipefail

awk '$1 == "host" && $4 == "all" { $1 = "hostssl" } { print }' \
    "$PGDATA/pg_hba.conf" > "$PGDATA/pg_hba.conf.new"
mv "$PGDATA/pg_hba.conf.new" "$PGDATA/pg_hba.conf"

echo "doom: pg_hba.conf now requires TLS for network connections"
