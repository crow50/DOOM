#!/bin/sh
# ---------------------------------------------------------------------------
# Wraps the official entrypoint for exactly one reason: postgres refuses to
# start with a private key file it does not own - "private key file ...
# must be owned by the database user or root" - and every secret this stack
# mounts is a host-owned, world-readable bind mount (see Makefile's `init`
# target for why: compose gives a file-based secret the host's ownership,
# and the alternative, a 0400 file owned by the host user, is simply
# unreadable to a container running as someone else).
#
# That workaround does not exist for postgres, because postgres itself
# checks ownership, not just readability. So the key is copied into a path
# THIS process creates - which makes the copy postgres-owned automatically -
# before anything else starts. The source file on the host is untouched and
# stays exactly as permissive (0444) as every other secret in this stack.
#
# Runs as root, which is this image's default and unchanged by this file;
# the official entrypoint below still does its own privilege drop to the
# postgres user for initdb, init scripts and the server itself.
# ---------------------------------------------------------------------------
set -eu

install -d -m 0700 -o postgres -g postgres /var/lib/postgresql/tls
cp /run/secrets/doom_db_tls_key /var/lib/postgresql/tls/key.pem
chown postgres:postgres /var/lib/postgresql/tls/key.pem
chmod 0400 /var/lib/postgresql/tls/key.pem

exec docker-entrypoint.sh "$@"
