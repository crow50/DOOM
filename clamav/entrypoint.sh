#!/bin/sh
# Populate the signature database before clamd starts - a fresh volume has
# none, and clamd refuses to start without one. `|| true`: some freshclam
# versions exit nonzero when the database is already current, and a
# transient network hiccup on restart should not stop clamd serving whatever
# the volume already has.
set -eu

freshclam --stdout || true

# Keeps the database current for the life of the container. Backgrounded so
# it runs alongside clamd rather than gating it - the scanner does not need
# today's signatures to start, only *a* database.
freshclam -d --stdout &

exec clamd --foreground=true
