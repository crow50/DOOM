# ---------------------------------------------------------------------------
# clamd - antivirus scanning of uploads (ASVS 5.0.0-5.4.3).
#
# Not the official clamav/clamav image: that image publishes no linux/arm64
# manifest for its current tags, and part of this fleet is Raspberry Pi
# hardware. Alpine's own clamav-daemon package is multi-arch, current, and
# keeps this container on the same distro branch as db, cache and caddy.
# ---------------------------------------------------------------------------
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# Upgrade first. The base image is pinned by digest, which freezes its OS packages
# at the day it was built while Alpine keeps shipping fixes on the branch: left
# alone, libssl3/libcrypto3 stayed at 3.5.8-r0 and carried four HIGH CVEs that
# 3.5.9-r0 fixes. app/Dockerfile's runtime stage does the same; see
# docs/PIPELINE-NOTES.md. clamav itself stays pinned on purpose, because
# clamav/clamav-vex.json is bound to those exact package URLs.
RUN apk upgrade --no-cache \
 && apk add --no-cache clamav=1.4.6-r0 clamav-daemon=1.4.6-r0 \
 && mkdir -p /run/clamav \
 && chown clamav:clamav /run/clamav /var/lib/clamav

COPY clamd.conf /etc/clamav/clamd.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# /var/lib/clamav is a named volume at runtime (docker-compose.yml); the
# chown above is what makes the volume come up clamav-owned on first mount,
# the same trick app/Dockerfile uses for the uploads volume.

EXPOSE 3310

ENTRYPOINT ["/entrypoint.sh"]
