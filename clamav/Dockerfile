# ---------------------------------------------------------------------------
# clamd - antivirus scanning of uploads (ASVS 5.0.0-5.4.3).
#
# Not the official clamav/clamav image: that image publishes no linux/arm64
# manifest for its current tags, and part of this fleet is Raspberry Pi
# hardware. Alpine's own clamav-daemon package is multi-arch, current, and
# keeps this container on the same distro branch as db, cache and caddy.
# ---------------------------------------------------------------------------
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk add --no-cache clamav=1.4.6-r0 clamav-daemon=1.4.6-r0 \
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
