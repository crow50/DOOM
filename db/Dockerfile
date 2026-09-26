# ---------------------------------------------------------------------------
# postgres, plus the one entrypoint change TLS needs: see entrypoint.sh for
# why the private key cannot be handled as a plain bind-mounted secret the
# way every other credential in this stack is.
# ---------------------------------------------------------------------------
FROM postgres:18.6-alpine

# db/init/*.sh (including 00-hba.sh) arrives via docker-compose.yml's own
# bind mount at /docker-entrypoint-initdb.d, not a COPY here - a build-time
# copy at that exact path would just be shadowed by the mount anyway.
COPY entrypoint.sh /usr/local/bin/doom-entrypoint.sh
RUN chmod +x /usr/local/bin/doom-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/doom-entrypoint.sh"]
CMD ["postgres"]
