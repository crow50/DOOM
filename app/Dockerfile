# ---------------------------------------------------------------------------
# Build stage - compilers and headers live here and never reach the runtime
# image, so the shipped container has a much smaller attack surface.
# ---------------------------------------------------------------------------
FROM python:3.12.7-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM python:3.12.7-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"

# libmagic1 backs python-magic, which identifies uploads by their content
# rather than their filename (T-12).
RUN apt-get update \
 && apt-get install -y --no-install-recommends libmagic1 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 doom \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin doom

COPY --from=builder /opt/venv /opt/venv

WORKDIR /srv/doom
COPY --chown=root:root . /srv/doom

# The upload directory is the one writable path in an otherwise read-only
# filesystem, and it must be owned by the unprivileged runtime user or the
# first write fails at boot.  Application code stays root-owned and
# non-writable so a compromised process cannot rewrite its own source.
RUN mkdir -p /var/lib/doom/uploads \
 && chown -R 10001:10001 /var/lib/doom

# Installed while still root: a non-root USER cannot chmod a root-owned file,
# and the entrypoint must stay root-owned and non-writable so the application
# cannot rewrite the thing that assembles its own credentials.
COPY --chown=root:root entrypoint.sh /usr/local/bin/doom-entrypoint
RUN chmod 0555 /usr/local/bin/doom-entrypoint

USER 10001:10001

EXPOSE 8000

# Assembles DATABASE_URL and REDIS_URL from the mounted secret files, so no
# password ever reaches the process environment (ASVS 6.4.1).
ENTRYPOINT ["/usr/local/bin/doom-entrypoint"]

# PYTHONDONTWRITEBYTECODE matters here: with read_only:true set in compose,
# any attempt to write .pyc files next to the source would fail.
CMD ["sh", "-c", "exec gunicorn \
      --bind 0.0.0.0:8000 \
      --workers ${GUNICORN_WORKERS:-2} \
      --threads ${GUNICORN_THREADS:-4} \
      --worker-tmp-dir /tmp \
      --access-logfile - \
      --error-logfile - \
      --forwarded-allow-ips '*' \
      wsgi:app"]
