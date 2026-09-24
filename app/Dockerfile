# ---------------------------------------------------------------------------
# Build stage - compilers and headers live here and never reach the runtime
# image, so the shipped container has a much smaller attack surface.
# ---------------------------------------------------------------------------
FROM python:3.14.7-alpine3.23@sha256:218761489de417a6eb0808e264cbdd7043ec6659fe5a61898815e9848536541d AS builder

ARG ZLIB_COMMIT=df84af25dc1942490e1d1c899a07619152a46148
ARG ZLIB_SOURCE_SHA256=03a76732cfaa124c58b67600699d935d081604385c03aa282f81a101b7536161

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

RUN apk add --no-cache \
    build-base=0.5-r3 \
    ca-certificates=20260909-r0 \
    curl=8.22.0-r0

# Alpine 3.23 currently ships zlib 1.3.2-r0, which contains the
# CVE-2026-85091 non-blocking gzwrite overflow. Build the upstream fix at an
# immutable commit and verify the downloaded source before compiling it.
# The exact runtime image is then checked below to ensure Python loads this
# patched shared library instead of the APK's original copy.
RUN curl --fail --location --silent --show-error \
      "https://github.com/madler/zlib/archive/${ZLIB_COMMIT}.tar.gz" \
      --output /tmp/zlib.tar.gz \
 && echo "${ZLIB_SOURCE_SHA256}  /tmp/zlib.tar.gz" | sha256sum -c - \
 && mkdir -p /build/zlib \
 && tar -xzf /tmp/zlib.tar.gz --strip-components=1 -C /build/zlib

WORKDIR /build/zlib
RUN ./configure --prefix=/opt/zlib --shared \
 && make -j"$(nproc)" \
 && make test \
 && make install

WORKDIR /build
RUN rm -f /tmp/zlib.tar.gz && rm -rf /build/zlib

COPY requirements.txt requirements-dev.txt ./
RUN python -m venv --upgrade-deps /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# A second venv for the `test` stage: the runtime venv plus pytest.  Built
# here, where pip and the compilers are, so the test stage below can copy it
# in without reinstating either.  Nothing from it reaches the runtime image.
#
# `python -m pip`, not `bin/pip`: the copied venv's console scripts still carry
# the ORIGINAL venv's interpreter in their shebang, so `venv-test/bin/pip`
# would install straight back into /opt/venv - which is exactly what happened
# the first time, and what the `! import pytest` check in the runtime stage
# exists to catch.  The interpreter resolves its prefix from its own location.
RUN cp -a /opt/venv /opt/venv-test \
 && /opt/venv-test/bin/python -m pip install --no-cache-dir -r requirements-dev.txt


# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM python:3.14.7-alpine3.23@sha256:218761489de417a6eb0808e264cbdd7043ec6659fe5a61898815e9848536541d AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    LD_LIBRARY_PATH="/usr/local/lib"

# The file package provides libmagic, which identifies uploads by their content
# rather than their filename (T-12).
# Upgrade the pinned Alpine branch before installing libmagic. Renovate keeps
# the language and distro tag current while the package manager takes security
# updates from that same stable branch.
RUN apk upgrade --no-cache \
 && apk add --no-cache file=5.46-r2 \
 && addgroup -S -g 10001 doom \
 && adduser -S -u 10001 -G doom -H -D -s /sbin/nologin doom

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /opt/zlib/lib/libz.so.1.3.2.1-motley /usr/local/lib/libz.so.1.3.2.1-motley

# Override the unpatched APK library for every process in this image. Verify
# the dynamic loader maps the upstream-built shared object into Python before
# this image can be scanned or shipped. The package inventory remains intact;
# the narrow VEX statement used by both image gates is generated from this
# build's SBOM and only covers its exact zlib package PURL.
RUN ln -s libz.so.1.3.2.1-motley /usr/local/lib/libz.so.1 \
 && python -c 'import zlib; maps = open("/proc/self/maps", encoding="utf-8").read(); assert "/usr/local/lib/libz.so.1.3.2.1-motley" in maps, maps; assert zlib.ZLIB_RUNTIME_VERSION == "1.3.2.1-motley", zlib.ZLIB_RUNTIME_VERSION; print("patched zlib loaded:", zlib.ZLIB_RUNTIME_VERSION)'

# pip is a build-time tool; nothing in the runtime image ever installs anything.
# Removing it removes its *vendored* dependency tree with it, which is where every
# Python CVE reported against this image has come from - pip vendors setuptools
# and msgpack (see pip/_vendor/vendor.txt), neither of which this application
# imports and neither of which appears in requirements.txt.  Stripping them
# deletes the vulnerable code rather than filing an exception for it (ASVS
# 14.2.2: unneeded features are removed).
#
# pip is present twice: once from the base image's --with-ensurepip, and once in
# /opt/venv from `python -m venv --upgrade-deps` above.
#
# The import check on the last line is the point of doing this in one layer: if
# stripping setuptools breaks anything still reaching for pkg_resources, the
# build fails here rather than the container failing at boot.
RUN set -eux; \
    for site in /usr/local/lib/python3.*/site-packages \
                /opt/venv/lib/python3.*/site-packages; do \
      rm -rf "$site"/pip          "$site"/pip-*.dist-info \
             "$site"/setuptools   "$site"/setuptools-*.dist-info \
             "$site"/pkg_resources \
             "$site"/wheel        "$site"/wheel-*.dist-info; \
    done; \
    rm -rf /usr/local/lib/python3.*/ensurepip; \
    rm -f /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.*; \
    python -c "import flask, sqlalchemy, gunicorn, PIL, magic, argon2, redis, qrcode"; \
    ! python -c "import pytest" 2>/dev/null

WORKDIR /srv/doom
# An explicit allowlist, not `COPY .`: the shipped image holds the package,
# the WSGI entry and the migrations, and nothing else from this directory -
# not the tests, not pytest.ini, not the lockfiles, not this file.  A glob
# with a .dockerignore beside it can regress silently (the ignore file was in
# the wrong directory for a while and excluded nothing); three named paths
# cannot.  ASVS 14.2.2.
COPY --chown=root:root doom       /srv/doom/doom
COPY --chown=root:root migrations /srv/doom/migrations
COPY --chown=root:root wsgi.py    /srv/doom/wsgi.py

# The upload directory is the one writable path in an otherwise read-only
# filesystem, and it must be owned by the unprivileged runtime user or the
# first write fails at boot.  Application code stays root-owned and
# non-writable so a compromised process cannot rewrite its own source.
RUN mkdir -p /var/lib/doom/uploads \
 && chown -R 10001:10001 /var/lib/doom

USER 10001:10001

EXPOSE 8000

# No ENTRYPOINT.  There used to be a shell script here that read the secret
# files and exported DATABASE_URL and REDIS_URL before exec'ing gunicorn - which
# put both passwords into PID 1's environment and every worker's, the exact
# thing the file-based secrets exist to prevent.  config.py now assembles the
# DSNs in-process (ASVS 6.4.1); `make verify-secrets` proves nothing leaks.

# PYTHONDONTWRITEBYTECODE matters here: with read_only:true set in compose,
# any attempt to write .pyc files next to the source would fail.
#
# --no-control-socket: gunicorn 25.1+ opens a management socket under the
# user's home by default, for `gunicornc`.  Nothing here uses it, the user has
# no home and the filesystem is read-only, so every boot logged
# "[ERROR] Control server error: Read-only file system: '/home/doom'" - an
# unneeded interface being attempted rather than removed (ASVS 14.2.2).
CMD ["sh", "-c", "exec gunicorn \
      --bind 0.0.0.0:8000 \
      --workers ${GUNICORN_WORKERS:-2} \
      --threads ${GUNICORN_THREADS:-4} \
      --worker-tmp-dir /tmp \
      --access-logfile - \
      --error-logfile - \
      --logger-class doom.security.gunicorn_logging.JsonAccessLogger \
      --forwarded-allow-ips '*' \
      --no-control-socket \
      wsgi:app"]


# ---------------------------------------------------------------------------
# Test stage - the runtime image plus the suite and a runner.  Never shipped.
#
# This is the LAST stage on purpose only in the sense that it has to come
# after `runtime`; it is NOT the default.  A plain `docker build` picks the
# final stage, so every consumer names its target: compose builds `web` with
# `target: runtime`, the Trivy and publish workflows pass `--target runtime`,
# and `make test` is the only thing that asks for this one.
# ---------------------------------------------------------------------------
FROM runtime AS test

USER 0:0
COPY --from=builder /opt/venv-test /opt/venv
COPY --chown=root:root tests      /srv/doom/tests
COPY --chown=root:root pytest.ini /srv/doom/pytest.ini
USER 10001:10001
