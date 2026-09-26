"""Prove db, cache and (from outside) web require TLS, verified against our CA.

Run inside the `web` container, where doom.config already knows the real
DSNs: `docker compose exec -T web python3 - < tools/verify_internal_tls.py`.
`make verify-internal-tls` is the entry point; see ASVS 5.0.0-12.3.1, 12.3.3,
12.3.4 and docs/security/POLICIES.md section 9.

This is a runtime probe, not a unit test - app/tests/test_uploads.py and
friends already run against real infrastructure, but none of them proves a
*plaintext* connection is refused, because refusing one is a server-side
property no application-level test exercises.
"""

from __future__ import annotations

import sys

import psycopg
import redis
import sqlalchemy as sa

from doom.config import Config

FAILURES: list[str] = []


def check(label: str, fn) -> None:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - reporting, not handling
        FAILURES.append(f"{label}: {exc}")
        print(f"FAIL: {label}: {exc}")
    else:
        print(f"  ok: {label}")


def db_verify_full_succeeds() -> None:
    engine = sa.create_engine(Config.SQLALCHEMY_DATABASE_URI)
    with engine.connect() as conn:
        assert conn.execute(sa.text("select 1")).scalar() == 1


def db_plaintext_is_refused() -> None:
    dsn = "postgresql://doom_app@db:5432/doom?sslmode=disable&connect_timeout=3"
    try:
        psycopg.connect(dsn)
    except psycopg.OperationalError:
        return
    raise AssertionError("plaintext connection was accepted")


def cache_verify_full_succeeds() -> None:
    assert redis.from_url(Config.REDIS_URL).ping() is True


def cache_plaintext_is_refused() -> None:
    client = redis.Redis(host="cache", port=6379, socket_connect_timeout=3)
    try:
        client.ping()
    except (redis.ConnectionError, redis.TimeoutError):
        return
    raise AssertionError("plaintext connection was accepted")


if __name__ == "__main__":
    print("checking web -> db and web -> cache (verify-full TLS)...")
    check("web reaches db over verify-full TLS", db_verify_full_succeeds)
    check("web reaches cache over verify-full TLS", cache_verify_full_succeeds)
    print("checking db and cache refuse plaintext...")
    check("db refuses a plaintext connection", db_plaintext_is_refused)
    check("cache refuses a plaintext connection", cache_plaintext_is_refused)

    if FAILURES:
        print(f"\n{len(FAILURES)} check(s) failed")
        sys.exit(1)
    print("\nclean: db and cache require TLS, verified against the internal CA")
