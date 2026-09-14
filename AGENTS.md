# DOOM Agent Instructions

This repository (DOOM) is a self-hosted inventory system focused on security, mapping physical items, and managing history without rewriting it. Much of its development has been handled through agentic tasks.

These instructions are here to help agents navigate and contribute to the codebase effectively.

## 1. Documentation is the Source of Truth for Controls

- The `docs/` folder contains extensive rationale, architecture, and threat modeling information.
- **`docs/COMPLIANCE.md`**: This is the exhaustive ASVS 4.0.3 control ledger.
- **Tests Pin Controls**: DOOM’s testing philosophy is that tests exist to pin controls. The number of published tests is verified automatically.
  - **Do not** manually update test counts in any file other than `docs/COMPLIANCE.md`.
  - Ensure that exceptions in `COMPLIANCE.md` match the exception list perfectly.

## 2. Testing Constraints

- When updating docs or tests, run `make lint` to verify that doc drift hasn't occurred. `tools/check_docs.py` asserts that the stated number of tests in `COMPLIANCE.md` matches what `pytest` actually collects.
- If you can't run tests via Docker in a sandbox environment due to `mount source: "overlay"` errors, install `pytest` and requirements manually via `pip install -r app/requirements.txt`, then run `pytest` inside the `app/` directory (note: some database-dependent tests may fail or be skipped if the DB is unreachable, but `pytest --collect-only` used by `make lint` will work).

## 3. Data Boundaries and Security Constraints

- **`app/doom/validation.py`**: This is the single source of truth for limits on user data (text lengths, quantities, etc.). If you change a form length or DB constraint, you must update it here.
- **AuthZ**: Ownership is a `WHERE` clause, not an `if` statement. Fetch-then-check is an anti-pattern here.
- **Audit**: History can only be added to, never modified. `UPDATE` and `DELETE` are revoked for the app role on the `audit_log` table.

## 4. Writing Documentation

- **Docs and README** are for humans. Use clear, accessible language.
- **Docstrings** are for everyone. They should clearly describe function signatures, return values, and context.
- **Code comments** can be terse but should focus on *why* something is done, rather than *what* is done.

## 5. Build and Deploy

- Standard startup: `cp .env.example .env && make init && make up && make upgrade && make seed`
- Labels bake `PUBLIC_BASE_URL` in permanently. This MUST be set before printing labels.
