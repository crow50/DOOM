#!/bin/bash
# ---------------------------------------------------------------------------
# Runs once, on first initialisation of an empty data directory.
#
# Establishes the two-role split that the whole SQL-injection defence rests on
# (T-08, T-35):
#
#   doom_admin  owns the schema.  Used ONLY by `make migrate`.
#   doom_app    SELECT/INSERT/UPDATE/DELETE and nothing else.  Used by the app.
#
# Because doom_app cannot ALTER, DROP, or CREATE, a successful injection through
# the application is confined to reading and writing rows it could already reach.
# It cannot drop a table, define a function, or read pg_shadow.
# ---------------------------------------------------------------------------
set -euo pipefail

# The password arrives as a file, and nothing hands it to us as a variable.
#
# The official image's file_env() is called for exactly four names -
# POSTGRES_PASSWORD, POSTGRES_USER, POSTGRES_DB and POSTGRES_INITDB_ARGS - and
# there is no generic *_FILE loop.  APP_DB_PASSWORD is ours, so APP_DB_PASSWORD
# _FILE is a path nobody opens unless we open it.
#
# Reading it here is not a nicety.  Referencing an unbound variable under
# `set -u` is fatal *while the heredoc below is expanded*, which means psql is
# never invoked at all: no role, no citext, and an init that fails silently
# because the container then restarts onto an already-initialised data
# directory and skips this script entirely.  `make verify-db-roles` exists to
# catch that, and this block is what stops it happening.
if [ -z "${APP_DB_PASSWORD:-}" ] && [ -n "${APP_DB_PASSWORD_FILE:-}" ]; then
    APP_DB_PASSWORD="$(tr -d '\n' < "$APP_DB_PASSWORD_FILE")"
fi
: "${APP_DB_PASSWORD:?set APP_DB_PASSWORD or APP_DB_PASSWORD_FILE}"
: "${APP_DB_USER:?set APP_DB_USER}"

# The heredoc is quoted, so the shell expands nothing and psql does the
# substitution: :'name' emits a correctly quoted literal, :"name" a correctly
# quoted identifier.  Splicing a password into SQL text works right up until the
# password contains a quote, and a project that argues about injection defences
# should not have one in its own bootstrap.
psql -v ON_ERROR_STOP=1 \
     -v app_user="$APP_DB_USER" \
     -v app_password="$APP_DB_PASSWORD" \
     -v db_name="$POSTGRES_DB" \
     -v schema_owner="$POSTGRES_USER" \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" <<-'EOSQL'
	-- citext gives case-insensitive UNIQUE on usernames, so "Admin" and "admin"
	-- cannot both exist.  Requires superuser, which is precisely why migrations
	-- run as doom_admin and not as the application role.
	CREATE EXTENSION IF NOT EXISTS citext;

	CREATE ROLE :"app_user" LOGIN PASSWORD :'app_password';

	GRANT CONNECT ON DATABASE :"db_name" TO :"app_user";
	GRANT USAGE   ON SCHEMA public               TO :"app_user";

	-- Explicitly withhold DDL.  Postgres 15+ already revokes this from PUBLIC,
	-- but stating it means the intent survives a version change.
	REVOKE CREATE ON SCHEMA public FROM PUBLIC;
	REVOKE CREATE ON SCHEMA public FROM :"app_user";

	-- Tables do not exist yet - migrations create them later.  Default
	-- privileges apply the grant automatically to everything doom_admin
	-- creates from here on, so no post-migration grant step can be forgotten.
	ALTER DEFAULT PRIVILEGES FOR ROLE :"schema_owner" IN SCHEMA public
	    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app_user";

	ALTER DEFAULT PRIVILEGES FOR ROLE :"schema_owner" IN SCHEMA public
	    GRANT USAGE, SELECT ON SEQUENCES TO :"app_user";
EOSQL

echo "doom: created restricted application role '${APP_DB_USER}' (DML only)"
