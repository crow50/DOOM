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

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" <<-EOSQL
	-- citext gives case-insensitive UNIQUE on usernames, so "Admin" and "admin"
	-- cannot both exist.  Requires superuser, which is precisely why migrations
	-- run as doom_admin and not as the application role.
	CREATE EXTENSION IF NOT EXISTS citext;

	CREATE ROLE ${APP_DB_USER} LOGIN PASSWORD '${APP_DB_PASSWORD}';

	GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO ${APP_DB_USER};
	GRANT USAGE   ON SCHEMA public          TO ${APP_DB_USER};

	-- Explicitly withhold DDL.  Postgres 15+ already revokes this from PUBLIC,
	-- but stating it means the intent survives a version change.
	REVOKE CREATE ON SCHEMA public FROM PUBLIC;
	REVOKE CREATE ON SCHEMA public FROM ${APP_DB_USER};

	-- Tables do not exist yet - migrations create them later.  Default
	-- privileges apply the grant automatically to everything doom_admin
	-- creates from here on, so no post-migration grant step can be forgotten.
	ALTER DEFAULT PRIVILEGES FOR ROLE ${POSTGRES_USER} IN SCHEMA public
	    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${APP_DB_USER};

	ALTER DEFAULT PRIVILEGES FOR ROLE ${POSTGRES_USER} IN SCHEMA public
	    GRANT USAGE, SELECT ON SEQUENCES TO ${APP_DB_USER};
EOSQL

echo "doom: created restricted application role '${APP_DB_USER}' (DML only)"
