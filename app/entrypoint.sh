#!/bin/sh
# Assemble connection strings from mounted secret files.
#
# The passwords never enter the environment as plain variables: they are read
# from files at startup, used to build the two DSNs, and the DSNs themselves
# are exported only into this process tree (ASVS 6.4.1).
set -eu

read_secret() {
    file_var="${1}_FILE"
    file_path=$(eval "printf '%s' \"\${$file_var:-}\"")
    if [ -n "$file_path" ] && [ -r "$file_path" ]; then
        tr -d '\n' < "$file_path"
    else
        eval "printf '%s' \"\${$1:-}\""
    fi
}

if [ -z "${DATABASE_URL:-}" ]; then
    APP_DB_PASSWORD_VALUE=$(read_secret APP_DB_PASSWORD)
    export DATABASE_URL="postgresql+psycopg://${APP_DB_USER:-doom_app}:${APP_DB_PASSWORD_VALUE}@db:5432/${POSTGRES_DB:-doom}"
    unset APP_DB_PASSWORD_VALUE
fi

if [ -z "${REDIS_URL:-}" ]; then
    REDIS_PASSWORD_VALUE=$(read_secret REDIS_PASSWORD)
    export REDIS_URL="redis://:${REDIS_PASSWORD_VALUE}@cache:6379/0"
    unset REDIS_PASSWORD_VALUE
fi

exec "$@"
