# ---------------------------------------------------------------------------
# D.O.O.M. - Don't Organize Only Move
# ---------------------------------------------------------------------------
.DEFAULT_GOAL := help
SHELL := /bin/bash

# Load .env so recipes can reach the DB credentials.  Missing file is fine -
# `make init` creates it.
-include .env
export

COMPOSE := docker compose

# Migrations run as the schema OWNER, never as the application role.
# doom_app holds DML only and cannot ALTER TABLE or CREATE EXTENSION, so
# pointing alembic at the app DSN would fail by design (T-35).
#
# sslmode=verify-full: this DSN crosses the network inside a `web` one-off
# container (db/init/00-hba.sh refuses that hop over anything else), which
# already has the internal CA mounted for config.py's own DSNs.
ADMIN_DSN := postgresql+psycopg://$(POSTGRES_ADMIN_USER):$(POSTGRES_PASSWORD)@db:5432/$(POSTGRES_DB)?sslmode=verify-full&sslrootcert=/run/secrets/doom_internal_ca_cert

BACKUP_DIR := backups
STAMP      := $(shell date +%Y%m%d-%H%M%S)

## ---------------------------------------------------------------- lifecycle
.PHONY: up
up: ## Build if needed and start the whole stack
	$(COMPOSE) up -d --build
	@echo
	@echo "  DOOM is starting at $(PUBLIC_BASE_URL)"
	@echo "  Follow boot with:  make logs"

.PHONY: down
down: ## Stop the stack, keep all data
	$(COMPOSE) down

.PHONY: restart
restart: down up ## Stop then start

.PHONY: build
build: ## Build images
	$(COMPOSE) build

.PHONY: rebuild
rebuild: ## Rebuild images from scratch, ignoring cache
	$(COMPOSE) build --no-cache

.PHONY: logs
logs: ## Follow logs from every service (interactive)
	$(COMPOSE) logs -f --tail=100

# `logs` follows, which is right at a terminal and wrong in CI: as a failure
# handler it never returns, so the job hangs until the runner times out instead
# of printing the reason it failed. This is the same thing without the -f.
.PHONY: logs-dump
logs-dump: ## Print recent logs and container state, then exit
	-$(COMPOSE) ps -a
	-$(COMPOSE) logs --no-color --tail=200

.PHONY: ps
ps: ## Show container status
	$(COMPOSE) ps

## ------------------------------------------------------------------- setup
.PHONY: init
init: ## Create .env and generate strong secrets (safe to re-run)
	@test -f .env || { cp .env.example .env; echo "created .env from .env.example"; }
	@for key in SECRET_KEY POSTGRES_PASSWORD APP_DB_PASSWORD REDIS_PASSWORD; do \
		current=$$(grep -E "^$$key=" .env | cut -d= -f2-); \
		if [ "$$current" = "CHANGE_ME" ] || [ -z "$$current" ]; then \
			secret=$$(openssl rand -hex 32); \
			sed -i.bak "s|^$$key=.*|$$key=$$secret|" .env && rm -f .env.bak; \
			echo "  generated $$key"; \
		else \
			echo "  $$key already set, leaving it alone"; \
		fi; \
	done
	@chmod 600 .env
	@# ASVS 6.4.1 — the real secrets live in files, not the environment.
	@# .env keeps only non-secret settings plus the values the admin tooling
	@# needs; the running application reads /run/secrets/* instead.
	@mkdir -p secrets && chmod 700 secrets
	@# Existing files are 0444 from a prior run (see the chmod below). Without
	@# this, re-running init on a deployment that already has secrets - which
	@# upgrading to internal TLS requires, to get the new CA and certs below -
	@# fails every redirect in the next block with "Permission denied".
	@chmod -f u+w secrets/* 2>/dev/null || true
	@set -a; . ./.env; set +a; \
	 printf '%s' "$$SECRET_KEY"        > secrets/secret_key; \
	 printf '%s' "$$POSTGRES_PASSWORD" > secrets/postgres_password; \
	 printf '%s' "$$APP_DB_PASSWORD"   > secrets/app_db_password; \
	 printf '%s' "$$REDIS_PASSWORD"    > secrets/redis_password; \
	 { echo "requirepass $$REDIS_PASSWORD"; \
	   echo "save \"\""; \
	   echo "appendonly no"; \
	   echo "port 0"; \
	   echo "tls-port 6379"; \
	   echo "tls-cert-file /run/secrets/doom_cache_tls_cert"; \
	   echo "tls-key-file /run/secrets/doom_cache_tls_key"; \
	   echo "tls-auth-clients no"; \
	   echo "tls-protocols \"TLSv1.2 TLSv1.3\""; \
	 } > secrets/redis.conf
	@# --- internal TLS: a private CA for caddy->web, web->db, web->cache -----
	@# (ASVS 5.0.0-12.3.1, 12.3.3, 12.3.4). One CA; three leaf certs, one per
	@# hostname a client on the internal network actually dials. Idempotent
	@# like the secrets above - an existing CA and its issued certs are left
	@# alone, so re-running `make init` does not invalidate certificates
	@# already trusted by a running stack.
	@test -f secrets/internal_ca.key || { \
		openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
			-keyout secrets/internal_ca.key -out secrets/internal_ca.crt \
			-subj "/CN=DOOM internal CA" \
			-addext "basicConstraints=critical,CA:true" \
			-addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null; \
		echo "  generated secrets/internal_ca.{key,crt} (10-year validity)"; \
	}
	@for svc in db cache web; do \
		test -f secrets/$${svc}_tls.key || { \
			tmp=$$(mktemp -d); \
			openssl req -newkey rsa:2048 -sha256 -nodes \
				-keyout secrets/$${svc}_tls.key -out $$tmp/$${svc}.csr \
				-subj "/CN=$${svc}" 2>/dev/null; \
			printf 'subjectAltName=DNS:%s\n' "$${svc}" > $$tmp/$${svc}.ext; \
			openssl x509 -req -in $$tmp/$${svc}.csr -CA secrets/internal_ca.crt \
				-CAkey secrets/internal_ca.key -CAcreateserial -days 825 -sha256 \
				-extfile $$tmp/$${svc}.ext -out secrets/$${svc}_tls.crt 2>/dev/null; \
			rm -rf "$$tmp"; \
			echo "  generated secrets/$${svc}_tls.{key,crt} (signed for CN=$${svc})"; \
		}; \
	done
	@rm -f secrets/internal_ca.srl
	@# Mode 0444, not 0400.
	@#
	@# Compose bind-mounts file-based secrets with their host permissions, and
	@# the containers run as unprivileged users that do not own these files
	@# (uid 10001 for the app, 999 for redis). A 0400 file owned by the host
	@# user is simply unreadable to them, so the containers fail to start.
	@#
	@# What actually protects these is the directory, not the file mode: the
	@# secrets/ directory is 0700, so no other host user can reach it, and
	@# each container runs a single process. The security gain over environment
	@# variables is unchanged and is the point of the exercise - these values
	@# do not appear in `docker inspect`, are not inherited by child processes,
	@# and cannot be read out of /proc/<pid>/environ.
	@chmod 444 secrets/*
	@echo "  wrote secrets/ (files 0444 inside a 0700 directory, gitignored)"
	@echo
	@echo "Secrets are hex-encoded: URL-safe, so they cannot corrupt a DSN."
	@echo "The application reads them from /run/secrets/, never from its"
	@echo "environment - an env var is visible in docker inspect and in"
	@echo "/proc/<pid>/environ, a mounted 0400 file is not."
	@echo
	@echo "Now set PUBLIC_BASE_URL in .env before printing any labels."

## --------------------------------------------------------------- database
# NOT the development path right now - see `make baseline` and D-38.  While the
# schema is still moving there is one regenerated baseline rather than a chain
# of revisions, so this target is for when that stops being true and real
# history starts.
#
# Generating a migration has to WRITE files, but the web container runs with a
# read-only root filesystem.  Rather than weaken that, generation happens in a
# throwaway container with a writable layer and the result is copied out.
.PHONY: migrate
migrate: ## Generate a migration from model changes (M="message")
	@docker rm -f doom-mig >/dev/null 2>&1 || true
	@# Silenced with @: make echoes recipe lines, and this one carries the
	@# admin DSN, SECRET_KEY and the redis password.  Unsilenced, all three
	@# landed in the terminal, in scrollback, and in any CI log that ran it.
	@# They are still passed as -e, visible in `docker inspect doom-mig` for
	@# the seconds the throwaway container exists: the dev-only exception to
	@# 6.4.1, because the app has no file-based path for the ADMIN role and
	@# should not grow one.  The trap guarantees that window closes even if
	@# `flask db migrate` itself fails, instead of leaving doom-mig stopped
	@# and inspectable indefinitely.
	@echo "  running 'flask db migrate' as $(POSTGRES_ADMIN_USER) in a throwaway container..."
	@set -e; \
	trap 'docker rm -f doom-mig >/dev/null 2>&1 || true' EXIT; \
	before=$$(ls app/migrations/versions/*.py 2>/dev/null | sort); \
	docker run --name doom-mig --network doom_internal --user root \
		-v "$(CURDIR)/secrets/internal_ca.crt:/run/secrets/doom_internal_ca_cert:ro" \
		-e DATABASE_URL="$(ADMIN_DSN)" \
		-e SECRET_KEY="$(SECRET_KEY)" \
		-e REDIS_URL="rediss://:$(REDIS_PASSWORD)@cache:6379/0?ssl_cert_reqs=required&ssl_check_hostname=true&ssl_ca_certs=/run/secrets/doom_internal_ca_cert" \
		-e PUBLIC_BASE_URL="$(PUBLIC_BASE_URL)" \
		doom-web flask db migrate -m "$(or $(M),auto)"; \
	docker cp doom-mig:/srv/doom/migrations/versions ./app/migrations/; \
	after=$$(ls app/migrations/versions/*.py 2>/dev/null | sort); \
	if [ "$$before" = "$$after" ]; then \
		echo "  no schema changes detected - nothing written"; \
	else \
		echo "  new migration written to app/migrations/versions - review it, then: make build && make upgrade"; \
	fi

# Two steps, because only one of them is schema.  `flask db-grants` applies the
# audit_log REVOKE, which used to live inside a migration - a bad home for it
# twice over: it depended on a particular revision having run, and that
# revision's downgrade() handed the verbs back.  Now the migration history is a
# regenerable baseline (D-38), so nothing durable can live in it at all.
# Development only, and deliberately destructive.
#
# While the schema is still moving, the migration history is a single baseline
# regenerated from the models rather than a chain of incremental revisions
# (D-38).  The trade is: no per-change migration file to write and review, at
# the cost of recreating the database whenever the schema changes.  This is that
# recreation.
#
# Autogenerate diffs the models against what is already in the database, so a
# database that is already up to date produces an EMPTY migration.  That is why
# this drops the volume first rather than just deleting the files.
.PHONY: baseline
baseline: ## Regenerate the one baseline migration from models (DESTROYS the database)
	@echo "This deletes every migration file and recreates the database from scratch."
	@read -p "Type 'yes' to continue: " ok; [ "$$ok" = "yes" ] || exit 1
	rm -f app/migrations/versions/*.py
	$(COMPOSE) down -v
	$(MAKE) up
	@docker rm -f doom-mig >/dev/null 2>&1 || true
	@# Silenced with @: make echoes recipe lines, and this one carries the
	@# admin DSN, SECRET_KEY and the redis password.  Unsilenced, all three
	@# landed in the terminal, in scrollback, and in any CI log that ran it.
	@# They are still passed as -e, visible in `docker inspect doom-mig` for
	@# the seconds the throwaway container exists: the dev-only exception to
	@# 6.4.1, because the app has no file-based path for the ADMIN role and
	@# should not grow one.  The trap guarantees that window closes even if
	@# `flask db migrate` itself fails, instead of leaving doom-mig stopped
	@# and inspectable indefinitely.
	@echo "  running 'flask db migrate' as $(POSTGRES_ADMIN_USER) in a throwaway container..."
	@set -e; \
	trap 'docker rm -f doom-mig >/dev/null 2>&1 || true' EXIT; \
	docker run --name doom-mig --network doom_internal --user root \
		-v "$(CURDIR)/secrets/internal_ca.crt:/run/secrets/doom_internal_ca_cert:ro" \
		-e DATABASE_URL="$(ADMIN_DSN)" \
		-e SECRET_KEY="$(SECRET_KEY)" \
		-e REDIS_URL="rediss://:$(REDIS_PASSWORD)@cache:6379/0?ssl_cert_reqs=required&ssl_check_hostname=true&ssl_ca_certs=/run/secrets/doom_internal_ca_cert" \
		-e PUBLIC_BASE_URL="$(PUBLIC_BASE_URL)" \
		doom-web flask db migrate -m "baseline schema"; \
	docker cp doom-mig:/srv/doom/migrations/versions ./app/migrations/
	@echo
	@echo "Baseline written to app/migrations/versions - read it, then:"
	@echo "  make build && make upgrade && make verify-db-roles"

.PHONY: upgrade
upgrade: ## Apply migrations and privilege rules (ADMIN role, never the app role)
	@# db/init/01-roles.sh creates citext once, on a fresh volume.  A volume
	@# that predates citext and never re-ran init would otherwise fail here
	@# on the first CITEXT column the baseline migration creates.
	$(COMPOSE) exec -T db psql -U $(POSTGRES_ADMIN_USER) -d $(POSTGRES_DB) -c "CREATE EXTENSION IF NOT EXISTS citext;"
	$(COMPOSE) run --rm -e DATABASE_URL="$(ADMIN_DSN)" web flask db upgrade
	$(COMPOSE) run --rm -e DATABASE_URL="$(ADMIN_DSN)" web flask db-grants

.PHONY: seed
seed: ## Load demo data
	$(COMPOSE) run --rm web flask seed

.PHONY: db-shell
db-shell: ## psql as the ADMIN role
	$(COMPOSE) exec db psql -U $(POSTGRES_ADMIN_USER) -d $(POSTGRES_DB)

.PHONY: db-shell-app
db-shell-app: ## psql as the RESTRICTED app role - use this to prove least privilege
	$(COMPOSE) exec -e PGPASSWORD=$(APP_DB_PASSWORD) db \
		psql -U $(APP_DB_USER) -d $(POSTGRES_DB) -h 127.0.0.1

# The two-role split is the control T-08, T-35 and D-08 all rest on, and until
# this target existed nothing checked it: `make test` connects to a separate
# doom_test database as the ADMIN role, so the whole suite passes whether or not
# doom_app exists.  It did not exist - db/init/01-roles.sh aborted on an unbound
# variable before creating it, and the container restarted onto an already
# initialised data directory, skipping the script and looking healthy.  Postgres
# reports a missing role as "password authentication failed" (it will not confirm
# whether a role exists), so the only symptom was `make seed` failing as though
# the password were wrong.
#
# The grant sweep below was added for the same reason one step further in: the
# original version proved doom_app could SELECT and stopped there, so INSERT -
# the one verb `make seed` actually needs - was never checked by anything.  A
# table that missed the ALTER DEFAULT PRIVILEGES grant would have passed every
# check in CI and failed on the first row written.  It asks the catalogue
# instead of writing a probe row, because the app role cannot clean up after
# itself on audit_log by design.
#
# Each assertion below is the executable evidence for a row in the ASVS ledger.
.PHONY: verify-db-roles
verify-db-roles: ## Prove the app role exists and is properly restricted
	@set -e; \
	app_psql() { $(COMPOSE) exec -T -e PGPASSWORD=$(APP_DB_PASSWORD) db \
		psql -v ON_ERROR_STOP=1 -qtAX -U $(APP_DB_USER) -d $(POSTGRES_DB) -h 127.0.0.1 "$$@"; }; \
	echo "checking the application database role..."; \
	\
	app_psql -c 'SELECT 1' >/dev/null \
		|| { echo "FAIL: $(APP_DB_USER) cannot log in - was db/init/01-roles.sh skipped?"; exit 1; }; \
	echo "  ok: $(APP_DB_USER) can connect over TCP"; \
	\
	test "$$(app_psql -c \
		"SELECT count(*) FROM pg_extension WHERE extname = 'citext'")" = "1" \
		|| { echo "FAIL: citext missing - 01-roles.sh creates it, so init did not complete"; exit 1; }; \
	echo "  ok: citext is installed"; \
	\
	app_psql -c 'SELECT count(*) FROM items' >/dev/null \
		|| { echo "FAIL: $(APP_DB_USER) cannot SELECT (migrations run?)"; exit 1; }; \
	echo "  ok: DML reads are permitted"; \
	\
	missing="$$(app_psql -c "SELECT coalesce(string_agg(c.relname || ' ' || v.verb, ', ' ORDER BY c.relname, v.verb), '') FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) AS v(verb) WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname NOT IN ('alembic_version') AND NOT (c.relname = 'audit_log' AND v.verb IN ('UPDATE', 'DELETE')) AND NOT has_table_privilege(c.oid, v.verb)")"; \
	[ -z "$$missing" ] || { echo "FAIL: $(APP_DB_USER) is missing DML grants on: $$missing"; exit 1; }; \
	echo "  ok: every table grants the verbs the application needs"; \
	\
	if app_psql -c 'CREATE TABLE doom_privilege_probe (id int)' >/dev/null 2>&1; then \
		app_psql -c 'DROP TABLE IF EXISTS doom_privilege_probe' >/dev/null 2>&1 || true; \
		echo "FAIL: $(APP_DB_USER) can CREATE TABLE - it holds DDL it must not have"; exit 1; \
	fi; \
	echo "  ok: DDL is refused"; \
	\
	if app_psql -c "UPDATE audit_log SET detail = 'x'" >/dev/null 2>&1; then \
		echo "FAIL: $(APP_DB_USER) can UPDATE audit_log - history is rewritable"; exit 1; \
	fi; \
	if app_psql -c 'DELETE FROM audit_log' >/dev/null 2>&1; then \
		echo "FAIL: $(APP_DB_USER) can DELETE from audit_log - history is erasable"; exit 1; \
	fi; \
	echo "  ok: audit_log is append-only for $(APP_DB_USER)"; \
	echo "  clean: the two-role split is in place"

# The 6.4.1 claim is that no password reaches a process environment.  The
# check that used to stand behind it grepped PID 1's environ for
# `APP_DB_PASSWORD=` and `REDIS_PASSWORD=` - and returned zero while both
# passwords sat right beside them inside DATABASE_URL= and REDIS_URL=, put
# there by an entrypoint that assembled the DSNs in shell and exported them.
# A check that names the variables it expects can only find the leak it
# already knows about.  This one looks for the password values themselves,
# in the master, in a worker, and in what `docker inspect` would show.
.PHONY: verify-secrets
verify-secrets: ## Prove no secret value is in any process environment or in docker inspect
	@set -e; \
	echo "checking that secret values stay out of process environments..."; \
	environs=$$($(COMPOSE) exec -T web sh -c 'for p in /proc/[0-9]*; do cat $$p/environ 2>/dev/null; echo; done | tr "\\0" "\\n"'); \
	for f in app_db_password redis_password secret_key; do \
		val=$$(cat secrets/$$f); \
		if docker inspect $$($(COMPOSE) ps -q web) --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -qF "$$val"; then \
			echo "FAIL: the value of secrets/$$f appears in docker inspect"; exit 1; fi; \
		if printf '%s' "$$environs" | grep -qF "$$val"; then \
			echo "FAIL: the value of secrets/$$f is in a process environment inside web"; exit 1; fi; \
	done; \
	echo "  ok: no secret value in docker inspect"; \
	echo "  ok: no secret value in any process environment (master or workers)"; \
	if $(COMPOSE) exec -T web sh -c "tr '\\0' '\\n' < /proc/1/environ" | grep -qE '^(DATABASE_URL|REDIS_URL|SECRET_KEY|APP_DB_PASSWORD|REDIS_PASSWORD)='; then \
		echo "FAIL: a DSN or raw secret variable is set in PID 1's environment"; exit 1; fi; \
	echo "  ok: only *_FILE paths reach the process; the DSNs are assembled in-process"; \
	echo "  clean: secrets are files, and stay files"

.PHONY: verify-internal-tls
verify-internal-tls: ## Prove db, cache and caddy->web require TLS, verified against our CA
	@$(COMPOSE) exec -T web python3 - < tools/verify_internal_tls.py
	@echo "checking caddy -> web (ASVS 5.0.0-12.3.3)..."
	@docker run --rm --network doom_proxy curlimages/curl \
		-sS --max-time 3 http://web:8000/healthz >/dev/null 2>&1 \
		&& { echo "FAIL: web accepted a plaintext connection"; exit 1; } \
		|| echo "  ok: web refuses a plaintext connection"
	@docker run --rm --network doom_proxy \
		-v "$(CURDIR)/secrets/internal_ca.crt:/ca.crt:ro" curlimages/curl \
		-fsS --max-time 3 --cacert /ca.crt https://web:8000/healthz >/dev/null \
		&& echo "  ok: web serves a certificate verify-full trusts" \
		|| { echo "FAIL: caddy's view of web's certificate did not verify against the internal CA"; exit 1; }
	@echo "clean: every internal hop requires TLS, verified against the CA make init generated"

.PHONY: shell
shell: ## Shell inside the web container
	$(COMPOSE) exec web /bin/bash

## ----------------------------------------------------------------- operate
.PHONY: unlock-user
unlock-user: ## Clear a lockout: make unlock-user USER=alice
	@test -n "$(USER_NAME)" || { echo "usage: make unlock-user USER_NAME=alice"; exit 1; }
	$(COMPOSE) run --rm web flask unlock-user "$(USER_NAME)"

## ------------------------------------------------------------------ verify
# Tests need CREATE privileges for db.create_all(), so they run against a
# separate database under the ADMIN role.  The application itself never gets
# these credentials.
#
# They run from the `test` build stage - the runtime image plus the suite and
# pytest - because the runtime image no longer carries either (ASVS 14.2.2).
# The service sits behind a compose profile so nothing but this target builds
# or starts it.  The one-off `-e` overrides that used to live here are now the
# service's own environment in docker-compose.yml.
.PHONY: test
test: ## Run the test suite
	@$(COMPOSE) exec -T db psql -U $(POSTGRES_ADMIN_USER) -d postgres \
		-c "SELECT 1 FROM pg_database WHERE datname='doom_test'" | grep -q 1 || { \
		$(COMPOSE) exec -T db psql -U $(POSTGRES_ADMIN_USER) -d postgres -c "CREATE DATABASE doom_test;" && \
		$(COMPOSE) exec -T db psql -U $(POSTGRES_ADMIN_USER) -d doom_test -c "CREATE EXTENSION IF NOT EXISTS citext;"; }
	$(COMPOSE) --profile test build --quiet test
	$(COMPOSE) --profile test run --rm test python -m pytest -p no:cacheprovider -q

.PHONY: audit-verify
audit-verify: ## Verify the audit hash chain and print the head hash
	$(COMPOSE) run --rm web flask audit-verify

.PHONY: lint
lint: ## Template safety grep - fails if user data could bypass autoescaping
	@echo "checking templates for autoescape bypasses..."
	@if grep -rnE '\|\s*safe|Markup\(' app/doom/templates app/doom 2>/dev/null | grep -v '^Binary'; then \
		echo; \
		echo "FAIL: '|safe' or 'Markup()' found."; \
		echo "User-supplied content must never bypass Jinja2 autoescaping (T-19)."; \
		echo "Render user content as text. If a genuine untrusted-HTML surface"; \
		echo "is ever needed, add a sanitiser as a dependency and a ledger row"; \
		echo "for ASVS 5.2.1 first - do not reach for |safe."; \
		exit 1; \
	fi
	@echo "  clean: no autoescape bypasses"
	@python3 tools/security_assessment.py

.PHONY: verify-version
verify-version: ## Check a release tag agrees with __version__ (TAG=v1.2.3, or HEAD's tag)
	@code=$$(grep -oE '^__version__ = "[^"]+"' app/doom/__init__.py | cut -d'"' -f2); \
	if [ -z "$$code" ]; then \
		echo "FAIL: no __version__ found in app/doom/__init__.py"; exit 1; \
	fi; \
	if ! echo "$$code" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "FAIL: __version__ '$$code' is not a bare semantic version (1.2.3)"; exit 1; \
	fi; \
	tag="$(TAG)"; \
	if [ -z "$$tag" ]; then \
		tag=$$(git describe --exact-match --tags HEAD 2>/dev/null || true); \
	fi; \
	if [ -z "$$tag" ]; then \
		echo "  note: HEAD carries no release tag; __version__ is $$code"; \
		exit 0; \
	fi; \
	if [ "$$tag" != "v$$code" ]; then \
		echo "FAIL: tag $$tag disagrees with __version__ $$code."; \
		echo "      A container tagged $$tag would report $$code at startup."; \
		echo "      Either retag as v$$code, or bump __version__ in"; \
		echo "      app/doom/__init__.py to $${tag#v} and commit before tagging."; \
		exit 1; \
	fi; \
	echo "  clean: tag $$tag matches __version__ $$code"

.PHONY: passwords-corpus
passwords-corpus: ## Regenerate the breach corpus in security/data/
	@python3 tools/build_password_corpus.py

## ------------------------------------------------------------------- certs
.PHONY: verify-cert
verify-cert: ## Check the served certificate, and that a renewed file was picked up
	@set -e; \
	command -v openssl >/dev/null 2>&1 \
		|| { echo "SKIP: openssl is not on this host, so the served certificate cannot be read"; exit 0; }; \
	host=$${DOOM_DOMAIN:-localhost}; port=$${HTTPS_PORT:-443}; \
	echo "checking the certificate served on 127.0.0.1:$$port for $$host..."; \
	served=$$(openssl s_client -connect 127.0.0.1:$$port -servername $$host </dev/null 2>/dev/null \
		| openssl x509 2>/dev/null); \
	test -n "$$served" \
		|| { echo "FAIL: nothing answered TLS on 127.0.0.1:$$port - is the stack up?"; exit 1; }; \
	printf '%s\n' "$$served" | openssl x509 -noout -subject -issuer -enddate | sed 's/^/  /'; \
	\
	configured=$$(cat caddy/conf.d/site/*.caddy 2>/dev/null \
		| sed -n 's/^[[:space:]]*tls[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' | head -1); \
	\
	if [ -z "$$configured" ]; then \
		if printf '%s\n' "$$served" | openssl x509 -noout -checkend 0 >/dev/null 2>&1; then \
			echo "  ok: Caddy is managing this certificate itself, and it is valid"; \
			echo "      A short expiry here is normal and not a finding: Caddy's"; \
			echo "      internal CA issues 12-hour leaves and renews them itself."; \
			exit 0; \
		fi; \
		echo "FAIL: the served certificate has expired and Caddy manages it, so"; \
		echo "      renewal is broken rather than merely due. Check the caddy logs."; \
		exit 1; \
	fi; \
	\
	if printf '%s\n' "$$served" | openssl x509 -noout -checkend $$((21*86400)) >/dev/null 2>&1; then \
		echo "  ok: more than 21 days of validity left"; \
	else \
		echo "FAIL: this certificate comes from a file, so nothing here renews it,"; \
		echo "      and it expires within 21 days (or already has)."; exit 1; \
	fi; \
	\
	onhost=caddy/certs/$${configured##*/}; \
	test -f "$$onhost" \
		|| { echo "FAIL: $$configured is configured but $$onhost does not exist"; exit 1; }; \
	disk=$$(openssl x509 -noout -fingerprint -sha256 -in "$$onhost" 2>/dev/null | cut -d= -f2); \
	wire=$$(printf '%s\n' "$$served" | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2); \
	if [ "$$disk" = "$$wire" ]; then \
		echo "  ok: the file on disk is the certificate being served"; \
	else \
		echo "FAIL: $$onhost has been replaced but Caddy is still serving the old"; \
		echo "      certificate. Caddy reads a 'tls <file>' certificate once, at"; \
		echo "      config load, and does not watch the file - so a renewal in"; \
		echo "      place takes effect only on restart:"; \
		echo; \
		echo "          docker compose restart caddy"; \
		echo; \
		echo "      Hook that onto your renewal (acme.sh --reloadcmd, certbot"; \
		echo "      --deploy-hook) so this cannot happen again."; \
		exit 1; \
	fi

.PHONY: trust-cert
trust-cert: ## Export Caddy's root CA for installing on a demo phone
	@mkdir -p certs
	$(COMPOSE) cp caddy:/data/caddy/pki/authorities/local/root.crt certs/doom-root-ca.crt
	@echo
	@echo "Wrote certs/doom-root-ca.crt"
	@echo "Transfer it to the phone and install under Settings > Security >"
	@echo "Encryption & credentials > Install a certificate > CA certificate."
	@echo
	@echo "If Android refuses it, use the cloudflared fallback in docs/DEMO.md -"
	@echo "Web NFC needs a genuine secure context and will not run without one."

## ------------------------------------------------------------------ backup
.PHONY: backup
backup: ## Back up BOTH the database and the uploaded files
	@mkdir -p $(BACKUP_DIR)
	$(COMPOSE) exec -T db pg_dump -U $(POSTGRES_ADMIN_USER) -d $(POSTGRES_DB) \
		| gzip > $(BACKUP_DIR)/doom-db-$(STAMP).sql.gz
	@# Streamed over stdout rather than written through a bind mount: the
	@# container runs as uid 10001 and cannot necessarily write to a host
	@# directory, which fails silently and leaves an empty archive.
	$(COMPOSE) exec -T web tar czf - -C /var/lib/doom uploads \
		> $(BACKUP_DIR)/doom-uploads-$(STAMP).tar.gz
	@echo
	@echo "  $(BACKUP_DIR)/doom-db-$(STAMP).sql.gz"
	@echo "  $(BACKUP_DIR)/doom-uploads-$(STAMP).tar.gz"
	@echo
	@echo "A database dump alone is NOT a backup here - every photo and"
	@echo "document lives in the uploads volume, not in Postgres."

.PHONY: restore
restore: ## Restore from a backup pair: make restore DB=... UPLOADS=...
	@test -n "$(DB)" || { echo "usage: make restore DB=backups/doom-db-*.sql.gz UPLOADS=backups/doom-uploads-*.tar.gz"; exit 1; }
	gunzip -c $(DB) | $(COMPOSE) exec -T db psql -U $(POSTGRES_ADMIN_USER) -d $(POSTGRES_DB)
	@test -z "$(UPLOADS)" || gunzip -c $(UPLOADS) | \
		$(COMPOSE) exec -T web tar xf - -C /var/lib/doom
	@echo "restore complete"

## ------------------------------------------------------------------- clean
.PHONY: clean
clean: ## Stop and DELETE all data volumes
	@echo "This destroys the database, every uploaded file, .env, and secrets."
	@read -p "Type 'yes' to continue: " ok; [ "$$ok" = "yes" ] || exit 1
	$(COMPOSE) --profile test down -v --rmi local
	@rm -f .env
	@rm -rf secrets

.PHONY: help
help: ## Show this help
	@echo "D.O.O.M. - Don't Organize Only Move"
	@echo
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
