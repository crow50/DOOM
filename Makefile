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
ADMIN_DSN := postgresql+psycopg://$(POSTGRES_ADMIN_USER):$(POSTGRES_PASSWORD)@db:5432/$(POSTGRES_DB)

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
logs: ## Tail logs from every service
	$(COMPOSE) logs -f --tail=100

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
	@set -a; . ./.env; set +a; \
	 printf '%s' "$$SECRET_KEY"        > secrets/secret_key; \
	 printf '%s' "$$POSTGRES_PASSWORD" > secrets/postgres_password; \
	 printf '%s' "$$APP_DB_PASSWORD"   > secrets/app_db_password; \
	 printf '%s' "$$REDIS_PASSWORD"    > secrets/redis_password; \
	 { echo "requirepass $$REDIS_PASSWORD"; \
	   echo "save \"\""; \
	   echo "appendonly no"; } > secrets/redis.conf
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
	@echo "  wrote secrets/ (mode 600, gitignored)"
	@echo
	@echo "Secrets are hex-encoded: URL-safe, so they cannot corrupt a DSN."
	@echo "The application reads them from /run/secrets/, never from its"
	@echo "environment - an env var is visible in docker inspect and in"
	@echo "/proc/<pid>/environ, a mounted 0400 file is not."
	@echo
	@echo "Now set PUBLIC_BASE_URL in .env before printing any labels."

## --------------------------------------------------------------- database
# Generating a migration has to WRITE files, but the web container runs with a
# read-only root filesystem.  Rather than weaken that, generation happens in a
# throwaway container with a writable layer and the result is copied out.
.PHONY: migrate
migrate: ## Generate a migration from model changes (M="message")
	@docker rm -f doom-mig >/dev/null 2>&1 || true
	docker run --name doom-mig --network doom_internal --user root \
		-e DATABASE_URL="$(ADMIN_DSN)" \
		-e SECRET_KEY="$(SECRET_KEY)" \
		-e REDIS_URL="redis://:$(REDIS_PASSWORD)@cache:6379/0" \
		-e PUBLIC_BASE_URL="$(PUBLIC_BASE_URL)" \
		doom-web flask db migrate -m "$(or $(M),auto)"
	docker cp doom-mig:/srv/doom/migrations/versions ./app/migrations/
	@docker rm -f doom-mig >/dev/null
	@echo "New migration written to app/migrations/versions - review it, then: make build && make upgrade"

.PHONY: upgrade
upgrade: ## Apply pending migrations (runs as the ADMIN role, never the app role)
	$(COMPOSE) run --rm -e DATABASE_URL="$(ADMIN_DSN)" web flask db upgrade

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
.PHONY: test
test: ## Run the test suite
	@$(COMPOSE) exec -T db psql -U $(POSTGRES_ADMIN_USER) -d postgres \
		-c "SELECT 1 FROM pg_database WHERE datname='doom_test'" | grep -q 1 || { \
		$(COMPOSE) exec -T db psql -U $(POSTGRES_ADMIN_USER) -d postgres -c "CREATE DATABASE doom_test;" && \
		$(COMPOSE) exec -T db psql -U $(POSTGRES_ADMIN_USER) -d doom_test -c "CREATE EXTENSION IF NOT EXISTS citext;"; }
	$(COMPOSE) run --rm \
		-e DATABASE_URL="postgresql+psycopg://$(POSTGRES_ADMIN_USER):$(POSTGRES_PASSWORD)@db:5432/doom_test" \
		-e REDIS_URL="redis://:$(REDIS_PASSWORD)@cache:6379/9" \
		web python -m pytest -p no:cacheprovider -q

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
		echo "Sanitise with nh3 instead and render the result as text."; \
		exit 1; \
	fi
	@echo "  clean: no autoescape bypasses"

## ------------------------------------------------------------------- certs
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
	@echo "This destroys the database and every uploaded file."
	@read -p "Type 'yes' to continue: " ok; [ "$$ok" = "yes" ] || exit 1
	$(COMPOSE) down -v

.PHONY: help
help: ## Show this help
	@echo "D.O.O.M. - Don't Organize Only Move"
	@echo
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
