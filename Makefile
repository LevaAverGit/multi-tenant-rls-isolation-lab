# Makefile -- single-command workflow for the RLS isolation lab.
#
# Typical run:
#   make up        # start Postgres (migrations apply automatically on init)
#   make test      # run the isolation + break-isolation tests on the real DB
#   make down      # stop and wipe the database

# DEV-ONLY local connection string for the NON-OWNER application role.
# Never use these credentials outside this local demo.
APP_DSN ?= postgresql://app_user:app_user@localhost:5432/rls_lab

.PHONY: up migrate test down

up: ## Start Postgres in the background and wait until it is healthy.
	docker compose up -d --wait
	@echo "Postgres ready on localhost:5432 (db=rls_lab). App role: app_user."

migrate: ## Re-apply migrations against a running DB (idempotent).
	docker compose exec -T db psql -U postgres -d rls_lab -v ON_ERROR_STOP=1 < migrations/001_schema.sql
	docker compose exec -T db psql -U postgres -d rls_lab -v ON_ERROR_STOP=1 < migrations/002_rls.sql
	@echo "Migrations applied."

test: ## Run the pytest suite against the running Postgres.
	APP_DSN="$(APP_DSN)" pytest -q

down: ## Stop containers and remove volumes so init re-runs next time.
	docker compose down -v
