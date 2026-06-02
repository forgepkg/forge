# envisia-forge — local dev helpers.
# Most cargo invocations set SQLX_OFFLINE=true so a live DB isn't needed to build.

export SQLX_OFFLINE := true
COMPOSE := docker compose
FORGE_URL ?= http://localhost:3000
ADMIN ?= admin:changeme

.PHONY: help up down logs ps psql run dev seed build check fmt clippy test e2e prepare clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

up: ## Start Postgres + versitygw (docker compose), wait until healthy
	$(COMPOSE) up -d --wait

down: ## Stop and remove the dev containers
	$(COMPOSE) down

logs: ## Tail the dev container logs
	$(COMPOSE) logs -f

ps: ## Show dev container status
	$(COMPOSE) ps

psql: ## Open a psql shell on the dev database
	$(COMPOSE) exec db psql -U forge -d forge

run: ## Run the server (expects `make up` first; loads ./forge.toml)
	cargo run -p forge-server

dev: up run ## Start infra, then run the server (one-command dev)

seed: ## Demo data: create an anonymous-readable repo + token, push the sample fixture (server must be running)
	@echo "Creating hosted repo 'nuget' (anonymous_read=true)…"
	@curl -fsS -u $(ADMIN) -X POST $(FORGE_URL)/admin/repositories \
		-H 'content-type: application/json' \
		-d '{"name":"nuget","kind":"hosted","anonymous_read":true}' >/dev/null 2>&1 \
		|| echo "  (repo already exists — continuing)"
	@TOKEN=$$(curl -fsS -u $(ADMIN) -X POST $(FORGE_URL)/admin/users/1/tokens \
		-H 'content-type: application/json' -d '{"name":"dev-seed"}' \
		| sed -n 's/.*"token":"\([^"]*\)".*/\1/p'); \
	echo "  push token: $$TOKEN"; \
	curl -fsS -o /dev/null -w "  push: HTTP %{http_code}\n" \
		-X PUT $(FORGE_URL)/v3/nuget/package -H "X-NuGet-ApiKey: $$TOKEN" \
		-F package=@fixtures/nuget/sample.lib.1.0.0.nupkg; \
	echo "  feed:     $(FORGE_URL)/v3/nuget/index.json"; \
	echo "  versions: $$(curl -fsS $(FORGE_URL)/v3/nuget/flat/sample.lib/index.json)"

build: ## Build the whole workspace
	cargo build --workspace

check: fmt clippy ## fmt --check + clippy -D warnings

fmt: ## Verify formatting
	cargo fmt --all --check

clippy: ## Lint with warnings denied
	cargo clippy --workspace --all-targets -- -D warnings

test: ## Run unit + integration tests (needs Docker for testcontainers)
	cargo test --workspace

e2e: ## Run the end-to-end suite (needs Docker)
	cargo test -p forge-e2e --features forge-e2e

prepare: ## Regenerate sqlx offline data (needs `make up` + sqlx-cli)
	DATABASE_URL=postgres://forge:forge@localhost:5433/forge \
		cargo sqlx prepare --workspace -- --all-targets --all-features

clean: ## Remove build artifacts
	cargo clean
