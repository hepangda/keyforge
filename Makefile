SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

GO              ?= go
PNPM            ?= pnpm
DOCKER          ?= docker
COMPOSE         ?= docker compose
BIN_DIR         := bin
PKG             := ./...
APP_PKG         := ./cmd/keyforge
SEED_PKG        := ./cmd/keyforge-seed
VERSION         ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS         := -X github.com/hepangda/keyforge/pkg/version.Version=$(VERSION)
GOFLAGS         ?=
INTEGRATION_TAG := integration

##@ Help
.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} \
		/^[a-zA-Z_-]+:.*?##/ {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2} \
		/^##@/ {printf "\n\033[1m%s\033[0m\n", substr($$0, 5)}' $(MAKEFILE_LIST)

##@ Build
.PHONY: build
build: ## Build the keyforge binary into bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/keyforge $(APP_PKG)

.PHONY: build-seed
build-seed: ## Build the keyforge-seed dev utility
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/keyforge-seed $(SEED_PKG)

.PHONY: build-all
build-all: build build-seed ## Build all Go binaries

##@ Test
.PHONY: test
test: ## Run unit tests with the race detector
	$(GO) test -race -count=1 -timeout 5m $(PKG)

.PHONY: test-integration
test-integration: ## Run integration tests (requires Docker for testcontainers)
	$(GO) test -race -count=1 -timeout 15m -tags=$(INTEGRATION_TAG) $(PKG)

.PHONY: cover
cover: ## Run unit tests with coverage report
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic $(PKG)
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

##@ Quality
.PHONY: fmt
fmt: ## Format Go code with gofumpt + goimports
	$(GO) run mvdan.cc/gofumpt@latest -w .
	$(GO) run golang.org/x/tools/cmd/goimports@latest -w -local github.com/hepangda/keyforge .

.PHONY: lint
lint: ## Run golangci-lint
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run

.PHONY: vuln
vuln: ## Run govulncheck
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest $(PKG)

.PHONY: tidy
tidy: ## Tidy go.mod / go.sum
	$(GO) mod tidy

##@ Database
.PHONY: migrate-up
migrate-up: ## Apply all pending migrations
	$(GO) run -tags=tools github.com/golang-migrate/migrate/v4/cmd/migrate \
		-path=migrations -database "$${DATABASE_URL:-postgres://keyforge:keyforge@localhost:5432/keyforge?sslmode=disable}" up

.PHONY: migrate-down
migrate-down: ## Roll back the most recent migration
	$(GO) run -tags=tools github.com/golang-migrate/migrate/v4/cmd/migrate \
		-path=migrations -database "$${DATABASE_URL:-postgres://keyforge:keyforge@localhost:5432/keyforge?sslmode=disable}" down 1

.PHONY: sqlc
sqlc: ## Regenerate typed database access code
	$(GO) run -tags=tools github.com/sqlc-dev/sqlc/cmd/sqlc generate

##@ Compose
.PHONY: compose-up
compose-up: ## Start the local Docker Compose dev stack
	$(COMPOSE) -f docker-compose.yml up -d --build

.PHONY: compose-down
compose-down: ## Stop the local Docker Compose dev stack
	$(COMPOSE) -f docker-compose.yml down -v

.PHONY: compose-logs
compose-logs: ## Tail logs from the dev stack
	$(COMPOSE) -f docker-compose.yml logs -f --tail=200

##@ Web
.PHONY: web-install
web-install: ## Install web (React SPA) dependencies
	cd web && $(PNPM) install --frozen-lockfile

.PHONY: web-dev
web-dev: ## Start the Vite dev server
	cd web && $(PNPM) dev

.PHONY: web-build
web-build: ## Build the React SPA to web/dist
	cd web && $(PNPM) build

.PHONY: web-lint
web-lint: ## Lint + typecheck the web app
	cd web && $(PNPM) lint && $(PNPM) typecheck

##@ End-to-end
.PHONY: e2e
e2e: ## Run Playwright browser end-to-end tests
	cd web && $(PNPM) test:e2e

.PHONY: e2e-shell
e2e-shell: ## Run curl-based shell end-to-end smoke tests
	bash scripts/smoke.sh

.PHONY: conformance
conformance: ## Run the OpenID Foundation conformance suite
	bash scripts/conformance.sh

##@ Clean
.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) coverage.out coverage.html web/dist
