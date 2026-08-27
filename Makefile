# Convenience targets. Nothing in the library needs make: `go test ./...` is the whole
# story for a consumer, and the module requires nothing at all.
#
# What this file is for is running what CI runs, before CI runs it. Every target below
# mirrors a step in .github/workflows/ci.yml, so a green `make ci` locally means a green
# pipeline, and the two cannot drift without one of them failing.
#
# The DSNs default to the ports in docker-compose.yml, which are deliberately not the
# default ones so the containers do not fight with a local install. Override either to
# point at a database of your own:
#
#	make test-integration MYSQL_DSN='user:pass@tcp(127.0.0.1:3306)/grantz'

.DEFAULT_GOAL := help

GO              ?= go
INTEGRATION_DIR := sqlstore/integration
COVERAGE        ?= coverage.out

POSTGRES_DSN ?= postgres://grantz:grantz@localhost:5433/grantz?sslmode=disable
MYSQL_DSN    ?= grantz:grantz@tcp(localhost:3307)/grantz

.PHONY: help test test-race cover cover-html fmt fmt-check vet deps-check check \
        db-up db-down test-integration test-postgres test-mysql ci tidy example demo clean

help: ## Show this help
	@echo "grantz make targets:"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "The SQL suite needs databases: make db-up, then make test-integration."

test: ## Run the unit tests (no database needed)
	$(GO) test ./...

test-race: ## Run the unit tests with the race detector, as CI does
	$(GO) test -race ./...

cover: ## Run the unit tests with coverage and print the total
	$(GO) test -race -coverprofile=$(COVERAGE) ./...
	$(GO) tool cover -func=$(COVERAGE) | tail -1

cover-html: cover ## Open the coverage report in a browser
	$(GO) tool cover -html=$(COVERAGE)

fmt: ## Format every package
	gofmt -w .
	cd $(INTEGRATION_DIR) && gofmt -w .

fmt-check: ## Fail if anything needs gofmt, as CI does
	@unformatted=$$(gofmt -l . $(INTEGRATION_DIR)); \
	if [ -n "$$unformatted" ]; then \
		echo "These files need gofmt:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

vet: ## Vet both modules, the integration one behind its build tag
	$(GO) vet ./...
	cd $(INTEGRATION_DIR) && $(GO) vet -tags=integration ./...

# A require line in a library is forced onto every consumer through minimal version
# selection, so a test-only driver here would silently upgrade the driver of a project
# that already used one. That is why the integration suite is its own module, and why
# this check exists rather than being left to review.
deps-check: ## Fail if the published module gained a dependency, as CI does
	@modules=$$($(GO) list -m all | grep -v '^github.com/mstgnz/grantz$$' || true); \
	if [ -n "$$modules" ]; then \
		echo "The module gained dependencies:"; \
		echo "$$modules"; \
		exit 1; \
	fi
	@echo "no dependencies"

check: fmt-check vet test-race deps-check ## Everything CI's test job runs, without a database

db-up: ## Start Postgres and MySQL and wait for both to be healthy
	docker compose up -d --wait

db-down: ## Stop the databases and remove their volumes
	docker compose down -v

test-integration: ## Run the SQL suite against both engines
	cd $(INTEGRATION_DIR) && \
	GRANTZ_TEST_DSN='$(POSTGRES_DSN)' \
	GRANTZ_TEST_MYSQL_DSN='$(MYSQL_DSN)' \
	$(GO) test -tags=integration ./...

# Each engine skips when its own DSN is unset, so naming one leaves the other out.
test-postgres: ## Run the SQL suite against Postgres only
	cd $(INTEGRATION_DIR) && \
	GRANTZ_TEST_DSN='$(POSTGRES_DSN)' \
	$(GO) test -tags=integration -run TestPostgres -v ./...

test-mysql: ## Run the SQL suite against MySQL only
	cd $(INTEGRATION_DIR) && \
	GRANTZ_TEST_MYSQL_DSN='$(MYSQL_DSN)' \
	$(GO) test -tags=integration -run TestMySQL -v ./...

ci: check db-up test-integration ## The whole pipeline, databases included

tidy: ## Tidy both modules
	$(GO) mod tidy
	cd $(INTEGRATION_DIR) && $(GO) mod tidy

example: ## Run the database-free example
	$(GO) run ./examples/basic

demo: ## Run the example HTTP server in a container, on :8090
	docker compose --profile demo up demo

clean: ## Remove build and coverage artifacts
	rm -f $(COVERAGE)
	$(GO) clean -testcache
