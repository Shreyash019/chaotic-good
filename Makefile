.PHONY: dev build tidy test test-verbose auth gateway user joke nginx nginx-stop nginx-reload nginx-test migrate migrate-auth migrate-user migrate-joke db db-stop db-reset db-logs

# Run all services
dev:
	@chmod +x scripts/dev.sh && ./scripts/dev.sh

# Build all services
build:
	@echo "Building auth-service..."
	@cd services/auth && go build ./...
	@echo "Building user-service..."
	@cd services/user && go build ./...
	@echo "Building joke-service..."
	@cd services/joke && go build ./...
	@echo "Building gateway..."
	@cd services/gateway && go build ./...
	@echo "Done!"

# Tidy all modules
tidy:
	@cd services/auth && go mod tidy
	@cd services/user && go mod tidy
	@cd services/joke && go mod tidy
	@cd services/gateway && go mod tidy
	@go work sync
	@echo "Done!"

# Test all services
test:
	@echo "Testing auth-service..."
	@cd services/auth && go test ./...
	@echo "Testing user-service..."
	@cd services/user && go test ./...
	@echo "Testing joke-service..."
	@cd services/joke && go test ./...
	@echo "All tests passed!"

# Test all services (verbose)
test-verbose:
	@echo "Testing auth-service..."
	@cd services/auth && go test -v ./...
	@echo "Testing user-service..."
	@cd services/user && go test -v ./...
	@echo "Testing joke-service..."
	@cd services/joke && go test -v ./...

# Run individual services
auth:
	@cd services/auth && go run cmd/auth/main.go

user:
	@cd services/user && go run cmd/user/main.go

joke:
	@cd services/joke && go run cmd/joke/main.go

gateway:
	@cd services/gateway && go run cmd/gateway/main.go

# Nginx commands
nginx:
	@echo "Starting Nginx..."
	@nginx -c $(PWD)/nginx/nginx.conf

nginx-stop:
	@echo "Stopping Nginx..."
	@nginx -s stop

nginx-reload:
	@echo "Reloading Nginx config..."
	@nginx -c $(PWD)/nginx/nginx.conf -s reload

nginx-test:
	@nginx -c $(PWD)/nginx/nginx.conf -t

# ─── Database ──────────────────────────────────────────────────────────────────
# Requires DATABASE_URL to be set, e.g.:
#   export DATABASE_URL=postgres://postgres:postgres@localhost:5432/funny_pipe?sslmode=disable

migrate-auth:
	@echo "Running auth migrations..."
	@psql "$(DATABASE_URL)" -f services/auth/migrations/001_create_users.sql
	@echo "Auth migrations done."

migrate-user:
	@echo "Running user migrations..."
	@psql "$(DATABASE_URL)" -f services/user/migrations/001_create_profiles.sql
	@echo "User migrations done."

migrate-joke:
	@echo "Running joke migrations..."
	@psql "$(DATABASE_URL)" -f services/joke/migrations/001_create_jokes.sql
	@echo "Joke migrations done."

migrate: migrate-auth migrate-user migrate-joke
	@echo "All migrations complete."

# ─── Docker (PostgreSQL) ───────────────────────────────────────────────────────
db:
	@echo "Starting PostgreSQL container..."
	@docker compose up -d postgres
	@echo "Waiting for Postgres to be ready..."
	@docker compose exec postgres sh -c 'until pg_isready -U postgres -d funny_pipe; do sleep 1; done'
	@echo "PostgreSQL is ready on localhost:5432"

db-stop:
	@echo "Stopping PostgreSQL container..."
	@docker compose stop postgres

db-reset:
	@echo "Removing PostgreSQL container and volume (all data will be lost)..."
	@docker compose down -v postgres
	@echo "Done."

db-logs:
	@docker compose logs -f postgres
