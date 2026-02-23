.PHONY: dev build tidy test test-verbose auth gateway user joke nginx nginx-stop nginx-reload nginx-test migrate migrate-auth migrate-user migrate-joke db db-stop db-reset db-logs docker-up docker-down docker-build docker-logs docker-ps docker-restart docker-clean

# Run all services (starts Docker Postgres first, then all Go services + Nginx)
dev: db
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
# Migrations run via the Docker Postgres container — no local psql required.
# Start the container first with: make db

migrate-auth:
	@echo "Running auth migrations..."
	@docker compose exec -T postgres psql -U postgres -d chaotic_good -f - < services/auth/migrations/001_create_users.sql
	@echo "Auth migrations done."

migrate-user:
	@echo "Running user migrations..."
	@docker compose exec -T postgres psql -U postgres -d chaotic_good -f - < services/user/migrations/001_create_profiles.sql
	@echo "User migrations done."

migrate-joke:
	@echo "Running joke migrations..."
	@docker compose exec -T postgres psql -U postgres -d chaotic_good -f - < services/joke/migrations/001_create_jokes.sql
	@echo "Joke migrations done."

migrate: db migrate-auth migrate-user migrate-joke
	@echo "All migrations complete."

# ─── Docker (PostgreSQL) ───────────────────────────────────────────────────────
db:
	@echo "Starting PostgreSQL container..."
	@docker compose up -d postgres
	@echo "Waiting for Postgres to be ready..."
	@docker compose exec -T postgres sh -c 'until pg_isready -U postgres; do sleep 1; done'
	@echo "Ensuring chaotic_good database exists..."
	@docker compose exec -T postgres psql -U postgres -tc "SELECT 1 FROM pg_database WHERE datname='chaotic_good'" | grep -q 1 \
		|| docker compose exec -T postgres psql -U postgres -c "CREATE DATABASE chaotic_good;"
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

# ─── Docker (Full Stack) ──────────────────────────────────────────────────────
# Builds all images and starts every container (postgres, auth, user, joke, gateway, nginx)
docker-up:
	@echo "Building images and starting all containers..."
	@docker compose up -d --build
	@echo ""
	@echo "Stack is up. API available at http://localhost"
	@echo "  Gateway  : http://localhost:8080"
	@echo "  Auth     : http://localhost:8081"
	@echo "  User     : http://localhost:8082"
	@echo "  Joke     : http://localhost:8083"
	@echo ""
	@docker compose ps

# Start full stack in foreground (streams all logs)
docker-up-logs:
	@docker compose up --build

# Stop and remove containers (keeps volumes/data)
docker-down:
	@echo "Stopping all containers..."
	@docker compose down

# Stop and remove containers + volumes (wipes database)
docker-clean:
	@echo "Removing all containers and volumes (all data will be lost)..."
	@docker compose down -v --remove-orphans
	@echo "Done."

# Build (or rebuild) all images without starting
docker-build:
	@docker compose build

# Stream logs from all containers (Ctrl+C to stop)
docker-logs:
	@docker compose logs -f

# Show running container status
docker-ps:
	@docker compose ps

# Restart all containers
docker-restart:
	@docker compose restart
