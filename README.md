# Funny-API

A Go monorepo of microservices — REST + GraphQL — connected through an API Gateway, JWT authentication, PostgreSQL, and Nginx.  
Fully containerised with Docker Compose.

> **API Reference** → see [API_DOC.md](API_DOC.md)

---

## Architecture

```
Client
  ↓
Nginx (:80)
  - Rate limiting (30 req/s)
  - Security headers
  ↓
Go Gateway (:8080)
  - JWT auth middleware (Bearer token)
  - CORS middleware
  - Rate limiting (60 req/min per IP)
  - Reverse proxy with path stripping
  ↓
┌──────────────────────────────────────┐
│  auth-service   :8081  REST + JWT    │
│  user-service   :8082  REST          │
│  joke-service   :8083  GraphQL       │
└──────────────────────────────────────┘
  ↓
PostgreSQL (:5432)
```

---

## Project Structure

```
funny-pipe/
├── services/
│   ├── auth/                        ← Authentication service (REST + JWT)
│   │   ├── cmd/auth/main.go
│   │   ├── internal/
│   │   │   ├── handler/             ← HTTP handlers + tests
│   │   │   ├── service/             ← JWT issuance, bcrypt — tested
│   │   │   ├── repository/          ← In-memory + PostgreSQL repositories
│   │   │   └── model/
│   │   ├── migrations/
│   │   └── Dockerfile
│   ├── user/                        ← User profile service (REST)
│   │   ├── cmd/user/main.go
│   │   ├── internal/
│   │   │   ├── handler/             ← HTTP handlers + tests
│   │   │   ├── service/             ← Profile CRUD — tested
│   │   │   ├── repository/          ← In-memory + PostgreSQL repositories
│   │   │   └── model/
│   │   ├── migrations/
│   │   └── Dockerfile
│   ├── joke/                        ← Joke service (GraphQL)
│   │   ├── cmd/joke/main.go
│   │   ├── internal/
│   │   │   ├── handler/             ← GraphQL HTTP handler
│   │   │   ├── schema/              ← GraphQL schema, queries, mutations
│   │   │   ├── repository/          ← In-memory + PostgreSQL repositories — tested
│   │   │   └── model/
│   │   ├── migrations/
│   │   └── Dockerfile
│   └── gateway/                     ← API Gateway
│       ├── cmd/gateway/main.go
│       ├── internal/
│       │   ├── middleware/          ← Logger, CORS, JWT auth, rate limiter
│       │   ├── proxy/               ← Reverse proxy with path stripping
│       │   └── router/
│       └── Dockerfile
├── packages/
│   └── config/                      ← Shared .env loader (zero external deps)
├── docker/
│   └── nginx/nginx.conf             ← Nginx config for Docker
├── nginx/
│   ├── nginx.conf                   ← Nginx config for local dev
│   └── conf.d/funny-api.conf
├── scripts/
│   └── dev.sh                       ← Start all services locally
├── docker-compose.yml               ← Full stack: 6 containers
├── .env                             ← Local env vars (git-ignored)
├── .env.example                     ← Config template
├── go.work                          ← Go workspace (links all 4 modules)
├── Makefile
└── API_DOC.md                       ← Full API reference
```

---

## Prerequisites

- [Go 1.22+](https://go.dev/dl/)
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes Docker Compose)
- [Nginx](https://nginx.org/) — local dev only: `brew install nginx`

---

## Getting Started

### Option A — Docker Compose (recommended)

Runs the full stack (Postgres + all 4 services + Nginx) in containers.

```bash
# 1. Copy env file
cp .env.example .env

# 2. Build images and start all containers
docker compose up --build
```

The API is available at `http://localhost` once all containers are healthy.

### Option B — Local development

Requires a running PostgreSQL instance (or `make db` to start one via Docker).

```bash
# 1. Copy env file and set DATABASE_URL
cp .env.example .env

# 2. Start PostgreSQL container
make db

# 3. Run migrations
make migrate

# 4. Start all services + Nginx
make dev
```

---

## Makefile Commands

| Command | Description |
|---|---|
| `make dev` | Start all services locally + Nginx |
| `make build` | Build all 4 services |
| `make tidy` | Tidy all Go modules + sync workspace |
| `make test` | Run all unit tests |
| `make test-verbose` | Run all unit tests with verbose output |
| `make auth` | Run auth-service only |
| `make user` | Run user-service only |
| `make joke` | Run joke-service only |
| `make gateway` | Run gateway only |
| `make nginx` | Start local Nginx |
| `make nginx-stop` | Stop local Nginx |
| `make nginx-reload` | Reload local Nginx config |
| `make nginx-test` | Test local Nginx config validity |
| `make db` | Start PostgreSQL container (Docker) |
| `make db-stop` | Stop PostgreSQL container |
| `make db-reset` | Destroy PostgreSQL container + volume |
| `make db-logs` | Tail PostgreSQL container logs |
| `make migrate` | Run all DB migrations |
| `make migrate-auth` | Run auth-service migrations only |
| `make migrate-user` | Run user-service migrations only |
| `make migrate-joke` | Run joke-service migrations only |

---

## API Reference

Full documentation with request/response examples is in **[API_DOC.md](API_DOC.md)**.

All routes go through Nginx (`:80`) → Gateway (`:8080`).

| Service | Prefix | Protocol | Auth Required |
|---|---|---|---|
| Auth | `/api/auth/` | REST (JSON) | No |
| User | `/api/users/` | REST (JSON) | Yes — Bearer token |
| Joke | `/api/jokes/graphql` | GraphQL | Mutations only |
| Gateway health | `/health` | — | No |

### Quick examples

**Register & login**
```bash
# Register
curl -X POST http://localhost/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

# Login — saves refresh_token cookie, prints access_token
curl -c cookies.txt -X POST http://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'
```

**Use access token**
```bash
export TOKEN="<access_token from login response>"

curl http://localhost/api/users/me \
  -H "Authorization: Bearer $TOKEN"
```

**GraphQL — list jokes**
```bash
curl -X POST http://localhost/api/jokes/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ jokes(category: \"tech\", limit: 5) { id content createdAt } }"}'
```

**GraphQL — create a joke (auth required)**
```bash
curl -X POST http://localhost/api/jokes/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { createJoke(content: \"Why do Go devs wear glasses? Because they cant C.\", category: \"tech\") { id } }"}'
```

---

## Environment Variables

Copy `.env.example` to `.env` and adjust values as needed.

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | `dev-secret-key` | Secret for signing JWTs — **change in production** |
| `AUTH_PORT` | `8081` | Port for auth-service |
| `USER_PORT` | `8082` | Port for user-service |
| `JOKE_PORT` | `8083` | Port for joke-service |
| `GATEWAY_PORT` | `8080` | Port for gateway |
| `JWT_ACCESS_TTL_MINUTES` | `15` | Access token TTL in minutes |
| `JWT_REFRESH_TTL_DAYS` | `7` | Refresh token TTL in days |
| `RATE_LIMIT_PER_MINUTE` | `60` | Gateway rate limit per IP per minute |
| `AUTH_SERVICE_URL` | `http://localhost:8081` | Auth service URL (gateway uses this) |
| `USER_SERVICE_URL` | `http://localhost:8082` | User service URL (gateway uses this) |
| `JOKE_SERVICE_URL` | `http://localhost:8083` | Joke service URL (gateway uses this) |
| `DATABASE_URL` | — | PostgreSQL connection string |

---

## Security Design

| Concern | Solution |
|---|---|
| Password storage | `bcrypt` hashing |
| Access token | JWT, short-lived (15 min), sent in response body |
| Refresh token | JWT, long-lived (7 days), sent as `HttpOnly` cookie only |
| XSS protection | Refresh token inaccessible to JavaScript |
| Rate limiting | Nginx (30 req/s) + Gateway (60 req/min) |
| CORS | Handled in Gateway middleware |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Go 1.22+ (pure `net/http`, no frameworks) |
| Auth | `golang-jwt/jwt/v5` + `bcrypt` |
| GraphQL | `graphql-go/graphql` |
| Database | PostgreSQL 16 (`lib/pq`) |
| Gateway | Custom reverse proxy (`net/http/httputil`) |
| Config | Pure Go `.env` loader (zero external deps) |
| Reverse proxy | Nginx |
| Containerisation | Docker + Docker Compose |
| Monorepo | Go Workspace (`go.work`) |

---

## Roadmap

- [x] Go monorepo with `go.work`
- [x] API Gateway with JWT auth, CORS, rate limiting
- [x] Auth service (register, login, refresh, validate)
- [x] User service (profile CRUD)
- [x] Joke service (GraphQL — queries + mutations)
- [x] PostgreSQL with migrations (auth, user, joke)
- [x] Docker + Docker Compose (full stack)
- [x] Shared config package
- [x] Nginx reverse proxy
- [x] Unit tests (auth, user, joke services)
- [ ] WebSocket support
- [ ] Integration / end-to-end tests
- [ ] CI pipeline
