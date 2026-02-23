# Chaotic-Good

An open-source Go microservices playground — REST + GraphQL — built for frontend developers who want a real backend to test against, and backend developers who want a clean reference implementation.  
Some services are deliberately chaotic (random crashes, flaky responses). Others are stable reference implementations.

> **API Reference** → see [API_DOC.md](API_DOC.md)

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Repo](https://img.shields.io/badge/GitHub-Shreyash019%2Fchaotic--good-181717?logo=github)](https://github.com/Shreyash019/chaotic-good)

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
│   └── conf.d/chaotic-good.conf
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

## Getting Started

```bash
git clone https://github.com/Shreyash019/chaotic-good.git
cd chaotic-good
cp .env.example .env   # set a strong JWT_SECRET before production use
```

---

### Option A — Docker Compose (recommended)

No Go or Nginx required locally. Spins up all 6 containers:
**Postgres → Auth → User → Joke → Gateway → Nginx**

```bash
# Build images + start all containers in background
make docker-up

# OR follow all logs in foreground (Ctrl+C stops everything)
make docker-up-logs
```

| URL | Description |
|---|---|
| `http://localhost` | Main entry point (Nginx :80) |
| `http://localhost:8080` | Gateway (direct) |
| `http://localhost:8081` | Auth service (direct) |
| `http://localhost:8082` | User service (direct) |
| `http://localhost:8083` | Joke service / GraphiQL (direct) |

```bash
make docker-ps          # show status of all containers
make docker-logs        # tail logs from all containers
make docker-restart     # restart all containers
make docker-down        # stop containers (database volume kept)
make docker-clean       # stop containers + delete volumes (wipes DB)
```

---

### Option B — Local development

**Prerequisites:** [Go 1.22+](https://go.dev/dl/) · [Docker Desktop](https://www.docker.com/products/docker-desktop/) · Nginx (`brew install nginx`) · psql (`brew install libpq`)

#### Step 1 — Start Postgres

```bash
make db
# waits until postgres is healthy on localhost:5432
```

#### Step 2 — Run migrations

```bash
# DATABASE_URL is already set in .env — export it first
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/chaotic_good?sslmode=disable
make migrate
```

#### Step 3 — Start everything

```bash
make dev
# starts auth (:8081), user (:8082), joke (:8083), gateway (:8080), nginx (:80)
# Ctrl+C shuts all processes down cleanly
```

#### Run a single service

```bash
make auth       # auth-service  on :8081
make user       # user-service  on :8082
make joke       # joke-service  on :8083
make gateway    # gateway       on :8080
```

#### Nginx

```bash
make nginx          # start Nginx (uses nginx/nginx.conf)
make nginx-reload   # reload config without downtime
make nginx-stop     # stop Nginx
make nginx-test     # validate config syntax
```

#### Database helpers

```bash
make db             # start Postgres container
make db-stop        # stop  Postgres container
make db-reset       # destroy container + volume
make db-logs        # tail  Postgres logs
```

---

### Build & Test

```bash
make build           # compile all 4 services
make tidy            # go mod tidy + go work sync
make test            # run all unit tests
make test-verbose    # run all unit tests with -v
```

---

## Makefile Commands

**Docker (full stack)**

| Command | Description |
|---|---|
| `make docker-up` | Build images + start all 6 containers (background) |
| `make docker-up-logs` | Build images + start all containers (foreground, streams logs) |
| `make docker-down` | Stop containers (volume kept) |
| `make docker-clean` | Stop containers + delete volumes (wipes DB) |
| `make docker-build` | Build / rebuild images without starting |
| `make docker-logs` | Stream logs from all containers |
| `make docker-ps` | Show container status |
| `make docker-restart` | Restart all containers |

**Local development**

| Command | Description |
|---|---|
| `make dev` | Start all services + Nginx (foreground, Ctrl+C to stop) |
| `make auth` | Run auth-service on :8081 |
| `make user` | Run user-service on :8082 |
| `make joke` | Run joke-service on :8083 |
| `make gateway` | Run gateway on :8080 |
| `make nginx` | Start local Nginx |
| `make nginx-stop` | Stop local Nginx |
| `make nginx-reload` | Reload local Nginx config |
| `make nginx-test` | Validate Nginx config syntax |

**Database (local Postgres via Docker)**

| Command | Description |
|---|---|
| `make db` | Start Postgres container + wait until healthy |
| `make db-stop` | Stop Postgres container |
| `make db-reset` | Destroy Postgres container + volume |
| `make db-logs` | Tail Postgres logs |
| `make migrate` | Run all service migrations |
| `make migrate-auth` | Run auth migrations only |
| `make migrate-user` | Run user migrations only |
| `make migrate-joke` | Run joke migrations only |

**Build & test**

| Command | Description |
|---|---|
| `make build` | Compile all 4 services |
| `make tidy` | `go mod tidy` + `go work sync` across all modules |
| `make test` | Run all unit tests |
| `make test-verbose` | Run all unit tests with `-v` |

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
