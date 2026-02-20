# Funny-API

A Go monorepo of microservices communicating over REST, with an API Gateway, JWT authentication, and Nginx as a reverse proxy.

---

## Architecture

```
Client
  ↓
Nginx (:80)
  - Rate limiting (30 req/s)
  - Security headers
  - WebSocket upgrade support
  ↓
Go Gateway (:8080)
  - JWT Auth middleware
  - CORS middleware
  - Rate limiting (60 req/min)
  - Reverse proxy with path stripping
  ↓
┌─────────────────┐
│  auth-service   │  :8081
│  user-service   │  :8082  (coming soon)
│  joke-service   │  :8083  (coming soon)
└─────────────────┘
```

---

## Project Structure

```
funny-pipe/
├── services/
│   ├── auth/                        ← Authentication microservice
│   │   ├── cmd/auth/main.go         ← Entry point
│   │   ├── internal/
│   │   │   ├── handler/             ← HTTP handlers
│   │   │   ├── service/             ← Business logic + JWT
│   │   │   ├── repository/          ← In-memory store (PostgreSQL coming)
│   │   │   └── model/               ← Data models
│   │   └── go.mod
│   └── gateway/                     ← API Gateway
│       ├── cmd/gateway/main.go      ← Entry point
│       ├── internal/
│       │   ├── middleware/           ← Logger, CORS, JWT Auth, Rate limiter
│       │   ├── proxy/               ← Reverse proxy with path stripping
│       │   └── router/              ← HTTP router wrapper
│       └── go.mod
├── packages/
│   └── config/                      ← Shared .env loader (pure Go, no deps)
├── nginx/
│   ├── nginx.conf                   ← Main Nginx config
│   └── conf.d/funny-api.conf        ← Server block, rate limiting
├── scripts/
│   └── dev.sh                       ← Start all services in one command
├── .env                             ← Environment variables (git ignored)
├── .env.example                     ← Template for team
├── .gitignore
├── go.work                          ← Go workspace (links all modules)
└── Makefile                         ← Root level commands
```

---

## Prerequisites

- [Go 1.22+](https://go.dev/dl/)
- [Nginx](https://nginx.org/) via Homebrew: `brew install nginx`

---

## Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/shreyashkumar/funny-pipe.git
cd funny-pipe
```

### 2. Set up environment variables

```bash
cp .env.example .env
```

Edit `.env` and set a strong `JWT_SECRET`:

```bash
JWT_SECRET=your-strong-secret-here
```

### 3. Run all services

```bash
make dev
```

This starts:
- `auth-service` on `:8081`
- `gateway` on `:8080`
- `nginx` on `:80`

---

## Makefile Commands

| Command | Description |
|---|---|
| `make dev` | Start all services + Nginx |
| `make build` | Build all services |
| `make tidy` | Tidy all Go modules |
| `make auth` | Run auth-service only |
| `make gateway` | Run gateway only |
| `make nginx` | Start Nginx |
| `make nginx-stop` | Stop Nginx |
| `make nginx-reload` | Reload Nginx config |
| `make nginx-test` | Test Nginx config validity |

---

## API Reference

All routes go through Nginx (`:80`) → Gateway (`:8080`).

### Auth Service `/api/auth`

| Method | Route | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/register` | No | Register a new user |
| `POST` | `/api/auth/login` | No | Login, returns access token + sets refresh cookie |
| `POST` | `/api/auth/refresh` | Cookie | Issue new access token using refresh cookie |
| `POST` | `/api/auth/validate` | Bearer | Validate a JWT token |
| `GET` | `/health` | No | Gateway health check |

### Request / Response Examples

**Register**
```bash
curl -X POST http://localhost/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'
```
```json
{ "message": "User registered successfully" }
```

**Login**
```bash
curl -X POST http://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'
```
```json
{
  "access_token": "<jwt>",
  "expires_in": 1234567890
}
```
> Refresh token is set automatically as an `HttpOnly` cookie (not visible in response body).

**Authenticated request**
```bash
curl http://localhost/api/users/ \
  -H "Authorization: Bearer <access_token>"
```

**Refresh access token**
```bash
curl -X POST http://localhost/api/auth/refresh \
  --cookie "refresh_token=<token>"
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | `dev-secret-key` | Secret for signing JWTs — **change in production** |
| `AUTH_PORT` | `8081` | Port for auth-service |
| `GATEWAY_PORT` | `8080` | Port for gateway |
| `JWT_ACCESS_TTL_MINUTES` | `15` | Access token TTL in minutes |
| `JWT_REFRESH_TTL_DAYS` | `7` | Refresh token TTL in days |
| `RATE_LIMIT_PER_MINUTE` | `60` | Gateway rate limit per IP |
| `AUTH_SERVICE_URL` | `http://localhost:8081` | Auth service URL used by gateway |
| `USER_SERVICE_URL` | `http://localhost:8082` | User service URL used by gateway |
| `JOKE_SERVICE_URL` | `http://localhost:8083` | Joke service URL used by gateway |

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
| Auth | `golang-jwt/jwt` + `bcrypt` |
| Gateway | Custom reverse proxy (`net/http/httputil`) |
| Config | Pure Go `.env` loader (no external deps) |
| Reverse Proxy | Nginx |
| Monorepo | Go Workspace (`go.work`) |

---

## Roadmap

- [x] Go monorepo with `go.work`
- [x] API Gateway with JWT auth, CORS, rate limiting
- [x] Auth service (register, login, refresh, validate)
- [x] Nginx reverse proxy
- [x] Shared config package
- [ ] user-service
- [ ] PostgreSQL (replace in-memory store)
- [ ] Docker + docker-compose
- [ ] joke-service
