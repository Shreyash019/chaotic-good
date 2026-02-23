# Chaotic-Good — API Reference

All routes are accessed through **Nginx** (`:80`) → **Gateway** (`:8080`).  
The gateway strips the service prefix before forwarding (e.g. `/api/auth/register` → `/register` on auth-service).

---

## Table of Contents

- [Authentication](#authentication)
- [Gateway](#gateway)
- [Auth Service — `/api/auth`](#auth-service)
- [User Service — `/api/users`](#user-service)
- [Joke Service — `/api/jokes` (GraphQL)](#joke-service)
- [Error Responses](#error-responses)

---

## Authentication

Most endpoints require a valid JWT **access token** in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

**Public routes (no token required):**

| Route | Method |
|---|---|
| `/health` | `GET` |
| `/api/auth/*` | Any |
| `/api/jokes/graphql` | `GET` (GraphiQL UI only) |

**Skipped routes** are configured in the gateway middleware. All other routes require a valid token.

### Token Lifecycle

| Token | TTL | Transport |
|---|---|---|
| Access token | 15 min (configurable) | JSON response body |
| Refresh token | 7 days (configurable) | `HttpOnly` cookie — not readable by JavaScript |

---

## Gateway

Base URL: `http://localhost:8080` (or `http://localhost` via Nginx)

### `GET /health`

Health check for the gateway. No authentication required.

**Response `200 OK`**
```
Gateway is running
```

---

## Auth Service

Base path: `/api/auth`  
Direct port: `:8081`

---

### `POST /api/auth/register`

Register a new user account.

**Request body** (JSON)

| Field | Type | Required | Description |
|---|---|---|---|
| `email` | `string` | Yes | User email address |
| `password` | `string` | Yes | Plain-text password (hashed with bcrypt before storage) |

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response `201 Created`**
```json
{
  "message": "User registered successfully"
}
```

**Error responses**

| Status | Reason |
|---|---|
| `400 Bad Request` | Missing `email` or `password`, or invalid body |
| `400 Bad Request` | Email already registered |

**Example**
```bash
curl -X POST http://localhost/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'
```

---

### `POST /api/auth/login`

Authenticate a user. Returns a short-lived access token and sets an `HttpOnly` refresh token cookie.

**Request body** (JSON)

| Field | Type | Required | Description |
|---|---|---|---|
| `email` | `string` | Yes | Registered email |
| `password` | `string` | Yes | Account password |

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response `200 OK`**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 1740000000
}
```

**Cookie set automatically**

| Name | `HttpOnly` | `SameSite` | Path | Max-Age |
|---|---|---|---|---|
| `refresh_token` | `true` | `Strict` | `/api/auth/refresh` | 7 days |

**Error responses**

| Status | Reason |
|---|---|
| `400 Bad Request` | Missing fields or invalid body |
| `401 Unauthorized` | Wrong email or password |

**Example**
```bash
curl -c cookies.txt -X POST http://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'
```

---

### `POST /api/auth/refresh`

Issue a new access token using the `HttpOnly` refresh token cookie.

**Requires** the `refresh_token` cookie (set automatically by `/login`).

**Response `200 OK`**
```json
{
  "user_id": "a3f1...",
  "email": "user@example.com",
  "exp": 1740000000
}
```

**Error responses**

| Status | Reason |
|---|---|
| `401 Unauthorized` | Cookie missing, invalid, or expired |

**Example**
```bash
curl -b cookies.txt -X POST http://localhost/api/auth/refresh
```

---

### `POST /api/auth/validate`

Validate a JWT access token and return its decoded claims.

**Headers**

```
Authorization: Bearer <access_token>
```

**Response `200 OK`**
```json
{
  "user_id": "a3f1...",
  "email": "user@example.com",
  "exp": 1740000000
}
```

**Error responses**

| Status | Reason |
|---|---|
| `401 Unauthorized` | Missing header, malformed token, or expired |

**Example**
```bash
curl -X POST http://localhost/api/auth/validate \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

---

## User Service

Base path: `/api/users`  
Direct port: `:8082`

All routes require a valid `Authorization: Bearer <token>` header (enforced by gateway).  
The gateway injects `X-User-ID` and `X-User-Email` headers from the verified JWT before forwarding.

### User Profile Object

```json
{
  "id": "a3f1...",
  "email": "user@example.com",
  "name": "Alice",
  "bio": "Loves bad puns.",
  "created_at": "2026-02-24T12:00:00Z",
  "updated_at": "2026-02-24T15:30:00Z"
}
```

---

### `GET /api/users/me`

Get the authenticated user's profile. Creates an empty profile on first access (lazy initialisation).

**Response `200 OK`** — [UserProfile](#user-profile-object)

**Error responses**

| Status | Reason |
|---|---|
| `401 Unauthorized` | Missing or invalid token |

**Example**
```bash
curl http://localhost/api/users/me \
  -H "Authorization: Bearer <access_token>"
```

---

### `PUT /api/users/me`

Update the authenticated user's profile. At least one field must be provided.

**Request body** (JSON)

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | `string` | At least one | Display name |
| `bio` | `string` | At least one | Short bio |

```json
{
  "name": "Alice",
  "bio": "Loves terrible puns."
}
```

**Response `200 OK`** — updated [UserProfile](#user-profile-object)

**Error responses**

| Status | Reason |
|---|---|
| `400 Bad Request` | Both `name` and `bio` are empty |
| `401 Unauthorized` | Missing or invalid token |
| `404 Not Found` | Profile does not exist |

**Example**
```bash
curl -X PUT http://localhost/api/users/me \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Alice", "bio": "Loves terrible puns."}'
```

---

### `DELETE /api/users/me`

Delete the authenticated user's profile.

**Response `200 OK`**
```json
{
  "message": "account deleted"
}
```

**Error responses**

| Status | Reason |
|---|---|
| `401 Unauthorized` | Missing or invalid token |
| `404 Not Found` | Profile does not exist |

**Example**
```bash
curl -X DELETE http://localhost/api/users/me \
  -H "Authorization: Bearer <access_token>"
```

---

### `GET /api/users/{id}`

Get a public profile by user ID. Requires authentication.

**Path parameters**

| Parameter | Type | Description |
|---|---|---|
| `id` | `string` | User ID (UUID) |

**Response `200 OK`** — [UserProfile](#user-profile-object)

**Error responses**

| Status | Reason |
|---|---|
| `400 Bad Request` | Missing `id` parameter |
| `401 Unauthorized` | Missing or invalid token |
| `404 Not Found` | Profile does not exist |

**Example**
```bash
curl http://localhost/api/users/a3f1c2d5-... \
  -H "Authorization: Bearer <access_token>"
```

---

## Joke Service

Base path: `/api/jokes`  
Direct port: `:8083`  
Transport: **GraphQL over HTTP**

The joke service exposes a single GraphQL endpoint.

---

### `GET /api/jokes/graphql`

Opens the **GraphiQL** interactive explorer in a browser. No authentication required.

```
http://localhost/api/jokes/graphql
```

---

### `POST /api/jokes/graphql`

Execute a GraphQL query or mutation.

**Request body** (JSON)

```json
{
  "query": "{ jokes { id content category } }",
  "variables": {}
}
```

**Mutations require** `Authorization: Bearer <token>`.

---

#### Query: `jokes`

List jokes, optionally filtered by category.

```graphql
query {
  jokes(category: "tech", limit: 10) {
    id
    userId
    content
    category
    createdAt
  }
}
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `category` | `String` | — | Filter by category (optional) |
| `limit` | `Int` | `20` | Max number of results |

**Response**
```json
{
  "data": {
    "jokes": [
      {
        "id": "b7e2...",
        "userId": "a3f1...",
        "content": "Why do Go devs wear glasses? Because they can't C.",
        "category": "tech",
        "createdAt": "2026-02-24T12:00:00Z"
      }
    ]
  }
}
```

---

#### Query: `joke`

Fetch a single joke by ID.

```graphql
query {
  joke(id: "b7e2...") {
    id
    userId
    content
    category
    createdAt
  }
}
```

**Arguments**

| Argument | Type | Required | Description |
|---|---|---|---|
| `id` | `String!` | Yes | Joke ID |

**Response** — single `Joke` object or `null` if not found.

---

#### Query: `randomJoke`

Fetch a random joke, optionally filtered by category.

```graphql
query {
  randomJoke(category: "dad") {
    id
    content
    category
  }
}
```

**Arguments**

| Argument | Type | Required | Description |
|---|---|---|---|
| `category` | `String` | No | Filter pool by category |

**Response** — single `Joke` object, or a GraphQL error if the pool is empty.

---

#### Mutation: `createJoke`

Create a new joke. **Requires authentication.**

```graphql
mutation {
  createJoke(content: "Why do Go devs wear glasses? Because they can't C.", category: "tech") {
    id
    userId
    content
    category
    createdAt
  }
}
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `content` | `String!` | — | Joke text |
| `category` | `String` | `"general"` | Joke category |

**Response** — the created `Joke` object.

**Error** — `"unauthorized"` if no valid token is present.

**Example**
```bash
curl -X POST http://localhost/api/jokes/graphql \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { createJoke(content: \"Why do Go devs wear glasses? Because they cant C.\", category: \"tech\") { id content createdAt } }"}'
```

---

#### Mutation: `deleteJoke`

Delete a joke you own. **Requires authentication.**

```graphql
mutation {
  deleteJoke(id: "b7e2...")
}
```

**Arguments**

| Argument | Type | Required | Description |
|---|---|---|---|
| `id` | `String!` | Yes | ID of the joke to delete |

**Response** — `true` on success.

**Errors**
- `"unauthorized"` — no valid token
- `"forbidden"` — joke exists but belongs to another user
- `"not found"` — joke ID does not exist

**Example**
```bash
curl -X POST http://localhost/api/jokes/graphql \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { deleteJoke(id: \"b7e2...\") }"}'
```

---

### GraphQL Type Reference

#### `Joke`

| Field | Type | Description |
|---|---|---|
| `id` | `String!` | UUID |
| `userId` | `String!` | Owner's user ID |
| `content` | `String!` | Joke text |
| `category` | `String!` | Joke category (e.g. `"tech"`, `"dad"`, `"general"`) |
| `createdAt` | `String!` | ISO 8601 timestamp |

---

## Error Responses

REST endpoints return plain-text error messages with the appropriate HTTP status.

| Status | Meaning |
|---|---|
| `400 Bad Request` | Malformed body or missing required fields |
| `401 Unauthorized` | Missing, invalid, or expired JWT / cookie |
| `403 Forbidden` | Authenticated but not authorised (e.g. deleting another user's joke) |
| `404 Not Found` | Resource does not exist |
| `429 Too Many Requests` | Gateway rate limit exceeded (60 req/min per IP) |
| `500 Internal Server Error` | Unexpected server error |

GraphQL errors are returned in the standard GraphQL error envelope:

```json
{
  "errors": [
    { "message": "unauthorized" }
  ],
  "data": null
}
```
