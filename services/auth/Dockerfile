# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy workspace definition first (better layer caching)
COPY go.work go.work.sum ./

# Copy only the modules this service depends on
COPY packages/config/ packages/config/
COPY services/auth/   services/auth/

RUN go build -o /bin/auth ./services/auth/cmd/auth

# ── Runtime stage ───────────────────────────────────────────────────────────────
FROM alpine:3.21

RUN adduser -D -u 1001 app
COPY --from=builder /bin/auth /bin/auth

USER app
EXPOSE 8081
CMD ["/bin/auth"]
