# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.work go.work.sum ./
COPY packages/config/ packages/config/
COPY services/joke/   services/joke/

RUN go build -o /bin/joke ./services/joke/cmd/joke

# ── Runtime stage ───────────────────────────────────────────────────────────────
FROM alpine:3.21

RUN adduser -D -u 1001 app
COPY --from=builder /bin/joke /bin/joke

USER app
EXPOSE 8083
CMD ["/bin/joke"]
