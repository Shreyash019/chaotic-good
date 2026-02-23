# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.work go.work.sum ./
COPY packages/config/ packages/config/
COPY services/user/   services/user/

RUN go build -o /bin/user ./services/user/cmd/user

# ── Runtime stage ───────────────────────────────────────────────────────────────
FROM alpine:3.21

RUN adduser -D -u 1001 app
COPY --from=builder /bin/user /bin/user

USER app
EXPOSE 8082
CMD ["/bin/user"]
