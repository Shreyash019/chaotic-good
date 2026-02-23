# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.work go.work.sum ./
COPY packages/config/  packages/config/
COPY services/gateway/ services/gateway/

RUN go build -o /bin/gateway ./services/gateway/cmd/gateway

# ── Runtime stage ───────────────────────────────────────────────────────────────
FROM alpine:3.21

RUN adduser -D -u 1001 app
COPY --from=builder /bin/gateway /bin/gateway

USER app
EXPOSE 8080
CMD ["/bin/gateway"]
