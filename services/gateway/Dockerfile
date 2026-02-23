# -- Build stage ----------------------------------------------------------------
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy workspace definition
COPY go.work go.work.sum ./

# Copy go.mod for every workspace module (go.work requires all to be present)
COPY packages/config/go.mod  packages/config/go.mod
COPY services/auth/go.mod    services/auth/go.mod
COPY services/user/go.mod    services/user/go.mod
COPY services/joke/go.mod    services/joke/go.mod
COPY services/gateway/go.mod services/gateway/go.mod

# Copy full source for this service and its dependencies
COPY packages/config/ packages/config/
COPY services/gateway/ services/gateway/

RUN go build -o /bin/gateway ./services/gateway/cmd/gateway

# -- Runtime stage ---------------------------------------------------------------
FROM alpine:3.21

RUN adduser -D -u 1001 app
COPY --from=builder /bin/gateway /bin/gateway

USER app
EXPOSE 8080
CMD ["/bin/gateway"]
