#!/bin/bash

ROOT=$(cd "$(dirname "$0")/.." && pwd)

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PIDS=()

cleanup() {
  echo -e "\n${YELLOW}Shutting down all services...${NC}"
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null
  done
  echo -e "${YELLOW}Stopping Nginx...${NC}"
  nginx -s stop 2>/dev/null
  exit 0
}

trap cleanup SIGINT SIGTERM

echo -e "${GREEN}Starting Funny-API services...${NC}\n"

# Start Auth Service
cd "$ROOT/services/auth"
go run cmd/auth/main.go &
PIDS+=($!)
echo -e "${GREEN}[auth-service]${NC}   started on :8081 (PID $!)"

# Start Gateway
cd "$ROOT/services/gateway"
go run cmd/gateway/main.go &
PIDS+=($!)
echo -e "${GREEN}[gateway]${NC}        started on :8080 (PID $!)"

# Start Nginx
sleep 1  # wait for gateway to be ready
nginx -c "$ROOT/nginx/nginx.conf"
echo -e "${GREEN}[nginx]${NC}          started on :80"

echo -e "\n${YELLOW}All services running. Press Ctrl+C to stop.${NC}"
echo -e "${YELLOW}Traffic flow: :80 (Nginx) -> :8080 (Gateway) -> :8081 (Auth)${NC}\n"

wait
