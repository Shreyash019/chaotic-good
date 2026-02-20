.PHONY: dev build tidy auth gateway nginx nginx-stop nginx-reload nginx-test

# Run all services
dev:
	@chmod +x scripts/dev.sh && ./scripts/dev.sh

# Build all services
build:
	@echo "Building auth-service..."
	@cd services/auth && go build ./...
	@echo "Building gateway..."
	@cd services/gateway && go build ./...
	@echo "Done!"

# Tidy all modules
tidy:
	@cd services/auth && go mod tidy
	@cd services/gateway && go mod tidy
	@go work sync
	@echo "Done!"

# Run individual services
auth:
	@cd services/auth && go run cmd/auth/main.go

gateway:
	@cd services/gateway && go run cmd/gateway/main.go

# Nginx commands
nginx:
	@echo "Starting Nginx..."
	@nginx -c $(PWD)/nginx/nginx.conf

nginx-stop:
	@echo "Stopping Nginx..."
	@nginx -s stop

nginx-reload:
	@echo "Reloading Nginx config..."
	@nginx -c $(PWD)/nginx/nginx.conf -s reload

nginx-test:
	@nginx -c $(PWD)/nginx/nginx.conf -t
