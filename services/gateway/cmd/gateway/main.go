package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/shreyashkumar/funny-pipe/packages/config"
	"github.com/shreyashkumar/funny-pipe/services/gateway/internal/middleware"
	"github.com/shreyashkumar/funny-pipe/services/gateway/internal/proxy"
	"github.com/shreyashkumar/funny-pipe/services/gateway/internal/router"
)

func main() {
	config.Load("../../.env")
	cfg := config.LoadGatewayConfig()

	r := router.NewRouter()
	p := proxy.NewProxy()

	p.AddTarget("auth", cfg.AuthServiceURL, "/api/auth")
	p.AddTarget("user", cfg.UserServiceURL, "/api/users")
	p.AddTarget("joke", cfg.JokeServiceURL, "/api/jokes")

	r.Register("/health", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Gateway is running")
	})
	r.Register("/api/auth/", func(w http.ResponseWriter, req *http.Request) {
		p.Forward("auth", w, req)
	})
	r.Register("/api/users/", func(w http.ResponseWriter, req *http.Request) {
		p.Forward("user", w, req)
	})
	r.Register("/api/jokes/", func(w http.ResponseWriter, req *http.Request) {
		p.Forward("joke", w, req)
	})

	handler := middleware.Chain(
		r,
		middleware.RateLimiter(middleware.RateLimiterConfig{
			RequestsPerMinute: cfg.RateLimitPerMinute,
		}),
		middleware.CORS,
		middleware.Auth(middleware.JWTConfig{
			Secret: []byte(cfg.JWTSecret),
			SkippedRoutes: []string{
				"/health",
				"/api/auth/",
			},
		}),
		middleware.Logger,
	)

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: handler,
	}

	log.Printf("Gateway running on :%s", cfg.Port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
