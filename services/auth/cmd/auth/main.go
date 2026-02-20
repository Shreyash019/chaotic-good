package main

import (
	"log"
	"net/http"

	"github.com/shreyashkumar/funny-pipe/packages/config"
	"github.com/shreyashkumar/funny-pipe/services/auth/internal/handler"
	"github.com/shreyashkumar/funny-pipe/services/auth/internal/repository"
	"github.com/shreyashkumar/funny-pipe/services/auth/internal/service"
)

func main() {
	config.Load("../../.env")
	cfg := config.LoadAuthConfig()

	repo := repository.NewInMemoryAuthRepository()
	svc := service.NewAuthService(repo, cfg.JWTSecret)
	h := handler.NewAuthHandler(svc)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Auth service is running"))
	})
	mux.HandleFunc("POST /register", h.Register)
	mux.HandleFunc("POST /login", h.Login)
	mux.HandleFunc("POST /refresh", h.Refresh)
	mux.HandleFunc("POST /validate", h.ValidateToken)

	log.Printf("Auth service running on :%s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
