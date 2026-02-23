package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/shreyashkumar/funny-pipe/packages/config"
	"github.com/shreyashkumar/funny-pipe/services/auth/internal/handler"
	"github.com/shreyashkumar/funny-pipe/services/auth/internal/repository"
	"github.com/shreyashkumar/funny-pipe/services/auth/internal/service"
)

func main() {
	config.Load("../../.env")
	cfg := config.LoadAuthConfig()

	repo := openAuthRepository()
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

func openAuthRepository() repository.IAuthRepository {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Println("[auth] DATABASE_URL not set — using in-memory store")
		return repository.NewInMemoryAuthRepository()
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Printf("[auth] failed to open DB: %v — falling back to in-memory store", err)
		return repository.NewInMemoryAuthRepository()
	}
	if err := db.Ping(); err != nil {
		log.Printf("[auth] failed to ping DB: %v — falling back to in-memory store", err)
		db.Close()
		return repository.NewInMemoryAuthRepository()
	}
	log.Println("[auth] connected to PostgreSQL")
	return repository.NewPostgresAuthRepository(db)
}
