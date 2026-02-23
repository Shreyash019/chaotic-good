package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/Shreyash019/chaotic-good/packages/config"
	"github.com/Shreyash019/chaotic-good/services/user/internal/handler"
	"github.com/Shreyash019/chaotic-good/services/user/internal/repository"
	"github.com/Shreyash019/chaotic-good/services/user/internal/service"
)

func main() {
	config.Load("../../.env")
	cfg := config.LoadUserConfig()

	repo := openUserRepository()
	svc := service.NewUserService(repo)
	h := handler.NewUserHandler(svc)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User service is running"))
	})

	// Gateway strips /api/users, so service sees /me, /{id}
	mux.HandleFunc("GET /me", h.GetMe)
	mux.HandleFunc("PUT /me", h.UpdateMe)
	mux.HandleFunc("DELETE /me", h.DeleteMe)
	mux.HandleFunc("GET /{id}", h.GetByID)

	log.Printf("User service running on :%s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func openUserRepository() repository.IUserRepository {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Println("[user] DATABASE_URL not set — using in-memory store")
		return repository.NewInMemoryUserRepository()
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Printf("[user] failed to open DB: %v — falling back to in-memory store", err)
		return repository.NewInMemoryUserRepository()
	}
	if err := db.Ping(); err != nil {
		log.Printf("[user] failed to ping DB: %v — falling back to in-memory store", err)
		db.Close()
		return repository.NewInMemoryUserRepository()
	}
	log.Println("[user] connected to PostgreSQL")
	return repository.NewPostgresUserRepository(db)
}
