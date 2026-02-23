package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/Shreyash019/chaotic-good/packages/config"
	"github.com/Shreyash019/chaotic-good/services/joke/internal/handler"
	"github.com/Shreyash019/chaotic-good/services/joke/internal/repository"
	"github.com/Shreyash019/chaotic-good/services/joke/internal/schema"
)

func main() {
	config.Load("../../.env")
	cfg := config.LoadJokeConfig()

	repo := openJokeRepository()

	gqlSchema, err := schema.Build(repo)
	if err != nil {
		log.Fatalf("Failed to build GraphQL schema: %v", err)
	}

	gqlHandler := handler.NewGraphQLHandler(gqlSchema)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Joke service is running"))
	})

	// Both GET (GraphiQL explorer) and POST (query execution) on /graphql
	mux.Handle("/graphql", gqlHandler)

	log.Printf("Joke service running on :%s  (GraphQL at /graphql)", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func openJokeRepository() repository.IJokeRepository {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Println("[joke] DATABASE_URL not set — using in-memory store")
		return repository.NewInMemoryJokeRepository()
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Printf("[joke] failed to open DB: %v — falling back to in-memory store", err)
		return repository.NewInMemoryJokeRepository()
	}
	if err := db.Ping(); err != nil {
		log.Printf("[joke] failed to ping DB: %v — falling back to in-memory store", err)
		db.Close()
		return repository.NewInMemoryJokeRepository()
	}
	log.Println("[joke] connected to PostgreSQL")
	return repository.NewPostgresJokeRepository(db)
}
