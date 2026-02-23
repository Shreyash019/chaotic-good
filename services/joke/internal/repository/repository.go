package repository

import (
	"database/sql"
	"errors"
	"math/rand"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/shreyashkumar/funny-pipe/services/joke/internal/model"
)

// ─── Interface ────────────────────────────────────────────────────────────────

type IJokeRepository interface {
	GetByID(id string) (*model.Joke, error)
	List(category string, limit int) ([]*model.Joke, error)
	Random(category string) (*model.Joke, error)
	Create(userID string, input *model.CreateJokeInput) (*model.Joke, error)
	Delete(id, userID string) error
}

// ─── In-Memory ────────────────────────────────────────────────────────────────

type InMemoryJokeRepository struct {
	mu    sync.RWMutex
	jokes []*model.Joke // ordered slice so Random is easy
}

func NewInMemoryJokeRepository() IJokeRepository {
	return &InMemoryJokeRepository{}
}

func (r *InMemoryJokeRepository) GetByID(id string) (*model.Joke, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, j := range r.jokes {
		if j.ID == id {
			return j, nil
		}
	}
	return nil, errors.New("joke not found")
}

func (r *InMemoryJokeRepository) List(category string, limit int) ([]*model.Joke, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*model.Joke
	for _, j := range r.jokes {
		if category == "" || j.Category == category {
			result = append(result, j)
		}
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result, nil
}

func (r *InMemoryJokeRepository) Random(category string) (*model.Joke, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var pool []*model.Joke
	for _, j := range r.jokes {
		if category == "" || j.Category == category {
			pool = append(pool, j)
		}
	}
	if len(pool) == 0 {
		return nil, errors.New("no jokes found")
	}
	return pool[rand.Intn(len(pool))], nil
}

func (r *InMemoryJokeRepository) Create(userID string, input *model.CreateJokeInput) (*model.Joke, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j := &model.Joke{
		ID:        generateID(),
		UserID:    userID,
		Content:   input.Content,
		Category:  input.Category,
		CreatedAt: time.Now(),
	}
	r.jokes = append(r.jokes, j)
	return j, nil
}

func (r *InMemoryJokeRepository) Delete(id, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, j := range r.jokes {
		if j.ID == id {
			if j.UserID != userID {
				return errors.New("forbidden: not the owner")
			}
			r.jokes = append(r.jokes[:i], r.jokes[i+1:]...)
			return nil
		}
	}
	return errors.New("joke not found")
}

// ─── PostgreSQL ───────────────────────────────────────────────────────────────

type PostgresJokeRepository struct {
	db *sql.DB
}

func NewPostgresJokeRepository(db *sql.DB) IJokeRepository {
	return &PostgresJokeRepository{db: db}
}

func (r *PostgresJokeRepository) GetByID(id string) (*model.Joke, error) {
	row := r.db.QueryRow(
		`SELECT id, user_id, content, category, created_at FROM jokes WHERE id = $1`, id,
	)
	j := &model.Joke{}
	if err := row.Scan(&j.ID, &j.UserID, &j.Content, &j.Category, &j.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("joke not found")
		}
		return nil, err
	}
	return j, nil
}

func (r *PostgresJokeRepository) List(category string, limit int) ([]*model.Joke, error) {
	if limit <= 0 {
		limit = 20
	}
	var (
		rows *sql.Rows
		err  error
	)
	if category != "" {
		rows, err = r.db.Query(
			`SELECT id, user_id, content, category, created_at
			 FROM jokes WHERE category = $1 ORDER BY created_at DESC LIMIT $2`,
			category, limit,
		)
	} else {
		rows, err = r.db.Query(
			`SELECT id, user_id, content, category, created_at
			 FROM jokes ORDER BY created_at DESC LIMIT $1`,
			limit,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jokes []*model.Joke
	for rows.Next() {
		j := &model.Joke{}
		if err := rows.Scan(&j.ID, &j.UserID, &j.Content, &j.Category, &j.CreatedAt); err != nil {
			return nil, err
		}
		jokes = append(jokes, j)
	}
	return jokes, rows.Err()
}

func (r *PostgresJokeRepository) Random(category string) (*model.Joke, error) {
	var row *sql.Row
	if category != "" {
		row = r.db.QueryRow(
			`SELECT id, user_id, content, category, created_at
			 FROM jokes WHERE category = $1 ORDER BY RANDOM() LIMIT 1`, category,
		)
	} else {
		row = r.db.QueryRow(
			`SELECT id, user_id, content, category, created_at
			 FROM jokes ORDER BY RANDOM() LIMIT 1`,
		)
	}
	j := &model.Joke{}
	if err := row.Scan(&j.ID, &j.UserID, &j.Content, &j.Category, &j.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("no jokes found")
		}
		return nil, err
	}
	return j, nil
}

func (r *PostgresJokeRepository) Create(userID string, input *model.CreateJokeInput) (*model.Joke, error) {
	id := generateID()
	now := time.Now()
	_, err := r.db.Exec(
		`INSERT INTO jokes (id, user_id, content, category, created_at) VALUES ($1, $2, $3, $4, $5)`,
		id, userID, input.Content, input.Category, now,
	)
	if err != nil {
		return nil, err
	}
	return &model.Joke{ID: id, UserID: userID, Content: input.Content, Category: input.Category, CreatedAt: now}, nil
}

func (r *PostgresJokeRepository) Delete(id, userID string) error {
	res, err := r.db.Exec(`DELETE FROM jokes WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Could be not found or not owner — check which
		var exists bool
		r.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM jokes WHERE id = $1)`, id).Scan(&exists)
		if !exists {
			return errors.New("joke not found")
		}
		return errors.New("forbidden: not the owner")
	}
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func generateID() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 12)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
