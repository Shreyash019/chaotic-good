package repository

import (
	"database/sql"
	"errors"
	"strings"
	"sync"

	_ "github.com/lib/pq"
	"github.com/shreyashkumar/funny-pipe/services/auth/internal/model"
)

// IAuthRepository defines the interface for auth repository
type IAuthRepository interface {
	CreateUser(user *model.User) error
	GetUserByEmail(email string) (*model.User, error)
	GetUserByID(id string) (*model.User, error)
}

// InMemoryAuthRepository is a simple in-memory implementation
// TODO: Replace with real database (PostgreSQL, MongoDB)
type InMemoryAuthRepository struct {
	mu    sync.RWMutex
	users map[string]*model.User // key: email
}

func NewInMemoryAuthRepository() IAuthRepository {
	return &InMemoryAuthRepository{
		users: make(map[string]*model.User),
	}
}

func (r *InMemoryAuthRepository) CreateUser(user *model.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.users[user.Email]; exists {
		return errors.New("user already exists")
	}

	r.users[user.Email] = user
	return nil
}

func (r *InMemoryAuthRepository) GetUserByEmail(email string) (*model.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, exists := r.users[email]
	if !exists {
		return nil, errors.New("user not found")
	}

	return user, nil
}

func (r *InMemoryAuthRepository) GetUserByID(id string) (*model.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, user := range r.users {
		if user.ID == id {
			return user, nil
		}
	}

	return nil, errors.New("user not found")
}

// ─── PostgreSQL implementation ────────────────────────────────────────────────

type PostgresAuthRepository struct {
	db *sql.DB
}

func NewPostgresAuthRepository(db *sql.DB) IAuthRepository {
	return &PostgresAuthRepository{db: db}
}

func (r *PostgresAuthRepository) CreateUser(user *model.User) error {
	_, err := r.db.Exec(
		`INSERT INTO users (id, email, password_hash, created_at) VALUES ($1, $2, $3, $4)`,
		user.ID, user.Email, user.Password, user.CreatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			return errors.New("user already exists")
		}
		return err
	}
	return nil
}

func (r *PostgresAuthRepository) GetUserByEmail(email string) (*model.User, error) {
	row := r.db.QueryRow(
		`SELECT id, email, password_hash, created_at FROM users WHERE email = $1`, email,
	)
	u := &model.User{}
	if err := row.Scan(&u.ID, &u.Email, &u.Password, &u.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return u, nil
}

func (r *PostgresAuthRepository) GetUserByID(id string) (*model.User, error) {
	row := r.db.QueryRow(
		`SELECT id, email, password_hash, created_at FROM users WHERE id = $1`, id,
	)
	u := &model.User{}
	if err := row.Scan(&u.ID, &u.Email, &u.Password, &u.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return u, nil
}
