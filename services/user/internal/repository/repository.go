package repository

import (
	"database/sql"
	"errors"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/shreyashkumar/funny-pipe/services/user/internal/model"
)

type IUserRepository interface {
	GetByID(id string) (*model.UserProfile, error)
	Upsert(profile *model.UserProfile) error
	Update(id string, req *model.UpdateProfileRequest) (*model.UserProfile, error)
	Delete(id string) error
}

type InMemoryUserRepository struct {
	mu       sync.RWMutex
	profiles map[string]*model.UserProfile
}

func NewInMemoryUserRepository() IUserRepository {
	return &InMemoryUserRepository{
		profiles: make(map[string]*model.UserProfile),
	}
}

func (r *InMemoryUserRepository) GetByID(id string) (*model.UserProfile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, exists := r.profiles[id]
	if !exists {
		return nil, errors.New("user profile not found")
	}
	return p, nil
}

// Upsert creates profile if it doesn't exist yet (lazy creation on first request)
func (r *InMemoryUserRepository) Upsert(profile *model.UserProfile) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.profiles[profile.ID]; !exists {
		r.profiles[profile.ID] = profile
	}
	return nil
}

func (r *InMemoryUserRepository) Update(id string, req *model.UpdateProfileRequest) (*model.UserProfile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, exists := r.profiles[id]
	if !exists {
		return nil, errors.New("user profile not found")
	}

	if req.Name != "" {
		p.Name = req.Name
	}
	if req.Bio != "" {
		p.Bio = req.Bio
	}
	p.UpdatedAt = time.Now()

	return p, nil
}

func (r *InMemoryUserRepository) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.profiles[id]; !exists {
		return errors.New("user profile not found")
	}

	delete(r.profiles, id)
	return nil
}

// ─── PostgreSQL implementation ────────────────────────────────────────────────

type PostgresUserRepository struct {
	db *sql.DB
}

func NewPostgresUserRepository(db *sql.DB) IUserRepository {
	return &PostgresUserRepository{db: db}
}

func (r *PostgresUserRepository) GetByID(id string) (*model.UserProfile, error) {
	row := r.db.QueryRow(
		`SELECT id, email, name, bio, created_at, updated_at FROM user_profiles WHERE id = $1`, id,
	)
	p := &model.UserProfile{}
	if err := row.Scan(&p.ID, &p.Email, &p.Name, &p.Bio, &p.CreatedAt, &p.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user profile not found")
		}
		return nil, err
	}
	return p, nil
}

// Upsert inserts a profile if it doesn't already exist (called lazily on first request).
func (r *PostgresUserRepository) Upsert(profile *model.UserProfile) error {
	_, err := r.db.Exec(
		`INSERT INTO user_profiles (id, email, name, bio, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (id) DO NOTHING`,
		profile.ID, profile.Email, profile.Name, profile.Bio, profile.CreatedAt, profile.UpdatedAt,
	)
	return err
}

func (r *PostgresUserRepository) Update(id string, req *model.UpdateProfileRequest) (*model.UserProfile, error) {
	row := r.db.QueryRow(
		`UPDATE user_profiles
		 SET name       = COALESCE(NULLIF($2, ''), name),
		     bio        = COALESCE(NULLIF($3, ''), bio),
		     updated_at = now()
		 WHERE id = $1
		 RETURNING id, email, name, bio, created_at, updated_at`,
		id, req.Name, req.Bio,
	)
	p := &model.UserProfile{}
	if err := row.Scan(&p.ID, &p.Email, &p.Name, &p.Bio, &p.CreatedAt, &p.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user profile not found")
		}
		return nil, err
	}
	return p, nil
}

func (r *PostgresUserRepository) Delete(id string) error {
	res, err := r.db.Exec(`DELETE FROM user_profiles WHERE id = $1`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("user profile not found")
	}
	return nil
}
