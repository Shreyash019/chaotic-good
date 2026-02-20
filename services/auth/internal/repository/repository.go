package repository

import (
	"errors"
	"sync"

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
