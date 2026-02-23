package service

import (
	"time"

	"github.com/Shreyash019/chaotic-good/services/user/internal/model"
	"github.com/Shreyash019/chaotic-good/services/user/internal/repository"
)

type IUserService interface {
	GetProfile(userID, email string) (*model.UserProfile, error)
	UpdateProfile(userID string, req *model.UpdateProfileRequest) (*model.UserProfile, error)
	DeleteProfile(userID string) error
}

type UserService struct {
	repo repository.IUserRepository
}

func NewUserService(repo repository.IUserRepository) IUserService {
	return &UserService{repo: repo}
}

// GetProfile fetches the profile, lazily creating it on first access
func (s *UserService) GetProfile(userID, email string) (*model.UserProfile, error) {
	// Lazily create profile if it doesn't exist yet
	_ = s.repo.Upsert(&model.UserProfile{
		ID:        userID,
		Email:     email,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	return s.repo.GetByID(userID)
}

func (s *UserService) UpdateProfile(userID string, req *model.UpdateProfileRequest) (*model.UserProfile, error) {
	return s.repo.Update(userID, req)
}

func (s *UserService) DeleteProfile(userID string) error {
	return s.repo.Delete(userID)
}
